"""Physical Yarn Modern lock assertions, separate from application ownership."""

from __future__ import annotations

import json
import re
from typing import Any

from depcheck.ecosystems.base import ProviderContext
from depcheck.ecosystems.javascript_packages import (
    exact_version,
    package_ref,
    registry_name,
)
from depcheck.ecosystems.static import DEFAULT_MAX_BYTES, StaticReadError, read_text
from depcheck.ecosystems.yaml_reader import read_lock_yaml
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    ProjectUnit,
    SourceLocation,
    VersionConstraint,
)

_MAX_ENTRIES = 20_000
_CONTEXT_FIELDS = frozenset(
    {
        "conditions",
        "checksum",
        "languageName",
        "linkType",
        "dependencies",
        "peerDependencies",
        "dependenciesMeta",
        "peerDependenciesMeta",
        "bin",
    }
)
_COORDINATE = re.compile(r"((?:@[^/]+/)?[^@/]+)@(.+)")


def _coordinate(value: str) -> tuple[str, str]:
    match = _COORDINATE.fullmatch(value) if len(value) <= 4096 else None
    if match is None:
        raise StaticReadError("Unsupported Yarn descriptor or locator")
    return registry_name(match[1]), match[2]


def _context_supported(key: str, value: Any) -> bool:
    if key in {"dependencies", "peerDependencies", "bin"}:
        return isinstance(value, dict) and all(
            isinstance(v, str) for v in value.values()
        )
    if key in {"dependenciesMeta", "peerDependenciesMeta"}:
        fields = (
            {"built", "optional", "unplugged"}
            if key == "dependenciesMeta"
            else {"optional"}
        )
        return isinstance(value, dict) and all(
            isinstance(v, dict)
            and not v.keys() - fields
            and all(
                isinstance(x, str) and x in {"true", "false"} or isinstance(x, bool)
                for x in v.values()
            )
            for v in value.values()
        )
    return isinstance(value, str) and (key != "linkType" or value in {"hard", "soft"})


def collect_yarn_inventory(
    context: ProviderContext, project: ProjectUnit
) -> EvidenceBundle:
    path = context.repository_root / project.manifests[0]
    declarations: list[DependencyDeclaration] = []
    diagnostics: list[Diagnostic] = []

    def issue(message: str, source: SourceLocation) -> None:
        if len(diagnostics) >= 64:
            raise StaticReadError("Yarn inventory diagnostic budget exceeded")
        diagnostics.append(
            Diagnostic("manifest.yarn-lock-incomplete", "warning", message, source)
        )

    try:
        locations: dict[str, tuple[int, int]] = {}
        document = read_lock_yaml(read_text(path), key_locations=locations)
        metadata = document.get("__metadata")
        if not isinstance(metadata, dict) or metadata.get("version") not in {"8", "10"}:
            raise StaticReadError(
                "Only Yarn Modern lock versions 8 and 10 are collected"
            )
        if metadata.keys() - {"version", "cacheKey"} or not isinstance(
            metadata.get("cacheKey", ""), str
        ):
            issue("Uncollected Yarn lock header assertions", SourceLocation(path))
        count = size = 0
        for key, record in document.items():
            if key == "__metadata":
                continue
            source = SourceLocation(path, *locations[key])
            if len(key) > 65_536:
                issue(
                    "Yarn descriptor group exceeds the text budget; this record was omitted",
                    source,
                )
                continue
            if not isinstance(record, dict) or not isinstance(
                record.get("resolution"), str
            ):
                issue(
                    "Yarn record requires a literal resolution; this record was omitted",
                    source,
                )
                continue
            try:
                name, reference = _coordinate(record["resolution"])
            except StaticReadError as exc:
                issue(str(exc), source)
                continue
            version = record.get("version")
            status = (
                "canonical-npm-assertion"
                if isinstance(version, str)
                and exact_version(version)
                and reference == "npm:" + version
                else "conflicting-npm-assertion"
                if reference.startswith("npm:")
                else "non-registry-assertion"
            )
            if not isinstance(version, str) or status == "conflicting-npm-assertion":
                issue(
                    "Yarn version and registry locator do not establish one canonical assertion",
                    source,
                )
            unknown = record.keys() - _CONTEXT_FIELDS - {"version", "resolution"}
            if unknown:
                issue("Uncollected Yarn record fields were omitted", source)
            context_assertions = {}
            for field in sorted(_CONTEXT_FIELDS & record.keys()):
                try:
                    json.dumps(record[field], allow_nan=False)
                except (TypeError, ValueError):
                    issue(
                        "Non-JSON Yarn context was omitted; its value remains unknown",
                        source,
                    )
                    continue
                context_assertions[field] = record[field]
            if not all(_context_supported(k, v) for k, v in context_assertions.items()):
                issue(
                    "Yarn context has unsupported shapes; retained values remain uninterpreted assertions",
                    source,
                )
            assertion: dict[str, Any] = {
                "yarn_kind": "lock-record",
                "lock_version": metadata["version"],
                "cache_key_assertion": metadata.get("cacheKey")
                if isinstance(metadata.get("cacheKey"), str)
                else None,
                "resolution_assertion": record["resolution"],
                "version_assertion": version if isinstance(version, str) else None,
                "version_status": status,
                "context": context_assertions,
                "application_ownership": "unknown",
                "activation": "unknown",
                "origin": {
                    "kind": "unknown",
                    "public": False,
                    "basis": "yarn-lock-assertion",
                    "reason": "yarn-source-and-activation-unverified",
                },
            }
            for descriptor in re.split(r" *, *", key):
                count += 1
                if count > _MAX_ENTRIES:
                    raise StaticReadError("Yarn inventory entry budget exceeded")
                try:
                    installation, request = _coordinate(descriptor)
                except StaticReadError as exc:
                    issue(str(exc), source)
                    continue
                item = {
                    **assertion,
                    "descriptor": descriptor,
                    "installation_name": installation,
                }
                size += len(json.dumps(item).encode("utf-8")) + len(
                    json.dumps(request).encode("utf-8")
                )
                if size > DEFAULT_MAX_BYTES:
                    raise StaticReadError(
                        "Yarn inventory metadata expansion budget exceeded"
                    )
                declarations.append(
                    DependencyDeclaration(
                        project.project_id,
                        package_ref(name, public=False),
                        VersionConstraint(request, "yarn-lock"),
                        source,
                        scope="unknown",
                        kind="conditional",
                        metadata=item,
                    )
                )
    except StaticReadError as exc:
        diagnostics.append(
            Diagnostic(
                "manifest.yarn-lock-invalid", "error", str(exc), SourceLocation(path)
            )
        )
    manifest_complete = not diagnostics
    diagnostics.append(
        Diagnostic(
            "resolution.yarn-activation-unknown",
            "warning",
            "Yarn lock records are configuration inventory. Application/workspace ownership, registry selection, overrides, peer virtualization, PnP, installation and source usage remain uncollected; no public advisory coordinates or application edges are inferred.",
            SourceLocation(path),
        )
    )
    return EvidenceBundle(
        project,
        declarations=tuple(declarations),
        diagnostics=tuple(diagnostics),
        capabilities=(
            Capability(
                "manifest",
                CapabilityState.COMPLETE
                if manifest_complete
                else CapabilityState.INCOMPLETE,
            ),
            Capability(
                "resolution",
                CapabilityState.INCOMPLETE,
                "Yarn activation and ownership are unknown",
            ),
            Capability(
                "usage",
                CapabilityState.UNSUPPORTED,
                "Yarn lock inventory does not establish source usage",
            ),
            Capability(
                "mapping",
                CapabilityState.UNSUPPORTED,
                "Yarn lock inventory does not bind application imports",
            ),
        ),
        evidence_files=(path,),
    )
