"""Static Gradle TOML library definitions, without binding them to a build."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
import json
import re
import tomllib
from typing import Any

from depcheck.ecosystems.base import ProviderContext
from depcheck.ecosystems.maven_identity import package_ref
from depcheck.ecosystems.static import DEFAULT_MAX_BYTES, StaticReadError, read_text
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
from depcheck.source_locations import SourcePositions

_ALIAS = re.compile(r"[a-z][A-Za-z0-9_.-]*\Z")
_COORDINATE_PART = re.compile(r"[A-Za-z0-9_.-]+\Z")
_MAX_ENTRIES = 20_000
_RICH_KEYS = {"require", "strictly", "prefer", "reject", "rejectAll"}


def _normalize(alias: str) -> str:
    return alias.replace("-", ".").replace("_", ".")


def _names(table: Mapping[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for alias in table:
        result[_normalize(alias)].append(alias)
    return result


def _version_supported(value: Any) -> bool:
    if isinstance(value, str):
        return True
    if not isinstance(value, dict) or value.keys() - _RICH_KEYS:
        return False
    for key, item in value.items():
        if key in {"require", "strictly", "prefer"}:
            if not isinstance(item, str):
                return False
        elif key == "rejectAll":
            if not isinstance(item, bool):
                return False
        elif not isinstance(item, list) or not all(isinstance(x, str) for x in item):
            return False
    return True


class _Catalog:
    def __init__(
        self, context: ProviderContext, project: ProjectUnit, path: Path
    ) -> None:
        self.context, self.project, self.path = context, project, path
        self.declarations: list[DependencyDeclaration] = []
        self.diagnostics: list[Diagnostic] = []
        self.size = 0

    def issue(self, suffix: str, message: str, source: SourceLocation) -> None:
        if len(self.diagnostics) >= 64:
            raise StaticReadError("Gradle catalog diagnostic budget exceeded")
        self.diagnostics.append(
            Diagnostic("manifest.gradle-catalog-" + suffix, "warning", message, source)
        )

    def table(self, data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
        value = data.get(name, {})
        if not isinstance(value, dict):
            self.issue(
                "unsupported",
                f"Catalog {name} must be a table; its entries are uncollected.",
                self.positions.value(name),
            )
            return {}
        return value

    def value(
        self, value: Any, source: SourceLocation
    ) -> tuple[VersionConstraint, dict[str, Any]]:
        supported = _version_supported(value)
        if not supported:
            self.issue(
                "unsupported-version",
                "Catalog version shape is uncollected; no version is selected.",
                source,
            )
        assertion = value if supported else None
        raw = (
            value
            if isinstance(value, str)
            else json.dumps(assertion, sort_keys=True)
            if supported
            else ""
        )
        return VersionConstraint(
            raw, "gradle-catalog", value or None if isinstance(value, str) else None
        ), {
            "version_assertion": assertion,
            "version_source": source.to_dict(self.context.repository_root),
            "version_status": "literal"
            if isinstance(value, str)
            else "rich"
            if supported
            else "unsupported",
        }

    def version(
        self, alias: str, value: Any
    ) -> tuple[VersionConstraint, dict[str, Any]]:
        source = self.positions.value("libraries", alias, "version")
        if isinstance(value, dict) and "ref" in value:
            reference = value.get("ref")
            reference_source = self.positions.value(
                "libraries", alias, "version", "ref"
            )
            metadata: dict[str, Any] = {
                "version_assertion": None,
                "version_status": "unresolved",
                "version_reference": reference if isinstance(reference, str) else None,
                "version_reference_source": reference_source.to_dict(
                    self.context.repository_root
                ),
            }
            constraint = VersionConstraint(
                json.dumps({"ref": metadata["version_reference"]}), "gradle-catalog"
            )
            names = (
                self.version_names.get(_normalize(reference), [])
                if isinstance(reference, str)
                else []
            )
            if value.keys() == {"ref"} and len(names) == 1:
                target, target_metadata = self.versions[names[0]]
                metadata.update(target_metadata)
                constraint = VersionConstraint(
                    constraint.raw, "gradle-catalog", target.normalized
                )
            else:
                self.issue(
                    "reference-unresolved",
                    "Catalog version reference is missing, ambiguous or mixed with inline fields; external overrides are unevaluated.",
                    reference_source,
                )
            return constraint, metadata
        return self.value(value, source)

    def read(self) -> None:
        text = read_text(self.path)
        data = tomllib.loads(text)
        self.positions = SourcePositions.toml(self.path, text)
        sections = ("versions", "libraries", "bundles", "plugins")
        tables = {name: self.table(data, name) for name in sections}
        if sum(len(t) for t in tables.values()) > _MAX_ENTRIES:
            raise StaticReadError("Gradle catalog entry budget exceeded")
        for name in data.keys() - set(sections):
            self.issue(
                "unsupported",
                "Uncollected catalog section; its semantics are unknown.",
                self.positions.key(name),
            )
        if tables["plugins"]:
            self.issue(
                "plugins-uncollected",
                "Catalog plugin IDs are uncollected; they do not establish Maven package coordinates or execution.",
                self.positions.key("plugins"),
            )
        self.version_names = _names(tables["versions"])
        self.versions = {
            alias: self.value(v, self.positions.value("versions", alias))
            for alias, v in tables["versions"].items()
        }
        libraries = tables["libraries"]
        library_names = _names(libraries)
        for section, names in (
            ("versions", self.version_names),
            ("libraries", library_names),
            ("bundles", _names(tables["bundles"])),
        ):
            for aliases in names.values():
                if len(aliases) > 1:
                    self.issue(
                        "alias-ambiguous",
                        "Aliases normalize to the same accessor; all assertions remain distinct and no binding is chosen.",
                        self.positions.key(section, aliases[1]),
                    )
        memberships = self.bundles(tables["bundles"], library_names)
        for alias, value in libraries.items():
            source = self.positions.key("libraries", alias)
            normalized = _normalize(alias)
            alias_valid = (
                bool(_ALIAS.fullmatch(alias))
                and normalized not in {"extensions", "convention"}
                and "class" not in normalized.split(".")
                and normalized.split(".")[0] not in {"bundles", "versions", "plugins"}
            )
            if not alias_valid:
                self.issue(
                    "unsupported-alias",
                    "Unsupported or reserved library alias; its literal coordinate assertion is retained without a binding.",
                    source,
                )
            coordinate: list[str] = []
            if isinstance(value, str):
                coordinate = value.split(":")
                if len(coordinate) == 3:
                    constraint, metadata = self.value(
                        coordinate.pop(), self.positions.value("libraries", alias)
                    )
                else:
                    coordinate = []
            elif isinstance(value, dict):
                if "module" in value and not ({"group", "name"} & value.keys()):
                    if isinstance(value["module"], str):
                        coordinate = value["module"].split(":")
                elif "module" not in value and all(
                    isinstance(value.get(k), str) for k in ("group", "name")
                ):
                    coordinate = [value["group"], value["name"]]
                if "version" in value:
                    constraint, metadata = self.version(alias, value["version"])
                else:
                    constraint = VersionConstraint("", "gradle-catalog")
                    metadata = {
                        "version_assertion": None,
                        "version_status": "unspecified",
                    }
                if value.keys() - {"module", "group", "name", "version"}:
                    self.issue(
                        "unsupported",
                        "Library fields outside the supported catalog notation are uncollected.",
                        source,
                    )
            if len(coordinate) != 2 or not all(
                _COORDINATE_PART.fullmatch(x) for x in coordinate
            ):
                self.issue(
                    "unsupported-library",
                    "Library identity is not an unambiguous literal group:artifact; no package is invented.",
                    source,
                )
                continue
            metadata.update(
                {
                    "gradle_kind": "catalog-library",
                    "gradle_catalog_alias": alias,
                    "catalog_file": self.path.relative_to(
                        self.context.repository_root
                    ).as_posix(),
                    "accessor_path": normalized,
                    "activation": "unknown",
                    "catalog_binding": "unknown",
                    "alias_status": "ambiguous"
                    if len(library_names[normalized]) > 1
                    else "literal"
                    if alias_valid
                    else "unsupported",
                    "bundles": memberships.get(alias, []),
                }
            )
            self.size += len(json.dumps(metadata).encode("utf-8")) + len(
                constraint.raw.encode("utf-8")
            )
            if self.size > DEFAULT_MAX_BYTES:
                raise StaticReadError(
                    "Gradle catalog metadata expansion budget exceeded"
                )
            self.declarations.append(
                DependencyDeclaration(
                    self.project.project_id,
                    package_ref(":".join(coordinate)),
                    constraint,
                    source,
                    scope="unknown",
                    kind="conditional",
                    metadata=metadata,
                )
            )

    def bundles(
        self, table: Mapping[str, Any], names: Mapping[str, list[str]]
    ) -> dict[str, list[dict[str, Any]]]:
        memberships: dict[str, list[dict[str, Any]]] = defaultdict(list)
        size = count = 0
        for alias, members in table.items():
            source = self.positions.value("bundles", alias)
            if not isinstance(members, list):
                self.issue(
                    "unsupported-bundle",
                    "Bundle members must be library alias strings; membership is uncollected.",
                    source,
                )
                continue
            for index, member in enumerate(members):
                count += 1
                location = self.positions.value("bundles", alias, index)
                candidates = (
                    names.get(_normalize(member), []) if isinstance(member, str) else []
                )
                if len(candidates) != 1:
                    self.issue(
                        "reference-unresolved",
                        "Bundle member has no unique library in this file; no dependency is invented.",
                        location,
                    )
                    continue
                metadata = {
                    "alias": alias,
                    "member": member,
                    "bundle_source": source.to_dict(self.context.repository_root),
                    "member_source": location.to_dict(self.context.repository_root),
                }
                size += len(json.dumps(metadata).encode("utf-8"))
                if count > _MAX_ENTRIES or size > DEFAULT_MAX_BYTES:
                    self.issue(
                        "budget",
                        "Catalog bundle expansion is incomplete after its evidence budget.",
                        location,
                    )
                    return memberships
                memberships[candidates[0]].append(metadata)
        return memberships


def collect_gradle_catalogs(
    context: ProviderContext, project: ProjectUnit
) -> EvidenceBundle:
    declarations: list[DependencyDeclaration] = []
    diagnostics: list[Diagnostic] = []
    for relative in project.manifests:
        catalog = _Catalog(context, project, context.repository_root / relative)
        try:
            catalog.read()
        except (StaticReadError, tomllib.TOMLDecodeError, RecursionError) as exc:
            catalog.diagnostics.append(
                Diagnostic(
                    "manifest.gradle-catalog-budget"
                    if isinstance(exc, StaticReadError) and "budget" in str(exc)
                    else "manifest.gradle-catalog-invalid",
                    "error",
                    str(exc),
                    SourceLocation(catalog.path),
                )
            )
        declarations.extend(catalog.declarations)
        diagnostics.extend(catalog.diagnostics)
    manifest_complete = not diagnostics
    diagnostics.append(
        Diagnostic(
            "resolution.gradle-catalog-activation-unknown",
            "warning",
            "Catalog definitions are configuration inventory. Catalog names/imports, programmatic overrides, build usage, selected versions and installed graph remain uncollected.",
            SourceLocation(context.repository_root / project.manifests[0]),
        )
    )
    return EvidenceBundle(
        project,
        declarations=tuple(declarations),
        diagnostics=tuple(diagnostics),
        evidence_files=tuple(context.repository_root / p for p in project.manifests),
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
                "Catalog definitions do not select versions",
            ),
            Capability(
                "usage",
                CapabilityState.UNSUPPORTED,
                "Catalog-to-build/source binding is unknown",
            ),
            Capability(
                "mapping",
                CapabilityState.UNSUPPORTED,
                "Catalog aliases do not establish source ownership",
            ),
            Capability(
                "security", CapabilityState.INCOMPLETE, "No selected package versions"
            ),
        ),
    )
