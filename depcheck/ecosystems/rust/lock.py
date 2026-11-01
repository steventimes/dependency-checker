"""Cargo lock instances, edges and qualified declaration bindings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from depcheck.ecosystems.rust.common import (
    _CRATES_IO,
    _NAME,
    _cargo_matches,
    _error,
    _exact_version,
    _package,
    _read_document,
)
from depcheck.ecosystems.rust.overrides import (
    _CargoOverrides,
    _override_detail,
    _override_source_matches,
)
from depcheck.ecosystems.static import StaticReadError
from depcheck.evidence.origins import redact_source
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
)

_LINK = re.compile(r"^([A-Za-z0-9_-]+)(?: ([^ ()]+))?(?: \((.+)\))?$")

_OVERRIDE_WORK_LIMIT = 100_000

_OVERRIDE_VIEW_DETAIL_BYTES = 65_536


def _collect_lock(
    root: Path,
    project: ProjectUnit,
    lock: Path,
    declarations: list[DependencyDeclaration],
    diagnostics: list[Diagnostic],
    overrides: _CargoOverrides | None = None,
) -> tuple[ResolvedDependency, ...]:
    document = _read_document(root, lock)
    if document.data.get("version") not in (3, 4):
        raise StaticReadError("Only Cargo.lock versions 3 and 4 are supported")
    records = document.data.get("package", [])
    if not isinstance(records, list):
        raise StaticReadError("Cargo.lock package must be an array of tables")
    valid: list[tuple[dict[str, Any], SourceLocation, str, int]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        location = document.positions.key("package", index)
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("name"), str)
            or not _NAME.fullmatch(record["name"])
            or not isinstance(record.get("version"), str)
            or not _exact_version(record["version"])
        ):
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Cargo.lock package requires a crate name and exact version",
                    location,
                )
            )
            continue
        if any(
            key in record and not isinstance(record[key], str)
            for key in ("source", "checksum")
        ) or not isinstance(record.get("dependencies", []), list):
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Cargo.lock source, checksum, or dependencies have invalid types",
                    location,
                )
            )
            continue
        source = record.get("source", "path")
        safe_source = redact_source(source)
        instance = f"{safe_source}#{record['name']}@{record['version']}"
        if safe_source != source:
            digest = hashlib.sha256(source.encode()).hexdigest()
            instance += f"[source-sha256:{digest}]"
        if instance in seen:
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Duplicate Cargo.lock package source/name/version",
                    location,
                )
            )
            continue
        seen.add(instance)
        valid.append((record, location, instance, index))
    overrides = overrides or _CargoOverrides({})
    named_records: dict[str, list[tuple[dict[str, Any], str]]] = {}
    named_versions: dict[str, set[str]] = {}
    for record, _, instance, _ in valid:
        named_records.setdefault(record["name"], []).append((record, instance))
        named_versions.setdefault(record["name"], set()).add(record["version"])
    override_versions: dict[str, set[str] | None] = {}
    for name, entries in overrides.by_name.items():
        versions = {entry.version for entry in entries if entry.version is not None}
        override_versions[name] = (
            None if any(entry.version is None for entry in entries) else versions
        )
    direct: set[str] = set()
    unknown_directness = overrides.unknown
    override_work = 0
    detail_bytes = _OVERRIDE_VIEW_DETAIL_BYTES
    details_omitted = False
    for declaration_index, declaration in enumerate(declarations):
        if declaration.kind != "direct":
            continue
        named = named_records.get(declaration.package.name, [])
        versions = named_versions.get(declaration.package.name, set())
        entries = overrides.by_name.get(declaration.package.name, [])
        override_work += len(entries) + (
            len(versions) if entries or unknown_directness else 0
        )
        if override_work > _OVERRIDE_WORK_LIMIT:
            unknown_directness = True
            diagnostics.append(
                _error(
                    "resolution.cargo-overrides-budget",
                    "Cargo override matching work budget exceeded; declaration-to-lock bindings remain unknown.",
                    declaration.source,
                )
            )
            break
        version_matches: dict[str, bool | None] = {}
        if unknown_directness:
            _check_override_constraint(
                declaration, versions, version_matches, diagnostics
            )
            continue
        matching = 0
        first_override = None
        for entry in entries:
            if entry.version is not None:
                if entry.version not in named_versions.get(entry.name, set()):
                    continue
                if entry.version not in version_matches:
                    version_matches[entry.version] = _cargo_matches(
                        declaration.constraint.raw, entry.version
                    )
                if version_matches[entry.version] is False:
                    continue
            if _override_source_matches(entry.source, declaration) is False:
                continue
            matching += 1
            if first_override is None:
                first_override = entry
        if first_override is not None:
            _check_override_constraint(
                declaration, versions, version_matches, diagnostics
            )
            detail = _override_detail(root, first_override)
            size = len(json.dumps(detail).encode()) if detail is not None else 0
            omitted = matching - 1
            if detail is None or size > detail_bytes:
                detail = None
                omitted = matching
            else:
                detail_bytes -= size
            declarations[declaration_index] = replace(
                declaration,
                metadata={
                    **declaration.metadata,
                    "cargo_override_status": "unsupported",
                    "directness_status": "unknown",
                    "cargo_overrides": {
                        "matching_entries": matching,
                        "omitted_entries": omitted,
                        **({"first": detail} if detail is not None else {}),
                    },
                },
            )
            if omitted and not details_omitted:
                details_omitted = True
                diagnostics.append(
                    _error(
                        "manifest.cargo-overrides-details-omitted",
                        "Cargo override detail projection is bounded; omitted entries remain unqualified and original locations remain in diagnostics.",
                        first_override.location,
                    )
                )
            continue
        source_matches = [
            (_source_matches(declaration, r.get("source")), r, i) for r, i in named
        ]
        sourced = [(r, i) for matches, r, i in source_matches if matches is True]
        if (
            named
            and not sourced
            and all(matches is False for matches, _, _ in source_matches)
        ):
            diagnostics.append(
                _error(
                    "resolution.cargo-source-mismatch",
                    f"Cargo.lock has no source matching the declaration of {declaration.package.name!r}",
                    declaration.source,
                )
            )
        if not declaration.package.purl or not sourced:
            continue  # Git/path/alternate registry evidence stays qualified.
        range_matches = [
            (_cargo_matches(declaration.constraint.raw, r["version"]), i)
            for r, i in sourced
        ]
        direct_candidates = [i for matches, i in range_matches if matches is True]
        if any(matches is None for matches, _ in range_matches):
            diagnostics.append(
                _error(
                    "resolution.cargo-constraint-unknown",
                    f"Cargo range {declaration.constraint.raw!r} for {declaration.package.name!r} cannot be compared safely with lock evidence",
                    declaration.source,
                )
            )
        elif len(direct_candidates) == 1:
            direct.add(direct_candidates[0])
        elif len(direct_candidates) > 1:
            diagnostics.append(
                _error(
                    "resolution.cargo-direct-ambiguous",
                    f"Cargo declaration {declaration.package.name!r} has multiple registry lock candidates; directness is unknown",
                    declaration.source,
                )
            )
        else:
            diagnostics.append(
                _error(
                    "resolution.cargo-constraint-mismatch",
                    f"Cargo.lock versions for {declaration.package.name!r} do not satisfy its declared range {declaration.constraint.raw!r}",
                    declaration.source,
                )
            )
    if unknown_directness:
        direct.clear()
        for index, declaration in enumerate(declarations):
            if declaration.kind == "direct":
                declarations[index] = replace(
                    declaration,
                    metadata={
                        **declaration.metadata,
                        "cargo_override_status": "unknown",
                        "directness_status": "unknown",
                        "cargo_override_details_omitted": True,
                    },
                )
    resolved = []
    for record, location, instance, index in valid:
        source = record.get("source")
        registry = source in _CRATES_IO
        if not registry:
            diagnostics.append(
                _error(
                    "security.cargo-source-unverified",
                    f"Cargo.lock {record['name']} source {redact_source(source) if source is not None else 'path/workspace'!r} has no verified crates.io coordinate",
                    location,
                )
            )
        links = []
        for reference in record.get("dependencies", []):
            match = _LINK.fullmatch(reference) if isinstance(reference, str) else None
            if match is None:
                diagnostics.append(
                    _error(
                        "lock.invalid",
                        "Invalid Cargo.lock dependency reference",
                        location,
                    )
                )
                continue
            name, version, dependency_source = match.groups()
            candidates = [
                (r, i)
                for r, _, i, _ in valid
                if r["name"] == name
                and (version is None or r["version"] == version)
                and _lock_source_matches(r.get("source"), dependency_source)
            ]
            if len(candidates) == 1:
                candidate, target_instance = candidates[0]
                links.append(
                    ResolvedDependencyLink(
                        _package(name, candidate.get("source") in _CRATES_IO),
                        candidate["version"],
                        target_instance,
                    )
                )
            else:
                diagnostics.append(
                    _error(
                        "resolution.cargo-link-ambiguous",
                        f"Cargo.lock dependency {redact_source(reference)!r} resolves to {len(candidates)} instances; no edge target was inferred",
                        location,
                    )
                )
                links.append(ResolvedDependencyLink(_package(name, False), version))
        resolved.append(
            ResolvedDependency(
                project.project_id,
                _package(record["name"], registry),
                record["version"],
                location,
                direct=instance in direct,
                integrity=record.get("checksum"),
                dependencies=tuple(link.package for link in links),
                instance_id=instance,
                dependency_links=tuple(links),
                origin={
                    "kind": "registry"
                    if registry or (source or "").startswith(("registry+", "sparse+"))
                    else "git"
                    if (source or "").startswith("git+")
                    else "path"
                    if source is None
                    else "unknown",
                    "public": registry,
                    "assertion": {"source": redact_source(source)}
                    if source is not None
                    else {},
                },
                metadata={
                    "cargo_kind": "lock-record",
                    "lock_format": "cargo",
                    "lock_version": document.data["version"],
                    "package_index": index,
                    "context": {"source": redact_source(source)}
                    if source is not None
                    else {},
                    **(
                        {"source_sha256": hashlib.sha256(source.encode()).hexdigest()}
                        if source is not None
                        else {}
                    ),
                    **(
                        {
                            "cargo_override_status": "unknown"
                            if unknown_directness
                            else "unsupported",
                            "directness_status": "unknown",
                        }
                        if instance not in direct
                        and (
                            unknown_directness
                            or record["name"] in override_versions
                            and (
                                override_versions[record["name"]] is None
                                or record["version"]
                                in (override_versions[record["name"]] or set())
                            )
                        )
                        else {}
                    ),
                    "activation": "unknown",
                },
            )
        )
    diagnostics.append(
        Diagnostic(
            "resolution.cargo-activation-unknown",
            "warning",
            "Cargo.lock records a workspace/feature/target superset; active features, platform conditions, and deployed crates are unknown.",
            SourceLocation(lock),
        )
    )
    return tuple(resolved)


def _check_override_constraint(
    declaration: DependencyDeclaration,
    versions: set[str],
    matches: dict[str, bool | None],
    diagnostics: list[Diagnostic],
) -> None:
    # Overrides add candidates without relaxing the original requirement.
    # One satisfying or unsupported comparison prevents this contradiction.
    if not versions:
        return
    for version in versions:
        if version not in matches:
            matches[version] = _cargo_matches(declaration.constraint.raw, version)
        if matches[version] is not False:
            return
    diagnostics.append(
        _error(
            "resolution.cargo-constraint-mismatch",
            f"Cargo.lock versions for {declaration.package.name!r} do not satisfy its declared range {declaration.constraint.raw!r}",
            declaration.source,
        )
    )


def _lock_source_matches(source: str | None, reference: str | None) -> bool:
    if reference is None or source == reference:
        return True
    # Cargo's dependency IDs omit a Git source's precise commit fragment.
    # Preserve the full source in instance identity, and retain repo/query
    # distinctions here. More than one matching instance stays ambiguous.
    return (
        isinstance(source, str)
        and source.startswith("git+")
        and reference.startswith("git+")
        and "#" not in reference
        and source.partition("#")[0] == reference
    )


def _source_matches(
    declaration: DependencyDeclaration, source: str | None
) -> bool | None:
    if declaration.package.purl:
        return source in _CRATES_IO
    git = declaration.metadata.get("git")
    if not isinstance(git, str):
        return None  # Lock entries do not locate path crates or named registries.
    if source is None or not source.startswith("git+"):
        return False
    try:
        declared, locked = urlsplit(git), urlsplit(source[4:])
        if (declared.scheme, declared.netloc, declared.path) != (
            locked.scheme,
            locked.netloc,
            locked.path,
        ):
            return False
        selectors = parse_qs(locked.query)
        return all(
            selectors.get(key) == [declaration.metadata[key]]
            for key in ("rev", "tag", "branch")
            if key in declaration.metadata
        )
    except ValueError:
        return None
