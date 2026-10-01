"""Read registry package instances from pnpm v9 locks without running pnpm."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depcheck.ecosystems.javascript_packages import (
    exact_version,
    package_ref,
    registry_name,
)
from depcheck.ecosystems.static import StaticReadError, read_text
from depcheck.ecosystems.yaml_reader import read_lock_yaml
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
)

_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


@dataclass(frozen=True, slots=True)
class PnpmLockEvidence:
    resolved: tuple[ResolvedDependency, ...]
    diagnostics: tuple[Diagnostic, ...]


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise StaticReadError(f"pnpm {label} must be a mapping")
    return value


def _coordinate(key: str) -> tuple[str, str, str]:
    base = key.split("(", 1)[0]
    name, separator, version = base.rpartition("@")
    if not separator or not exact_version(version):
        raise StaticReadError(f"Unsupported pnpm registry snapshot: {key!r}")
    registry_name(name)
    return name, version, base


def collect_pnpm_lock(
    path: Path,
    project: ProjectUnit,
    declarations: Sequence[DependencyDeclaration],
    repository_root: Path,
) -> PnpmLockEvidence:
    source = SourceLocation(path, 1, 1)
    diagnostics: dict[str, Diagnostic] = {}

    def incomplete(message: str) -> None:
        diagnostics.setdefault(
            message, Diagnostic("lock.unsupported", "warning", message, source)
        )

    document = read_lock_yaml(read_text(path))
    if document.get("lockfileVersion") != "9.0":
        incomplete("Only pnpm lockfileVersion 9.0 is supported")
        return PnpmLockEvidence((), tuple(diagnostics.values()))
    importers = _mapping(document.get("importers"), "importers")
    importer_key = (repository_root / project.root).relative_to(path.parent).as_posix()
    importer = _mapping(importers.get(importer_key), f"importer {importer_key!r}")
    packages = _mapping(document.get("packages", {}), "packages")
    snapshots = _mapping(document.get("snapshots", {}), "snapshots")
    instance_prefix = (
        f"pnpm:{path.relative_to(repository_root).as_posix()}:{importer_key}:"
    )

    # Validate nodes lazily: unrelated importers must not add packages to this project.
    nodes: dict[str, tuple[str, str, Mapping[str, Any], Mapping[str, Any]]] = {}
    rejected: set[str] = set()

    def node(key: str) -> tuple[str, str, Mapping[str, Any], Mapping[str, Any]] | None:
        if key in nodes:
            return nodes[key]
        if key in rejected:
            return None
        try:
            name, version, base = _coordinate(key)
            snapshot = _mapping(snapshots.get(key), f"snapshot {key!r}")
            metadata = _mapping(packages.get(base), f"package {base!r}")
            resolution = _mapping(
                metadata.get("resolution"), f"resolution for {base!r}"
            )
            if any(
                field in resolution
                for field in ("tarball", "directory", "repo", "type")
            ):
                raise StaticReadError(f"Non-registry pnpm resolution for {base!r}")
            integrity = resolution.get("integrity")
            if not isinstance(integrity, str) or not integrity:
                raise StaticReadError(
                    f"Missing registry integrity for pnpm package {base!r}"
                )
        except StaticReadError as exc:
            rejected.add(key)
            incomplete(str(exc))
            return None
        nodes[key] = (name, version, snapshot, resolution)
        return nodes[key]

    def reference(name: str, value: object) -> str | None:
        if not isinstance(value, str):
            incomplete(f"Invalid pnpm reference for {name!r}")
            return None
        if value.startswith(
            ("link:", "file:", "workspace:", "git:", "git+", "http:", "https:")
        ):
            incomplete(f"Unresolved pnpm reference {name!r}: {value}")
            return None
        # Aliases store the actual name in the version; ordinary references omit it.
        key = value if value in snapshots else f"{name}@{value}"
        return key if node(key) is not None else None

    roots: set[str] = set()
    locked: dict[tuple[str, str], str] = {}
    declared_identities: dict[str, set[str]] = {}
    declared_entries: set[tuple[str, str]] = set()
    for item in declarations:
        installation = str(item.metadata.get("installation_name", item.package.name))
        declared_identities.setdefault(installation, set()).add(item.package.name)
        declared_entries.add(
            (str(item.metadata.get("section", "dependencies")), installation)
        )
    for section in _SECTIONS:
        values = _mapping(importer.get(section, {}), f"importer {section}")
        for name, raw in values.items():
            entry = _mapping(raw, f"importer dependency {name!r}")
            specifier = entry.get("specifier")
            if not isinstance(specifier, str):
                incomplete(f"Missing pnpm specifier for {name!r}")
            else:
                locked[(section, name)] = specifier
            if (section, name) not in declared_entries and (
                "peerDependencies",
                name,
            ) not in declared_entries:
                incomplete(
                    f"pnpm importer contains undeclared dependency {name!r} in {section}"
                )
            key = reference(name, entry.get("version"))
            if key is not None:
                roots.add(key)
                expected = declared_identities.get(name, set())
                if expected and nodes[key][0] not in expected:
                    incomplete(f"pnpm registry identity disagrees for {name!r}")

    for declaration in declarations:
        section = str(declaration.metadata.get("section", "dependencies"))
        if section == "peerDependencies":
            continue
        name = str(
            declaration.metadata.get("installation_name", declaration.package.name)
        )
        if locked.get((section, name)) != declaration.constraint.raw:
            incomplete(
                f"pnpm importer does not match package.json for {name!r} in {section}"
            )

    pending = sorted(roots, reverse=True)
    visited: set[str] = set()
    resolved: list[ResolvedDependency] = []
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        name, version, snapshot, resolution = nodes[key]
        links: dict[str, ResolvedDependencyLink] = {}
        for section in ("dependencies", "optionalDependencies"):
            children = _mapping(snapshot.get(section, {}), f"snapshot {section}")
            for child, value in children.items():
                target = reference(child, value)
                if target is None:
                    continue
                child_name, child_version, _, _ = nodes[target]
                links[target] = ResolvedDependencyLink(
                    package_ref(child_name),
                    child_version,
                    instance_prefix + target,
                )
                if target not in visited:
                    pending.append(target)
        ordered_links = tuple(links[target] for target in sorted(links))
        resolved.append(
            ResolvedDependency(
                project_id=project.project_id,
                package=package_ref(name),
                version=version,
                source=source,
                direct=key in roots,
                integrity=resolution["integrity"],
                dependencies=tuple(link.package for link in ordered_links),
                instance_id=instance_prefix + key,
                dependency_links=ordered_links,
            )
        )
    return PnpmLockEvidence(
        tuple(sorted(resolved, key=lambda item: item.identity.sort_key)),
        tuple(diagnostics.values()),
    )
