"""npm declaration identities and versioned lockfile instances."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from depcheck.ecosystems.javascript_packages import (
    NpmSources,
    dependency_identity,
    registry_name,
)
from depcheck.ecosystems.javascript_packages import (
    package_ref as _package_ref,
)
from depcheck.ecosystems.static import StaticReadError, read_json
from depcheck.model import (
    DependencyDeclaration,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
    VersionConstraint,
)
from depcheck.source_locations import SourcePositions

_DEPENDENCY_SECTIONS = (
    ("dependencies", "runtime"),
    ("devDependencies", "development"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)


def parse_declarations(
    project: ProjectUnit,
    manifest: Path,
    document: Mapping[str, object],
    positions: SourcePositions,
    sources: NpmSources,
) -> tuple[DependencyDeclaration, ...]:
    declarations: list[DependencyDeclaration] = []
    seen: set[tuple[str, str]] = set()
    identities: dict[str, str] = {}
    for section, scope in _DEPENDENCY_SECTIONS:
        values = document.get(section, {})
        if not isinstance(values, Mapping):
            raise StaticReadError(
                f"{section} must be a package-to-version object",
                source=positions.key(section),
            )
        for display_name, raw_constraint in sorted(values.items()):
            if (
                not isinstance(display_name, str)
                or not isinstance(raw_constraint, str)
                or not display_name.strip()
            ):
                raise StaticReadError(
                    f"{section} entries require non-empty names and string specifiers",
                    source=positions.key(section, str(display_name)),
                )
            installed_name = display_name.lower()
            name, constraint = dependency_identity(installed_name, raw_constraint)
            if identities.setdefault(installed_name, name) != name:
                raise StaticReadError(
                    f"Conflicting registry identities for npm alias {installed_name}",
                    source=positions.key(section, display_name),
                )
            key = (installed_name, scope)
            if key in seen:
                continue
            seen.add(key)
            origin = sources.declaration_origin(name, constraint)
            declarations.append(
                DependencyDeclaration(
                    project_id=project.project_id,
                    package=_package_ref(name, public=origin["public"]),
                    constraint=VersionConstraint(raw_constraint, "semver", constraint),
                    source=positions.key(section, display_name),
                    scope=scope,
                    kind="direct",
                    metadata={
                        "section": section,
                        "installation_name": installed_name,
                        "origin": origin,
                    },
                )
            )
    return tuple(declarations)


def collect_npm_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
    sources: NpmSources,
) -> tuple[ResolvedDependency, ...]:
    document = read_json(lock)
    direct = {
        str(item.metadata["installation_name"]): item.package.name
        for item in declarations
    }
    direct_paths = {f"node_modules/{alias}" for alias in direct}
    direct_origins: dict[str, list[Mapping[str, object]]] = {}
    for item in declarations:
        direct_origins.setdefault(str(item.metadata["installation_name"]), []).append(
            item.metadata["origin"]
        )
    packages = document.get("packages")
    if "packages" in document and not isinstance(packages, Mapping):
        raise StaticReadError("lockfile packages must be an object")
    resolved: list[ResolvedDependency] = []
    if isinstance(packages, Mapping):
        nodes: dict[str, tuple[str, str, Mapping[object, object]]] = {}
        for lock_path, raw in sorted(packages.items()):
            if not isinstance(lock_path, str) or not isinstance(raw, Mapping):
                raise StaticReadError("lockfile package entries must be objects")
            name = _lock_package_name(lock_path)
            version = raw.get("version")
            if name is None or not isinstance(version, str) or not version:
                continue
            expected = direct.get(name) if lock_path == f"node_modules/{name}" else None
            identity = raw.get("name", expected or name)
            if not isinstance(identity, str):
                raise StaticReadError("lockfile package name must be a string")
            name = registry_name(identity)
            if expected is not None and name != expected:
                raise StaticReadError(
                    f"lockfile registry identity disagrees at {lock_path}"
                )
            nodes[lock_path] = (name, version, raw)
        origins = {
            path: sources.resolution_origin(
                name,
                version,
                raw,
                direct_origins.get(path.removeprefix("node_modules/"), ())
                if path in direct_paths
                else (),
            )
            for path, (name, version, raw) in nodes.items()
        }
        identities = {
            path: _package_ref(node[0], public=origins[path]["public"])
            for path, node in nodes.items()
        }
        for lock_path, (name, version, raw) in sorted(nodes.items()):
            dependencies = raw.get("dependencies", {})
            links: list[ResolvedDependencyLink] = []
            if isinstance(dependencies, Mapping):
                for child in sorted(dependencies):
                    if not isinstance(child, str):
                        continue
                    child_name = child.lower()
                    child_path = _resolve_lock_dependency(lock_path, child_name, nodes)
                    child_version = (
                        nodes[child_path][1] if child_path is not None else None
                    )
                    if child_path is not None:
                        child_name = nodes[child_path][0]
                    links.append(
                        ResolvedDependencyLink(
                            package=identities[child_path]
                            if child_path is not None
                            else _package_ref(child_name, public=False),
                            version=child_version,
                            instance_id=child_path,
                        )
                    )
            resolved.append(
                ResolvedDependency(
                    project_id=project.project_id,
                    package=identities[lock_path],
                    version=version,
                    source=SourceLocation(lock, 1, 1),
                    direct=lock_path in direct_paths,
                    integrity=(
                        str(raw["integrity"])
                        if isinstance(raw.get("integrity"), str)
                        else None
                    ),
                    dependencies=tuple(link.package for link in links),
                    instance_id=lock_path,
                    dependency_links=tuple(links),
                    origin=origins[lock_path],
                )
            )
        return tuple(resolved)
    dependencies = document.get("dependencies", {})
    if not isinstance(dependencies, Mapping):
        raise StaticReadError("lockfile dependencies must be an object")
    _walk_legacy_lock(
        project,
        lock,
        dependencies,
        direct,
        resolved,
        sources,
        direct_origins,
        parent_instance="",
        top_level=True,
    )
    return tuple(resolved)


def _walk_legacy_lock(
    project: ProjectUnit,
    lock: Path,
    dependencies: Mapping[object, object],
    direct: Mapping[str, str],
    resolved: list[ResolvedDependency],
    sources: NpmSources,
    direct_origins: Mapping[str, Sequence[Mapping[str, object]]],
    *,
    parent_instance: str,
    top_level: bool,
) -> None:
    for raw_name, raw in sorted(dependencies.items(), key=lambda item: str(item[0])):
        if not isinstance(raw_name, str) or not isinstance(raw, Mapping):
            continue
        installed_name = raw_name.lower()
        version = raw.get("version")
        name, version = (
            dependency_identity(installed_name, version)
            if isinstance(version, str)
            else (installed_name, version)
        )
        if (
            top_level
            and installed_name in direct
            and isinstance(raw.get("version"), str)
            and str(raw["version"]).startswith("npm:")
            and name != direct[installed_name]
        ):
            raise StaticReadError(
                f"lockfile registry identity disagrees for {installed_name}"
            )
        identity = raw.get(
            "name", direct.get(installed_name, name) if top_level else name
        )
        if not isinstance(identity, str):
            raise StaticReadError("lockfile package name must be a string")
        name = registry_name(identity)
        if top_level and installed_name in direct and name != direct[installed_name]:
            raise StaticReadError(
                f"lockfile registry identity disagrees for {installed_name}"
            )
        children = raw.get("dependencies", {})
        instance_id = (
            f"{parent_instance}/node_modules/{installed_name}"
            if parent_instance
            else f"node_modules/{installed_name}"
        )
        child_links: list[ResolvedDependencyLink] = []
        if isinstance(children, Mapping):
            for child, child_raw in sorted(children.items()):
                if not isinstance(child, str) or not isinstance(child_raw, Mapping):
                    continue
                child_version = child_raw.get("version")
                child_name = child.lower()
                if isinstance(child_version, str):
                    child_name, child_version = dependency_identity(
                        child_name, child_version
                    )
                identity = child_raw.get("name", child_name)
                if not isinstance(identity, str):
                    raise StaticReadError("lockfile package name must be a string")
                child_name = registry_name(identity)
                child_links.append(
                    ResolvedDependencyLink(
                        package=_package_ref(
                            child_name,
                            public=sources.resolution_origin(
                                child_name,
                                child_version if isinstance(child_version, str) else "",
                                child_raw,
                            )["public"],
                        ),
                        version=child_version
                        if isinstance(child_version, str)
                        else None,
                        instance_id=f"{instance_id}/node_modules/{child.lower()}",
                    )
                )
        if isinstance(version, str) and version:
            origin = sources.resolution_origin(
                name,
                version,
                raw,
                direct_origins.get(installed_name, ()) if top_level else (),
            )
            resolved.append(
                ResolvedDependency(
                    project.project_id,
                    _package_ref(name, public=origin["public"]),
                    version,
                    SourceLocation(lock, 1, 1),
                    direct=top_level and installed_name in direct,
                    dependencies=tuple(link.package for link in child_links),
                    instance_id=instance_id,
                    dependency_links=tuple(child_links),
                    integrity=raw.get("integrity")
                    if isinstance(raw.get("integrity"), str)
                    else None,
                    origin=origin,
                )
            )
        if isinstance(children, Mapping):
            _walk_legacy_lock(
                project,
                lock,
                children,
                direct,
                resolved,
                sources,
                direct_origins,
                parent_instance=instance_id,
                top_level=False,
            )


def _lock_package_name(lock_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in lock_path:
        return None
    name = lock_path.rsplit(marker, 1)[1].strip("/")
    return name.lower() if name else None


def _resolve_lock_dependency(
    parent_path: str,
    child_name: str,
    nodes: Mapping[str, object],
) -> str | None:
    parent = PurePosixPath(parent_path)
    while True:
        candidate = (parent / "node_modules" / child_name).as_posix()
        if candidate in nodes:
            return candidate
        if str(parent) in {"", "."}:
            break
        parent = parent.parent
    return None
