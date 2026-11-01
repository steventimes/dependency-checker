"""npm declaration identities and versioned lockfile instances."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from depcheck.ecosystems.javascript.packages import (
    NpmSources,
    dependency_identity,
    registry_name,
)
from depcheck.ecosystems.javascript.packages import package_ref as _package_ref
from depcheck.ecosystems.static import StaticReadError, read_json
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
    VersionConstraint,
)

_DEPENDENCY_SECTIONS = (
    ("dependencies", "runtime"),
    ("devDependencies", "development"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)
_LOCK_CONTEXT_FLAGS = frozenset(
    {
        "dev",
        "optional",
        "devOptional",
        "peer",
        "inBundle",
        "bundled",
        "hasInstallScript",
        "hasShrinkwrap",
    }
)
_LOCK_PLATFORM_FIELDS = frozenset({"os", "cpu", "libc"})
_LOCK_CONTEXT_FIELDS = _LOCK_CONTEXT_FLAGS | _LOCK_PLATFORM_FIELDS
_MODERN_CONTEXT_FIELDS = _LOCK_CONTEXT_FIELDS | {
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bundleDependencies",
    "bundledDependencies",
}
_MAX_ANCESTOR_CANDIDATE_CHARACTERS = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class NpmLockEvidence:
    resolved: tuple[ResolvedDependency, ...]
    diagnostics: tuple[Diagnostic, ...]


@dataclass(slots=True)
class _AncestorBudget:
    remaining: int
    exhausted: bool = False

    def consume(self, characters: int) -> bool:
        if self.exhausted or characters > self.remaining:
            self.exhausted = True
            return False
        self.remaining -= characters
        return True


def _instance_label(path: str) -> str:
    return repr(path) if len(path) <= 256 else repr(path[:256]) + "..."


def _lock_issue(
    diagnostics: list[Diagnostic],
    lock: Path,
    message: str,
    *,
    unsupported: bool = False,
) -> None:
    diagnostics.append(
        Diagnostic(
            "lock.unsupported" if unsupported else "lock.invalid",
            "warning" if unsupported else "error",
            message,
            SourceLocation(lock),
        )
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
    optional = document.get("optionalDependencies", {})
    optional_names = (
        {name.lower() for name in optional if isinstance(name, str)}
        if isinstance(optional, Mapping)
        else set()
    )
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
            overridden = section == "dependencies" and installed_name in optional_names
            if not overridden and identities.setdefault(installed_name, name) != name:
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
                    kind="hint" if overridden else "direct",
                    metadata={
                        "section": section,
                        "installation_name": installed_name,
                        "origin": origin,
                        **(
                            {"overridden_by": "optionalDependencies"}
                            if overridden
                            else {}
                        ),
                    },
                )
            )
    return tuple(declarations)


def _context_supported(field: str, value: object) -> bool:
    if field in _LOCK_CONTEXT_FLAGS:
        return isinstance(value, bool)
    if field in _LOCK_PLATFORM_FIELDS:
        return isinstance(value, str) or (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        )
    if field in {"bundleDependencies", "bundledDependencies"}:
        return isinstance(value, bool) or (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        )
    if field == "peerDependenciesMeta":
        return isinstance(value, Mapping) and all(
            isinstance(name, str)
            and isinstance(record, Mapping)
            and not record.keys() - {"optional"}
            and all(isinstance(item, bool) for item in record.values())
            for name, record in value.items()
        )
    return isinstance(value, Mapping) and all(
        isinstance(name, str) and isinstance(request, str)
        for name, request in value.items()
    )


def collect_npm_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
    sources: NpmSources,
) -> NpmLockEvidence:
    document = read_json(lock)
    diagnostics: list[Diagnostic] = []
    lock_version_metadata: dict[str, object] = {}
    if "lockfileVersion" in document:
        value = document["lockfileVersion"]
        if (
            type(value) is int
            and value.bit_length() <= 32
            or isinstance(value, str)
            and len(value) <= 128
            or isinstance(value, bool)
            or value is None
        ):
            lock_version_metadata["lock_version_assertion"] = value
        else:
            lock_version_metadata["lock_version_state"] = "omitted-with-budget"
        if type(value) is not int or value not in {1, 2, 3}:
            _lock_issue(
                diagnostics,
                lock,
                "npm lockfileVersion is not a supported 1/2/3 integer; complex or oversized header assertions were omitted to bound copied metadata",
                unsupported=True,
            )
    direct = {
        str(item.metadata["installation_name"]): item.package.name
        for item in declarations
        if item.kind == "direct"
    }
    direct_paths = {f"node_modules/{alias}" for alias in direct}
    direct_origins: dict[str, list[Mapping[str, object]]] = {}
    for item in declarations:
        if item.kind != "direct":
            continue
        direct_origins.setdefault(str(item.metadata["installation_name"]), []).append(
            item.metadata["origin"]
        )
    packages = document.get("packages")
    if "packages" in document and not isinstance(packages, Mapping):
        raise StaticReadError("lockfile packages must be an object")
    nodes: dict[str, tuple[str, str, Mapping[object, object]]] = {}
    instances: dict[str, None] = {}
    if isinstance(packages, Mapping):
        for lock_path, raw in sorted(packages.items()):
            try:
                if not isinstance(lock_path, str):
                    raise StaticReadError("lockfile package locations must be strings")
                name = _lock_package_name(lock_path)
                if name is not None:
                    instances[lock_path] = None
                if not isinstance(raw, Mapping):
                    raise StaticReadError("lockfile package entries must be objects")
                if name is None:
                    continue  # Root/workspace metadata is not a registry instance.
                if raw.get("link") is True:
                    _lock_issue(
                        diagnostics,
                        lock,
                        f"Local npm link target is not resolved at {_instance_label(lock_path)}",
                        unsupported=True,
                    )
                if "version" not in raw:
                    if raw.get("link") is not True:
                        _lock_issue(
                            diagnostics,
                            lock,
                            f"npm instance has no asserted version at {_instance_label(lock_path)}",
                            unsupported=True,
                        )
                    continue
                version = raw["version"]
                if not isinstance(version, str) or not version:
                    raise StaticReadError(
                        f"npm instance version must be a non-empty string at {_instance_label(lock_path)}"
                    )
                expected = (
                    direct.get(name) if lock_path == f"node_modules/{name}" else None
                )
                identity = raw.get("name", expected or name)
                if not isinstance(identity, str):
                    raise StaticReadError("lockfile package name must be a string")
                name = registry_name(identity)
                if expected is not None and name != expected:
                    raise StaticReadError(
                        f"lockfile registry identity disagrees at {_instance_label(lock_path)}"
                    )
            except StaticReadError as exc:
                _lock_issue(diagnostics, lock, str(exc))
                continue
            nodes[lock_path] = (name, version, raw)
    else:
        dependencies = document.get("dependencies", {})
        if not isinstance(dependencies, Mapping):
            raise StaticReadError("lockfile dependencies must be an object")
        _walk_legacy_lock(
            lock,
            dependencies,
            direct,
            nodes,
            instances,
            diagnostics,
            parent_instance="",
        )
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
    lookup_budget = _AncestorBudget(_MAX_ANCESTOR_CANDIDATE_CHARACTERS)
    resolved: list[ResolvedDependency] = []
    section = "dependencies" if isinstance(packages, Mapping) else "requires"
    context_fields = (
        _MODERN_CONTEXT_FIELDS
        if isinstance(packages, Mapping)
        else _LOCK_CONTEXT_FIELDS | {"requires"}
    )
    conditional_context = False
    for lock_path, (name, version, raw) in sorted(nodes.items()):
        # Values reference the bounded JSON input once per physical record. In
        # particular, legacy nested dependencies are locations, not copied context.
        context = {field: raw[field] for field in sorted(context_fields & raw.keys())}
        for field, value in context.items():
            if not _context_supported(field, value):
                _lock_issue(
                    diagnostics,
                    lock,
                    f"npm {field} has an unsupported context shape at {_instance_label(lock_path)}; retained as an uninterpreted assertion",
                    unsupported=True,
                )
        conditional_context |= (
            bool(context.keys() & _LOCK_PLATFORM_FIELDS)
            or any(
                bool(context.get(field))
                for field in (
                    "optionalDependencies",
                    "peerDependencies",
                    "peerDependenciesMeta",
                )
            )
            or any(
                context.get(flag) is True
                for flag in ("dev", "optional", "devOptional", "peer")
            )
        )
        dependencies = raw.get(section, {})
        if section == "requires" and "requires" not in raw and raw.get("dependencies"):
            _lock_issue(
                diagnostics,
                lock,
                f"legacy npm instance has nested locations but no requires metadata at {_instance_label(lock_path)}",
                unsupported=True,
            )
        links: list[ResolvedDependencyLink] = []
        if not isinstance(dependencies, Mapping):
            _lock_issue(
                diagnostics,
                lock,
                f"npm {section} must be an object at {_instance_label(lock_path)}",
            )
        else:
            optional = (
                raw.get("optionalDependencies", {}) if section == "dependencies" else {}
            )
            # An uninterpretable optional section cannot establish which required
            # requests it overrides. Preserve context without asserting those edges.
            if not isinstance(optional, Mapping):
                dependencies = {}
                optional = {}
            for child, request in sorted(dependencies.items()):
                if child in optional:
                    continue
                try:
                    if not isinstance(child, str):
                        raise StaticReadError("npm dependency names must be strings")
                    child_name = registry_name(child.lower())
                    if not isinstance(request, str):
                        raise StaticReadError(
                            f"npm dependency specifier must be a string at {_instance_label(lock_path)}"
                        )
                    requested_name, _ = dependency_identity(child_name, request)
                except StaticReadError as exc:
                    _lock_issue(diagnostics, lock, str(exc))
                    continue
                child_path = _resolve_lock_dependency(
                    lock_path, child_name, instances, budget=lookup_budget
                )
                child_version: str | None
                if child_path is not None and child_path in nodes:
                    child_name, child_version, _ = nodes[child_path]
                    if request.startswith("npm:") and child_name != requested_name:
                        _lock_issue(
                            diagnostics,
                            lock,
                            f"npm alias request for {_instance_label(requested_name)} disagrees with locked identity {_instance_label(child_name)} at {_instance_label(child_path)}",
                        )
                        child_version = None
                        child_package = _package_ref(requested_name, public=False)
                    else:
                        child_package = identities[child_path]
                else:
                    child_name = requested_name
                    child_version = None
                    child_package = _package_ref(child_name, public=False)
                    if not lookup_budget.exhausted:
                        _lock_issue(
                            diagnostics,
                            lock,
                            f"npm required dependency {_instance_label(child)} has no usable locked instance at {_instance_label(lock_path)}",
                            unsupported=True,
                        )
                links.append(
                    ResolvedDependencyLink(
                        package=child_package,
                        version=child_version,
                        instance_id=child_path,
                    )
                )
        resolved.append(
            ResolvedDependency(
                project_id=project.project_id,
                package=identities[lock_path],
                version=version,
                source=SourceLocation(lock),
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
                metadata={
                    "npm_kind": "lock-record",
                    "lock_format": "packages"
                    if isinstance(packages, Mapping)
                    else "legacy",
                    **lock_version_metadata,
                    "context": context,
                    "activation": "unknown",
                },
            )
        )
    if conditional_context:
        _lock_issue(
            diagnostics,
            lock,
            "npm dependency flags, optional/peer requests and platform conditions remain uninterpreted context; installation and activation are unknown and the active graph is incomplete",
            unsupported=True,
        )
    if lookup_budget.exhausted:
        _lock_issue(
            diagnostics,
            lock,
            "npm ancestor lookup character budget exhausted; dependency edges are incomplete",
            unsupported=True,
        )
    return NpmLockEvidence(tuple(resolved), tuple(diagnostics))


def _walk_legacy_lock(
    lock: Path,
    dependencies: Mapping[object, object],
    direct: Mapping[str, str],
    nodes: dict[str, tuple[str, str, Mapping[object, object]]],
    instances: dict[str, None],
    diagnostics: list[Diagnostic],
    *,
    parent_instance: str,
) -> None:
    """Capture physical locations before resolving the separate requires graph."""
    for raw_name, raw in sorted(dependencies.items(), key=lambda item: str(item[0])):
        try:
            if not isinstance(raw_name, str):
                raise StaticReadError("legacy npm package names must be strings")
            installed_name = registry_name(raw_name.lower())
        except StaticReadError as exc:
            _lock_issue(diagnostics, lock, str(exc))
            continue
        instance_id = (
            f"{parent_instance}/node_modules/{installed_name}"
            if parent_instance
            else f"node_modules/{installed_name}"
        )
        instances[instance_id] = None
        if not isinstance(raw, Mapping):
            _lock_issue(
                diagnostics, lock, "legacy npm dependency entries must be objects"
            )
            continue
        children = raw.get("dependencies", {})
        if not isinstance(children, Mapping):
            _lock_issue(
                diagnostics,
                lock,
                f"legacy npm dependencies must be an object at {_instance_label(instance_id)}",
            )
            children = {}
        try:
            version = raw.get("version")
            name, version = (
                dependency_identity(installed_name, version)
                if isinstance(version, str)
                else (installed_name, version)
            )
            expected = direct.get(installed_name) if not parent_instance else None
            if (
                expected is not None
                and isinstance(raw.get("version"), str)
                and str(raw["version"]).startswith("npm:")
                and name != expected
            ):
                raise StaticReadError(
                    f"lockfile registry identity disagrees for {installed_name!r}"
                )
            identity = raw.get("name", expected or name)
            if not isinstance(identity, str):
                raise StaticReadError("lockfile package name must be a string")
            name = registry_name(identity)
            if expected is not None and name != expected:
                raise StaticReadError(
                    f"lockfile registry identity disagrees for {installed_name!r}"
                )
            if raw.get("link") is True:
                _lock_issue(
                    diagnostics,
                    lock,
                    f"Local npm link target is not resolved at {_instance_label(instance_id)}",
                    unsupported=True,
                )
            if "version" not in raw:
                if raw.get("link") is not True:
                    _lock_issue(
                        diagnostics,
                        lock,
                        f"legacy npm instance has no asserted version at {_instance_label(instance_id)}",
                        unsupported=True,
                    )
            elif not isinstance(version, str) or not version:
                raise StaticReadError(
                    f"legacy npm instance version must be a non-empty string at {_instance_label(instance_id)}"
                )
            if isinstance(version, str) and version:
                nodes[instance_id] = (name, version, raw)
        except StaticReadError as exc:
            _lock_issue(diagnostics, lock, str(exc))
        _walk_legacy_lock(
            lock,
            children,
            direct,
            nodes,
            instances,
            diagnostics,
            parent_instance=instance_id,
        )


def _lock_package_name(lock_path: str) -> str | None:
    if not lock_path:
        return None
    path = PurePosixPath(lock_path)
    if (
        path.is_absolute()
        or PureWindowsPath(lock_path).drive
        or "\\" in lock_path
        or ".." in path.parts
        or path.as_posix() != lock_path
        or any(ord(character) < 32 or ord(character) == 127 for character in lock_path)
    ):
        raise StaticReadError("npm package locations must be canonical relative paths")
    if "node_modules" not in path.parts:
        return None
    index = len(path.parts) - 1 - path.parts[::-1].index("node_modules")
    name = "/".join(path.parts[index + 1 :]).lower()
    return registry_name(name)


def _resolve_lock_dependency(
    parent_path: str,
    child_name: str,
    nodes: Mapping[str, object],
    *,
    budget: _AncestorBudget | None = None,
) -> str | None:
    work = (
        budget
        if budget is not None
        else _AncestorBudget(_MAX_ANCESTOR_CANDIDATE_CHARACTERS)
    )
    if work.exhausted or work.remaining <= 0:
        work.exhausted = True
        return None
    parent = PurePosixPath(parent_path)
    anchor_parts = int(bool(parent.anchor))
    parent_characters = (
        len(parent.anchor)
        + sum(len(part) for part in parent.parts[anchor_parts:])
        + max(0, len(parent.parts) - anchor_parts - 1)
    )
    suffix_characters = len("node_modules/") + len(child_name)
    while True:
        separator = int(len(parent.parts) > anchor_parts)
        if not work.consume(parent_characters + separator + suffix_characters):
            return None
        candidate = (parent / "node_modules" / child_name).as_posix()
        if candidate in nodes:
            return candidate
        if len(parent.parts) == anchor_parts:
            break
        if work.remaining <= 0:
            work.exhausted = True
            return None
        next_parent = parent.parent
        if next_parent == parent:
            break
        parent_characters -= len(parent.name) + int(
            len(parent.parts) > anchor_parts + 1
        )
        parent = next_parent
    return None
