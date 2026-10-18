from __future__ import annotations

from depcheck.bounded_io import repository_operation

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from depcheck.model import Diagnostic, SourceLocation
from depcheck.source_locations import SourcePositions
from depcheck.ecosystems.javascript_aliases import (
    AliasResolution,
    resolve_package_import,
)
from depcheck.ecosystems.javascript_packages import (
    NpmSources,
    dependency_identity,
    package_ref as _package_ref,
    registry_name,
)
from depcheck.ecosystems.javascript_pnpm import collect_pnpm_lock
from depcheck.ecosystems.javascript_yarn import collect_yarn_inventory
from depcheck.ecosystems.workspaces import pnpm_membership
from depcheck.ecosystems.frontend import (
    ModuleLoad as _ModuleLoad,
    SourceFragment,
    SourceIssue,
    astro_regions,
    component_regions,
    css_imports,
)
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_json,
    parse_json,
    read_text,
)

_LOCK_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
)
_LOCK_MANAGERS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
}
_SOURCE_SUFFIXES = frozenset(
    {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx", ".astro", ".css", ".vue", ".svelte"}
)
_UNPARSED_SOURCE_SUFFIXES = frozenset({".scss", ".sass"})
_CSS_BUILD_CONFIGS = {
    "vite.config": "vite",
    "astro.config": "astro",
    "webpack.config": "webpack",
    "rollup.config": "rollup",
}
_DEPENDENCY_SECTIONS = (
    ("dependencies", "runtime"),
    ("devDependencies", "development"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)
_NODE_BUILTINS = frozenset(
    {
        "assert",
        "assert/strict",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "dns/promises",
        "domain",
        "events",
        "fs",
        "fs/promises",
        "http",
        "http2",
        "https",
        "inspector",
        "inspector/promises",
        "module",
        "net",
        "os",
        "path",
        "path/posix",
        "path/win32",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "readline/promises",
        "repl",
        "stream",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "string_decoder",
        "timers",
        "timers/promises",
        "tls",
        "tty",
        "url",
        "util",
        "util/types",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)


@dataclass(frozen=True, slots=True)
class _JsToken:
    kind: str
    value: str
    line: int
    column: int


class NpmProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        projects: list[ProjectUnit] = []
        for manifest in discover_files(
            root,
            names=frozenset({"package.json"}),
            excluded_directories=exclusions_for(context.settings),
        ):
            project_root = manifest.parent
            relative_root = project_root.relative_to(root)
            if relative_root == Path(""):
                relative_root = Path(".")
            locks = tuple(
                (relative_root / name) if relative_root != Path(".") else Path(name)
                for name in _LOCK_NAMES
                if (project_root / name).is_file()
            )
            if not any(path.name == "pnpm-lock.yaml" for path in locks):
                for parent in project_root.parents:
                    if parent != root and root not in parent.parents:
                        break
                    candidate = parent / "pnpm-lock.yaml"
                    if candidate.is_file():
                        membership, _ = pnpm_membership(root, project_root, candidate)
                        if membership is not False:
                            locks = (*locks, candidate.relative_to(root))
                        break
                    boundary = parent / "pnpm-workspace.yaml"
                    if boundary.exists() or boundary.is_symlink():
                        break
            relative_manifest = (
                relative_root / "package.json"
                if relative_root != Path(".")
                else Path("package.json")
            )
            language = (
                "typescript"
                if (project_root / "tsconfig.json").is_file()
                else "javascript"
            )
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "npm", "npm"),
                    root=relative_root,
                    language=language,
                    ecosystem="npm",
                    manager="npm",
                    manifests=(relative_manifest,),
                    locks=locks,
                )
            )
        for lock in discover_files(
            root,
            names=frozenset({"yarn.lock"}),
            excluded_directories=exclusions_for(context.settings),
        ):
            relative_root = lock.parent.relative_to(root)
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "npm", "yarn-lock"),
                    root=relative_root,
                    language="yaml",
                    ecosystem="npm",
                    manager="yarn-lock",
                    manifests=(lock.relative_to(root),),
                    locks=(lock.relative_to(root),),
                )
            )
        return tuple(
            sorted(
                projects,
                key=lambda item: (len(item.root.parts), item.root.as_posix()),
            )
        )


class NpmEvidenceCollector:
    def __init__(self, mappings: Mapping[str, str] | None = None) -> None:
        self.mappings = {
            str(key).lower(): str(value).lower()
            for key, value in (mappings or {}).items()
        }

    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        del pack
        if project.manager == "yarn-lock":
            return collect_yarn_inventory(context, project)
        root = context.repository_root
        project_root = root / project.root
        manifest = project_root / "package.json"
        sources = NpmSources(root, project_root)
        diagnostics: list[Diagnostic] = []
        declarations: tuple[DependencyDeclaration, ...] = ()
        document: Mapping[str, object] = {}
        manifest_complete = True
        try:
            text = read_text(manifest)
            document = parse_json(text, manifest)
            positions = SourcePositions.json_keys(
                manifest,
                text,
                frozenset(section for section, _ in _DEPENDENCY_SECTIONS),
            )
            declarations = self._declarations(
                project, manifest, document, positions, sources
            )
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(
                _diagnostic("manifest.invalid", str(exc), exc.source or manifest)
            )

        resolved: tuple[ResolvedDependency, ...] = ()
        resolution_complete = True
        pnpm_lock = next(
            (root / path for path in project.locks if path.name == "pnpm-lock.yaml"),
            None,
        )
        supported_lock = next(
            (
                project_root / name
                for name in ("npm-shrinkwrap.json", "package-lock.json")
                if (project_root / name).is_file()
            ),
            None,
        )
        managers = {
            _LOCK_MANAGERS[path.name]
            for path in project.locks
            if path.name in _LOCK_MANAGERS
        }
        workspace_files: tuple[Path, ...] = ()
        membership: bool | None = True
        if pnpm_lock is not None:
            membership, workspace_files = pnpm_membership(root, project_root, pnpm_lock)
        if membership is not True:
            resolution_complete = False
            diagnostics.append(
                _diagnostic(
                    "resolution.workspace-ambiguous",
                    f"{project.project_id}: inherited pnpm lock ownership is unknown; no active graph was selected",
                    workspace_files[0] if workspace_files else pnpm_lock or manifest,
                    severity="warning",
                )
            )
        elif len(managers) > 1:
            resolution_complete = False
            diagnostics.append(
                _diagnostic(
                    "resolution.package-manager-ambiguous",
                    f"{project.project_id}: lockfiles from multiple package managers "
                    f"({', '.join(sorted(managers))}) do not establish one active dependency graph. "
                    "No resolved versions were inferred; confirm the intended manager and lockfile before updating.",
                    manifest,
                    severity="warning",
                )
            )
        elif supported_lock is not None:
            try:
                resolved = self._resolved(
                    project, supported_lock, declarations, sources
                )
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(
                    _diagnostic("lock.invalid", str(exc), supported_lock)
                )
        elif pnpm_lock is not None:
            try:
                evidence = collect_pnpm_lock(
                    pnpm_lock, project, declarations, root, sources
                )
                resolved = evidence.resolved
                diagnostics.extend(evidence.diagnostics)
                resolution_complete = not evidence.diagnostics
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(_diagnostic("lock.invalid", str(exc), pnpm_lock))
        elif (project_root / "yarn.lock").is_file():
            resolution_complete = False
            lock = project_root / "yarn.lock"
            diagnostics.append(
                _diagnostic(
                    "lock.unsupported",
                    f"static resolution for {lock.name} is not implemented",
                    lock,
                    severity="warning",
                )
            )

        usages, source_files, usage_diagnostics, usage_complete = self._usages(
            project,
            project_root,
            exclusions_for(context.settings, project.root),
            document.get("imports"),
            {
                str(item.metadata["installation_name"]): item.package.name
                for item in declarations
            },
        )
        diagnostics.extend(usage_diagnostics)
        if any(
            item.origin.get("kind") == "unknown"
            or item.origin.get("reason") == "non-canonical-registry-version"
            for item in resolved
        ):
            resolution_complete = False
            diagnostics.append(
                _diagnostic(
                    "resolution.source-incomplete",
                    "Some npm lock entries lack supported source identities; retained versions and origins are inventory assertions",
                    supported_lock or pnpm_lock or manifest,
                    severity="warning",
                )
            )
        diagnostics.extend(sources.diagnostics)
        resolution_complete = (
            resolution_complete and not sources.incomplete and not sources.ambiguous
        )
        known_origins: dict[str, bool] = {}
        source_items: tuple[DependencyDeclaration | ResolvedDependency, ...] = (
            *declarations,
            *resolved,
        )
        for item in source_items:
            public = item.package.purl is not None
            known_origins[item.package.name] = (
                known_origins.get(item.package.name, True) and public
            )
        usages = tuple(
            replace(
                usage,
                mapped_package=_package_ref(
                    usage.mapped_package.name,
                    public=known_origins[usage.mapped_package.name],
                ),
            )
            if usage.mapped_package is not None
            and usage.mapped_package.name in known_origins
            else usage
            for usage in usages
        )
        capabilities = (
            _status("manifest", manifest_complete),
            _status("resolution", resolution_complete),
            _status("usage", usage_complete),
            _status("mapping", usage_complete),
        )
        return EvidenceBundle(
            project=project,
            declarations=declarations,
            resolved=resolved,
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=capabilities,
            source_files=source_files,
            evidence_files=(*workspace_files, *sources.files),
        )

    def _declarations(
        self,
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
                        constraint=VersionConstraint(
                            raw_constraint, "semver", constraint
                        ),
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

    def _resolved(
        self,
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
            direct_origins.setdefault(
                str(item.metadata["installation_name"]), []
            ).append(item.metadata["origin"])
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
                expected = (
                    direct.get(name) if lock_path == f"node_modules/{name}" else None
                )
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
                        child_path = _resolve_lock_dependency(
                            lock_path, child_name, nodes
                        )
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
        self._walk_legacy_lock(
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
        self,
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
        for raw_name, raw in sorted(
            dependencies.items(), key=lambda item: str(item[0])
        ):
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
            if (
                top_level
                and installed_name in direct
                and name != direct[installed_name]
            ):
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
                                    child_version
                                    if isinstance(child_version, str)
                                    else "",
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
                self._walk_legacy_lock(
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

    def _usages(
        self,
        project: ProjectUnit,
        project_root: Path,
        excluded_directories: Sequence[str] = (),
        imports: object = None,
        installation_names: Mapping[str, str] | None = None,
    ) -> tuple[tuple[UsageEvidence, ...], tuple[Path, ...], list[Diagnostic], bool]:
        usages: list[UsageEvidence] = []
        diagnostics: list[Diagnostic] = []
        complete = True
        source_files = tuple(
            path
            for path in discover_files(
                project_root,
                suffixes=_SOURCE_SUFFIXES | _UNPARSED_SOURCE_SUFFIXES,
                excluded_directories=excluded_directories,
            )
            if _nearest_package_root(path.parent, project_root) == project_root
        )
        source_paths = frozenset(source_files)
        css_scope = (
            "build"
            if any(
                path.parent == project_root
                and path.suffix.lower() in {".js", ".mjs", ".cjs", ".ts"}
                and _CSS_BUILD_CONFIGS.get(path.stem)
                in (installation_names or {}).values()
                for path in source_files
            )
            else "unknown"
        )
        alias_resolutions: dict[str, AliasResolution] = {}
        for path in source_files:
            if path.suffix.lower() in _UNPARSED_SOURCE_SUFFIXES:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        "usage.unsupported-source",
                        f"Static imports in {path.suffix} components are not supported",
                        path,
                        severity="warning",
                    )
                )
                continue
            try:
                text = read_text(path)
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
                continue
            lexical_issues: list[tuple[int, int, str]] = []
            dynamic_sources: list[tuple[int, int]] = []
            loads: list[_ModuleLoad] = []
            positions = SourcePositions(path, text)
            frontend_issues: list[SourceIssue] = []
            fragments = [SourceFragment(text, 0, "module")]
            if path.suffix.lower() == ".astro":
                fragments, loads, frontend_issues = astro_regions(text, positions)
            elif path.suffix.lower() in {".vue", ".svelte"}:
                fragments, loads, frontend_issues = component_regions(text, positions)
            elif path.suffix.lower() == ".css":
                fragments = [SourceFragment(text, 0, "css")]
            ambiguous_count = dynamic_count = 0
            for fragment in fragments:
                if fragment.context == "css":
                    css_loads, css_issues = css_imports(
                        fragment.text, positions, fragment.offset
                    )
                    loads.extend(css_loads)
                    frontend_issues.extend(css_issues)
                    continue
                source = positions.at(fragment.offset)
                tokens, ambiguous = _lex_javascript(
                    fragment.text,
                    lexical_issues,
                    start_line=source.line or 1,
                    start_column=source.column or 1,
                )
                module_loads, dynamic = _module_loads(tokens, dynamic_sources)
                loads.extend(
                    replace(load, context=fragment.context) for load in module_loads
                )
                ambiguous_count += ambiguous
                dynamic_count += dynamic
            for issue in frontend_issues:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        issue.code,
                        f"{project.project_id}: {issue.reason}",
                        issue.source,
                        severity="warning",
                    )
                )
            for load in loads:
                scope = (
                    css_scope
                    if load.context == "css"
                    else _source_scope(path, project_root)
                )
                package_name = _import_package(load.reference)
                mapped_name = self.mappings.get(
                    load.reference.lower()
                ) or self.mappings.get(package_name or "")
                confidence = (
                    MappingConfidence.CONFIGURED
                    if mapped_name is not None
                    else MappingConfidence.EXACT
                )
                reason = (
                    "project import mapping"
                    if mapped_name is not None
                    else "literal npm package specifier"
                )
                if load.context in {"css", "src"}:
                    # CSS and src references can resolve to a local file before a
                    # package. Trust only this project's safely discovered files.
                    if (
                        (path.parent / load.reference) in source_paths
                        or load.reference.startswith((".", "/"))
                        and not load.reference.startswith("//")
                    ):
                        continue
                    if (
                        package_name not in (installation_names or {})
                        and mapped_name is None
                    ):
                        complete = False
                        source = SourceLocation(path, load.line, load.column)
                        usages.append(
                            UsageEvidence(
                                project_id=project.project_id,
                                language=project.language,
                                reference=load.reference,
                                source=source,
                                scope=scope,
                                kind=load.kind,
                                mapping_confidence=MappingConfidence.UNKNOWN,
                                mapping_reason="CSS/src reference has no verified local or declared npm owner",
                            )
                        )
                        diagnostics.append(
                            _diagnostic(
                                "usage.unsupported-frontend-reference",
                                f"{project.project_id}: CSS/src reference {load.reference!r} has no verified local or declared npm owner",
                                source,
                                severity="warning",
                            )
                        )
                        continue
                    reason = "literal frontend import of a declared npm installation"
                if load.context == "browser" or _external_reference(load.reference):
                    complete = False
                    source = SourceLocation(path, load.line, load.column)
                    usages.append(
                        UsageEvidence(
                            project_id=project.project_id,
                            language=project.language,
                            reference=load.reference,
                            source=source,
                            scope=scope,
                            kind=load.kind,
                            mapping_confidence=MappingConfidence.UNKNOWN,
                            mapping_reason="browser/import-map or external URL resolution is not collected",
                        )
                    )
                    diagnostics.append(
                        _diagnostic(
                            "usage.unsupported-browser-reference",
                            f"{project.project_id}: browser/import-map or external URL resolution is not collected for {load.reference!r}",
                            source,
                            severity="warning",
                        )
                    )
                    continue
                if load.reference.startswith("#") and mapped_name is None:
                    if load.reference not in alias_resolutions:
                        alias_resolutions[load.reference] = resolve_package_import(
                            load.reference,
                            imports,
                            project_root,
                            source_paths,
                            builtin_names=_NODE_BUILTINS,
                        )
                    alias = alias_resolutions[load.reference]
                    if alias.kind in {"local", "builtin"}:
                        continue
                    if alias.kind == "package":
                        package_name = alias.target
                        reason = alias.reason
                    else:
                        complete = False
                        source = SourceLocation(path, load.line, load.column)
                        usages.append(
                            UsageEvidence(
                                project_id=project.project_id,
                                language=project.language,
                                reference=load.reference,
                                source=source,
                                scope=scope,
                                kind=load.kind,
                                mapping_confidence=MappingConfidence.UNKNOWN,
                                mapping_reason=alias.reason,
                            )
                        )
                        diagnostics.append(
                            Diagnostic(
                                "mapping.alias-unsupported",
                                "warning",
                                alias.reason,
                                source,
                            )
                        )
                        continue
                if package_name is None and mapped_name is None:
                    continue
                mapped_name = (
                    mapped_name
                    or (installation_names or {}).get(package_name or "")
                    or package_name
                )
                assert mapped_name is not None
                if scope == "unknown":
                    complete = False
                    diagnostics.append(
                        _diagnostic(
                            "usage.unsupported-css-scope",
                            f"{project.project_id}: CSS import {load.reference!r} has a known npm owner but no verified build configuration; dependency scope is unknown",
                            SourceLocation(path, load.line, load.column),
                            severity="warning",
                        )
                    )
                usages.append(
                    UsageEvidence(
                        project_id=project.project_id,
                        language=project.language,
                        reference=load.reference,
                        source=SourceLocation(path, load.line, load.column),
                        scope=scope,
                        kind=load.kind,
                        mapped_package=_package_ref(mapped_name),
                        mapping_confidence=confidence,
                        mapping_reason=reason,
                    )
                )
            if dynamic_count:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        "usage.dynamic",
                        f"{project.project_id}: {dynamic_count} non-literal module loads could not be mapped",
                        SourceLocation(path, *dynamic_sources[0]),
                        severity="warning",
                    )
                )
            if ambiguous_count:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        "usage.ambiguous",
                        f"{project.project_id}: {ambiguous_count} ambiguous JavaScript lexical constructs "
                        f"prevented exact module mapping: {lexical_issues[0][2]}",
                        SourceLocation(
                            path, lexical_issues[0][0], lexical_issues[0][1]
                        ),
                        severity="warning",
                    )
                )
        return tuple(usages), source_files, diagnostics, complete


def create_npm_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="npm",
        detector=NpmProjectDetector(),
        capabilities=frozenset(
            {"manifest", "mapping", "resolution", "security", "usage"}
        ),
        collector=NpmEvidenceCollector(mappings),
    )


def _lock_package_name(lock_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in lock_path:
        return None
    name = lock_path.rsplit(marker, 1)[1].strip("/")
    return name.lower() if name else None


def _import_package(reference: str) -> str | None:
    value = reference.strip()
    if not value or value.startswith((".", "/", "#")):
        return None
    if value.startswith(("node:", "astro:")) or _external_reference(value):
        return None
    if value in _NODE_BUILTINS:
        return None
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else None
    return value.split("/", 1)[0].lower()


def _external_reference(reference: str) -> bool:
    if reference.startswith(("node:", "astro:")):
        return False
    return reference.startswith("//") or ":" in reference.split("/", 1)[0]


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


def _lex_javascript(
    text: str,
    issues: list[tuple[int, int, str]] | None = None,
    *,
    start_line: int = 1,
    start_column: int = 1,
) -> tuple[tuple[_JsToken, ...], int]:
    """Tokenize only the bounded syntax needed for static module evidence."""
    tokens: list[_JsToken] = []
    incomplete = 0
    index = 0
    line = start_line
    column = start_column

    def uncertain(reason: str, issue_line: int, issue_column: int) -> None:
        nonlocal incomplete
        incomplete += 1
        if issues is not None and len(issues) < 5:
            issues.append((issue_line, issue_column, reason))

    def advance(count: int = 1) -> None:
        nonlocal index, line, column
        end = min(index + count, len(text))
        for character in text[index:end]:
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
        index = end

    while index < len(text):
        character = text[index]
        if character.isspace():
            advance()
            continue
        if index == 0 and text.startswith("#!", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("/*", index):
            token_line, token_column = line, column
            advance(2)
            closed = False
            while index < len(text):
                if text.startswith("*/", index):
                    advance(2)
                    closed = True
                    break
                advance()
            if not closed:
                uncertain("unterminated block comment", token_line, token_column)
            continue
        if character in {"'", '"'}:
            quote_character = character
            token_line = line
            token_column = column
            value: list[str] = []
            safe = True
            closed = False
            advance()
            while index < len(text):
                character = text[index]
                if character == quote_character:
                    advance()
                    closed = True
                    break
                if character in "\r\n":
                    break
                if character == "\\":
                    advance()
                    if index >= len(text):
                        break
                    escaped = text[index]
                    if escaped in {"\\", "'", '"', "/"}:
                        value.append(escaped)
                    else:
                        safe = False
                    advance()
                    continue
                value.append(character)
                advance()
            if not closed:
                uncertain("unterminated string", token_line, token_column)
                break
            if not safe:
                uncertain("unsupported string escape", token_line, token_column)
            if closed and safe:
                tokens.append(
                    _JsToken("string", "".join(value), token_line, token_column)
                )
            continue
        if character == "`":
            token_line, token_column = line, column
            advance()
            closed = False
            interpolated = False
            while index < len(text):
                if text[index] == "\\":
                    advance(2)
                    continue
                if text.startswith("${", index):
                    interpolated = True
                    uncertain("template interpolation is not parsed", line, column)
                    break
                if text[index] == "`":
                    advance()
                    closed = True
                    break
                advance()
            if interpolated:
                break
            if not closed:
                uncertain("unterminated template literal", token_line, token_column)
                break
            continue
        if character == "/" and _can_start_regex(tokens):
            token_line, token_column = line, column
            advance()
            closed = False
            in_character_class = False
            while index < len(text):
                character = text[index]
                if character == "\\":
                    advance(2)
                    continue
                if character in "\r\n":
                    break
                if character == "[":
                    in_character_class = True
                elif character == "]":
                    in_character_class = False
                elif character == "/" and not in_character_class:
                    advance()
                    while index < len(text) and (
                        text[index].isalnum() or text[index] in {"_", "$"}
                    ):
                        advance()
                    closed = True
                    break
                advance()
            if not closed:
                uncertain("unterminated regular expression", token_line, token_column)
                break
            continue
        if character == "<" and _looks_like_jsx_start(
            text,
            index,
            tokens[-1] if tokens else None,
        ):
            uncertain("JSX syntax is not parsed", line, column)
            break
        if character.isalpha() or character in {"_", "$"}:
            token_line = line
            token_column = column
            start = index
            while index < len(text) and (
                text[index].isalnum() or text[index] in {"_", "$"}
            ):
                advance()
            tokens.append(
                _JsToken("identifier", text[start:index], token_line, token_column)
            )
            continue
        tokens.append(_JsToken("punctuation", character, line, column))
        advance()
    return tuple(tokens), incomplete


def _can_start_regex(tokens: Sequence[_JsToken]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1]
    if previous.kind == "punctuation":
        return (
            previous.value in "([{=,:;!?&|+-*%^~<>"
            or previous.value == ")"
            and _closes_control_condition(tokens)
        )
    return previous.value in {
        "await",
        "case",
        "delete",
        "in",
        "instanceof",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }


def _closes_control_condition(tokens: Sequence[_JsToken]) -> bool:
    depth = 0
    for index in range(len(tokens) - 1, -1, -1):
        token = tokens[index]
        if token.value == ")":
            depth += 1
            continue
        if token.value != "(":
            continue
        depth -= 1
        if depth != 0:
            continue
        keyword = tokens[index - 1] if index else None
        return (
            keyword is not None
            and keyword.kind == "identifier"
            and keyword.value in {"catch", "for", "if", "switch", "while", "with"}
        )
    return False


def _looks_like_jsx_start(
    text: str,
    index: int,
    previous: _JsToken | None,
) -> bool:
    cursor = index + 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or not (text[cursor].isalpha() or text[cursor] == "/"):
        return False
    if previous is None:
        return True
    if previous.kind == "punctuation":
        return previous.value in "=([{,:;!&|?"
    return previous.value in {"return", "yield"}


def _module_loads(
    tokens: Sequence[_JsToken],
    dynamic_sources: list[tuple[int, int]] | None = None,
) -> tuple[tuple[_ModuleLoad, ...], int]:
    loads: list[_ModuleLoad] = []
    dynamic_count = 0
    seen: set[tuple[str, int, int, str]] = set()

    def dynamic(token: _JsToken) -> None:
        nonlocal dynamic_count
        dynamic_count += 1
        if dynamic_sources is not None and len(dynamic_sources) < 5:
            dynamic_sources.append((token.line, token.column))

    def add(token: _JsToken, kind: str) -> None:
        key = (token.value, token.line, token.column, kind)
        if key in seen:
            return
        seen.add(key)
        loads.append(_ModuleLoad(token.value, token.line, token.column, kind))

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {
            "export",
            "import",
            "require",
        }:
            continue
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.value == "require":
            if previous is not None and previous.value == ".":
                continue
            if following is None or following.value != "(":
                continue
            argument = tokens[index + 2] if index + 2 < len(tokens) else None
            closing = tokens[index + 3] if index + 3 < len(tokens) else None
            if (
                argument is not None
                and argument.kind == "string"
                and closing is not None
                and closing.value == ")"
            ):
                add(argument, "regular")
            else:
                dynamic(token)
            continue
        if token.value == "import":
            if following is not None and following.value == ".":
                continue
            if following is not None and following.value == "(":
                argument = tokens[index + 2] if index + 2 < len(tokens) else None
                closing = tokens[index + 3] if index + 3 < len(tokens) else None
                if (
                    argument is not None
                    and argument.kind == "string"
                    and closing is not None
                    and closing.value == ")"
                ):
                    add(argument, "dynamic")
                else:
                    dynamic(token)
                continue
            if following is not None and following.kind == "string":
                add(following, "regular")
                continue
        specifier = _from_specifier(tokens, index)
        if specifier is not None:
            add(specifier, "regular")
    return tuple(loads), dynamic_count


def _from_specifier(
    tokens: Sequence[_JsToken],
    start: int,
) -> _JsToken | None:
    opening = tokens[start]
    for index in range(start + 1, min(len(tokens), start + 257)):
        token = tokens[index]
        if token.value == ";":
            return None
        if (
            index > start + 1
            and token.kind == "identifier"
            and token.value in {"export", "import"}
        ):
            return None
        if (
            token.line > opening.line
            and token.kind == "identifier"
            and token.value
            in {"class", "const", "function", "if", "let", "return", "var"}
        ):
            return None
        if token.value != "from":
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        return (
            following if following is not None and following.kind == "string" else None
        )
    return None


def _nearest_package_root(path: Path, boundary: Path) -> Path:
    current = path
    while current != boundary and boundary in current.parents:
        if (current / "package.json").is_file():
            return current
        current = current.parent
    return boundary


def _source_scope(path: Path, root: Path) -> str:
    parts = {item.lower() for item in path.relative_to(root).parts}
    stem = path.stem.lower()
    if (
        parts & {"__tests__", "spec", "specs", "test", "tests"}
        or stem.endswith((".test", ".spec"))
        or stem in {"playwright.config", "vitest.config", "jest.config", "karma.config"}
    ):
        return "test"
    if stem in {"astro.config", "vite.config", "webpack.config", "rollup.config"}:
        return "build"
    return "runtime"


def _diagnostic(
    code: str,
    message: str,
    path: Path | SourceLocation,
    *,
    severity: str = "error",
) -> Diagnostic:
    source = path if isinstance(path, SourceLocation) else SourceLocation(path)
    return Diagnostic(code, severity, message, source)


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
