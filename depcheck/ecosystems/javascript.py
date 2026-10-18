from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from depcheck.bounded_io import repository_operation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.ecosystems.frontend import (
    ModuleLoad as _ModuleLoad,
)
from depcheck.ecosystems.frontend import (
    SourceFragment,
    SourceIssue,
    astro_regions,
    component_regions,
    css_imports,
)
from depcheck.ecosystems.javascript_aliases import (
    AliasResolution,
    resolve_package_import,
)
from depcheck.ecosystems.javascript_packages import (
    NpmSources,
)
from depcheck.ecosystems.javascript_packages import (
    package_ref as _package_ref,
)
from depcheck.ecosystems.javascript_pnpm import collect_pnpm_lock
from depcheck.ecosystems.javascript_yarn import collect_yarn_inventory
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    parse_json,
    read_text,
)
from depcheck.ecosystems.workspaces import pnpm_membership
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    MappingConfidence,
    ProjectUnit,
    ResolvedDependency,
    SourceLocation,
    UsageEvidence,
)
from depcheck.source_locations import SourcePositions

from .javascript_lexer import _lex_javascript, _module_loads
from .javascript_npm import _DEPENDENCY_SECTIONS, collect_npm_lock, parse_declarations
from .javascript_packages import _NODE_BUILTINS, _external_reference, _import_package

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
            declarations = parse_declarations(
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
                resolved = collect_npm_lock(
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
