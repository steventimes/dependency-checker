from __future__ import annotations

from depcheck.profiling import measured

from depcheck.bounded_io import repository_operation

from collections.abc import Mapping, Sequence
from dataclasses import replace
import os
import hashlib
import json
from pathlib import Path
import tomllib
from urllib.parse import quote

from packaging.utils import canonicalize_name
from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.version import InvalidVersion, Version

from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ImportEvidence,
    ImportScanResult,
    ManifestParseResult,
)
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    PackageRef,
    ProjectUnit,
    SourceLocation,
    ResolvedDependency,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.ecosystems.static import exclusions_for, discover_files, read_text
from depcheck.ecosystems.python_manifest import (
    PythonManifestCollector,
    IGNORED_DIRECTORIES,
    is_requirements_file,
    parser_map,
)
from depcheck.ecosystems.python_script import inline_script_files, parse_inline_script

DEFAULT_IMPORT_MAP: dict[str, str] = {
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "git": "gitpython",
    "jose": "python-jose",
    "jwt": "pyjwt",
    "mysqldb": "mysqlclient",
    "pil": "pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
}


_MANIFEST_RESULT = "python_manifest_result"
_USAGE_RESULT = "python_usage_result"
_LOCK_NAMES = frozenset({"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"})


def named_component_roots(
    root: Path, settings: Mapping[str, object]
) -> tuple[Path, ...]:
    configured = settings.get("python_roots", ())
    roots = (
        [Path(p) for p in configured if isinstance(p, str)]
        if isinstance(configured, (list, tuple))
        else []
    )
    for path in discover_files(
        root,
        names=frozenset({"pyproject.toml"}),
        excluded_directories=exclusions_for(settings),
    ):
        try:
            data = tomllib.loads(read_text(path))
            name = data.get("project", {}).get("name") or data.get("tool", {}).get(
                "poetry", {}
            ).get("name")
            if (isinstance(name, str) and name.strip()) or "workspace" in data.get(
                "tool", {}
            ).get("uv", {}):
                roots.append(path.parent.relative_to(root))
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            continue
    return tuple(sorted(set(roots), key=lambda p: (len(p.parts), p.as_posix())))


def _component_exclusions(
    root: Path, project: ProjectUnit, settings: Mapping[str, object]
) -> tuple[str, ...]:
    exclusions = exclusions_for(settings, project.root)
    children = tuple(
        p.relative_to(project.root).as_posix()
        for p in named_component_roots(root, settings)
        if p != project.root and project.root in p.parents
    )
    return (*exclusions, *children)


class PythonProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        exclusions = exclusions_for(context.settings)
        source_files = ImportScanner(exclusions).discover_files(root)
        scripts = inline_script_files(root, exclusions, paths=source_files)
        script_paths = set(scripts)
        has_python_manifest = _has_manifest_candidate(
            root,
            exclusions,
            include_install_hints=False,
        )
        if not source_files and not has_python_manifest:
            return ()
        manifests = (
            tuple(
                PythonManifestCollector(
                    root,
                    exclusions,
                ).find_dependency_file()
            )
            if _has_manifest_candidate(root, exclusions)
            else ()
        )

        roots = named_component_roots(root, context.settings)
        paths = tuple(_relative(p, root) for p in manifests)

        def owner(path: Path) -> Path:
            return next(
                (p for p in reversed(roots) if p == path.parent or p in path.parents),
                Path("."),
            )

        active_roots = set(roots)
        active_roots.update(
            owner(p)
            for p in (
                *paths,
                *(_relative(p, root) for p in source_files if p not in script_paths),
            )
        )
        if not active_roots and not scripts:
            active_roots.add(Path("."))
        projects = []
        for relative_root in sorted(
            active_roots, key=lambda p: (len(p.parts), p.as_posix())
        ):
            relative_manifests = tuple(p for p in paths if owner(p) == relative_root)
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "PyPI", "python"),
                    root=relative_root,
                    language="python",
                    ecosystem="PyPI",
                    manager="python",
                    manifests=relative_manifests,
                    locks=tuple(
                        p
                        for p in relative_manifests
                        if p.name in _LOCK_NAMES
                        or (p.suffix.lower() == ".lock" and is_requirements_file(p))
                    ),
                )
            )
        projects.extend(
            ProjectUnit(
                project_id=ProjectUnit.stable_id(
                    script.relative_to(root), "PyPI", "pep723"
                ),
                root=script.parent.relative_to(root),
                language="python",
                ecosystem="PyPI",
                manager="pep723",
                manifests=(script.relative_to(root),),
            )
            for script in scripts
        )
        return tuple(projects)


class PythonManifestProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[DependencyDeclaration, ...]:
        result = _manifest_result(context, project)
        return tuple(
            _adapt_declaration(project.project_id, item) for item in result.declarations
        )


class PythonResolutionProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[ResolvedDependency, ...]:
        result = _manifest_result(context, project)
        direct_names = {
            item.name
            for item in result.declarations
            if item.kind == "direct" and item.group != "build"
        }
        resolved: list[ResolvedDependency] = []
        seen: set[tuple[str, str, str]] = set()
        locked_names = {i.name for i in result.declarations if i.kind == "locked"}
        overrides = {
            i.name: dict(i.origin)
            for i in result.declarations
            if i.kind == "direct" and i.origin.get("public") is False
        }
        for item in result.declarations:
            version = item.pinned_version
            if version is None or item.kind not in {"direct", "locked"}:
                continue
            if item.kind == "direct" and item.name in locked_names:
                continue
            origin = {**dict(item.origin), **overrides.get(item.name, {})}
            origin_key = json.dumps(origin, sort_keys=True)
            if "lock" in origin:
                origin_key += (
                    "\0"
                    + _relative(item.source.path, context.repository_root).as_posix()
                )
            key = (item.name, version, origin_key)
            if key in seen:
                continue
            seen.add(key)
            resolved.append(
                ResolvedDependency(
                    project_id=project.project_id,
                    package=_package_ref(
                        item.name,
                        item.display_name,
                        public=origin.get("public") is True,
                    ),
                    version=version,
                    source=item.source,
                    direct=item.name in direct_names,
                    origin=origin,
                    instance_id=(
                        "lock:uv:"
                        + hashlib.sha256(origin_key.encode()).hexdigest()[:24]
                        if "lock" in origin
                        else None
                        if origin.get("public") is True
                        else "source:"
                        + hashlib.sha256(origin_key.encode()).hexdigest()[:24]
                    ),
                )
            )
        return tuple(resolved)


class PythonUsageProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[UsageEvidence, ...]:
        result = _usage_result(context, project)
        return tuple(_adapt_usage(project.project_id, item) for item in result.imports)


class PythonUsageMapper:
    def __init__(self, import_mapping: Mapping[str, str] | None = None) -> None:
        configured = import_mapping or {}
        self._configured = {
            key.lower(): str(canonicalize_name(value))
            for key, value in configured.items()
        }
        self._known = {
            key.lower(): str(canonicalize_name(value))
            for key, value in DEFAULT_IMPORT_MAP.items()
        }

    def map(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        usage: UsageEvidence,
    ) -> UsageEvidence:
        del context, project
        reference = usage.reference.lower()
        if reference in self._configured:
            name = self._configured[reference]
            confidence = MappingConfidence.CONFIGURED
            reason = "project import mapping"
        elif reference in self._known:
            name = self._known[reference]
            confidence = MappingConfidence.EXACT
            reason = "built-in Python import mapping"
        else:
            name = str(canonicalize_name(reference))
            confidence = MappingConfidence.INFERRED
            reason = "inferred distribution name from top-level Python import"
        return replace(
            usage,
            mapped_package=_package_ref(name, name),
            mapping_confidence=confidence,
            mapping_reason=reason,
        )


class PythonEvidenceCollector:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        return collect_python_bundle(
            context.repository_root,
            project,
            pack,
            context.settings,
        )


def create_python_pack(
    import_mapping: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="PyPI",
        detector=PythonProjectDetector(),
        manifest_provider=PythonManifestProvider(),
        resolution_provider=PythonResolutionProvider(),
        usage_provider=PythonUsageProvider(),
        usage_mapper=PythonUsageMapper(import_mapping),
        capabilities=frozenset(
            {
                "compatibility",
                "manifest",
                "mapping",
                "resolution",
                "security",
                "update_preview",
                "usage",
            }
        ),
        collector=PythonEvidenceCollector(),
    )


@measured("collection.python")
def collect_python_bundle(
    repository_root: Path,
    project: ProjectUnit,
    pack: EcosystemPack,
    settings: Mapping[str, object] | None = None,
) -> EvidenceBundle:
    root = Path(repository_root).resolve()
    project_root = root / project.root
    exclusions = _component_exclusions(root, project, settings or {})
    if project.manager == "pep723":
        script = root / project.manifests[0]
        bundle = adapt_python_bundle(
            root,
            project,
            pack,
            filter_python_manifest(
                parse_inline_script(script), (settings or {}).get("python_version")
            ),
            ImportScanner(exclusions).scan_files(project_root, [script]),
        )
        return replace(
            bundle,
            capabilities=tuple(
                _status(capability.name, False)
                if capability.name in {"usage", "mapping"}
                else capability
                for capability in bundle.capabilities
            ),
            diagnostics=(
                *bundle.diagnostics,
                Diagnostic(
                    code="usage.script-helper-coverage-unknown",
                    severity="warning",
                    message="Only this independent script is scanned; imported local helpers and runner injection remain outside its usage scope. Zero observed imports do not establish an unused requirement.",
                    source=SourceLocation(script),
                ),
            ),
        )
    manifest_result = (
        PythonManifestCollector(project_root, exclusions).collect()
        if project.manifests
        else ManifestParseResult()
    )
    manifest_result = filter_python_manifest(
        manifest_result,
        (settings or {}).get("python_version"),
    )
    scanner = ImportScanner(exclusions)
    source_files = scanner.discover_files(project_root)
    scripts = set(inline_script_files(project_root, exclusions, paths=source_files))
    usage_result = scanner.scan_files(
        project_root, [path for path in source_files if path not in scripts]
    )
    bundle = adapt_python_bundle(
        root,
        project,
        pack,
        manifest_result,
        usage_result,
    )
    workspace = _uv_workspace_root(root, project_root)
    if workspace is not None:
        diagnostic = Diagnostic(
            code="resolution.uv-workspace-activation-unknown",
            severity="warning",
            message="uv workspace members share an installation environment and lock. Component ownership describes declarations and source; lock activation and cross-member availability are unknown.",
            source=SourceLocation(workspace / "pyproject.toml"),
        )
        bundle = replace(
            bundle,
            capabilities=tuple(_status(c.name, False) for c in bundle.capabilities),
            diagnostics=(*bundle.diagnostics, diagnostic),
            evidence_files=tuple(
                dict.fromkeys(
                    (
                        *bundle.evidence_files,
                        workspace / "pyproject.toml",
                        *(
                            (workspace / "uv.lock",)
                            if (workspace / "uv.lock").is_file()
                            else ()
                        ),
                    )
                )
            ),
        )
    return bundle


def _uv_workspace_root(root: Path, project_root: Path) -> Path | None:
    """Locate a shared-environment boundary without guessing active lock subsets."""
    for parent in (project_root, *project_root.parents):
        if parent != root and root not in parent.parents:
            break
        path = parent / "pyproject.toml"
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(read_text(path))
            uv = data.get("tool", {}).get("uv", {})
            if uv.get("managed") is False:
                return None
            if "workspace" in uv:
                if parent == project_root:
                    return parent
                from depcheck.ecosystems.workspaces import _workspace_pattern

                workspace = uv["workspace"]
                if not isinstance(workspace, dict):
                    return parent
                members, excluded = (
                    workspace.get("members"),
                    workspace.get("exclude", []),
                )
                if (
                    not isinstance(members, list)
                    or not isinstance(excluded, list)
                    or not all(isinstance(p, str) for p in [*members, *excluded])
                ):
                    return parent
                patterns = [_workspace_pattern(p) for p in [*members, *excluded]]
                if any(p is None for p in patterns):
                    return parent
                relative = project_root.relative_to(parent).as_posix()
                included = any(
                    p is not None and p.fullmatch(relative)
                    for p in patterns[: len(members)]
                )
                rejected = any(
                    p is not None and p.fullmatch(relative)
                    for p in patterns[len(members) :]
                )
                return parent if included and not rejected else None
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            continue
    return None


def filter_python_manifest(
    manifest_result: ManifestParseResult,
    python_version: object | None,
) -> ManifestParseResult:
    """Apply target-Python markers before any scan or index consumes evidence."""
    if python_version is None:
        return manifest_result
    version = Version(str(python_version))
    environment = {
        "python_version": f"{version.major}.{version.minor}",
        "python_full_version": str(version),
    }
    diagnostics = list(manifest_result.diagnostics)
    active: list[PythonRequirement] = []
    for item in manifest_result.declarations:
        try:
            applies = item.is_active(environment)
        except (UndefinedComparison, UndefinedEnvironmentName, InvalidVersion) as exc:
            diagnostic = Diagnostic(
                code="manifest.marker-evaluation-unknown",
                severity="error",
                message=f"{item.raw_requirement}: marker applicability is unknown: {exc}",
                source=item.source,
            )
            if diagnostic not in diagnostics:
                diagnostics.append(diagnostic)
            # Retain the declaration without asserting its activation.
            applies = True
        if applies:
            active.append(item)
    active_direct = {
        item.name for item in active if item.kind == "direct" and item.group != "build"
    }
    inactive_direct = {
        item.name
        for item in manifest_result.declarations
        if item.kind == "direct" and item.group != "build"
    } - active_direct
    return ManifestParseResult(
        declarations=tuple(
            item
            for item in active
            if not (item.kind == "locked" and item.name in inactive_direct)
        ),
        diagnostics=tuple(diagnostics),
        files=manifest_result.files,
    )


def adapt_python_bundle(
    repository_root: Path,
    project: ProjectUnit,
    pack: EcosystemPack,
    manifest_result: ManifestParseResult,
    usage_result: ImportScanResult,
) -> EvidenceBundle:
    """Adapt cached Python scanner results without reading the repository again."""
    root = Path(repository_root).resolve()
    context = ProviderContext(
        root,
        {
            _MANIFEST_RESULT: manifest_result,
            _USAGE_RESULT: usage_result,
        },
    )

    declarations = (
        pack.manifest_provider.collect(context, project)
        if pack.manifest_provider is not None
        else ()
    )
    resolved = (
        pack.resolution_provider.collect(context, project)
        if pack.resolution_provider is not None
        else ()
    )
    raw_usages = (
        pack.usage_provider.collect(context, project)
        if pack.usage_provider is not None
        else ()
    )
    usages = (
        tuple(pack.usage_mapper.map(context, project, usage) for usage in raw_usages)
        if pack.usage_mapper is not None
        else raw_usages
    )

    component_manifests = sorted(
        {
            item.source.path
            for item in declarations
            if item.kind == "direct"
            and item.scope != "build"
            and item.source.path.name == "pyproject.toml"
        }
    )
    component_diagnostics = (
        (
            Diagnostic(
                code="analysis.python-component-scope-ambiguous",
                severity="error",
                message=(
                    "Multiple Python dependency roots share an aggregate project ID; "
                    "their installation scopes cannot be compared safely. "
                    "Scan each component root separately."
                ),
                source=next(
                    item.source
                    for item in declarations
                    if item.source.path == component_manifests[0]
                ),
            ),
        )
        if len(component_manifests) > 1
        else ()
    )
    manifest_complete = _complete(
        (*manifest_result.diagnostics, *component_diagnostics)
    )
    usage_complete = (
        not component_diagnostics
        and _complete(usage_result.diagnostics)
        and not any(item.code == "usage.dynamic" for item in usage_result.diagnostics)
    )
    mapping_complete = usage_complete and all(
        item.mapping_confidence is not MappingConfidence.UNKNOWN for item in usages
    )
    source_diagnostics = tuple(
        Diagnostic(
            code="resolution.python-source-unverified",
            severity="warning",
            message=f"{item.package.name}: {item.origin.get('kind', 'unknown')} source does not establish a public PyPI identity; public registry checks are skipped.",
            source=item.source,
        )
        for item in resolved
        if item.origin.get("public") is not True
    )
    conditional_locks = any(
        item.origin.get("lock", {}).get("conditional") for item in resolved
    )
    capabilities = (
        _status("manifest", manifest_complete),
        _status(
            "resolution",
            manifest_complete and not source_diagnostics and not conditional_locks,
        ),
        _status("usage", usage_complete),
        _status("mapping", mapping_complete),
    )
    return EvidenceBundle(
        project=project,
        declarations=declarations,
        resolved=resolved,
        usages=usages,
        diagnostics=(
            *manifest_result.diagnostics,
            *component_diagnostics,
            *source_diagnostics,
            *usage_result.diagnostics,
        ),
        capabilities=capabilities,
        source_files=usage_result.files,
        evidence_files=manifest_result.files,
    )


def _manifest_result(
    context: ProviderContext,
    project: ProjectUnit,
) -> ManifestParseResult:
    cached = context.settings.get(_MANIFEST_RESULT)
    if isinstance(cached, ManifestParseResult):
        return cached
    if project.manager == "pep723":
        return parse_inline_script(context.repository_root / project.manifests[0])
    return (
        PythonManifestCollector(
            context.repository_root / project.root,
            exclusions_for(context.settings, project.root),
        ).collect()
        if project.manifests
        else ManifestParseResult()
    )


def _usage_result(
    context: ProviderContext,
    project: ProjectUnit,
) -> ImportScanResult:
    cached = context.settings.get(_USAGE_RESULT)
    if isinstance(cached, ImportScanResult):
        return cached
    return ImportScanner(exclusions_for(context.settings, project.root)).scan_detailed(
        context.repository_root / project.root
    )


def _adapt_declaration(
    project_id: str,
    declaration: PythonRequirement,
) -> DependencyDeclaration:
    normalized = str(declaration.specifier)
    return DependencyDeclaration(
        project_id=project_id,
        package=_package_ref(
            declaration.name,
            declaration.display_name,
            public=declaration.origin.get("public") is True,
        ),
        constraint=VersionConstraint(
            raw=normalized,
            scheme="pep440",
            normalized=normalized or None,
        ),
        source=declaration.source,
        scope=_scope(declaration.group),
        kind=declaration.kind,
        marker=str(declaration.marker) if declaration.marker is not None else None,
        metadata={
            "extras": list(declaration.extras),
            "raw_requirement": declaration.raw_requirement,
            "group": declaration.group,
            "origin": dict(declaration.origin),
        },
    )


def _adapt_usage(project_id: str, usage: ImportEvidence) -> UsageEvidence:
    return UsageEvidence(
        project_id=project_id,
        language="python",
        reference=usage.module,
        source=usage.source,
        scope=usage.scope,
        kind=usage.kind,
    )


def _package_ref(name: str, display_name: str, *, public: bool = True) -> PackageRef:
    canonical = str(canonicalize_name(name))
    return PackageRef(
        ecosystem="PyPI",
        name=canonical,
        display_name=display_name,
        purl=f"pkg:pypi/{quote(canonical, safe='')}" if public else None,
    )


def _scope(group: str) -> str:
    if group == "dev" or group.startswith(("dev:", "development")):
        return "development"
    if group.startswith("optional:"):
        return "optional"
    return group


def _complete(diagnostics: Sequence[Diagnostic]) -> bool:
    return not any(item.severity == "error" for item in diagnostics)


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name=name,
        state=CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        reason=None if complete else f"{name} evidence is incomplete",
    )


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path


def _has_manifest_candidate(
    root: Path,
    excluded_directories: Sequence[str] = (),
    *,
    include_install_hints: bool = True,
) -> bool:
    install_hint_names = {
        "CMakeLists.txt",
        "Dockerfile",
        "Makefile",
        "dockerfile",
        "makefile",
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if not name.startswith(".")
            and name not in IGNORED_DIRECTORIES
            and not _excluded_child(
                root,
                Path(dirpath) / name,
                excluded_directories,
            )
        ]
        if any(
            (
                name in parser_map
                and (include_install_hints or name not in install_hint_names)
            )
            or is_requirements_file(Path(name))
            for name in filenames
        ):
            return True
    return False


def _excluded_child(
    root: Path,
    path: Path,
    excluded_directories: Sequence[str],
) -> bool:
    from depcheck.ecosystems.static import is_excluded

    return is_excluded(path.relative_to(root), excluded_directories)
