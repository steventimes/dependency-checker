from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
import os
from pathlib import Path
from urllib.parse import quote

from packaging.utils import canonicalize_name

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
    ResolvedDependency,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.ecosystems.static import exclusions_for
from depcheck.ecosystems.python_manifest import (
    PythonManifestCollector,
    IGNORED_DIRECTORIES,
    parser_map,
)

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


class PythonProjectDetector:
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        exclusions = exclusions_for(context.settings)
        source_files = ImportScanner(exclusions).discover_files(root)
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

        relative_root = Path(".")
        relative_manifests = tuple(_relative(path, root) for path in manifests)
        locks = tuple(path for path in relative_manifests if path.name in _LOCK_NAMES)
        return (
            ProjectUnit(
                project_id=ProjectUnit.stable_id(
                    relative_root,
                    "PyPI",
                    "python",
                ),
                root=relative_root,
                language="python",
                ecosystem="PyPI",
                manager="python",
                manifests=relative_manifests,
                locks=locks,
            ),
        )


class PythonManifestProvider:
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
        seen: set[tuple[str, str]] = set()
        for item in result.declarations:
            version = item.pinned_version
            if version is None or item.kind not in {"direct", "locked"}:
                continue
            key = (item.name, version)
            if key in seen:
                continue
            seen.add(key)
            resolved.append(
                ResolvedDependency(
                    project_id=project.project_id,
                    package=_package_ref(item.name, item.display_name),
                    version=version,
                    source=item.source,
                    direct=item.name in direct_names,
                )
            )
        return tuple(resolved)


class PythonUsageProvider:
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
            confidence = MappingConfidence.EXACT
            reason = "canonical top-level Python import"
        return replace(
            usage,
            mapped_package=_package_ref(name, name),
            mapping_confidence=confidence,
            mapping_reason=reason,
        )


class PythonEvidenceCollector:
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


def collect_python_bundle(
    repository_root: Path,
    project: ProjectUnit,
    pack: EcosystemPack,
    settings: Mapping[str, object] | None = None,
) -> EvidenceBundle:
    root = Path(repository_root).resolve()
    project_root = root / project.root
    exclusions = exclusions_for(settings or {}, project.root)
    manifest_result = (
        PythonManifestCollector(project_root, exclusions).collect()
        if project.manifests
        else ManifestParseResult()
    )
    manifest_result = filter_python_manifest(
        manifest_result,
        (settings or {}).get("python_version"),
    )
    usage_result = ImportScanner(exclusions).scan_detailed(project_root)
    return adapt_python_bundle(
        root,
        project,
        pack,
        manifest_result,
        usage_result,
    )


def filter_python_manifest(
    manifest_result: ManifestParseResult,
    python_version: object | None,
) -> ManifestParseResult:
    """Apply target-Python markers before any scan or index consumes evidence."""
    if python_version is None:
        return manifest_result
    environment = {"python_version": str(python_version)}
    active_direct = {
        item.name
        for item in manifest_result.declarations
        if item.kind == "direct"
        and item.group != "build"
        and item.is_active(environment)
    }
    inactive_direct = {
        item.name
        for item in manifest_result.declarations
        if item.kind == "direct" and item.group != "build"
    } - active_direct
    return ManifestParseResult(
        declarations=tuple(
            item
            for item in manifest_result.declarations
            if item.is_active(environment)
            and not (item.kind == "locked" and item.name in inactive_direct)
        ),
        diagnostics=manifest_result.diagnostics,
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

    manifest_complete = _complete(manifest_result.diagnostics)
    usage_complete = _complete(usage_result.diagnostics)
    mapping_complete = usage_complete and all(
        item.mapping_confidence is not MappingConfidence.UNKNOWN for item in usages
    )
    capabilities = (
        _status("manifest", manifest_complete),
        _status("resolution", manifest_complete),
        _status("usage", usage_complete),
        _status("mapping", mapping_complete),
    )
    return EvidenceBundle(
        project=project,
        declarations=declarations,
        resolved=resolved,
        usages=usages,
        diagnostics=(*manifest_result.diagnostics, *usage_result.diagnostics),
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
        package=_package_ref(declaration.name, declaration.display_name),
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


def _package_ref(name: str, display_name: str) -> PackageRef:
    canonical = str(canonicalize_name(name))
    return PackageRef(
        ecosystem="PyPI",
        name=canonical,
        display_name=display_name,
        purl=f"pkg:pypi/{quote(canonical, safe='')}",
    )


def _scope(group: str) -> str:
    if group == "dev" or group.startswith("development"):
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
        reason=None if complete else f"{name} evidence contains errors",
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
            or name.startswith("requirements")
            and name.endswith(".txt")
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
