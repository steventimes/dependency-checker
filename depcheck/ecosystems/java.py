from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from depcheck.bounded_io import repository_operation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.ecosystems.gradle_catalog import collect_gradle_catalogs
from depcheck.ecosystems.maven_identity import package_ref as _package_ref
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_text,
)
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

from .java_common import _diagnostic, _is_exact_version
from .java_gradle import _GRADLE_LOCK_NAMES, _merge_gradle_lock, _parse_gradle
from .java_maven import _parse_pom

_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")
_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)")
_CURATED_IMPORTS = {
    "com.fasterxml.jackson": "com.fasterxml.jackson.core:jackson-databind",
    "com.google.common": "com.google.guava:guava",
    "org.apache.commons.lang3": "org.apache.commons:commons-lang3",
    "org.junit": "junit:junit",
    "org.slf4j": "org.slf4j:slf4j-api",
}


class JavaProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        candidates = discover_files(
            root,
            names=frozenset({"pom.xml", "build.gradle", "build.gradle.kts"}),
            suffixes=frozenset({".toml"}),
            excluded_directories=exclusions_for(context.settings),
        )
        by_root: dict[Path, set[str]] = {}
        catalogs: dict[Path, list[Path]] = {}
        for path in candidates:
            if path.name.lower().endswith(".versions.toml"):
                catalogs.setdefault(path.parent, []).append(path.relative_to(root))
            elif path.name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
                by_root.setdefault(path.parent, set()).add(path.name)
        projects: list[ProjectUnit] = []
        for project_root, names in sorted(
            by_root.items(), key=lambda item: item[0].as_posix()
        ):
            relative_root = project_root.relative_to(root)
            if relative_root == Path(""):
                relative_root = Path(".")
            if "pom.xml" in names:
                projects.append(
                    _project_unit(relative_root, "maven", "pom.xml", project_root)
                )
            gradle_name = (
                "build.gradle.kts"
                if "build.gradle.kts" in names
                else "build.gradle"
                if "build.gradle" in names
                else None
            )
            if gradle_name is not None:
                unit = _project_unit(relative_root, "gradle", gradle_name, project_root)
                scripts = tuple(
                    relative_root / name
                    for name in ("build.gradle", "build.gradle.kts")
                    if name in names
                )
                projects.append(replace(unit, manifests=scripts))
        for directory, manifests in catalogs.items():
            relative = directory.relative_to(root)
            projects.append(
                ProjectUnit(
                    ProjectUnit.stable_id(relative, "Maven", "gradle-catalog"),
                    relative,
                    "toml",
                    "Maven",
                    "gradle-catalog",
                    tuple(sorted(manifests)),
                )
            )
        return tuple(
            sorted(
                projects,
                key=lambda item: (
                    len(item.root.parts),
                    item.root.as_posix(),
                    item.manager,
                ),
            )
        )


class JavaEvidenceCollector:
    def __init__(self, mappings: Mapping[str, str] | None = None) -> None:
        self.mappings = {
            str(key): str(value) for key, value in (mappings or {}).items()
        }

    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        del pack
        if project.manager == "gradle-catalog":
            return collect_gradle_catalogs(context, project)
        project_root = context.repository_root / project.root
        manifest = context.repository_root / project.manifests[0]
        diagnostics: list[Diagnostic] = []
        manifest_complete = True
        declarations: tuple[DependencyDeclaration, ...] = ()
        evidence_files: tuple[Path, ...] = (manifest,)
        try:
            if project.manager == "maven":
                declarations, parse_diagnostics, evidence_files = _parse_pom(
                    project,
                    manifest,
                    context.repository_root,
                )
            else:
                collected: list[DependencyDeclaration] = []
                parse_diagnostics = []
                evidence_files = tuple(
                    context.repository_root / p for p in project.manifests
                )
                for script in evidence_files:
                    rows, problems = _parse_gradle(
                        project, script, context.repository_root
                    )
                    collected.extend(rows)
                    parse_diagnostics.extend(problems)
                declarations = tuple(collected)
                if len(evidence_files) > 1:
                    parse_diagnostics.append(
                        _diagnostic(
                            "manifest.gradle-build-file-ambiguous",
                            "Both Gradle DSL build files are inventoried; no active script was selected.",
                            manifest,
                            severity="warning",
                        )
                    )
            diagnostics.extend(parse_diagnostics)
            manifest_complete = not parse_diagnostics
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        resolution_complete = False
        if project.manager == "maven":
            resolution_complete = False
            diagnostics.append(
                _diagnostic(
                    "resolution.maven-build-graph-unknown",
                    "Maven coordinates are static assertions; implicit lifecycle plugins, "
                    "effective build selection and the installed graph remain uncollected",
                    manifest,
                    severity="warning",
                )
            )
        plugin = next((d for d in declarations if d.metadata.get("maven_kind")), None)
        if plugin is not None:
            resolution_complete = False
            diagnostics.append(
                _diagnostic(
                    "resolution.maven-plugin-activation-unknown",
                    "Maven plugin inventory does not establish an effective build, "
                    "profile/lifecycle selection, classloader resolution or execution; "
                    "plugin configuration bodies and runtime use remain uncollected",
                    plugin.source,
                    severity="warning",
                )
            )
        resolved = list(
            ResolvedDependency(
                project_id=project.project_id,
                package=item.package,
                version=item.constraint.normalized or item.constraint.raw,
                source=item.source,
                direct=item.kind == "direct",
            )
            for item in declarations
            if item.kind == "direct"
            and not item.metadata.get("resolution_blocked", False)
            and _is_exact_version(item.constraint.normalized or item.constraint.raw)
        )
        if project.manager == "gradle":
            diagnostics.append(
                _diagnostic(
                    "resolution.gradle-build-graph-unknown",
                    "Gradle declarations are requested configuration; lock assertions retain configuration variants, not active build selection or installation.",
                    manifest,
                    severity="warning",
                )
            )
            for name in _GRADLE_LOCK_NAMES:
                lock = project_root / name
                if not (lock.exists() or lock.is_symlink()):
                    continue
                try:
                    resolved, lock_diagnostics = _merge_gradle_lock(
                        project, lock, resolved
                    )
                    diagnostics.extend(lock_diagnostics)
                except StaticReadError as exc:
                    resolution_complete = False
                    diagnostics.append(_diagnostic("lock.invalid", str(exc), lock))

        (
            usages,
            source_files,
            usage_diagnostics,
            usage_complete,
            mapping_complete,
        ) = self._usages(
            project,
            project_root,
            exclusions_for(context.settings, project.root),
        )
        diagnostics.extend(usage_diagnostics)
        return EvidenceBundle(
            project=project,
            declarations=declarations,
            resolved=tuple(resolved),
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=(
                _status("manifest", manifest_complete),
                _status("resolution", resolution_complete),
                _status("security", resolution_complete),
                _status("usage", usage_complete),
                _status("mapping", mapping_complete),
            ),
            source_files=source_files,
            evidence_files=evidence_files,
        )

    def _usages(
        self,
        project: ProjectUnit,
        project_root: Path,
        excluded_directories: Sequence[str] = (),
    ) -> tuple[
        tuple[UsageEvidence, ...],
        tuple[Path, ...],
        list[Diagnostic],
        bool,
        bool,
    ]:
        files = discover_files(
            project_root,
            suffixes=frozenset({".java", ".kt", ".kts"}),
            excluded_directories=excluded_directories,
        )
        owned = tuple(
            path
            for path in files
            if _nearest_java_root(path.parent, project_root) == project_root
            and not path.name.endswith(".gradle.kts")
        )
        local_packages: set[str] = set()
        texts: dict[Path, str] = {}
        diagnostics: list[Diagnostic] = []
        complete = True
        for path in owned:
            try:
                text = read_text(path)
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
                continue
            texts[path] = text
            for line in text.splitlines():
                match = _PACKAGE.match(line)
                if match is not None:
                    local_packages.add(match.group(1))

        mappings = {**_CURATED_IMPORTS, **self.mappings}
        prefixes = tuple(sorted(mappings, key=len, reverse=True))
        usages: list[UsageEvidence] = []
        mapping_complete = True
        for path, text in texts.items():
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = _IMPORT.match(line)
                if match is None:
                    continue
                reference = match.group(1)
                if reference.startswith(("java.", "kotlin.")) or any(
                    reference == prefix or reference.startswith(prefix + ".")
                    for prefix in local_packages
                ):
                    continue
                mapped_name: str | None = None
                confidence = MappingConfidence.UNKNOWN
                reason = "Java namespace is not a package coordinate"
                for prefix in prefixes:
                    if reference == prefix or reference.startswith(prefix + "."):
                        mapped_name = mappings[prefix]
                        confidence = (
                            MappingConfidence.CONFIGURED
                            if prefix in self.mappings
                            else MappingConfidence.EXACT
                        )
                        reason = (
                            "project import mapping"
                            if confidence is MappingConfidence.CONFIGURED
                            else "curated Java namespace mapping"
                        )
                        break
                if mapped_name is None:
                    mapping_complete = False
                usages.append(
                    UsageEvidence(
                        project_id=project.project_id,
                        language="kotlin" if path.suffix in {".kt", ".kts"} else "java",
                        reference=reference,
                        source=SourceLocation(path, line_number, match.start(1) + 1),
                        scope=_source_scope(path, project_root),
                        mapped_package=(
                            _package_ref(mapped_name)
                            if mapped_name is not None
                            else None
                        ),
                        mapping_confidence=confidence,
                        mapping_reason=reason,
                    )
                )
        return tuple(usages), owned, diagnostics, complete, mapping_complete


def create_maven_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="Maven",
        detector=JavaProjectDetector(),
        capabilities=frozenset(
            {"manifest", "mapping", "resolution", "security", "usage"}
        ),
        collector=JavaEvidenceCollector(mappings),
    )


def _project_unit(
    relative_root: Path,
    manager: str,
    manifest_name: str,
    project_root: Path,
) -> ProjectUnit:
    relative_manifest = (
        relative_root / manifest_name
        if relative_root != Path(".")
        else Path(manifest_name)
    )
    locks = tuple(
        relative_root / name
        for name in _GRADLE_LOCK_NAMES
        if manager == "gradle"
        and ((project_root / name).exists() or (project_root / name).is_symlink())
    )
    return ProjectUnit(
        project_id=ProjectUnit.stable_id(relative_root, "Maven", manager),
        root=relative_root,
        language="java",
        ecosystem="Maven",
        manager=manager,
        manifests=(relative_manifest,),
        locks=locks,
    )


def _nearest_java_root(path: Path, boundary: Path) -> Path:
    current = path
    while current != boundary and boundary in current.parents:
        if any(
            (current / name).is_file()
            for name in ("pom.xml", "build.gradle", "build.gradle.kts")
        ):
            return current
        current = current.parent
    return boundary


def _source_scope(path: Path, root: Path) -> str:
    parts = {part.lower() for part in path.relative_to(root).parts}
    return "test" if "test" in parts or "tests" in parts else "runtime"


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
