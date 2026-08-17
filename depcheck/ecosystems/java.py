from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from depcheck.model import Diagnostic, SourceLocation
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
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_text,
)

_GRADLE_CONFIGURATIONS = {
    "api": "runtime",
    "implementation": "runtime",
    "compile": "runtime",
    "compileOnly": "optional",
    "runtimeOnly": "runtime",
    "annotationProcessor": "build",
    "kapt": "build",
    "testImplementation": "test",
    "testCompile": "test",
    "testRuntimeOnly": "test",
}
_GRADLE_LITERAL = re.compile(
    r"^\s*([A-Za-z][\w]*)\s*(?:\(\s*)?['\"]([^'\"]+)['\"]\s*\)?"
)
_GRADLE_CALL = re.compile(r"^\s*([A-Za-z][\w]*)\s*\(")
_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")
_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)")
_PROPERTY = re.compile(r"\$\{([^}]+)\}")
_MAX_POM_PARENT_DEPTH = 16
_CURATED_IMPORTS = {
    "com.fasterxml.jackson": "com.fasterxml.jackson.core:jackson-databind",
    "com.google.common": "com.google.guava:guava",
    "org.apache.commons.lang3": "org.apache.commons:commons-lang3",
    "org.junit": "junit:junit",
    "org.slf4j": "org.slf4j:slf4j-api",
}


@dataclass(frozen=True, slots=True)
class _MavenDependencySpec:
    group: str
    artifact: str
    version: str
    scope: str
    optional: bool
    packaging: str
    classifier: str
    source: Path


@dataclass(frozen=True, slots=True)
class _EffectivePom:
    properties: Mapping[str, str]
    group_id: str
    artifact_id: str
    version: str
    parent_group_id: str
    parent_artifact_id: str
    parent_version: str
    management: tuple[_MavenDependencySpec, ...]
    dependencies: tuple[_MavenDependencySpec, ...]


class JavaProjectDetector:
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        candidates = discover_files(
            root,
            names=frozenset({"pom.xml", "build.gradle", "build.gradle.kts"}),
            excluded_directories=exclusions_for(context.settings),
        )
        by_root: dict[Path, set[str]] = {}
        for path in candidates:
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
                projects.append(
                    _project_unit(relative_root, "gradle", gradle_name, project_root)
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

    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        del pack
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
                declarations, parse_diagnostics = _parse_gradle(project, manifest)
            diagnostics.extend(parse_diagnostics)
            manifest_complete = not parse_diagnostics
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        resolution_complete = manifest_complete
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
            lock = project_root / "gradle.lockfile"
            if lock.is_file():
                try:
                    resolved = _merge_gradle_lock(project, lock, resolved)
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
            and path.name not in {"build.gradle.kts"}
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
                        source=SourceLocation(path, line_number, 1),
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
    lock = project_root / "gradle.lockfile"
    locks = (
        (
            (
                relative_root / "gradle.lockfile"
                if relative_root != Path(".")
                else Path("gradle.lockfile")
            ),
        )
        if manager == "gradle" and lock.is_file()
        else ()
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


def _parse_pom(
    project: ProjectUnit,
    manifest: Path,
    repository_root: Path,
) -> tuple[
    tuple[DependencyDeclaration, ...],
    list[Diagnostic],
    tuple[Path, ...],
]:
    diagnostics: list[Diagnostic] = []
    evidence_files: list[Path] = []
    model = _load_effective_pom(
        repository_root.resolve(),
        manifest,
        diagnostics,
        evidence_files,
        stack=(),
        depth=0,
    )
    if model is None:
        return (), diagnostics, tuple(dict.fromkeys(evidence_files))

    properties = _pom_properties(model)
    declarations: list[DependencyDeclaration] = []
    managed: dict[
        tuple[str, str, str, str],
        tuple[str, str, _MavenDependencySpec],
    ] = {}
    for dependency in model.management:
        group = _substitute_properties(dependency.group, properties)
        artifact = _substitute_properties(dependency.artifact, properties)
        version = _substitute_properties(dependency.version, properties)
        packaging = _substitute_properties(dependency.packaging, properties) or "jar"
        classifier = _substitute_properties(dependency.classifier, properties)
        scope = _substitute_properties(dependency.scope, properties)
        if not _valid_maven_coordinate(group, artifact):
            diagnostics.append(
                _diagnostic(
                    "manifest.invalid-dependency",
                    "Maven dependency is missing a usable groupId or artifactId",
                    dependency.source,
                    severity="warning",
                )
            )
            continue
        if _diagnose_maven_identity_expressions(
            dependency,
            packaging,
            classifier,
            scope,
            diagnostics,
        ):
            continue
        if packaging == "pom" and scope == "import":
            diagnostics.append(
                _diagnostic(
                    "manifest.bom-unavailable",
                    f"Imported Maven BOM {group}:{artifact} is not available from local static evidence.",
                    dependency.source,
                )
            )
        _diagnose_maven_expression(
            dependency.version,
            version,
            dependency.source,
            diagnostics,
        )
        managed[(group, artifact, packaging, classifier)] = (
            version,
            scope,
            dependency,
        )

    for (
        group,
        artifact,
        packaging,
        classifier,
    ), (version, scope, dependency) in managed.items():
        declarations.append(
            DependencyDeclaration(
                project_id=project.project_id,
                package=_package_ref(f"{group}:{artifact}"),
                constraint=VersionConstraint(
                    dependency.version,
                    "maven",
                    version or None,
                ),
                source=SourceLocation(dependency.source, 1, 1),
                scope=(
                    "optional"
                    if dependency.optional
                    else _maven_scope(scope or "compile")
                ),
                kind="constraint",
                metadata={
                    "maven_scope": scope or "compile",
                    "maven_type": packaging,
                    "maven_classifier": classifier,
                },
            )
        )

    effective_dependencies: dict[
        tuple[str, str, str, str],
        tuple[
            _MavenDependencySpec,
            str,
            str,
            str,
            str,
            str,
        ],
    ] = {}
    for dependency in model.dependencies:
        group = _substitute_properties(dependency.group, properties)
        artifact = _substitute_properties(dependency.artifact, properties)
        packaging = _substitute_properties(dependency.packaging, properties) or "jar"
        classifier = _substitute_properties(dependency.classifier, properties)
        scope = _substitute_properties(dependency.scope, properties)
        if not _valid_maven_coordinate(group, artifact):
            diagnostics.append(
                _diagnostic(
                    "manifest.invalid-dependency",
                    "Maven dependency is missing a usable groupId or artifactId",
                    dependency.source,
                    severity="warning",
                )
            )
            continue
        effective_dependencies[(group, artifact, packaging, classifier)] = (
            dependency,
            group,
            artifact,
            packaging,
            classifier,
            scope,
        )

    for (
        dependency,
        group,
        artifact,
        packaging,
        classifier,
        scope,
    ) in effective_dependencies.values():
        raw_version = dependency.version
        version = _substitute_properties(raw_version, properties)
        managed_entry = managed.get((group, artifact, packaging, classifier))
        if not version and managed_entry is not None:
            version = managed_entry[0]
        resolution_blocked = _diagnose_maven_identity_expressions(
            dependency,
            packaging,
            classifier,
            scope,
            diagnostics,
        )
        effective_scope = (
            scope
            or (managed_entry[1] if managed_entry is not None else "")
            or "compile"
        )
        if raw_version:
            _diagnose_maven_expression(
                raw_version,
                version,
                dependency.source,
                diagnostics,
            )
        if not version:
            diagnostics.append(
                _diagnostic(
                    "manifest.version-unresolved",
                    f"Maven dependency {group}:{artifact} has no locally verifiable version.",
                    dependency.source,
                )
            )
        declarations.append(
            DependencyDeclaration(
                project_id=project.project_id,
                package=_package_ref(f"{group}:{artifact}"),
                constraint=VersionConstraint(raw_version, "maven", version or None),
                source=SourceLocation(dependency.source, 1, 1),
                scope=(
                    "optional"
                    if dependency.optional
                    else _maven_scope(
                        "unknown"
                        if _PROPERTY.search(effective_scope)
                        else effective_scope
                    )
                ),
                kind="direct",
                metadata={
                    "maven_scope": effective_scope,
                    "maven_type": packaging,
                    "maven_classifier": classifier,
                    "managed": not raw_version and managed_entry is not None,
                    "resolution_blocked": resolution_blocked,
                },
            )
        )
    return (
        tuple(declarations),
        diagnostics,
        tuple(dict.fromkeys(evidence_files)),
    )


def _load_effective_pom(
    repository_root: Path,
    manifest: Path,
    diagnostics: list[Diagnostic],
    evidence_files: list[Path],
    *,
    stack: tuple[Path, ...],
    depth: int,
) -> _EffectivePom | None:
    try:
        canonical = manifest.resolve()
    except OSError as exc:
        raise StaticReadError(f"cannot resolve {manifest}: {exc}") from exc
    if canonical in stack:
        diagnostics.append(
            _diagnostic(
                "manifest.parent-cycle",
                f"Maven parent cycle reaches {canonical}.",
                manifest,
            )
        )
        return None
    if depth >= _MAX_POM_PARENT_DEPTH:
        diagnostics.append(
            _diagnostic(
                "manifest.parent-depth-exceeded",
                f"Maven parent chain exceeds {_MAX_POM_PARENT_DEPTH} local files.",
                manifest,
            )
        )
        return None

    evidence_files.append(canonical)
    root = _read_pom_root(canonical)
    parent_element = root.find("./{*}parent")
    parent_model: _EffectivePom | None = None
    declared_parent = {
        field: (_child_text(parent_element, field) or "")
        if parent_element is not None
        else ""
        for field in ("groupId", "artifactId", "version")
    }
    if parent_element is not None:
        relative_element = parent_element.find("{*}relativePath")
        explicit_path = relative_element is not None
        relative_path = (
            "../pom.xml"
            if relative_element is None
            else (relative_element.text or "").strip()
        )
        if not relative_path:
            _diagnose_parent_unavailable(manifest, declared_parent, diagnostics)
        else:
            candidate = Path(relative_path)
            invalid_path = candidate.is_absolute()
            if not invalid_path:
                try:
                    candidate = (manifest.parent / candidate).resolve()
                    candidate.relative_to(repository_root)
                except (OSError, ValueError):
                    invalid_path = True
            if invalid_path:
                code = (
                    "manifest.parent-path-invalid"
                    if explicit_path
                    else "manifest.parent-unavailable"
                )
                message = (
                    f"Maven parent relativePath {relative_path!r} leaves the repository."
                    if explicit_path
                    else "The Maven parent is not available as bounded local repository evidence."
                )
                diagnostics.append(_diagnostic(code, message, manifest))
            elif not candidate.is_file():
                _diagnose_parent_unavailable(manifest, declared_parent, diagnostics)
            else:
                parent_model = _load_effective_pom(
                    repository_root,
                    candidate,
                    diagnostics,
                    evidence_files,
                    stack=(*stack, canonical),
                    depth=depth + 1,
                )
                if parent_model is None:
                    return None
                actual_parent = _pom_properties(parent_model)
                expected_parent = tuple(
                    declared_parent[field]
                    for field in ("groupId", "artifactId", "version")
                )
                actual_coordinate = tuple(
                    actual_parent.get(f"project.{field}", "")
                    for field in ("groupId", "artifactId", "version")
                )
                if (
                    not all(expected_parent)
                    or any(_PROPERTY.search(value) for value in expected_parent)
                    or expected_parent != actual_coordinate
                ):
                    diagnostics.append(
                        _diagnostic(
                            "manifest.parent-coordinate-mismatch",
                            "The local Maven parent does not match the declared parent coordinate.",
                            manifest,
                        )
                    )
                    return None

    parent_properties = _pom_properties(parent_model) if parent_model else {}
    inherited_properties = dict(parent_model.properties) if parent_model else {}
    for container in root.findall("./{*}properties"):
        for child in list(container):
            if child.text and child.text.strip():
                inherited_properties[_local_name(child.tag)] = child.text.strip()

    parent_group = parent_properties.get("project.groupId", declared_parent["groupId"])
    parent_artifact = parent_properties.get(
        "project.artifactId", declared_parent["artifactId"]
    )
    parent_version = parent_properties.get(
        "project.version", declared_parent["version"]
    )
    group_id = _child_text(root, "groupId") or parent_group
    artifact_id = _child_text(root, "artifactId") or ""
    version = _child_text(root, "version") or parent_version
    inherited_management = parent_model.management if parent_model else ()
    inherited_dependencies = parent_model.dependencies if parent_model else ()
    return _EffectivePom(
        properties=inherited_properties,
        group_id=group_id,
        artifact_id=artifact_id,
        version=version,
        parent_group_id=declared_parent["groupId"] or parent_group,
        parent_artifact_id=declared_parent["artifactId"] or parent_artifact,
        parent_version=declared_parent["version"] or parent_version,
        management=(
            *inherited_management,
            *_pom_dependency_specs(
                root,
                "./{*}dependencyManagement/{*}dependencies/{*}dependency",
                manifest,
            ),
        ),
        dependencies=(
            *inherited_dependencies,
            *_pom_dependency_specs(
                root,
                "./{*}dependencies/{*}dependency",
                manifest,
            ),
        ),
    )


def _read_pom_root(manifest: Path) -> ET.Element:
    text = read_text(manifest)
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise StaticReadError(f"unsafe XML declarations are not allowed in {manifest}")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise StaticReadError(f"invalid XML in {manifest}: {exc}") from exc
    if _local_name(root.tag) != "project":
        raise StaticReadError(f"invalid Maven POM root in {manifest}: expected project")
    return root


def _pom_dependency_specs(
    root: ET.Element,
    query: str,
    manifest: Path,
) -> tuple[_MavenDependencySpec, ...]:
    return tuple(
        _MavenDependencySpec(
            group=_child_text(dependency, "groupId") or "",
            artifact=_child_text(dependency, "artifactId") or "",
            version=_child_text(dependency, "version") or "",
            scope=_child_text(dependency, "scope") or "",
            optional=(_child_text(dependency, "optional") or "").lower() == "true",
            packaging=_child_text(dependency, "type") or "jar",
            classifier=_child_text(dependency, "classifier") or "",
            source=manifest,
        )
        for dependency in root.findall(query)
    )


def _pom_properties(model: _EffectivePom | None) -> dict[str, str]:
    if model is None:
        return {}
    values = dict(model.properties)
    values.update(
        {
            "project.groupId": model.group_id,
            "pom.groupId": model.group_id,
            "project.artifactId": model.artifact_id,
            "pom.artifactId": model.artifact_id,
            "project.version": model.version,
            "pom.version": model.version,
            "project.parent.groupId": model.parent_group_id,
            "parent.groupId": model.parent_group_id,
            "project.parent.artifactId": model.parent_artifact_id,
            "parent.artifactId": model.parent_artifact_id,
            "project.parent.version": model.parent_version,
            "parent.version": model.parent_version,
        }
    )
    for _ in range(16):
        updated = {
            key: _substitute_properties(value, values) for key, value in values.items()
        }
        if updated == values:
            break
        values = updated
    return values


def _valid_maven_coordinate(group: str, artifact: str) -> bool:
    return bool(group and artifact) and not (
        _PROPERTY.search(group) or _PROPERTY.search(artifact)
    )


def _diagnose_maven_identity_expressions(
    dependency: _MavenDependencySpec,
    packaging: str,
    classifier: str,
    scope: str,
    diagnostics: list[Diagnostic],
) -> bool:
    unresolved = False
    for field, raw, effective in (
        ("type", dependency.packaging, packaging),
        ("classifier", dependency.classifier, classifier),
        ("scope", dependency.scope, scope),
    ):
        if not _PROPERTY.search(effective):
            continue
        unresolved = True
        diagnostics.append(
            _diagnostic(
                "manifest.unsupported-expression",
                f"Cannot resolve Maven {field} expression {raw}.",
                dependency.source,
                severity="warning",
            )
        )
    return unresolved


def _diagnose_maven_expression(
    raw_version: str,
    version: str,
    manifest: Path,
    diagnostics: list[Diagnostic],
) -> None:
    if version and _PROPERTY.search(version):
        diagnostics.append(
            _diagnostic(
                "manifest.unsupported-expression",
                f"Cannot resolve Maven version expression {raw_version}.",
                manifest,
                severity="warning",
            )
        )


def _diagnose_parent_unavailable(
    manifest: Path,
    coordinate: Mapping[str, str],
    diagnostics: list[Diagnostic],
) -> None:
    name = ":".join(
        coordinate.get(field, "") for field in ("groupId", "artifactId", "version")
    ).strip(":")
    diagnostics.append(
        _diagnostic(
            "manifest.parent-unavailable",
            f"Maven parent {name or '(unspecified)'} is not available from bounded local repository evidence.",
            manifest,
        )
    )


def _parse_gradle(
    project: ProjectUnit,
    manifest: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    text = read_text(manifest)
    declarations: list[DependencyDeclaration] = []
    diagnostics: list[Diagnostic] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("//", 1)[0]
        match = _GRADLE_LITERAL.match(line)
        if match is not None and match.group(1) in _GRADLE_CONFIGURATIONS:
            configuration, coordinate = match.groups()
            parts = coordinate.split(":")
            if len(parts) < 3 or not all(parts[:3]):
                diagnostics.append(
                    _diagnostic(
                        "manifest.invalid-dependency",
                        f"invalid Gradle coordinate: {coordinate}",
                        manifest,
                        severity="warning",
                    )
                )
                continue
            group, artifact, version = parts[:3]
            declarations.append(
                DependencyDeclaration(
                    project_id=project.project_id,
                    package=_package_ref(f"{group}:{artifact}"),
                    constraint=VersionConstraint(version, "maven", version),
                    source=SourceLocation(manifest, line_number, 1),
                    scope=_GRADLE_CONFIGURATIONS[configuration],
                    kind="direct",
                    metadata={"configuration": configuration},
                )
            )
            continue
        call = _GRADLE_CALL.match(line)
        if call is not None and call.group(1) in _GRADLE_CONFIGURATIONS:
            diagnostics.append(
                _diagnostic(
                    "manifest.unsupported-expression",
                    f"Gradle {call.group(1)} uses a non-literal dependency expression",
                    manifest,
                    severity="warning",
                )
            )
    return tuple(declarations), diagnostics


def _merge_gradle_lock(
    project: ProjectUnit,
    lock: Path,
    existing: Sequence[ResolvedDependency],
) -> list[ResolvedDependency]:
    by_name = {item.package.name: item for item in existing}
    for line_number, raw_line in enumerate(read_text(lock).splitlines(), start=1):
        coordinate = raw_line.split("=", 1)[0].strip()
        parts = coordinate.split(":")
        if len(parts) != 3 or not all(parts):
            continue
        group, artifact, version = parts
        package = _package_ref(f"{group}:{artifact}")
        by_name[package.name] = ResolvedDependency(
            project.project_id,
            package,
            version,
            SourceLocation(lock, line_number, 1),
            direct=package.name in by_name,
        )
    return [by_name[name] for name in sorted(by_name)]


def _package_ref(coordinate: str) -> PackageRef:
    group, separator, artifact = coordinate.partition(":")
    canonical = f"{group}:{artifact}" if separator else coordinate
    purl = None
    if separator and group and artifact:
        purl = f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='-._~')}"
    return PackageRef("Maven", canonical, coordinate, purl)


def _substitute_properties(value: str, properties: Mapping[str, str]) -> str:
    result = value
    for _ in range(8):
        updated = _PROPERTY.sub(
            lambda match: properties.get(match.group(1), match.group(0)),
            result,
        )
        if updated == result:
            break
        result = updated
    return result


def _child_text(element: ET.Element, name: str) -> str | None:
    child = element.find(f"{{*}}{name}")
    if child is None or child.text is None or not child.text.strip():
        return None
    return child.text.strip()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _maven_scope(scope: str) -> str:
    return {
        "compile": "runtime",
        "runtime": "runtime",
        "test": "test",
        "provided": "optional",
        "system": "build",
        "import": "build",
    }.get(scope, scope)


def _is_exact_version(version: str) -> bool:
    dynamic_tokens = ("${", "+", "[", "]", "(", ")", ",")
    lowered = version.lower()
    return bool(version) and not (
        lowered in {"latest", "release"}
        or lowered.startswith("latest.")
        or lowered.endswith("-snapshot")
        or any(token in version for token in dynamic_tokens)
        or any(character.isspace() for character in version)
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


def _diagnostic(
    code: str,
    message: str,
    path: Path,
    *,
    severity: str = "error",
) -> Diagnostic:
    return Diagnostic(code, severity, message, SourceLocation(path))


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
