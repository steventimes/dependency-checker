"""Bounded Maven POM inheritance, declarations and plugin assertions."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PureWindowsPath
from typing import Any
from xml.parsers import expat

from depcheck.ecosystems.maven_identity import package_ref as _package_ref
from depcheck.ecosystems.static import DEFAULT_MAX_BYTES, StaticReadError, read_text
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    SourceLocation,
    VersionConstraint,
)

from .java_common import _PROPERTY, _diagnostic, _valid_maven_coordinate

_MAX_POM_PARENT_DEPTH = 16


@dataclass(frozen=True, slots=True)
class _MavenDependencySpec:
    group: str
    artifact: str
    version: str
    scope: str
    optional: bool
    packaging: str
    classifier: str
    source: SourceLocation


@dataclass(frozen=True, slots=True)
class _MavenPluginSpec:
    group: str
    artifact: str
    version: str
    inherited: str
    source: SourceLocation
    properties: Mapping[str, str]
    metadata: Mapping[str, Any]
    dependencies: tuple[_MavenDependencySpec, ...]


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
    plugins: tuple[_MavenPluginSpec, ...] = ()


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
                source=dependency.source,
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
                source=dependency.source,
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
    declarations.extend(
        _maven_plugin_declarations(
            project, manifest, repository_root, model.plugins, diagnostics
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
    root, positions = _read_pom_root(canonical)
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
            candidate = Path(relative_path.replace("\\", "/"))
            invalid_path = (
                candidate.is_absolute() or PureWindowsPath(relative_path).is_absolute()
            )
            if not invalid_path:
                try:
                    candidate = (manifest.parent / candidate).resolve()
                    candidate.relative_to(repository_root)
                    if candidate.is_dir():
                        candidate = (candidate / "pom.xml").resolve()
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
                    parent_model = None

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
    model = _EffectivePom(
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
                positions,
            ),
        ),
        dependencies=(
            *inherited_dependencies,
            *_pom_dependency_specs(
                root,
                "./{*}dependencies/{*}dependency",
                manifest,
                positions,
            ),
        ),
        plugins=tuple(
            p
            for p in parent_model.plugins
            if p.inherited.lower() != "false"
            or (
                p.metadata["maven_kind"] != "reporting-plugin"
                and p.metadata["executions"]
            )
        )
        if parent_model
        else (),
    )
    return replace(
        model,
        plugins=(
            *model.plugins,
            *_pom_plugin_specs(
                root, manifest, repository_root, positions, model, diagnostics
            ),
        ),
    )


def _pom_plugin_specs(
    root: ET.Element,
    manifest: Path,
    repository_root: Path,
    positions: Mapping[int, SourceLocation],
    model: _EffectivePom,
    diagnostics: list[Diagnostic],
) -> tuple[_MavenPluginSpec, ...]:
    specs: list[_MavenPluginSpec] = []
    properties: Mapping[str, str] | None = None
    if root.find("./{*}build/{*}extensions/{*}extension") is not None:
        diagnostics.append(
            _diagnostic(
                "manifest.maven-build-extensions-uncollected",
                "Maven build extension inventory remains uncollected",
                SourceLocation(manifest),
                severity="warning",
            )
        )
    scopes: list[tuple[ET.Element, dict[str, object] | None]] = [(root, None)]
    for index, profile in enumerate(root.findall("./{*}profiles/{*}profile")):
        if (
            profile.find("./{*}dependencies/{*}dependency") is not None
            or profile.find("./{*}dependencyManagement/{*}dependencies/{*}dependency")
            is not None
        ):
            diagnostics.append(
                _diagnostic(
                    "manifest.maven-profile-dependencies-uncollected",
                    "Maven profile application dependencies and management remain uncollected; profile activation is unknown",
                    positions.get(id(profile), SourceLocation(manifest)),
                    severity="warning",
                )
            )
        activation: dict[str, object] = {}
        container = profile.find("{*}activation")
        if container is not None:
            for condition in container:
                activation[_local_name(condition.tag)] = (
                    {
                        _local_name(child.tag): (child.text or "").strip()
                        for child in condition
                    }
                    if len(condition)
                    else (condition.text or "").strip()
                )
                allowed = {
                    "activeByDefault": set(),
                    "jdk": set(),
                    "os": {"name", "family", "arch", "version"},
                    "property": {"name", "value"},
                    "file": {"exists", "missing"},
                }
                name = _local_name(condition.tag)
                if name not in allowed or any(
                    _local_name(child.tag) not in allowed[name] or len(child)
                    for child in condition
                ):
                    activation["uncollected_conditions"] = True
                    diagnostics.append(
                        _diagnostic(
                            "manifest.maven-profile-activation-uncollected",
                            "Maven profile activation contains unsupported nested conditions; activation remains unknown",
                            positions.get(id(condition), SourceLocation(manifest)),
                            severity="warning",
                        )
                    )
        scopes.append(
            (
                profile,
                {
                    "id": _child_text(profile, "id") or "",
                    "index": index,
                    "activation": activation,
                },
            )
        )
    for scope, profile_metadata in scopes:
        for context, kind in (
            ("build/plugins", "build-plugin"),
            ("build/pluginManagement/plugins", "plugin-management"),
            ("reporting/plugins", "reporting-plugin"),
        ):
            query = (
                "./"
                + "/".join(f"{{*}}{part}" for part in context.split("/"))
                + "/{*}plugin"
            )
            for plugin in scope.findall(query):
                if profile_metadata is None and properties is None:
                    properties = _pom_properties(model)
                extensions = _pom_flag(plugin, "extensions", "false")
                inherited = _pom_flag(plugin, "inherited", "true")
                executions = []
                for execution in plugin.findall("./{*}executions/{*}execution"):
                    executions.append(
                        {
                            "id": _child_text(execution, "id") or "",
                            "phase": _child_text(execution, "phase") or "",
                            "goals": [
                                (goal.text or "").strip()
                                for goal in execution.findall("./{*}goals/{*}goal")
                            ],
                            "inherited": _pom_flag(execution, "inherited", inherited),
                            "inherited_explicit": execution.find("{*}inherited")
                            is not None,
                            "source": positions.get(
                                id(execution), SourceLocation(manifest)
                            ).to_dict(repository_root),
                        }
                    )
                report_sets = [
                    {
                        "id": _child_text(report, "id") or "",
                        "reports": [
                            (node.text or "").strip()
                            for node in report.findall("./{*}reports/{*}report")
                        ],
                        "inherited": _pom_flag(report, "inherited", inherited),
                        "inherited_explicit": report.find("{*}inherited") is not None,
                        "source": positions.get(
                            id(report), SourceLocation(manifest)
                        ).to_dict(repository_root),
                    }
                    for report in plugin.findall("./{*}reportSets/{*}reportSet")
                ]
                metadata: dict[str, Any] = {
                    "maven_kind": kind,
                    "plugin_context": context.replace("/", "."),
                    "activation": "unknown",
                    "effective_model": "not-evaluated",
                    "classpath": "build-extension"
                    if extensions.lower() == "true"
                    else "plugin"
                    if extensions.lower() == "false"
                    else "unknown",
                    "extensions": extensions,
                    "configuration_present": plugin.find("{*}configuration")
                    is not None,
                    "configuration_collected": False,
                    "executions": executions,
                    "report_sets": report_sets,
                    "property_context": "declaring-pom"
                    if profile_metadata is None
                    else "unevaluated-profile",
                }
                if profile_metadata is not None:
                    metadata["profile"] = profile_metadata
                group = _child_text(plugin, "groupId") or ""
                if plugin.find("{*}groupId") is None:
                    group = "org.apache.maven.plugins"
                specs.append(
                    _MavenPluginSpec(
                        group,
                        _child_text(plugin, "artifactId") or "",
                        _child_text(plugin, "version") or "",
                        inherited,
                        positions.get(id(plugin), SourceLocation(manifest)),
                        (properties or {}) if profile_metadata is None else {},
                        metadata,
                        _pom_dependency_specs(
                            plugin,
                            "./{*}dependencies/{*}dependency",
                            manifest,
                            positions,
                        ),
                    )
                )
    return tuple(specs)


def _pom_flag(element: ET.Element, name: str, default: str) -> str:
    child = element.find(f"{{*}}{name}")
    return default if child is None else (child.text or "").strip()


def _maven_plugin_declarations(
    project: ProjectUnit,
    manifest: Path,
    repository_root: Path,
    plugins: tuple[_MavenPluginSpec, ...],
    diagnostics: list[Diagnostic],
) -> list[DependencyDeclaration]:
    declarations: list[DependencyDeclaration] = []
    remaining = DEFAULT_MAX_BYTES
    for plugin in plugins:
        resolver = _PropertyResolver(plugin.properties)
        group, artifact = (
            resolver.substitute(plugin.group),
            resolver.substitute(plugin.artifact),
        )
        if not _valid_maven_coordinate(group, artifact) or not all(
            re.fullmatch(r"[A-Za-z0-9_.-]+", value) for value in (group, artifact)
        ):
            diagnostics.append(
                _diagnostic(
                    "manifest.maven-plugin-identity-unresolved",
                    "Maven plugin identity is missing, invalid or unresolved",
                    plugin.source,
                    severity="warning",
                )
            )
            continue
        coordinate = f"{group}:{artifact}"
        metadata = dict(plugin.metadata)
        metadata["inherited"] = plugin.inherited
        metadata["source_relationship"] = (
            "current-pom"
            if plugin.source.path == manifest.resolve()
            else "local-parent-assertion"
        )
        metadata["declaring_pom"] = plugin.source.to_dict(repository_root)["path"]
        if plugin.source.path != manifest.resolve():
            metadata["executions"] = [
                e
                for e in metadata["executions"]
                if str(e["inherited"]).lower() != "false"
            ]
            metadata["report_sets"] = [
                r
                for r in metadata["report_sets"]
                if str(r["inherited"]).lower() != "false"
            ]
        assertions = [(group, artifact, plugin.version, plugin.source, metadata)]
        for dependency in plugin.dependencies:
            dep_group, dep_artifact = (
                resolver.substitute(dependency.group),
                resolver.substitute(dependency.artifact),
            )
            if not _valid_maven_coordinate(dep_group, dep_artifact):
                diagnostics.append(
                    _diagnostic(
                        "manifest.maven-plugin-identity-unresolved",
                        "Maven plugin dependency identity is missing or unresolved",
                        dependency.source,
                        severity="warning",
                    )
                )
                continue
            dependency_metadata = {
                key: metadata[key]
                for key in (
                    "plugin_context",
                    "activation",
                    "classpath",
                    "property_context",
                    "source_relationship",
                    "declaring_pom",
                    "profile",
                )
                if key in metadata
            }
            dependency_metadata.update(
                {
                    "maven_kind": "plugin-dependency",
                    "owner_plugin": coordinate,
                    "owner_plugin_kind": metadata["maven_kind"],
                    "maven_scope": dependency.scope or "compile",
                    "maven_type": dependency.packaging,
                    "maven_classifier": dependency.classifier,
                }
            )
            assertions.append(
                (
                    dep_group,
                    dep_artifact,
                    dependency.version,
                    dependency.source,
                    dependency_metadata,
                )
            )
        for (
            assertion_group,
            assertion_artifact,
            raw_version,
            source,
            assertion_metadata,
        ) in assertions:
            version = resolver.substitute(raw_version)
            normalized = version if version and not _PROPERTY.search(version) else None
            assertion_metadata["version_state"] = (
                "asserted"
                if normalized
                else "unresolved-expression"
                if raw_version
                else "unspecified-or-managed"
            )
            remaining -= len(json.dumps(assertion_metadata).encode("utf-8")) + sum(
                len(value.encode("utf-8"))
                for value in (assertion_group, assertion_artifact, raw_version, version)
            )
            if remaining < 0:
                diagnostics.append(
                    _diagnostic(
                        "manifest.maven-plugin-budget",
                        "Maven plugin evidence expansion exceeded the bounded metadata budget; remaining assertions are uncollected",
                        source,
                        severity="warning",
                    )
                )
                return declarations
            declaration = DependencyDeclaration(
                project.project_id,
                _package_ref(f"{assertion_group}:{assertion_artifact}"),
                VersionConstraint(raw_version, "maven", normalized),
                source,
                scope="build",
                kind="conditional",
                metadata=assertion_metadata,
            )
            declarations.append(declaration)
    return declarations


def _read_pom_root(manifest: Path) -> tuple[ET.Element, dict[int, SourceLocation]]:
    text = read_text(manifest)
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise StaticReadError(f"unsafe XML declarations are not allowed in {manifest}")
    parser = expat.ParserCreate()
    starts: list[SourceLocation] = []

    def start(name: str, attrs: dict[str, str]) -> None:
        if len(starts) >= 100_000:
            raise StaticReadError(f"Maven XML element budget exceeded in {manifest}")
        starts.append(
            SourceLocation(
                manifest, parser.CurrentLineNumber, parser.CurrentColumnNumber + 1
            )
        )

    parser.StartElementHandler = start
    try:
        parser.Parse(text, True)
        root = ET.fromstring(text)
    except (ET.ParseError, expat.ExpatError) as exc:
        raise StaticReadError(f"invalid XML in {manifest}: {exc}") from exc
    if _local_name(root.tag) != "project":
        raise StaticReadError(f"invalid Maven POM root in {manifest}: expected project")
    return root, {
        id(element): source for element, source in zip(root.iter(), starts, strict=True)
    }


def _pom_dependency_specs(
    root: ET.Element,
    query: str,
    manifest: Path,
    positions: Mapping[int, SourceLocation],
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
            source=positions.get(id(dependency), SourceLocation(manifest)),
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
    resolver = _PropertyResolver(values)
    return {key: resolver.substitute(value) for key, value in values.items()}


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
    manifest: Path | SourceLocation,
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


def _substitute_properties(value: str, properties: Mapping[str, str]) -> str:
    return _PropertyResolver(properties).substitute(value)


class _PropertyResolver:
    def __init__(self, properties: Mapping[str, str]) -> None:
        self.properties = properties
        self.cache: dict[str, str] = {}
        self.active: set[str] = set()
        self.remaining = 1024 * 1024

    def substitute(self, value: str) -> str:
        parts: list[str] = []
        offset = 0
        for match in _PROPERTY.finditer(value):
            name = match.group(1)
            if name in self.active or len(self.active) >= 64:
                raise StaticReadError("Maven property cycle or nesting limit exceeded")
            if name in self.properties and name not in self.cache:
                self.active.add(name)
                self.cache[name] = self.substitute(self.properties[name])
                self.active.remove(name)
            literal = value[offset : match.start()]
            replacement = self.cache.get(name, match.group(0))
            self.remaining -= len(literal) + len(replacement)
            if self.remaining < 0:
                raise StaticReadError("Maven property expansion exceeds 1 MiB")
            parts.extend((literal, replacement))
            offset = match.end()
        self.remaining -= len(value) - offset
        if self.remaining < 0:
            raise StaticReadError("Maven property expansion exceeds 1 MiB")
        parts.append(value[offset:])
        return "".join(parts)


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
