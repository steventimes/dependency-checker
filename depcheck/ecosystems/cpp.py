from __future__ import annotations

from depcheck.bounded_io import repository_operation

import ast
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import quote

from depcheck.model import Diagnostic, SourceLocation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.ecosystems.cmake import cmake_commands
from depcheck.ecosystems.cpp_source import CppSourceGap, cpp_includes
from depcheck.source_locations import SourcePositions, parse_python_ast
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
    DEFAULT_MAX_BYTES,
    StaticReadError,
    discover_files,
    exclusions_for,
    parse_json,
    read_text,
)

_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
_STANDARD_HEADERS = frozenset(
    {
        "algorithm",
        "array",
        "assert.h",
        "atomic",
        "bitset",
        "chrono",
        "cmath",
        "complex",
        "condition_variable",
        "cstddef",
        "cstdint",
        "cstdio",
        "cstdlib",
        "cstring",
        "deque",
        "errno.h",
        "exception",
        "filesystem",
        "float.h",
        "fstream",
        "functional",
        "future",
        "initializer_list",
        "iomanip",
        "ios",
        "iostream",
        "istream",
        "iterator",
        "limits",
        "list",
        "map",
        "math.h",
        "memory",
        "mutex",
        "new",
        "numeric",
        "optional",
        "ostream",
        "queue",
        "set",
        "signal.h",
        "sstream",
        "stack",
        "stdarg.h",
        "stdbool.h",
        "stddef.h",
        "stdint.h",
        "stdio.h",
        "stdlib.h",
        "string",
        "string.h",
        "string_view",
        "thread",
        "time.h",
        "tuple",
        "type_traits",
        "unordered_map",
        "unordered_set",
        "utility",
        "variant",
        "vector",
    }
)
_CURATED = {
    "Conan": {
        "boost": "boost",
        "catch2": "catch2",
        "fmt": "fmt",
        "gmock": "gtest",
        "gtest": "gtest",
        "nlohmann": "nlohmann_json",
        "spdlog": "spdlog",
    },
    "vcpkg": {
        "catch2": "catch2",
        "fmt": "fmt",
        "gmock": "gtest",
        "gtest": "gtest",
        "nlohmann": "nlohmann-json",
        "spdlog": "spdlog",
    },
}


class CppProjectDetector:
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        preferred: tuple[str, ...]
        if self.ecosystem == "Conan":
            names = frozenset({"conanfile.txt", "conanfile.py"})
            preferred = ("conanfile.txt", "conanfile.py")
            manager = "conan"
            lock_name = "conan.lock"
        else:
            names = frozenset({"vcpkg.json"})
            preferred = ("vcpkg.json",)
            manager = "vcpkg"
            lock_name = "vcpkg-lock.json"
        by_root: dict[Path, set[str]] = {}
        for manifest in discover_files(
            root,
            names=names,
            excluded_directories=exclusions_for(context.settings),
        ):
            by_root.setdefault(manifest.parent, set()).add(manifest.name)
        projects: list[ProjectUnit] = []
        for project_root, found_names in sorted(
            by_root.items(),
            key=lambda item: item[0].as_posix(),
        ):
            manifest_name = next(name for name in preferred if name in found_names)
            relative_root = project_root.relative_to(root)
            if relative_root == Path(""):
                relative_root = Path(".")
            relative_manifest = _relative_child(relative_root, manifest_name)
            locks = (
                (_relative_child(relative_root, lock_name),)
                if (project_root / lock_name).is_file()
                else ()
            )
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(
                        relative_root,
                        self.ecosystem,
                        manager,
                    ),
                    root=relative_root,
                    language="cpp",
                    ecosystem=self.ecosystem,
                    manager=manager,
                    manifests=(relative_manifest,),
                    locks=locks,
                )
            )
        return tuple(
            sorted(
                projects,
                key=lambda item: (len(item.root.parts), item.root.as_posix()),
            )
        )


class CppEvidenceCollector:
    def __init__(
        self,
        ecosystem: str,
        mappings: Mapping[str, str] | None = None,
    ) -> None:
        self.ecosystem = ecosystem
        self.mappings = {
            str(key).lower().strip("/"): str(value)
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
        project_root = context.repository_root / project.root
        manifest = context.repository_root / project.manifests[0]
        diagnostics: list[Diagnostic] = []
        declarations: tuple[DependencyDeclaration, ...] = ()
        manifest_complete = True
        try:
            if self.ecosystem == "Conan":
                if manifest.name == "conanfile.py":
                    declarations, parse_diagnostics = _parse_conan_python(
                        project,
                        manifest,
                    )
                else:
                    declarations, parse_diagnostics = _parse_conan_text(
                        project,
                        manifest,
                    )
            else:
                declarations, parse_diagnostics = _parse_vcpkg(project, manifest)
            diagnostics.extend(parse_diagnostics)
            manifest_complete = not parse_diagnostics
            conditional = next(
                (d for d in declarations if d.kind == "conditional"), None
            )
            if conditional is not None:
                diagnostics.append(
                    Diagnostic(
                        "resolution.vcpkg-feature-activation-unknown",
                        "warning",
                        "vcpkg feature dependencies are conditional assertions; default features, "
                        "platforms and build selection are not evaluated",
                        conditional.source,
                    )
                )
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(
                _diagnostic("manifest.invalid", str(exc), exc.source or manifest)
            )

        resolved: tuple[ResolvedDependency, ...] = tuple(
            ResolvedDependency(
                project.project_id,
                item.package,
                item.constraint.normalized or item.constraint.raw,
                item.source,
                direct=item.kind == "direct",
                instance_id=f"manifest:{index}",
                origin={
                    "kind": "manifest-pin",
                    "activation": "unknown",
                    "scope": item.scope,
                    **(
                        {"reference": item.metadata["reference"]}
                        if "reference" in item.metadata
                        else {}
                    ),
                },
            )
            for index, item in enumerate(declarations)
            if item.constraint.normalized and item.kind != "conditional"
        )
        # Manifest pins and lock entries do not identify an active build graph.
        resolution_complete = False
        lock = project_root / (
            "conan.lock" if self.ecosystem == "Conan" else "vcpkg-lock.json"
        )
        if lock.is_file():
            try:
                resolved = (
                    _parse_conan_lock(project, lock, declarations)
                    if self.ecosystem == "Conan"
                    else _parse_vcpkg_lock(project, lock, declarations)
                )
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(
                    _diagnostic("lock.invalid", str(exc), exc.source or lock)
                )
        diagnostics.append(
            _diagnostic(
                "resolution.cpp-activation-unknown",
                "C/C++ versions are static assertions; active build contexts, "
                "lock selection and installed packages remain unknown",
                lock if lock.is_file() else manifest,
                severity="warning",
            )
        )

        (
            usages,
            source_files,
            evidence_files,
            usage_diagnostics,
            usage_complete,
            mapping_complete,
        ) = self._usages(
            project,
            project_root,
            declarations,
            exclusions_for(context.settings, project.root),
        )
        diagnostics.extend(usage_diagnostics)
        return EvidenceBundle(
            project=project,
            declarations=declarations,
            resolved=resolved,
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=(
                _status("manifest", manifest_complete),
                _status("resolution", resolution_complete),
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
        declarations: Sequence[DependencyDeclaration],
        excluded_directories: Sequence[str] = (),
    ) -> tuple[
        tuple[UsageEvidence, ...],
        tuple[Path, ...],
        tuple[Path, ...],
        list[Diagnostic],
        bool,
        bool,
    ]:
        mappings = {**_CURATED[self.ecosystem], **self.mappings}
        prefixes = tuple(sorted(mappings, key=len, reverse=True))
        usages: list[UsageEvidence] = []
        evidence_files: list[Path] = []
        diagnostics: list[Diagnostic] = []
        complete = True
        mapping_complete = True
        source_files = tuple(
            path
            for path in discover_files(
                project_root,
                suffixes=_SOURCE_SUFFIXES,
                excluded_directories=excluded_directories,
            )
            if _nearest_cpp_root(path.parent, project_root, self.ecosystem)
            == project_root
        )
        for path in source_files:
            try:
                text = read_text(path)
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
                continue
            positions = SourcePositions(path, text)
            includes = []
            try:
                for item in cpp_includes(text):
                    if isinstance(item, CppSourceGap):
                        complete = False
                        diagnostics.append(
                            _diagnostic(
                                "source.cpp-uncollected",
                                item.reason,
                                positions.at(item.offset),
                                severity="warning",
                            )
                        )
                    else:
                        includes.append(item)
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
            for include in includes:
                delimiter, reference = include.delimiter, include.reference
                if _ignore_header(reference, delimiter, path, project_root):
                    continue
                mapped_name: str | None = None
                confidence = MappingConfidence.UNKNOWN
                reason = "header ownership is not provable statically"
                normalized = reference.lower().strip("/")
                for prefix in prefixes:
                    if normalized == prefix or normalized.startswith(prefix + "/"):
                        mapped_name = mappings[prefix]
                        confidence = (
                            MappingConfidence.CONFIGURED
                            if prefix in self.mappings
                            else MappingConfidence.EXACT
                        )
                        reason = (
                            "project header mapping"
                            if confidence is MappingConfidence.CONFIGURED
                            else "curated header prefix mapping"
                        )
                        break
                if mapped_name is None:
                    mapping_complete = False
                elif include.conditional:
                    confidence = MappingConfidence.INFERRED
                    reason += "; preprocessor condition activation unknown"
                usages.append(
                    UsageEvidence(
                        project.project_id,
                        "cpp",
                        reference,
                        positions.at(include.offset),
                        scope=_source_scope(path, project_root),
                        kind="conditional" if include.conditional else "regular",
                        mapped_package=(
                            _package_ref(self.ecosystem, mapped_name)
                            if mapped_name is not None
                            else None
                        ),
                        mapping_confidence=confidence,
                        mapping_reason=reason,
                    )
                )

        declared_by_lower = {
            item.package.name.lower(): item.package.name for item in declarations
        }
        for cmake in discover_files(
            project_root,
            names=frozenset({"CMakeLists.txt"}),
            excluded_directories=excluded_directories,
        ):
            if (
                _nearest_cpp_root(cmake.parent, project_root, self.ecosystem)
                != project_root
            ):
                continue
            evidence_files.append(cmake)
            try:
                text = read_text(cmake)
                positions = SourcePositions(cmake, text)
                for command in cmake_commands(text):
                    if command.name != "find_package" or not command.arguments:
                        continue
                    argument = command.arguments[0]
                    if not argument.literal:
                        continue
                    reference = argument.value
                    name = declared_by_lower.get(reference.lower())
                    if name is None:
                        continue
                    usages.append(
                        UsageEvidence(
                            project.project_id,
                            "cmake",
                            f"find_package:{reference}",
                            positions.at(argument.offset),
                            scope="build",
                            kind="build-hint",
                            mapped_package=_package_ref(self.ecosystem, name),
                            mapping_confidence=MappingConfidence.INFERRED,
                            mapping_reason="CMake package name matches a declaration",
                        )
                    )
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), cmake))
        return (
            tuple(usages),
            source_files,
            tuple(dict.fromkeys(evidence_files)),
            diagnostics,
            complete,
            mapping_complete,
        )


def create_conan_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="Conan",
        detector=CppProjectDetector("Conan"),
        capabilities=frozenset({"manifest", "mapping", "resolution", "usage"}),
        collector=CppEvidenceCollector("Conan", mappings),
    )


def create_vcpkg_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="vcpkg",
        detector=CppProjectDetector("vcpkg"),
        capabilities=frozenset({"manifest", "mapping", "resolution", "usage"}),
        collector=CppEvidenceCollector("vcpkg", mappings),
    )


def _parse_conan_text(
    project: ProjectUnit,
    manifest: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    sections = {
        "requires": "runtime",
        "tool_requires": "build",
        "build_requires": "build",
        "test_requires": "test",
    }
    active_scope: str | None = None
    declarations: list[DependencyDeclaration] = []
    for line_number, raw_line in enumerate(read_text(manifest).splitlines(), start=1):
        line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            active_scope = sections.get(line[1:-1].strip().lower())
            continue
        if active_scope is None:
            continue
        parsed = _conan_reference(line)
        if parsed is None:
            continue
        name, version = parsed
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref("Conan", name),
                _conan_constraint(version),
                SourceLocation(
                    manifest, line_number, len(raw_line) - len(raw_line.lstrip()) + 1
                ),
                scope=active_scope,
                kind="direct",
                metadata={"reference": line},
            )
        )
    return tuple(declarations), []


def _parse_conan_python(
    project: ProjectUnit,
    manifest: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    text = read_text(manifest)
    try:
        tree = parse_python_ast(text)
    except SyntaxError as exc:
        raise StaticReadError(
            f"invalid Python syntax in {manifest}: {exc}",
            source=SourceLocation(manifest, exc.lineno, exc.offset),
        ) from exc
    positions = SourcePositions(manifest, text)
    entries: list[tuple[str, str, ast.AST]] = []
    diagnostics: list[Diagnostic] = []
    scope_by_name = {
        "requires": "runtime",
        "tool_requires": "build",
        "build_requires": "build",
        "test_requires": "test",
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                name = target.id if isinstance(target, ast.Name) else None
                if name not in scope_by_name:
                    continue
                literals = _string_literals(value)
                if literals is None:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.unsupported-expression",
                            "warning",
                            f"Conan {name} is not a literal string/list",
                            positions.ast_node(value or node),
                        )
                    )
                    continue
                entries.extend(
                    (str(item.value), scope_by_name[name], item) for item in literals
                )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if name in scope_by_name:
                literals = _string_literals(node.args[0]) if node.args else None
                if literals is None:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.unsupported-expression",
                            "warning",
                            f"Conan {name} call has no supported literal requirement",
                            positions.ast_node(node),
                        )
                    )
                else:
                    entries.extend(
                        (str(item.value), scope_by_name[name], item)
                        for item in literals
                    )
    declarations = []
    for raw, scope, literal in entries:
        parsed = _conan_reference(raw)
        if parsed is None:
            continue
        name, version = parsed
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref("Conan", name),
                _conan_constraint(version),
                positions.ast_node(literal),
                scope=scope,
                kind="direct",
                metadata={"reference": raw},
            )
        )
    return tuple(declarations), diagnostics


def _parse_vcpkg(
    project: ProjectUnit,
    manifest: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    text = read_text(manifest)
    document = parse_json(text, manifest)
    positions = SourcePositions.json_keys(
        manifest,
        text,
        frozenset({"dependencies", "overrides", "features", "default-features"}),
        max_depth=4,
    )
    overrides: dict[str, list[tuple[str, SourceLocation]]] = {}
    raw_overrides = document.get("overrides", [])
    if not isinstance(raw_overrides, list):
        raise StaticReadError(f"overrides in {manifest} must be an array")
    for index, item in enumerate(raw_overrides):
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            raise StaticReadError(f"invalid vcpkg override in {manifest}")
        fields = [
            key
            for key in ("version", "version-string", "version-semver", "version-date")
            if key in item
        ]
        if (
            len(fields) != 1
            or not isinstance(item[fields[0]], str)
            or not item[fields[0]]
        ):
            raise StaticReadError(
                f"vcpkg override must have one string version in {manifest}"
            )
        field = fields[0]
        version = item[field]
        if "port-version" in item:
            port = item["port-version"]
            if type(port) is not int or port < 0 or "#" in version:
                raise StaticReadError(
                    f"invalid vcpkg override port-version in {manifest}"
                )
            version += f"#{port}"
        overrides.setdefault(str(item["name"]), []).append(
            (version, positions.value("overrides", index, field))
        )
    dependencies = document.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise StaticReadError(f"dependencies in {manifest} must be an array")
    declarations: list[DependencyDeclaration] = []
    diagnostics: list[Diagnostic] = []
    for name, values in overrides.items():
        if len(values) > 1:
            diagnostics.append(
                Diagnostic(
                    "manifest.ambiguous-vcpkg-override",
                    "warning",
                    f"Multiple vcpkg overrides for {name}; no version pin was selected",
                    values[1][1],
                )
            )

    def collect(
        dependencies: object,
        path: tuple[str | int, ...],
        feature_context: Mapping[str, object] | None = None,
    ) -> None:
        if not isinstance(dependencies, list):
            raise StaticReadError(f"vcpkg dependencies must be an array in {manifest}")
        for index, item in enumerate(dependencies):
            source = positions.value(*path, index)
            minimum = ""
            platform: str | None = None
            default_features = True
            if isinstance(item, str):
                name = item
                features: list[str | dict[str, str]] = []
                host = False
            elif isinstance(item, Mapping) and isinstance(item.get("name"), str):
                name = str(item["name"])
                features = _vcpkg_feature_assertions(item.get("features", []), manifest)
                host = item.get("host", False)
                default_features = item.get("default-features", True)
                platform = item.get("platform")
                minimum = item.get("version>=", "")
                if (
                    not isinstance(host, bool)
                    or not isinstance(default_features, bool)
                    or (platform is not None and not isinstance(platform, str))
                    or not isinstance(minimum, str)
                ):
                    raise StaticReadError(
                        f"invalid vcpkg dependency fields in {manifest}"
                    )
                source = positions.value(*path, index, "name")
            else:
                raise StaticReadError(f"invalid vcpkg dependency in {manifest}")
            selected = overrides.get(name, [])
            version = selected[0][0] if len(selected) == 1 else ""
            metadata: dict[str, object] = {
                "features": features,
                "minimum_version": minimum,
                "default_features": default_features,
            }
            if platform is not None:
                metadata["platform"] = platform
            if len(selected) == 1:
                metadata["override_source"] = selected[0][1].to_dict(manifest.parent)
            if feature_context is not None:
                metadata.update(feature_context)
                metadata["self_reference"] = name == document.get("name") and not host
            declarations.append(
                DependencyDeclaration(
                    project.project_id,
                    _package_ref("vcpkg", name),
                    VersionConstraint(
                        version or (f">={minimum}" if minimum else ""),
                        "vcpkg",
                        version or None,
                    ),
                    source,
                    scope="host" if host else "runtime",
                    kind="conditional" if feature_context is not None else "direct",
                    marker=platform,
                    metadata=metadata,
                )
            )

    collect(dependencies, ("dependencies",))
    features_table = document.get("features", {})
    if not isinstance(features_table, Mapping):
        raise StaticReadError(f"vcpkg features must be an object in {manifest}")
    defaults: dict[str, list[object]] = {}
    defaults_complete = True
    try:
        for item in _vcpkg_feature_assertions(
            document.get("default-features", []), manifest
        ):
            name = item if isinstance(item, str) else str(item["name"])
            defaults.setdefault(name, []).append(item)
            if name not in features_table:
                raise StaticReadError(
                    f"default feature {name[:80]!r} is not defined in {manifest}"
                )
    except StaticReadError as exc:
        defaults_complete = False
        diagnostics.append(
            _diagnostic(
                "manifest.invalid-vcpkg-default-feature",
                str(exc),
                positions.key("default-features"),
                severity="warning",
            )
        )
    project_supports = document.get("supports")
    if project_supports is not None and not isinstance(project_supports, str):
        raise StaticReadError(f"vcpkg supports must be a string in {manifest}")
    remaining_context_bytes = DEFAULT_MAX_BYTES
    for feature, value in features_table.items():
        exhausted = False
        try:
            if not isinstance(value, Mapping):
                raise StaticReadError(
                    f"vcpkg feature {feature[:80]!r} must be an object in {manifest}"
                )
            dependencies = value.get("dependencies", [])
            supports = value.get("supports")
            if not isinstance(dependencies, list) or (
                supports is not None and not isinstance(supports, str)
            ):
                raise StaticReadError(
                    f"invalid dependencies or supports for vcpkg feature {feature[:80]!r} in {manifest}"
                )
            if not dependencies:
                continue
            context: dict[str, object] = {
                "group": f"feature:{feature}",
                "feature": feature,
                "activation": "unknown",
                "default_feature_assertions": defaults.get(feature, []),
                "default_feature_assertions_complete": defaults_complete,
            }
            if supports is not None:
                context["feature_supports"] = supports
            if project_supports is not None:
                context["project_supports"] = project_supports
            cost = len(json.dumps(context).encode("utf-8"))
            limit = min(len(dependencies), remaining_context_bytes // cost)
            remaining_context_bytes -= limit * cost
            exhausted = limit < len(dependencies)
            if exhausted:
                diagnostics.append(
                    _diagnostic(
                        "manifest.vcpkg-feature-budget",
                        "vcpkg feature context expansion exceeded the evidence budget; remaining declarations are uncollected",
                        positions.key("features", feature),
                        severity="warning",
                    )
                )
            collect(
                dependencies[:limit], ("features", feature, "dependencies"), context
            )
        except StaticReadError as exc:
            diagnostics.append(
                _diagnostic(
                    "manifest.invalid-vcpkg-feature",
                    str(exc),
                    positions.key("features", feature),
                    severity="warning",
                )
            )
        if exhausted:
            break
    return tuple(declarations), diagnostics


def _vcpkg_feature_assertions(
    value: object, manifest: Path
) -> list[str | dict[str, str]]:
    if not isinstance(value, list):
        raise StaticReadError(
            f"vcpkg feature assertions must be an array in {manifest}"
        )
    assertions: list[str | dict[str, str]] = []
    for item in value:
        if isinstance(item, str):
            assertions.append(item)
        elif (
            isinstance(item, Mapping)
            and isinstance(item.get("name"), str)
            and ("platform" not in item or isinstance(item["platform"], str))
        ):
            assertions.append(
                {key: str(item[key]) for key in ("name", "platform") if key in item}
            )
        else:
            raise StaticReadError(f"invalid vcpkg feature assertion in {manifest}")
    return assertions


def _parse_conan_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
) -> tuple[ResolvedDependency, ...]:
    text = read_text(lock)
    document = parse_json(text, lock)
    groups = frozenset(
        {"requires", "build_requires", "python_requires", "config_requires"}
    )
    if document.get("version", "0.5") != "0.5" or not groups.intersection(document):
        raise StaticReadError(f"unsupported Conan lock format in {lock}")
    positions = SourcePositions.json_keys(lock, text, groups)
    direct = {
        (item.package.name, "build_requires" if item.scope == "build" else "requires")
        for item in declarations
    }
    resolved: list[ResolvedDependency] = []
    for key in ("requires", "build_requires", "python_requires", "config_requires"):
        values = document.get(key, [])
        if not isinstance(values, list):
            raise StaticReadError(f"Conan lock {key} must be an array in {lock}")
        for index, raw in enumerate(values):
            parsed = _conan_reference(raw) if isinstance(raw, str) else None
            if parsed is None:
                raise StaticReadError(f"invalid Conan lock reference in {lock}")
            name, version = parsed
            if _conan_constraint(version).normalized is None:
                raise StaticReadError(
                    f"Conan lock reference must have an exact version in {lock}"
                )
            resolved.append(
                ResolvedDependency(
                    project.project_id,
                    _package_ref("Conan", name),
                    version,
                    positions.value(key, index),
                    direct=(name, key) in direct,
                    integrity=raw.split("#", 1)[1].split("%", 1)[0]
                    if "#" in raw
                    else None,
                    instance_id=f"conan:{key}:{index}",
                    origin={
                        "kind": "conan-lock",
                        "reference": raw,
                        "context": key,
                        "activation": "unknown",
                    },
                )
            )
    return tuple(resolved)


def _parse_vcpkg_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
) -> tuple[ResolvedDependency, ...]:
    text = read_text(lock)
    document = parse_json(text, lock)
    if "dependencies" not in document:
        raise StaticReadError(
            f"no supported dependency inventory in {lock}; registry locks do not establish package versions"
        )
    positions = SourcePositions.json_keys(lock, text, frozenset({"dependencies"}))
    values = document["dependencies"]
    if not isinstance(values, Mapping):
        raise StaticReadError(f"dependencies in {lock} must be an object")
    direct = {item.package.name for item in declarations if item.kind == "direct"}
    resolved: list[ResolvedDependency] = []
    for raw_name, raw in sorted(values.items()):
        if not isinstance(raw_name, str) or not isinstance(raw, Mapping):
            continue
        version = (
            raw.get("version")
            or raw.get("version-string")
            or raw.get("version-semver")
            or raw.get("version-date")
        )
        if not isinstance(version, str) or not version:
            continue
        children = raw.get("dependencies", [])
        resolved.append(
            ResolvedDependency(
                project.project_id,
                _package_ref("vcpkg", raw_name),
                version,
                positions.key("dependencies", raw_name),
                direct=raw_name in direct,
                instance_id=f"dependencies:{raw_name}",
                origin={
                    "kind": "supplied-dependency-inventory",
                    "activation": "unknown",
                },
                dependencies=tuple(
                    _package_ref("vcpkg", str(child))
                    for child in children
                    if isinstance(child, str)
                )
                if isinstance(children, list)
                else (),
            )
        )
    return tuple(resolved)


def _string_literals(node: ast.AST | None) -> list[ast.Constant] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[ast.Constant] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                return None
            values.append(element)
        return values
    return None


def _conan_reference(reference: str) -> tuple[str, str] | None:
    base = reference.split("#", 1)[0].split("%", 1)[0].split("@", 1)[0]
    name, separator, version = base.partition("/")
    if not separator or not name or not version:
        return None
    return name.lower(), version


def _conan_constraint(version: str) -> VersionConstraint:
    exact = version if re.fullmatch(r"[A-Za-z0-9_.+-]+", version) else None
    return VersionConstraint(version, "conan", exact)


def _package_ref(ecosystem: str, name: str) -> PackageRef:
    canonical = name.lower()
    purl_type = "conan" if ecosystem == "Conan" else "vcpkg"
    return PackageRef(
        ecosystem,
        canonical,
        name,
        f"pkg:{purl_type}/{quote(canonical, safe='-._~')}",
    )


def _ignore_header(
    reference: str,
    delimiter: str,
    source: Path,
    project_root: Path,
) -> bool:
    if reference in _STANDARD_HEADERS or reference.startswith("sys/"):
        return True
    if delimiter == '"' and (
        (source.parent / reference).is_file() or (project_root / reference).is_file()
    ):
        return True
    return False


def _nearest_cpp_root(path: Path, boundary: Path, ecosystem: str) -> Path:
    names = (
        ("conanfile.txt", "conanfile.py") if ecosystem == "Conan" else ("vcpkg.json",)
    )
    current = path
    while current != boundary and boundary in current.parents:
        if any((current / name).is_file() for name in names):
            return current
        current = current.parent
    return boundary


def _source_scope(path: Path, root: Path) -> str:
    parts = {part.lower() for part in path.relative_to(root).parts}
    return (
        "test"
        if parts & {"test", "tests"}
        or path.stem.lower().endswith(("_test", "_unittest"))
        else "runtime"
    )


def _relative_child(root: Path, name: str) -> Path:
    return root / name if root != Path(".") else Path(name)


def _diagnostic(
    code: str,
    message: str,
    path: Path | SourceLocation,
    *,
    severity: str = "error",
) -> Diagnostic:
    return Diagnostic(
        code,
        severity,
        message,
        path if isinstance(path, SourceLocation) else SourceLocation(path),
    )


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
