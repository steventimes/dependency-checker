from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence
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
    read_json,
    read_text,
)

_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
_INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]')
_FIND_PACKAGE = re.compile(r"\bfind_package\s*\(\s*([A-Za-z0-9_.+-]+)", re.IGNORECASE)
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
        "nlohmann": "nlohmann_json",
        "spdlog": "spdlog",
    },
    "vcpkg": {
        "catch2": "catch2",
        "fmt": "fmt",
        "nlohmann": "nlohmann-json",
        "spdlog": "spdlog",
    },
}


class CppProjectDetector:
    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem

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
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        resolved: tuple[ResolvedDependency, ...] = tuple(
            ResolvedDependency(
                project.project_id,
                item.package,
                item.constraint.normalized or item.constraint.raw,
                item.source,
                direct=item.kind == "direct",
            )
            for item in declarations
            if item.constraint.normalized
        )
        resolution_complete = manifest_complete
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
                diagnostics.append(_diagnostic("lock.invalid", str(exc), lock))

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
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = _INCLUDE.match(line)
                if match is None:
                    continue
                delimiter, reference = match.groups()
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
                usages.append(
                    UsageEvidence(
                        project.project_id,
                        "cpp",
                        reference,
                        SourceLocation(path, line_number, 1),
                        scope=_source_scope(path, project_root),
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
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), cmake))
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = _FIND_PACKAGE.search(line)
                if match is None:
                    continue
                reference = match.group(1)
                name = declared_by_lower.get(reference.lower())
                if name is None:
                    continue
                usages.append(
                    UsageEvidence(
                        project.project_id,
                        "cmake",
                        f"find_package:{reference}",
                        SourceLocation(cmake, line_number, 1),
                        scope="build",
                        kind="build-hint",
                        mapped_package=_package_ref(self.ecosystem, name),
                        mapping_confidence=MappingConfidence.INFERRED,
                        mapping_reason="CMake package name matches a declaration",
                    )
                )
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
        line = raw_line.split("#", 1)[0].strip()
        if not line:
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
                VersionConstraint(version, "conan", version),
                SourceLocation(manifest, line_number, 1),
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
        tree = ast.parse(text, filename=str(manifest))
    except SyntaxError as exc:
        raise StaticReadError(f"invalid Python syntax in {manifest}: {exc}") from exc
    entries: list[tuple[str, str, int]] = []
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
                        _diagnostic(
                            "manifest.unsupported-expression",
                            f"Conan {name} is not a literal string/list",
                            manifest,
                            severity="warning",
                        )
                    )
                    continue
                entries.extend(
                    (item, scope_by_name[name], node.lineno) for item in literals
                )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if name in scope_by_name and node.args:
                literals = _string_literals(node.args[0])
                if literals is not None:
                    entries.extend(
                        (item, scope_by_name[name], node.lineno) for item in literals
                    )
    declarations = []
    for raw, scope, line_number in entries:
        parsed = _conan_reference(raw)
        if parsed is None:
            continue
        name, version = parsed
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref("Conan", name),
                VersionConstraint(version, "conan", version),
                SourceLocation(manifest, line_number, 1),
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
    document = read_json(manifest)
    overrides = (
        {
            str(item.get("name")): str(
                item.get("version")
                or item.get("version-string")
                or item.get("version-semver")
                or ""
            )
            for item in document.get("overrides", [])
            if isinstance(item, Mapping) and item.get("name")
        }
        if isinstance(document.get("overrides", []), list)
        else {}
    )
    dependencies = document.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise StaticReadError(f"dependencies in {manifest} must be an array")
    declarations: list[DependencyDeclaration] = []
    for item in dependencies:
        if isinstance(item, str):
            name = item
            features: list[str] = []
            host = False
        elif isinstance(item, Mapping) and isinstance(item.get("name"), str):
            name = str(item["name"])
            raw_features = item.get("features", [])
            features = (
                [str(value) for value in raw_features]
                if isinstance(raw_features, list)
                else []
            )
            host = bool(item.get("host", False))
        else:
            continue
        version = overrides.get(name, "")
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref("vcpkg", name),
                VersionConstraint(version, "vcpkg", version or None),
                SourceLocation(manifest, 1, 1),
                scope="host" if host else "runtime",
                kind="direct",
                metadata={"features": features},
            )
        )
    return tuple(declarations), []


def _parse_conan_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
) -> tuple[ResolvedDependency, ...]:
    document = read_json(lock)
    direct = {item.package.name for item in declarations}
    entries: list[tuple[str, bool]] = []
    for key, build in (("requires", False), ("build_requires", True)):
        values = document.get(key, [])
        if isinstance(values, list):
            entries.extend(
                (str(value), build) for value in values if isinstance(value, str)
            )
    resolved: list[ResolvedDependency] = []
    for raw, build in entries:
        parsed = _conan_reference(raw)
        if parsed is None:
            continue
        name, version = parsed
        resolved.append(
            ResolvedDependency(
                project.project_id,
                _package_ref("Conan", name),
                version,
                SourceLocation(lock, 1, 1),
                direct=name in direct,
                integrity=raw.split("#", 1)[1] if "#" in raw else None,
            )
        )
    return tuple(resolved)


def _parse_vcpkg_lock(
    project: ProjectUnit,
    lock: Path,
    declarations: Sequence[DependencyDeclaration],
) -> tuple[ResolvedDependency, ...]:
    document = read_json(lock)
    values = document.get("dependencies", {})
    if not isinstance(values, Mapping):
        raise StaticReadError(f"dependencies in {lock} must be an object")
    direct = {item.package.name for item in declarations}
    resolved: list[ResolvedDependency] = []
    for raw_name, raw in sorted(values.items()):
        if not isinstance(raw_name, str) or not isinstance(raw, Mapping):
            continue
        version = (
            raw.get("version") or raw.get("version-string") or raw.get("version-semver")
        )
        if not isinstance(version, str) or not version:
            continue
        children = raw.get("dependencies", [])
        resolved.append(
            ResolvedDependency(
                project.project_id,
                _package_ref("vcpkg", raw_name),
                version,
                SourceLocation(lock, 1, 1),
                direct=raw_name in direct,
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


def _string_literals(node: ast.AST | None) -> list[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                return None
            values.append(element.value)
        return values
    return None


def _conan_reference(reference: str) -> tuple[str, str] | None:
    base = reference.split("#", 1)[0].split("%", 1)[0].split("@", 1)[0]
    name, separator, version = base.partition("/")
    if not separator or not name or not version:
        return None
    return name.lower(), version


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
    return "test" if parts & {"test", "tests"} else "runtime"


def _relative_child(root: Path, name: str) -> Path:
    return root / name if root != Path(".") else Path(name)


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
