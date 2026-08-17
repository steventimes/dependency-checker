from __future__ import annotations

import re
from collections.abc import Mapping
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

_IMPORT_SINGLE = re.compile(r'^\s*import\s+(?:[._A-Za-z][\w]*\s+)?"([^"]+)"')
_IMPORT_BLOCK_ITEM = re.compile(r'^\s*(?:[._A-Za-z][\w]*\s+)?"([^"]+)"')


@dataclass(frozen=True, slots=True)
class _Requirement:
    name: str
    version: str
    indirect: bool
    line: int


@dataclass(frozen=True, slots=True)
class _Replacement:
    original_module: str
    original_version: str | None
    target_module: str | None
    target_version: str | None
    local_path: str | None
    line: int

    @property
    def is_local(self) -> bool:
        return self.local_path is not None

    @property
    def target(self) -> str:
        if self.local_path is not None:
            return self.local_path
        if self.target_version is not None:
            return f"{self.target_module} {self.target_version}"
        return str(self.target_module)


@dataclass(frozen=True, slots=True)
class _EffectiveRequirement:
    requirement: _Requirement
    package_name: str
    version: str | None
    replacement: _Replacement | None


class GoProjectDetector:
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        projects: list[ProjectUnit] = []
        for manifest in discover_files(
            root,
            names=frozenset({"go.mod"}),
            excluded_directories=exclusions_for(context.settings),
        ):
            project_root = manifest.parent
            relative_root = project_root.relative_to(root)
            if relative_root == Path(""):
                relative_root = Path(".")
            relative_manifest = (
                relative_root / "go.mod"
                if relative_root != Path(".")
                else Path("go.mod")
            )
            go_sum = project_root / "go.sum"
            locks = (
                (
                    (
                        relative_root / "go.sum"
                        if relative_root != Path(".")
                        else Path("go.sum")
                    ),
                )
                if go_sum.is_file()
                else ()
            )
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "Go", "gomod"),
                    root=relative_root,
                    language="go",
                    ecosystem="Go",
                    manager="gomod",
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


class GoEvidenceCollector:
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
        manifest = project_root / "go.mod"
        diagnostics: list[Diagnostic] = []
        manifest_complete = True
        module_path: str | None = None
        requirements: tuple[_Requirement, ...] = ()
        replacements: dict[tuple[str, str | None], _Replacement] = {}
        excluded_versions: dict[str, list[str]] = {}
        try:
            (
                module_path,
                requirements,
                replacements,
                excluded_versions,
            ) = _parse_go_mod(read_text(manifest))
            if module_path is None:
                raise StaticReadError(f"{manifest} has no module directive")
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        checksums: dict[tuple[str, str], str] = {}
        go_sum = project_root / "go.sum"
        resolution_complete = True
        if go_sum.is_file():
            try:
                checksums = _parse_go_sum(read_text(go_sum))
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(_diagnostic("lock.invalid", str(exc), go_sum))

        effective_requirements = tuple(
            _effective_requirement(item, replacements) for item in requirements
        )
        security_complete = manifest_complete
        for item in effective_requirements:
            replacement = item.replacement
            if replacement is None:
                continue
            if replacement.is_local:
                resolution_complete = False
                security_complete = False
                diagnostics.append(
                    Diagnostic(
                        code="security.local-replacement",
                        severity="error",
                        message=(
                            f"Local replacement {replacement.original_module} => "
                            f"{replacement.local_path} has no externally verifiable "
                            "security coordinate; the OSV query was skipped."
                        ),
                        source=SourceLocation(manifest, replacement.line, 1),
                    )
                )
            elif replacement.target_version is None:
                resolution_complete = False
                security_complete = False
                diagnostics.append(
                    Diagnostic(
                        code="resolution.replacement-version-missing",
                        severity="error",
                        message=(
                            f"Remote replacement {replacement.original_module} => "
                            f"{replacement.target_module} has no target version; "
                            "no externally verifiable security coordinate was inferred."
                        ),
                        source=SourceLocation(manifest, replacement.line, 1),
                    )
                )

        declarations = tuple(
            DependencyDeclaration(
                project_id=project.project_id,
                package=_package_ref(item.package_name),
                constraint=VersionConstraint(
                    item.version or item.requirement.version,
                    "go",
                    item.version or item.requirement.version,
                ),
                source=SourceLocation(manifest, item.requirement.line, 1),
                scope="runtime",
                kind="transitive" if item.requirement.indirect else "direct",
                metadata={
                    **({"indirect": True} if item.requirement.indirect else {}),
                    **(
                        _replacement_metadata(item.replacement, item.requirement)
                        if item.replacement is not None
                        else {}
                    ),
                    **(
                        {"excluded_versions": excluded_versions[item.requirement.name]}
                        if item.requirement.name in excluded_versions
                        else {}
                    ),
                },
            )
            for item in effective_requirements
        )
        resolved = tuple(
            ResolvedDependency(
                project_id=project.project_id,
                package=_package_ref(item.package_name),
                version=item.version,
                source=SourceLocation(
                    go_sum if go_sum.is_file() else manifest,
                    item.requirement.line,
                    1,
                ),
                direct=not item.requirement.indirect,
                integrity=checksums.get((item.package_name, item.version)),
            )
            for item in effective_requirements
            if item.version is not None
        )
        (
            usages,
            source_files,
            usage_diagnostics,
            usage_complete,
            mapping_complete,
        ) = self._usages(
            project,
            project_root,
            module_path,
            tuple(
                (item.requirement.name, item.package_name)
                for item in effective_requirements
            ),
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
                _status("resolution", resolution_complete and manifest_complete),
                _status("security", security_complete and manifest_complete),
                _status("usage", usage_complete),
                _status("mapping", mapping_complete),
            ),
            source_files=source_files,
        )

    def _usages(
        self,
        project: ProjectUnit,
        project_root: Path,
        module_path: str | None,
        declared_modules: tuple[tuple[str, str], ...],
        excluded_directories: tuple[str, ...] = (),
    ) -> tuple[
        tuple[UsageEvidence, ...],
        tuple[Path, ...],
        list[Diagnostic],
        bool,
        bool,
    ]:
        usages: list[UsageEvidence] = []
        diagnostics: list[Diagnostic] = []
        usage_complete = True
        mapping_complete = True
        declared = tuple(
            sorted(declared_modules, key=lambda item: len(item[0]), reverse=True)
        )
        configured = tuple(sorted(self.mappings, key=len, reverse=True))
        source_files = tuple(
            path
            for path in discover_files(
                project_root,
                suffixes=frozenset({".go"}),
                excluded_directories=excluded_directories,
            )
            if _nearest_module_root(path.parent, project_root) == project_root
        )
        for path in source_files:
            try:
                text = read_text(path)
            except StaticReadError as exc:
                usage_complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
                continue
            in_block = False
            for line_number, raw_line in enumerate(text.splitlines(), start=1):
                line = raw_line.split("//", 1)[0]
                if re.match(r"^\s*import\s*\(\s*$", line):
                    in_block = True
                    continue
                if in_block and re.match(r"^\s*\)\s*$", line):
                    in_block = False
                    continue
                match = (
                    _IMPORT_BLOCK_ITEM.match(line)
                    if in_block
                    else _IMPORT_SINGLE.match(line)
                )
                if match is None:
                    continue
                reference = match.group(1)
                if _is_local_or_standard(reference, module_path):
                    continue
                mapped_name, confidence, reason = self._map_usage(
                    reference,
                    declared,
                    configured,
                )
                if mapped_name is None:
                    mapping_complete = False
                usages.append(
                    UsageEvidence(
                        project_id=project.project_id,
                        language="go",
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
        return (
            tuple(usages),
            source_files,
            diagnostics,
            usage_complete,
            mapping_complete,
        )

    def _map_usage(
        self,
        reference: str,
        declared: tuple[tuple[str, str], ...],
        configured: tuple[str, ...],
    ) -> tuple[str | None, MappingConfidence, str]:
        for prefix in configured:
            if reference == prefix or reference.startswith(prefix + "/"):
                return (
                    self.mappings[prefix],
                    MappingConfidence.CONFIGURED,
                    "project import mapping",
                )
        for module, effective_module in declared:
            if reference == module or reference.startswith(module + "/"):
                reason = (
                    "declared Go module prefix"
                    if module == effective_module
                    else "declared Go module prefix mapped to replacement module"
                )
                return effective_module, MappingConfidence.EXACT, reason
        return None, MappingConfidence.UNKNOWN, "module root is not provable statically"


def create_go_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="Go",
        detector=GoProjectDetector(),
        capabilities=frozenset(
            {"manifest", "mapping", "resolution", "security", "usage"}
        ),
        collector=GoEvidenceCollector(mappings),
    )


def _parse_go_mod(
    text: str,
) -> tuple[
    str | None,
    tuple[_Requirement, ...],
    dict[tuple[str, str | None], _Replacement],
    dict[str, list[str]],
]:
    module_path: str | None = None
    requirements: list[_Requirement] = []
    replacements: dict[tuple[str, str | None], _Replacement] = {}
    excluded_versions: dict[str, list[str]] = {}
    block: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.endswith("("):
            directive = stripped[:-1].strip()
            block = (
                directive if directive in {"require", "replace", "exclude"} else None
            )
            continue
        if stripped == ")":
            block = None
            continue
        content = stripped
        active_directive = block
        if active_directive is None:
            head, separator, tail = stripped.partition(" ")
            if not separator:
                if head in {"module", "require", "replace", "exclude"}:
                    raise StaticReadError(
                        f"malformed {head} directive at line {line_number}"
                    )
                continue
            active_directive, content = head, tail.strip()
        if active_directive == "module":
            tokens = content.split()
            if len(tokens) != 1:
                raise StaticReadError(
                    f"malformed module directive at line {line_number}"
                )
            module_path = tokens[0]
        elif active_directive == "require":
            indirect = "// indirect" in content
            tokens = content.split("//", 1)[0].split()
            if len(tokens) != 2:
                raise StaticReadError(
                    f"malformed require directive at line {line_number}"
                )
            requirements.append(
                _Requirement(tokens[0], tokens[1], indirect, line_number)
            )
        elif active_directive == "replace":
            content = content.split("//", 1)[0].strip()
            if "=>" not in content:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            left, right = content.split("=>", 1)
            left_tokens = left.split()
            right_tokens = right.split()
            if len(left_tokens) not in {1, 2} or len(right_tokens) not in {1, 2}:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            original_version = left_tokens[1] if len(left_tokens) == 2 else None
            target = right_tokens[0]
            local_path = target if _is_local_replacement(target) else None
            if local_path is not None and len(right_tokens) == 2:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            replacements[(left_tokens[0], original_version)] = _Replacement(
                original_module=left_tokens[0],
                original_version=original_version,
                target_module=None if local_path is not None else target,
                target_version=(
                    right_tokens[1]
                    if local_path is None and len(right_tokens) == 2
                    else None
                ),
                local_path=local_path,
                line=line_number,
            )
        elif active_directive == "exclude":
            tokens = content.split("//", 1)[0].split()
            if len(tokens) != 2:
                raise StaticReadError(
                    f"malformed exclude directive at line {line_number}"
                )
            excluded_versions.setdefault(tokens[0], []).append(tokens[1])
    return module_path, tuple(requirements), replacements, excluded_versions


def _effective_requirement(
    requirement: _Requirement,
    replacements: Mapping[tuple[str, str | None], _Replacement],
) -> _EffectiveRequirement:
    replacement = replacements.get(
        (requirement.name, requirement.version)
    ) or replacements.get((requirement.name, None))
    if replacement is None:
        return _EffectiveRequirement(
            requirement,
            requirement.name,
            requirement.version,
            None,
        )
    if replacement.is_local:
        return _EffectiveRequirement(requirement, requirement.name, None, replacement)
    return _EffectiveRequirement(
        requirement,
        str(replacement.target_module),
        replacement.target_version,
        replacement,
    )


def _replacement_metadata(
    replacement: _Replacement,
    requirement: _Requirement,
) -> dict[str, object]:
    metadata: dict[str, object] = {
        "original_module": requirement.name,
        "original_version": requirement.version,
        "replacement": replacement.target,
        "replacement_type": "local" if replacement.is_local else "module",
    }
    if replacement.local_path is not None:
        metadata["replacement_path"] = replacement.local_path
    else:
        metadata["replacement_module"] = replacement.target_module
        if replacement.target_version is not None:
            metadata["replacement_version"] = replacement.target_version
    return metadata


def _is_local_replacement(target: str) -> bool:
    return (
        target in {".", ".."}
        or target.startswith(("./", "../", "/", "\\"))
        or re.match(r"^[A-Za-z]:[\\/]", target) is not None
    )


def _parse_go_sum(text: str) -> dict[tuple[str, str], str]:
    checksums: dict[tuple[str, str], str] = {}
    for raw_line in text.splitlines():
        tokens = raw_line.split()
        if len(tokens) != 3 or tokens[1].endswith("/go.mod"):
            continue
        checksums[(tokens[0], tokens[1])] = tokens[2]
    return checksums


def _package_ref(name: str) -> PackageRef:
    return PackageRef(
        ecosystem="Go",
        name=name,
        display_name=name,
        purl=f"pkg:golang/{quote(name, safe='/')}",
    )


def _is_local_or_standard(reference: str, module_path: str | None) -> bool:
    if module_path and (
        reference == module_path or reference.startswith(module_path + "/")
    ):
        return True
    first = reference.split("/", 1)[0]
    return "." not in first


def _nearest_module_root(path: Path, boundary: Path) -> Path:
    current = path
    while current != boundary and boundary in current.parents:
        if (current / "go.mod").is_file():
            return current
        current = current.parent
    return boundary


def _source_scope(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    return (
        "test"
        if path.name.endswith("_test.go") or "test" in relative.parts
        else "runtime"
    )


def _diagnostic(code: str, message: str, path: Path) -> Diagnostic:
    return Diagnostic(code, "error", message, SourceLocation(path))


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
