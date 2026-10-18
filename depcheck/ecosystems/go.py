from __future__ import annotations

from depcheck.bounded_io import DEFAULT_MAX_BYTES, repository_operation

import base64
import binascii
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
_CHECKSUM_VERSION = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:/go\.mod)?"
)


@dataclass(frozen=True, slots=True)
class _Requirement:
    name: str
    version: str
    indirect: bool
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class _Replacement:
    original_module: str
    original_version: str | None
    target_module: str | None
    target_version: str | None
    local_path: str | None
    line: int
    column: int

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


@dataclass(frozen=True, slots=True)
class _Token:
    value: str
    column: int


@dataclass(frozen=True, slots=True)
class _Tool:
    reference: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class _Exclusion:
    version: str
    line: int
    column: int


class GoProjectDetector:
    @repository_operation("context.repository_root")
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

    @repository_operation("context.repository_root")
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
        tools: tuple[_Tool, ...] = ()
        replacements: dict[tuple[str, str | None], _Replacement] = {}
        excluded_versions: dict[str, list[_Exclusion]] = {}
        try:
            (
                module_path,
                requirements,
                replacements,
                excluded_versions,
                uncollected,
                tools,
            ) = _parse_go_mod(read_text(manifest))
            if module_path is None:
                raise StaticReadError(f"{manifest} has no module directive")
            for directive, line, column in uncollected:
                manifest_complete = False
                diagnostics.append(
                    Diagnostic(
                        "manifest.go-directive-uncollected",
                        "warning",
                        f"Go {directive} configuration is not collected; tool use, "
                        "source selection and dependency completeness remain unknown.",
                        SourceLocation(manifest, line, column),
                    )
                )
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        checksum_declarations: tuple[DependencyDeclaration, ...] = ()
        go_sum = project_root / "go.sum"
        if go_sum.is_file():
            try:
                checksum_declarations, checksum_diagnostics = _parse_go_sum(
                    read_text(go_sum), project, go_sum
                )
                diagnostics.extend(checksum_diagnostics)
            except StaticReadError as exc:
                diagnostics.append(_diagnostic("lock.invalid", str(exc), go_sum))

        diagnostics.append(
            Diagnostic(
                "resolution.go-build-list-unknown",
                "warning",
                "Go require directives specify minimum versions; go.sum records "
                "unverified checksum assertions, including unused versions and "
                "module-file hashes. Neither establishes the MVS build list, "
                "workspace/vendor selection or installation. Exact selected "
                "versions and complete security coverage remain unknown.",
                SourceLocation(manifest),
            )
        )

        effective_requirements = tuple(
            _effective_requirement(item, replacements) for item in requirements
        )
        # Repeated requirements can multiply an exclusion list in serialized output.
        # Bound that expansion before constructing each declaration's metadata.
        manifest_bytes = len(
            manifest.relative_to(context.repository_root).as_posix().encode("utf-8")
        )
        exclusion_costs = {
            name: sum(
                128 + 12 * len(entry.version.encode("utf-8")) + 6 * manifest_bytes
                for entry in entries
            )
            for name, entries in excluded_versions.items()
        }
        remaining = DEFAULT_MAX_BYTES
        for index, item in enumerate(effective_requirements):
            cost = (
                1024
                + 32
                * (
                    manifest_bytes
                    + len(
                        (
                            item.requirement.name
                            + item.requirement.version
                            + (item.replacement.target if item.replacement else "")
                        ).encode("utf-8")
                    )
                )
                + exclusion_costs.get(item.requirement.name, 0)
            )
            if cost > remaining:
                manifest_complete = False
                diagnostics.append(
                    Diagnostic(
                        "manifest.go-context-budget",
                        "warning",
                        "Go requirement metadata expansion exceeded its byte budget; only the bounded prefix is collected.",
                        SourceLocation(
                            manifest, item.requirement.line, item.requirement.column
                        ),
                    )
                )
                effective_requirements = effective_requirements[:index]
                break
            remaining -= cost
        for item in effective_requirements:
            replacement = item.replacement
            if replacement is None:
                continue
            if replacement.is_local:
                diagnostics.append(
                    Diagnostic(
                        code="security.local-replacement",
                        severity="error",
                        message=(
                            f"Local replacement {replacement.original_module} => "
                            f"{replacement.local_path} has no externally verifiable "
                            "security coordinate; the OSV query was skipped."
                        ),
                        source=SourceLocation(
                            manifest, replacement.line, replacement.column
                        ),
                    )
                )
            elif replacement.target_version is None:
                diagnostics.append(
                    Diagnostic(
                        code="resolution.replacement-version-missing",
                        severity="error",
                        message=(
                            f"Remote replacement {replacement.original_module} => "
                            f"{replacement.target_module} has no target version; "
                            "no externally verifiable security coordinate was inferred."
                        ),
                        source=SourceLocation(
                            manifest, replacement.line, replacement.column
                        ),
                    )
                )

        declarations = (
            tuple(
                DependencyDeclaration(
                    project_id=project.project_id,
                    package=_package_ref(item.package_name),
                    constraint=VersionConstraint(
                        item.version or item.requirement.version,
                        "go-replacement"
                        if item.replacement and item.version
                        else "go-minimum",
                        item.version or item.requirement.version,
                    ),
                    source=SourceLocation(
                        manifest, item.requirement.line, item.requirement.column
                    ),
                    scope="runtime",
                    kind="transitive" if item.requirement.indirect else "direct",
                    metadata={
                        "go_kind": "require",
                        "version_semantics": "replacement-assertion"
                        if item.replacement and item.version
                        else "minimum",
                        "selection": "unknown",
                        **({"indirect": True} if item.requirement.indirect else {}),
                        **(
                            _replacement_metadata(item.replacement, item.requirement)
                            if item.replacement is not None
                            else {}
                        ),
                        **(
                            {
                                "replacement_source": SourceLocation(
                                    manifest,
                                    item.replacement.line,
                                    item.replacement.column,
                                ).to_dict(context.repository_root)
                            }
                            if item.replacement
                            else {}
                        ),
                        **(
                            {
                                "excluded_versions": [
                                    entry.version
                                    for entry in excluded_versions[
                                        item.requirement.name
                                    ]
                                ],
                                "excluded_assertions": [
                                    {
                                        "version": entry.version,
                                        "source": SourceLocation(
                                            manifest, entry.line, entry.column
                                        ).to_dict(context.repository_root),
                                    }
                                    for entry in excluded_versions[
                                        item.requirement.name
                                    ]
                                ],
                            }
                            if item.requirement.name in excluded_versions
                            else {}
                        ),
                    },
                )
                for item in effective_requirements
            )
            + checksum_declarations
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
            tools=tools,
        )
        diagnostics.extend(usage_diagnostics)
        return EvidenceBundle(
            project=project,
            declarations=declarations,
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=(
                _status("manifest", manifest_complete),
                _status("resolution", False),
                _status("security", False),
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
        *,
        tools: tuple[_Tool, ...] = (),
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
        # Only these declarations can override the local/standard-path shortcut.
        # Filter once instead of walking all dependencies for every local import.
        nonstandard_modules = tuple(
            (module, effective)
            for module, effective in declared
            if "." not in module.split("/", 1)[0]
            or (module_path is not None and module.startswith(module_path + "/"))
        )
        configured = tuple(sorted(self.mappings, key=len, reverse=True))
        remaining = DEFAULT_MAX_BYTES
        manifest = project_root / "go.mod"
        for tool in tools:
            reference = tool.reference
            if _is_local_or_standard(reference, module_path, nonstandard_modules):
                continue
            source = SourceLocation(manifest, tool.line, tool.column)
            cost = 512 + 32 * len((reference + project.project_id).encode("utf-8"))
            if cost > remaining:
                usage_complete = mapping_complete = False
                diagnostics.append(
                    Diagnostic(
                        "configuration.go-tool-budget",
                        "warning",
                        "Go tool configuration exceeded its evidence byte budget; only the bounded prefix is collected.",
                        source,
                    )
                )
                break
            remaining -= cost
            mapped_name, confidence, reason = self._map_usage(
                reference, declared, configured
            )
            if mapped_name is None:
                usage_complete = mapping_complete = False
                diagnostics.append(
                    Diagnostic(
                        "configuration.go-tool-owner-unresolved",
                        "warning",
                        f"The declared owner of Go tool {reference[:160]!r} is unknown; no module identity or execution was inferred.",
                        source,
                    )
                )
            usages.append(
                UsageEvidence(
                    project.project_id,
                    "go",
                    reference,
                    source,
                    scope="build",
                    kind="configuration",
                    mapped_package=_package_ref(mapped_name)
                    if mapped_name is not None
                    else None,
                    mapping_confidence=confidence,
                    mapping_reason=f"Literal go.mod tool directive; {reason}. Configuration only; execution, installation and package availability are not established.",
                )
            )
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
                if _is_local_or_standard(reference, module_path, nonstandard_modules):
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
    dict[str, list[_Exclusion]],
    tuple[tuple[str, int, int], ...],
    tuple[_Tool, ...],
]:
    module_path: str | None = None
    requirements: list[_Requirement] = []
    replacements: dict[tuple[str, str | None], _Replacement] = {}
    excluded_versions: dict[str, list[_Exclusion]] = {}
    uncollected: list[tuple[str, int, int]] = []
    tools: list[_Tool] = []
    block: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        tokens, comment = _go_tokens(raw_line, line_number)
        if not tokens:
            continue
        if len(tokens) == 2 and tokens[1].value == "(":
            if block is not None:
                raise StaticReadError(
                    f"nested Go directive block at line {line_number}"
                )
            block = tokens[0].value
            if block not in {
                "module",
                "require",
                "replace",
                "exclude",
                "retract",
                "godebug",
                "tool",
            }:
                uncollected.append((block, line_number, tokens[0].column))
            continue
        if len(tokens) == 1 and tokens[0].value == ")":
            if block is None:
                raise StaticReadError(f"unexpected Go block end at line {line_number}")
            block = None
            continue
        active_directive = block
        if active_directive is None:
            active_directive = tokens[0].value
            if active_directive not in {
                "module",
                "require",
                "replace",
                "exclude",
                "go",
                "toolchain",
                "retract",
                "godebug",
                "tool",
            }:
                uncollected.append((active_directive, line_number, tokens[0].column))
            tokens = tokens[1:]
        if active_directive in {"module", "require", "replace", "exclude", "tool"} and (
            not tokens or any(not token.value for token in tokens)
        ):
            raise StaticReadError(
                f"malformed {active_directive} directive at line {line_number}"
            )
        if active_directive == "tool":
            if (
                len(tokens) != 1
                or not re.fullmatch(
                    r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", tokens[0].value
                )
                or any(
                    part in {".", "..", "..."} for part in tokens[0].value.split("/")
                )
            ):
                raise StaticReadError(f"malformed tool directive at line {line_number}")
            tools.append(_Tool(tokens[0].value, line_number, tokens[0].column))
        elif active_directive == "module":
            if len(tokens) != 1 or module_path is not None:
                raise StaticReadError(
                    f"malformed module directive at line {line_number}"
                )
            module_path = tokens[0].value
        elif active_directive == "require":
            comment_tokens = comment.split()
            indirect = bool(
                comment_tokens and comment_tokens[0] in {"indirect", "indirect;"}
            )
            if len(tokens) != 2:
                raise StaticReadError(
                    f"malformed require directive at line {line_number}"
                )
            requirements.append(
                _Requirement(
                    tokens[0].value,
                    tokens[1].value,
                    indirect,
                    line_number,
                    tokens[0].column,
                )
            )
        elif active_directive == "replace":
            arrows = [
                index for index, token in enumerate(tokens) if token.value == "=>"
            ]
            if len(arrows) != 1:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            arrow = arrows[0]
            left_tokens = tokens[:arrow]
            right_tokens = tokens[arrow + 1 :]
            if len(left_tokens) not in {1, 2} or len(right_tokens) not in {1, 2}:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            original_version = left_tokens[1].value if len(left_tokens) == 2 else None
            target = right_tokens[0].value
            local_path = target if _is_local_replacement(target) else None
            if local_path is not None and len(right_tokens) == 2:
                raise StaticReadError(
                    f"malformed replace directive at line {line_number}"
                )
            key = (left_tokens[0].value, original_version)
            if key in replacements:
                raise StaticReadError(
                    f"repeated replace directive at line {line_number}"
                )
            replacements[key] = _Replacement(
                original_module=left_tokens[0].value,
                original_version=original_version,
                target_module=None if local_path is not None else target,
                target_version=(
                    right_tokens[1].value
                    if local_path is None and len(right_tokens) == 2
                    else None
                ),
                local_path=local_path,
                line=line_number,
                column=left_tokens[0].column,
            )
        elif active_directive == "exclude":
            if len(tokens) != 2:
                raise StaticReadError(
                    f"malformed exclude directive at line {line_number}"
                )
            excluded_versions.setdefault(tokens[0].value, []).append(
                _Exclusion(tokens[1].value, line_number, tokens[0].column)
            )
    if block is not None:
        raise StaticReadError(f"unterminated {block} directive block")
    return (
        module_path,
        tuple(requirements),
        replacements,
        excluded_versions,
        tuple(uncollected),
        tuple(tools),
    )


def _go_tokens(line: str, line_number: int) -> tuple[list[_Token], str]:
    """Read a literal directive line without splitting quoted paths or comments."""
    tokens: list[_Token] = []
    index = 0
    while index < len(line):
        if line[index] in " \t\r":
            index += 1
            continue
        if line.startswith("//", index):
            return tokens, line[index + 2 :]
        start = index
        if line[index] in {'"', "`"}:
            quote_char = line[index]
            index += 1
            content = index
            while index < len(line) and line[index] != quote_char:
                if quote_char == '"' and line[index] == "\\":
                    raise StaticReadError(
                        f"escaped Go directive strings are unsupported at line {line_number}"
                    )
                index += 1
            if index == len(line):
                raise StaticReadError(
                    f"unterminated Go directive string at line {line_number}"
                )
            value = line[content:index]
            index += 1
            if (
                index < len(line)
                and line[index] not in " \t\r)"
                and not line.startswith(("//", "=>"), index)
            ):
                raise StaticReadError(
                    f"joined Go directive tokens at line {line_number}"
                )
        elif line.startswith("=>", index):
            value = "=>"
            index += 2
        elif line[index] in "()":
            value = line[index]
            index += 1
        else:
            while (
                index < len(line)
                and line[index] not in ' \t\r()"`'
                and not line.startswith(("//", "=>"), index)
            ):
                index += 1
            if index == start:
                raise StaticReadError(
                    f"unsupported Go directive token at line {line_number}"
                )
            value = line[start:index]
        tokens.append(_Token(value, start + 1))
    return tokens, ""


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
    if replacement.is_local or replacement.original_version is not None:
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
        "replacement_applicability": "unknown"
        if replacement.original_version
        else "all-versions-assertion",
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
        or target.startswith(("./", "../", ".\\", "..\\", "/", "\\"))
        or re.match(r"^[A-Za-z]:[\\/]", target) is not None
    )


def _parse_go_sum(
    text: str, project: ProjectUnit, path: Path
) -> tuple[tuple[DependencyDeclaration, ...], tuple[Diagnostic, ...]]:
    declarations: list[DependencyDeclaration] = []
    diagnostics: list[Diagnostic] = []
    checksums: dict[tuple[str, str], str] = {}
    invalid_count = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        tokens = raw_line.split()
        if not tokens:
            continue
        source = SourceLocation(
            path, line_number, len(raw_line) - len(raw_line.lstrip()) + 1
        )
        valid_hash = False
        if (
            len(tokens) == 3
            and _CHECKSUM_VERSION.fullmatch(tokens[1])
            and re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", tokens[0])
            and tokens[2].startswith("h1:")
        ):
            try:
                valid_hash = len(base64.b64decode(tokens[2][3:], validate=True)) == 32
            except (ValueError, binascii.Error):
                pass
        if not valid_hash:
            invalid_count += 1
            if invalid_count <= 3:
                diagnostics.append(
                    Diagnostic(
                        "lock.go-sum-invalid",
                        "warning",
                        "Malformed or unsupported Go checksum assertion; no integrity or version selection was inferred.",
                        source,
                    )
                )
            continue
        key = (tokens[0], tokens[1])
        if (
            key in checksums
            and checksums[key] != tokens[2]
            and not any(d.code == "lock.go-sum-conflict" for d in diagnostics)
        ):
            diagnostics.append(
                Diagnostic(
                    "lock.go-sum-conflict",
                    "warning",
                    "Conflicting checksum assertions exist for the same Go module artifact; neither is verified.",
                    source,
                )
            )
        checksums[key] = tokens[2]
        module_file = tokens[1].endswith("/go.mod")
        version = tokens[1][:-7] if module_file else tokens[1]
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref(tokens[0]),
                VersionConstraint(version, "go-checksum"),
                source,
                scope="unknown",
                kind="checksum",
                metadata={
                    "go_kind": "checksum",
                    "checksum_kind": "go.mod" if module_file else "module-zip",
                    "version": version,
                    "checksum": tokens[2],
                    "integrity_verified": False,
                    "selection": "unknown",
                },
            )
        )
    if invalid_count > 3:
        diagnostics.append(
            Diagnostic(
                "lock.go-sum-invalid",
                "warning",
                f"{invalid_count} Go checksum lines were malformed or unsupported; only the first three locations are reported.",
                SourceLocation(path),
            )
        )
    return tuple(declarations), tuple(diagnostics)


def _package_ref(name: str) -> PackageRef:
    return PackageRef(
        ecosystem="Go",
        name=name,
        display_name=name,
        purl=f"pkg:golang/{quote(name, safe='/')}",
    )


def _is_local_or_standard(
    reference: str,
    module_path: str | None,
    declared: tuple[tuple[str, str], ...] = (),
) -> bool:
    if module_path and (
        reference == module_path or reference.startswith(module_path + "/")
    ):
        return not any(
            module.startswith(module_path + "/")
            and (reference == module or reference.startswith(module + "/"))
            for module, _ in declared
        )
    first = reference.split("/", 1)[0]
    return "." not in first and not any(
        reference == module or reference.startswith(module + "/")
        for module, _ in declared
    )


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
