"""Bounded CMake configuration inventory; never configure or populate content."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import re

from depcheck.bounded_io import repository_operation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
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
    PackageRef,
    ProjectUnit,
    SourceLocation,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.source_locations import SourcePositions

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_CONTENT_NAME = re.compile(r"[A-Za-z0-9_.+-]+\Z")
_BRACKET = re.compile(r"\[(=*)\[")
_SINGLE_OPTIONS = frozenset(
    {
        "GIT_REPOSITORY",
        "GIT_TAG",
        "GIT_SHALLOW",
        "GIT_SUBMODULES_RECURSE",
        "URL_HASH",
        "URL_MD5",
        "SOURCE_DIR",
        "BINARY_DIR",
        "SOURCE_SUBDIR",
        "DOWNLOAD_EXTRACT_TIMESTAMP",
        "DOWNLOAD_NO_EXTRACT",
    }
)
_FLAGS = frozenset({"SYSTEM", "EXCLUDE_FROM_ALL", "OVERRIDE_FIND_PACKAGE"})
_OPTIONS = _SINGLE_OPTIONS | _FLAGS | {"URL", "FIND_PACKAGE_ARGS"}


@dataclass(frozen=True)
class CMakeArgument:
    value: str
    offset: int
    end: int
    literal: bool = True
    structural: bool = False


@dataclass(frozen=True)
class CMakeCommand:
    name: str
    arguments: tuple[CMakeArgument, ...]
    offset: int


def _tokens(text: str, *, template: bool = False) -> Iterator[CMakeArgument]:
    offset = 0
    count = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        if text[offset] == "#":
            bracket = _BRACKET.match(text, offset + 1)
            if bracket:
                closing = "]" + bracket[1] + "]"
                end = text.find(closing, bracket.end())
                if end < 0:
                    raise StaticReadError("Unclosed CMake bracket comment")
                offset = end + len(closing)
            else:
                end = text.find("\n", offset)
                offset = len(text) if end < 0 else end + 1
            continue
        start = offset
        structural = text[offset] in "()"
        literal = True
        bracket = _BRACKET.match(text, offset)
        if structural:
            value = text[offset]
            offset += 1
        elif bracket:
            closing = "]" + bracket[1] + "]"
            end = text.find(closing, bracket.end())
            if end < 0:
                raise StaticReadError("Unclosed CMake bracket argument")
            value = text[bracket.end() : end]
            if value.startswith("\r\n"):
                value = value[2:]
            elif value.startswith("\n"):
                value = value[1:]
            offset = end + len(closing)
        elif text[offset] == '"':
            offset += 1
            content = offset
            while offset < len(text) and text[offset] != '"':
                if text[offset] == "\\":
                    literal = False
                    offset += 2
                else:
                    literal &= text[offset] != "$"
                    offset += 1
            if offset >= len(text):
                raise StaticReadError("Unclosed CMake quoted argument")
            value = text[content:offset]
            offset += 1
        else:
            while offset < len(text) and not (
                text[offset].isspace() or text[offset] in '()#"'
            ):
                if text[offset] == "\\":
                    literal = False
                    offset += 2
                else:
                    literal &= text[offset] not in "$;"
                    offset += 1
            value = text[start:offset]
        count += 1
        if count > 100_000 or len(value) > 65_536:
            raise StaticReadError("CMake token budget exceeded")
        if template and "@" in value:
            literal = False
        yield CMakeArgument(value, start, offset, literal, structural)


def cmake_commands(text: str, *, template: bool = False) -> Iterator[CMakeCommand]:
    """Yield lexical calls, ignoring comments/strings and qualifying expansion.

    All control flow remains unevaluated. A command invocation in a function or
    condition is an assertion in the file, not proof that it was executed.
    """
    tokens = iter(_tokens(text, template=template))
    for name in tokens:
        # PackageConfigHelpers inserts code here. Retain later literal calls
        # without evaluating the expansion; the collector reports that gap.
        if template and name.value == "@PACKAGE_INIT@" and text[name.offset] == "@":
            continue
        if (
            not name.literal
            or text[name.offset] in '"['
            or not _IDENTIFIER.fullmatch(name.value)
        ):
            raise StaticReadError("Unsupported CMake command syntax")
        opening = next(tokens, None)
        if opening is None or not opening.structural or opening.value != "(":
            raise StaticReadError("Expected a CMake command argument list")
        arguments: list[CMakeArgument] = []
        depth = 1
        previous = opening
        for token in tokens:
            if token.structural:
                depth += 1 if token.value == "(" else -1
                if depth == 0:
                    break
                if depth > 64:
                    raise StaticReadError("CMake parenthesis depth budget exceeded")
            if (
                arguments
                and previous.end == token.offset
                and not (previous.structural or token.structural)
            ):
                raise StaticReadError("Unsupported adjacent CMake arguments")
            arguments.append(token)
            previous = token
            if len(arguments) > 16_384:
                raise StaticReadError("CMake command argument budget exceeded")
        else:
            raise StaticReadError("Unclosed CMake command argument list")
        yield CMakeCommand(name.value.casefold(), tuple(arguments), name.offset)


class CMakeProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        files = discover_files(
            root,
            names=frozenset({"CMakeLists.txt"}),
            suffixes=frozenset({".cmake", ".cmake.in"}),
            excluded_directories=exclusions_for(context.settings),
        )
        # A lexical tree is one inventory. Do not infer add_subdirectory/include
        # execution, or call every nested CMakeLists an independent project.
        project_roots = _topmost_roots(
            {path.parent for path in files if path.name == "CMakeLists.txt"}
        )
        scripts = [path for path in files if _owner(path, project_roots) is None]
        script_roots = _topmost_roots({path.parent for path in scripts})
        groups: dict[tuple[Path, str], list[Path]] = {}
        for path in files:
            parent = _owner(path, project_roots)
            manager = "cmake"
            if parent is None:
                parent = _owner(path, script_roots)
                manager = "cmake-script"
            assert parent is not None
            groups.setdefault((parent, manager), []).append(path)
        projects = []
        for (parent, manager), owned in sorted(groups.items()):
            primary = (
                parent / "CMakeLists.txt"
                if manager == "cmake"
                else min(path for path in owned if path.parent == parent)
            )
            projects.append(
                ProjectUnit(
                    ProjectUnit.stable_id(parent.relative_to(root), "CMake", manager),
                    parent.relative_to(root),
                    "cpp" if manager == "cmake" else "cmake",
                    "CMake",
                    manager,
                    tuple(
                        path.relative_to(root)
                        for path in sorted(
                            owned, key=lambda path: (path != primary, path.as_posix())
                        )
                    ),
                )
            )
        return tuple(
            sorted(
                projects,
                key=lambda p: (len(p.root.parts), p.root.as_posix(), p.project_id),
            )
        )


def _topmost_roots(candidates: set[Path]) -> set[Path]:
    roots: set[Path] = set()
    for path in sorted(candidates, key=lambda p: (len(p.parts), p.as_posix())):
        if not any(parent in roots for parent in path.parents):
            roots.add(path)
    return roots


def _owner(path: Path, roots: set[Path]) -> Path | None:
    return next((parent for parent in path.parents if parent in roots), None)


class CMakeEvidenceCollector:
    @repository_operation("context.repository_root")
    def collect(
        self, context: ProviderContext, project: ProjectUnit, pack: EcosystemPack
    ) -> EvidenceBundle:
        del pack
        root = context.repository_root
        files = tuple(root / relative for relative in project.manifests)
        declarations: list[DependencyDeclaration] = []
        availability: list[tuple[CMakeArgument, SourceLocation]] = []
        diagnostics: list[Diagnostic] = []
        for path in files:
            try:
                text = read_text(path)
                positions = SourcePositions(path, text)
                template = path.name.lower().endswith(".cmake.in")
                if template:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.unsupported-cmake-template-expansion",
                            "warning",
                            "Template substitutions and injected code are unevaluated; retained literal calls do not establish generated dependencies or activation.",
                            SourceLocation(path),
                        )
                    )
                for command in cmake_commands(text, template=template):
                    arguments = command.arguments
                    if command.name in {
                        "fetchcontent_declare",
                        "find_package",
                        "find_dependency",
                    }:
                        declaration, problems = _declaration(
                            project, command, positions, template=template
                        )
                        diagnostics.extend(problems)
                        if declaration is not None:
                            declarations.append(declaration)
                    elif command.name == "fetchcontent_makeavailable":
                        availability.extend(
                            (a, positions.at(a.offset)) for a in arguments
                        )
                        if any(not a.literal for a in arguments):
                            diagnostics.append(
                                Diagnostic(
                                    "manifest.cmake-dynamic",
                                    "warning",
                                    "CMake availability arguments require evaluation; activation is unknown.",
                                    positions.at(command.offset),
                                )
                            )
                    elif command.name in {
                        "externalproject_add",
                        "fetchcontent_populate",
                        "cmake_language",
                        "cpmaddpackage",
                        "cpmfindpackage",
                    }:
                        diagnostics.append(
                            Diagnostic(
                                "manifest.unsupported-cmake-command",
                                "warning",
                                f"{command.name} dependency semantics are not collected.",
                                positions.at(command.offset),
                            )
                        )
            except StaticReadError as exc:
                diagnostics.append(
                    Diagnostic(
                        "manifest.invalid", "error", str(exc), SourceLocation(path)
                    )
                )
        manifest_complete = not diagnostics
        diagnostics.append(
            Diagnostic(
                "resolution.cmake-activation-unknown",
                "warning",
                "CMake calls are unevaluated configuration assertions. Conditions, includes, first-declaration precedence, dependency providers and source overrides leave active dependencies and installed versions unknown.",
                SourceLocation(root / project.manifests[0]),
            )
        )
        packages = {d.package.name: d.package for d in declarations}
        usages = tuple(
            UsageEvidence(
                project.project_id,
                "cmake",
                f"FetchContent_MakeAvailable:{a.value}",
                location,
                scope="build",
                kind="configuration",
                mapped_package=packages[a.value.casefold()],
                mapping_confidence=MappingConfidence.INFERRED,
                mapping_reason="literal availability request; execution and provider selection unknown",
            )
            for a, location in availability
            if a.literal and a.value.casefold() in packages
        )
        return EvidenceBundle(
            project,
            declarations=tuple(declarations),
            usages=usages,
            diagnostics=tuple(diagnostics),
            evidence_files=files,
            capabilities=(
                Capability(
                    "manifest",
                    CapabilityState.INCOMPLETE
                    if not manifest_complete
                    else CapabilityState.COMPLETE,
                ),
                Capability(
                    "resolution",
                    CapabilityState.INCOMPLETE,
                    "active graph and installed versions are unknown",
                ),
                Capability(
                    "usage",
                    CapabilityState.UNSUPPORTED,
                    "CMake target/source usage is not collected",
                ),
                Capability(
                    "mapping",
                    CapabilityState.UNSUPPORTED,
                    "CMake content names do not establish package-manager coordinates",
                ),
            ),
        )


def _declaration(
    project: ProjectUnit,
    command: CMakeCommand,
    positions: SourcePositions,
    *,
    template: bool = False,
) -> tuple[DependencyDeclaration | None, list[Diagnostic]]:
    arguments = command.arguments
    source = positions.at(arguments[0].offset if arguments else command.offset)
    problems: list[Diagnostic] = []
    dynamic = [i for i, argument in enumerate(arguments[1:]) if not argument.literal]
    if (
        not arguments
        or not arguments[0].literal
        or not _CONTENT_NAME.fullmatch(arguments[0].value)
    ):
        return None, [
            Diagnostic(
                "manifest.cmake-dynamic",
                "warning",
                "CMake dependency name is not a supported literal.",
                source,
            )
        ]
    if dynamic:
        problems.append(
            Diagnostic(
                "manifest.cmake-dynamic",
                "warning",
                "CMake dependency arguments require evaluation; literal name retained.",
                source,
            )
        )
    options: dict[str, list[str]] = {}
    unparsed: list[str] = []
    constraint = ""
    if command.name == "fetchcontent_declare":
        index = 1
        while index < len(arguments):
            key = arguments[index].value
            index += 1
            if key in _FLAGS:
                options.setdefault(key, [])
                continue
            if key == "FIND_PACKAGE_ARGS":
                options[key] = [a.value for a in arguments[index:]]
                break
            if key not in _SINGLE_OPTIONS | {"URL"}:
                unparsed = [a.value for a in arguments[index - 1 :]]
                break
            values = []
            while index < len(arguments) and not (
                arguments[index].value in _OPTIONS
                or (
                    key == "URL"
                    and re.fullmatch(r"[A-Z][A-Z0-9_]+", arguments[index].value)
                )
            ):
                values.append(arguments[index].value)
                index += 1
                if key != "URL":
                    break
            if not values or key in options:
                unparsed = [a.value for a in arguments]
                break
            options[key] = values
        if unparsed:
            problems.append(
                Diagnostic(
                    "manifest.unsupported-cmake-options",
                    "warning",
                    "Unsupported, repeated or missing CMake content options retained as raw assertions.",
                    source,
                )
            )
    elif (
        len(arguments) > 1
        and arguments[1].literal
        and re.fullmatch(r"\d[\d.]*", arguments[1].value)
    ):
        constraint = arguments[1].value
    name = arguments[0].value
    return DependencyDeclaration(
        project.project_id,
        PackageRef("CMake", name.casefold(), name),
        VersionConstraint(constraint, "cmake"),
        source,
        scope="build",
        metadata={
            "mechanism": command.name,
            "activation": "unknown",
            **({"template": True} if template else {}),
            "arguments": [a.value for a in arguments[1:]],
            "dynamic_arguments": dynamic,
            "options": options,
            "unparsed_options": unparsed,
        },
    ), problems


def create_cmake_pack() -> EcosystemPack:
    return EcosystemPack(
        "CMake",
        CMakeProjectDetector(),
        collector=CMakeEvidenceCollector(),
        capabilities=frozenset({"manifest"}),
    )
