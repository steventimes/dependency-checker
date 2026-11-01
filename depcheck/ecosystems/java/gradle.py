"""Bounded lexical Gradle calls; this module does not evaluate either DSL."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path

from depcheck.ecosystems.java.coordinates import (
    _diagnostic,
    _is_exact_version,
    _valid_maven_coordinate,
)
from depcheck.ecosystems.java.coordinates import package_ref as _package_ref
from depcheck.ecosystems.static import read_text
from depcheck.filesystem import DEFAULT_MAX_BYTES
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    ResolvedDependency,
    SourceLocation,
    VersionConstraint,
)

_MAX_TOKENS = 100_000
_MAX_DEPTH = 64
_WRAPPERS = frozenset({"platform", "enforcedPlatform", "testFixtures"})


@dataclass(frozen=True, slots=True)
class GradleCall:
    configuration: str
    notation: str
    source: SourceLocation
    call_source: SourceLocation
    contexts: tuple[str, ...]
    wrapper: str | None = None
    literal: bool = True


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    offset: int
    end: int
    literal: bool = True


class _Unsupported(ValueError):
    def __init__(self, offset: int, message: str):
        self.offset = offset
        super().__init__(message)


def _comment_end(text: str, start: int, kotlin: bool) -> int:
    index, depth = start + 2, 1
    while index < len(text):
        if text.startswith("/*", index):
            if not kotlin:
                raise _Unsupported(
                    index, "nested Groovy block comments are uncollected"
                )
            depth += 1
            if depth > _MAX_DEPTH:
                raise _Unsupported(start, "block comment nesting exceeds the budget")
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    raise _Unsupported(start, "unterminated block comment")


def _string_end(
    text: str, start: int, depth: int = 0, *, kotlin: bool
) -> tuple[int, bool, bool]:
    if depth > _MAX_DEPTH:
        raise _Unsupported(start, "string interpolation nesting exceeds the budget")
    quote = text[start]
    triple = text.startswith(quote * 3, start)
    delimiter = quote * (3 if triple else 1)
    index = start + len(delimiter)
    literal = not triple
    while index < len(text):
        if text.startswith(delimiter, index):
            return index + len(delimiter), literal, triple
        if not triple and text[index] in "\r\n":
            raise _Unsupported(start, "unterminated quoted string")
        if text[index] == "\\" and (not triple or not kotlin):
            literal = False
            index += 2
            continue
        if quote == '"' and text.startswith("${", index):
            literal = False
            index = _interpolation_end(text, index + 2, depth + 1, kotlin)
            continue
        if quote == '"' and text[index] == "$":
            literal = False
        index += 1
    raise _Unsupported(start, "unterminated quoted string")


def _interpolation_end(text: str, index: int, depth: int, kotlin: bool) -> int:
    braces = 1
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
        elif text.startswith("/*", index):
            index = _comment_end(text, index, kotlin)
        elif text[index] in {'"', "'"}:
            index, _, _ = _string_end(text, index, depth, kotlin=kotlin)
        elif text[index] == "{":
            braces += 1
            if braces + depth > _MAX_DEPTH:
                raise _Unsupported(index, "interpolation nesting exceeds the budget")
            index += 1
        elif text[index] == "}":
            braces -= 1
            index += 1
            if not braces:
                return index
        elif text[index] == "/" or text.startswith("$/", index):
            raise _Unsupported(index, "ambiguous slash syntax inside interpolation")
        else:
            index += 1
    raise _Unsupported(index, "unterminated interpolation")


def _tokens(text: str, kotlin: bool) -> tuple[list[_Token], list[_Unsupported]]:
    tokens: list[_Token] = []
    index = 0
    try:
        while index < len(text):
            if len(tokens) >= _MAX_TOKENS:
                raise _Unsupported(index, "token budget exceeded")
            char = text[index]
            if char.isspace():
                index += 1
            elif text.startswith("//", index):
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
            elif text.startswith("/*", index):
                index = _comment_end(text, index, kotlin)
            elif char in {'"', "'"}:
                end, literal, triple = _string_end(text, index, kotlin=kotlin)
                tokens.append(
                    _Token(
                        "opaque" if triple else "string",
                        "" if triple else text[index + 1 : end - 1],
                        index,
                        end,
                        literal,
                    )
                )
                index = end
            elif char == "`":
                end = text.find("`", index + 1)
                if end < 0:
                    raise _Unsupported(index, "unterminated backtick identifier")
                tokens.append(_Token("opaque", "", index, end + 1))
                index = end + 1
            elif char == "/" or text.startswith("$/", index):
                raise _Unsupported(
                    index, "slashy strings and slash operators are uncollected"
                )
            elif char.isalpha() or char in "_$":
                end = index + 1
                while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                    end += 1
                tokens.append(_Token("identifier", text[index:end], index, end))
                index = end
            else:
                tokens.append(_Token("punctuation", char, index, index + 1))
                index += 1
    except _Unsupported as exc:
        return tokens, [exc]
    return tokens, []


def literal_gradle_calls(
    text: str, manifest: Path, configurations: Collection[str]
) -> tuple[tuple[GradleCall, ...], list[Diagnostic]]:
    starts = [0] + [i + 1 for i, char in enumerate(text) if char == "\n"]

    def location(offset: int) -> SourceLocation:
        line = bisect_right(starts, min(offset, len(text)))
        return SourceLocation(manifest, line, offset - starts[line - 1] + 1)

    def problem(
        offset: int, message: str, code: str = "manifest.unsupported-expression"
    ) -> None:
        if len(diagnostics) < 20:
            diagnostics.append(Diagnostic(code, "warning", message, location(offset)))

    tokens, errors = _tokens(text, manifest.name.endswith(".kts"))
    diagnostics = [
        Diagnostic(
            "manifest.gradle-lexical-uncollected", "warning", str(e), location(e.offset)
        )
        for e in errors
    ]
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, token in enumerate(tokens):
        if token.kind != "punctuation":
            continue
        if token.value == "(":
            if len(stack) >= _MAX_DEPTH:
                problem(
                    token.offset,
                    "Gradle call nesting exceeds the budget",
                    "manifest.gradle-budget",
                )
                tokens = tokens[:index]
                break
            stack.append(index)
        elif token.value == ")":
            if stack:
                opening = stack.pop()
                pairs[opening] = index
                pairs[index] = opening
            else:
                problem(token.offset, "Unmatched Gradle call delimiter")
    if stack:
        problem(tokens[stack[0]].offset, "Unclosed Gradle call delimiter")

    calls: list[GradleCall] = []
    contexts: list[str] = []
    remaining = DEFAULT_MAX_BYTES
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "punctuation" and token.value == "{":
            previous = tokens[index - 1] if index else None
            if previous is not None and previous.value == ")":
                opening = pairs.get(index - 1, 0)
                previous = tokens[opening - 1] if opening else None
            owner = (
                previous.value
                if previous is not None and previous.kind == "identifier"
                else "<block>"
            )
            if len(contexts) >= _MAX_DEPTH:
                problem(
                    token.offset,
                    "Gradle block nesting exceeds the budget",
                    "manifest.gradle-budget",
                )
                break
            contexts.append(owner)
        elif token.kind == "punctuation" and token.value == "}":
            if contexts:
                contexts.pop()
            else:
                problem(token.offset, "Unmatched Gradle block delimiter")
        elif token.kind == "identifier" and index + 1 < len(tokens):
            following = tokens[index + 1]
            known = token.value in configurations
            candidate = known or ("dependencies" in contexts and following.value == "(")
            if (
                candidate
                and following.value != "{"
                and not (index and tokens[index - 1].value in {"fun", "def"})
            ):
                parenthesized = (
                    following.kind == "punctuation" and following.value == "("
                )
                closing = pairs.get(index + 1) if parenthesized else None
                start = index + 2 if parenthesized else index + 1
                end = closing if closing is not None else start + 1
                wrapper: str | None = None
                if (
                    parenthesized
                    and end > start + 2
                    and tokens[start].value in _WRAPPERS
                    and tokens[start + 1].value == "("
                ):
                    wrapper = tokens[start].value
                    inner = pairs.get(start + 1)
                    if inner == end - 1:
                        start += 2
                        end -= 1
                argument = tokens[start] if start < len(tokens) else None
                valid = (
                    argument is not None
                    and argument.kind == "string"
                    and end == start + 1
                )
                if parenthesized:
                    valid = valid and closing is not None
                elif argument is not None:
                    valid = (
                        valid
                        and location(following.offset).line
                        == location(token.offset).line
                    )
                    after = tokens[end] if end < len(tokens) else None
                    valid = valid and (
                        after is None
                        or bisect_right(starts, after.offset)
                        > bisect_right(starts, argument.end)
                        or after.value in {";", "}", "{"}
                    )
                if valid and argument is not None:
                    cost = 1024 + 16 * len(
                        (argument.value + "".join(contexts)).encode("utf-8")
                    )
                    if cost > remaining:
                        problem(
                            token.offset,
                            "Gradle declaration context expansion exceeds the budget",
                            "manifest.gradle-budget",
                        )
                        break
                    remaining -= cost
                    calls.append(
                        GradleCall(
                            token.value,
                            argument.value,
                            location(argument.offset),
                            location(token.offset),
                            tuple(contexts),
                            wrapper,
                            argument.literal,
                        )
                    )
                    if not known:
                        problem(
                            token.offset,
                            f"Custom Gradle configuration {token.value[:160]!r} has unknown scope",
                            "manifest.gradle-configuration-uncollected",
                        )
                else:
                    problem(
                        token.offset,
                        f"Gradle {token.value[:160]} uses an uncollected dependency expression",
                    )
                if parenthesized and closing is not None:
                    index = closing
                elif not valid:
                    line = location(token.offset).line
                    while (
                        index + 1 < len(tokens)
                        and location(tokens[index + 1].offset).line == line
                        and tokens[index + 1].value not in {";", "}"}
                    ):
                        index += 1
        index += 1
    if contexts and not errors:
        problem(tokens[-1].offset if tokens else 0, "Unclosed Gradle block delimiter")
    return tuple(calls), diagnostics


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
    "classpath": "build",
}


_GRADLE_LOCK_NAMES = ("gradle.lockfile", "buildscript-gradle.lockfile")


def _parse_gradle(
    project: ProjectUnit,
    manifest: Path,
    repository_root: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    calls, diagnostics = literal_gradle_calls(
        read_text(manifest), manifest, _GRADLE_CONFIGURATIONS
    )
    declarations: list[DependencyDeclaration] = []
    for call in calls:
        group, separator, remainder = call.notation.partition(":")
        artifact, version_separator, version = remainder.partition(":")
        if not separator or not _valid_maven_coordinate(group, artifact):
            diagnostics.append(
                _diagnostic(
                    "manifest.invalid-dependency",
                    f"Unresolved Gradle coordinate identity: {call.notation[:160]}",
                    call.source,
                    severity="warning",
                )
            )
            continue
        classifier = extension = None
        literal = call.literal and "$" not in call.notation
        if literal:
            version, extension_separator, extension_value = version.partition("@")
            extension = extension_value if extension_separator else None
            version, classifier_separator, classifier_value = version.partition(":")
            classifier = classifier_value if classifier_separator else None
        constraint = "constraints" in call.contexts
        scope = _GRADLE_CONFIGURATIONS.get(call.configuration, "unknown")
        if call.wrapper in {"platform", "enforcedPlatform"} or constraint:
            scope = "build"
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref(f"{group}:{artifact}"),
                VersionConstraint(
                    version if version_separator else "",
                    "gradle-required",
                    version if version_separator and literal else None,
                ),
                call.source,
                scope=scope,
                kind="constraint" if constraint else "conditional",
                metadata={
                    "configuration": call.configuration,
                    "gradle_kind": call.wrapper
                    or ("constraint" if constraint else "dependency"),
                    "notation": call.notation,
                    "literal": literal,
                    "activation": "unknown",
                    "ownership": "lexical-script",
                    "contexts": list(call.contexts),
                    "call_source": call.call_source.to_dict(repository_root),
                    **({"classifier": classifier} if classifier is not None else {}),
                    **({"extension": extension} if extension is not None else {}),
                },
            )
        )
    diagnostics.append(
        _diagnostic(
            "manifest.gradle-evaluation-uncollected",
            "Only bounded literal configuration calls are inventoried. Evaluated script ownership, settings, plugins, catalogs and custom build logic remain uncollected.",
            manifest,
            severity="warning",
        )
    )
    return tuple(declarations), diagnostics


def _merge_gradle_lock(
    project: ProjectUnit,
    lock: Path,
    existing: Sequence[ResolvedDependency],
) -> tuple[list[ResolvedDependency], list[Diagnostic]]:
    resolved = list(existing)
    diagnostics: list[Diagnostic] = []
    occurrences: dict[str, int] = {}
    for line_number, raw_line in enumerate(read_text(lock).splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinate, separator, raw_configurations = line.partition("=")
        coordinate = coordinate.strip()
        parts = coordinate.split(":")
        source = SourceLocation(
            lock, line_number, len(raw_line) - len(raw_line.lstrip()) + 1
        )
        configurations = [name.strip() for name in raw_configurations.split(",")]
        if (
            len(parts) != 3
            or not all(parts)
            or not separator
            or not all(configurations)
            or not _valid_maven_coordinate(parts[0], parts[1])
            or not _is_exact_version(parts[2])
            or "$" in parts[2]
        ):
            if len(diagnostics) < 20:
                diagnostics.append(
                    _diagnostic(
                        "lock.gradle-invalid-entry",
                        "Malformed or unsupported Gradle lock assertion; no version was inferred.",
                        source,
                        severity="warning",
                    )
                )
            continue
        group, artifact, version = parts
        package = _package_ref(f"{group}:{artifact}")
        key = hashlib.sha256(
            json.dumps(
                [lock.name, package.name, version, sorted(configurations)]
            ).encode("utf-8")
        ).hexdigest()[:24]
        occurrences[key] = occurrences.get(key, 0) + 1
        resolved.append(
            ResolvedDependency(
                project.project_id,
                package,
                version,
                source,
                instance_id=f"gradle-lock:{key}:{occurrences[key]}",
                origin={
                    "kind": "gradle-lock",
                    "public": False,
                    "lock_kind": "buildscript"
                    if lock.name.startswith("buildscript-")
                    else "project",
                    "configurations": configurations,
                    "selection": "unknown",
                    "installed": "unknown",
                },
            )
        )
    return resolved, diagnostics
