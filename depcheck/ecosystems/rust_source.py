"""Bounded Rust crate-reference candidates, without compiler name resolution."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
import json
import re

from depcheck.ecosystems.static import StaticReadError, read_text
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    MappingConfidence,
    PackageRef,
    ProjectUnit,
    SourceLocation,
    UsageEvidence,
)
from depcheck.source_locations import SourcePositions

_NAME = re.compile(r"(?:r#)?[^\W\d]\w*", re.UNICODE)
_RAW_STRING = re.compile(r'(?:br|cr|r)(#{0,255})"')
_CHAR = re.compile(
    r"(?:b)?'(?:[^'\\\r\n]|\\(?:[nrt0\\'\"]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}))'"
)
_LIFETIME = re.compile(r"'[^\W\d]\w*", re.UNICODE)
_LOCAL = frozenset({"crate", "self", "super", "Self"})
_PRELUDE = frozenset({"std", "core", "alloc", "proc_macro", "test"})
_MAX_TOKENS = 100_000
_MAX_FILES = 1_000
_MAX_CHARACTERS = 8 * 1024 * 1024
_MAX_REFERENCES = 20_000
_MAX_DIAGNOSTICS = 64


@dataclass(frozen=True, slots=True)
class _Token:
    value: str
    offset: int
    name: bool = False


def _tokens(text: str) -> Iterator[_Token]:
    offset = count = 0
    if text.startswith("#!") and not text.startswith("#!["):
        newline = text.find("\n")
        offset = len(text) if newline < 0 else newline
    while offset < len(text):
        if count >= _MAX_TOKENS:
            raise StaticReadError("Rust lexical token budget exhausted")
        if text[offset].isspace():
            offset += 1
            continue
        if text.startswith("//", offset):
            end = text.find("\n", offset + 2)
            offset = len(text) if end < 0 else end
            continue
        if text.startswith("/*", offset):
            depth = 1
            offset += 2
            while depth and offset < len(text):
                if text.startswith("/*", offset):
                    depth += 1
                    if depth > 64:
                        raise StaticReadError("Rust nested comment budget exhausted")
                    offset += 2
                elif text.startswith("*/", offset):
                    depth -= 1
                    offset += 2
                else:
                    offset += 1
            if depth:
                raise StaticReadError("Unclosed Rust block comment")
            continue
        raw = _RAW_STRING.match(text, offset)
        if raw:
            closing = '"' + raw[1]
            end = text.find(closing, raw.end())
            if end < 0:
                raise StaticReadError("Unclosed Rust raw string")
            offset = end + len(closing)
            continue
        start = offset
        if text.startswith(('b"', 'c"'), offset):
            offset += 1
        if text[offset] == '"':
            offset += 1
            while offset < len(text) and text[offset] != '"':
                offset += 2 if text[offset] == "\\" else 1
            if offset >= len(text):
                raise StaticReadError("Unclosed Rust string")
            offset += 1
            continue
        char = _CHAR.match(text, offset)
        if char:
            offset = char.end()
            continue
        if text[offset] == "'":
            lifetime = _LIFETIME.match(text, offset)
            if lifetime is None:
                raise StaticReadError("Unsupported Rust character or lifetime literal")
            yield _Token(lifetime[0], offset)
            offset = lifetime.end()
        else:
            name = _NAME.match(text, offset)
            if name:
                value = name[0]
                yield _Token(value.removeprefix("r#"), offset, True)
                offset = name.end()
            else:
                value = "::" if text.startswith("::", offset) else text[offset]
                yield _Token(value, start)
                offset += len(value)
        count += 1


def collect_rust_references(
    project: ProjectUnit,
    declarations: Sequence[DependencyDeclaration],
    files: Sequence[Path],
    *,
    source_owner: bool,
) -> tuple[tuple[UsageEvidence, ...], tuple[Diagnostic, ...]]:
    diagnostics = [
        Diagnostic(
            "usage.rust-uncollected",
            "warning",
            "Rust literal crate references are conditional candidates. Module/target/cfg selection, macro expansion, generated code, custom crate names and compiler bindings remain unknown; zero references do not prove non-use.",
            SourceLocation(project.manifests[0]),
        )
    ]
    if not source_owner:
        diagnostics.append(
            Diagnostic(
                "usage.rust-owner-unresolved",
                "warning",
                "No valid literal Cargo package owns these sources; crate mapping is uncollected.",
                SourceLocation(project.manifests[0]),
            )
        )
        return (), tuple(diagnostics)
    bindings: dict[str, set[tuple[PackageRef, str]]] = {}
    for declaration in declarations:
        alias = declaration.metadata.get("installation_name")
        if declaration.kind != "direct" or not isinstance(alias, str):
            continue
        origin = json.dumps(
            {
                key: declaration.metadata[key]
                for key in ("path", "git", "registry", "branch", "rev", "tag")
                if key in declaration.metadata
            },
            sort_keys=True,
        )
        bindings.setdefault(alias.replace("-", "_"), set()).add(
            (declaration.package, origin)
        )

    shadows: set[str] = set()
    candidates: list[tuple[str, SourceLocation]] = []
    characters = omitted_diagnostics = 0
    reference_budget_reported = False

    def gap(code: str, message: str, source: SourceLocation) -> None:
        nonlocal omitted_diagnostics
        if len(diagnostics) < _MAX_DIAGNOSTICS:
            diagnostics.append(Diagnostic(code, "warning", message, source))
        else:
            omitted_diagnostics += 1

    for index, path in enumerate(files):
        if index >= _MAX_FILES or characters >= _MAX_CHARACTERS:
            gap(
                "usage.rust-budget",
                "Rust source file/context budget exhausted; remaining files are uncollected",
                SourceLocation(path),
            )
            break
        try:
            text = read_text(path)
        except StaticReadError as exc:
            gap("usage.rust-read", str(exc), SourceLocation(path))
            continue
        if characters + len(text) > _MAX_CHARACTERS:
            gap(
                "usage.rust-budget",
                "Rust source context budget exhausted; file is uncollected",
                SourceLocation(path),
            )
            break
        characters += len(text)
        positions = SourcePositions(path, text)
        tokens: list[_Token] = []
        try:
            tokens.extend(_tokens(text))
        except StaticReadError as exc:
            gap("usage.rust-lexical", str(exc), SourceLocation(path))
        for i, token in enumerate(tokens):
            if not token.name:
                continue
            previous = tokens[i - 1].value if i else ""
            following = tokens[i + 1].value if i + 1 < len(tokens) else ""
            if (
                previous in {"mod", "struct", "enum", "trait", "type", "union", "as"}
                and token.value in bindings
            ):
                shadows.add(token.value)
            external = (
                i >= 2 and previous == "crate" and tokens[i - 2].value == "extern"
            )
            bare_use = previous == "use" and following in {";", "as"}
            if not (external or bare_use or following == "::") or token.value in _LOCAL:
                continue
            if (
                previous == "::"
                and i >= 2
                and (tokens[i - 2].name or tokens[i - 2].value in {")", "]", ">", "?"})
            ):
                continue
            if token.value not in bindings and (
                not external or token.value in _PRELUDE
            ):
                continue
            if len(candidates) >= _MAX_REFERENCES:
                if not reference_budget_reported:
                    gap(
                        "usage.rust-budget",
                        "Rust reference budget exhausted; remaining references are uncollected",
                        positions.at(token.offset),
                    )
                    reference_budget_reported = True
                continue
            candidates.append((token.value, positions.at(token.offset)))

    usages = []
    for alias, source in candidates:
        owners = bindings.get(alias, set())
        unique = len(owners) == 1 and alias not in shadows
        package = next(iter(owners))[0] if unique else None
        reason = (
            "Literal Cargo dependency alias matches; local/compiler bindings, target/cfg activation and macro expansion are unevaluated"
            if unique
            else "Crate owner is unknown: undeclared alias, conflicting origins or possible local shadowing"
        )
        usages.append(
            UsageEvidence(
                project.project_id,
                "rust",
                alias,
                source,
                "unknown",
                "conditional",
                package,
                MappingConfidence.INFERRED if unique else MappingConfidence.UNKNOWN,
                reason,
            )
        )
        if not unique:
            gap(
                "usage.rust-owner-unresolved",
                f"Rust crate reference {alias!r}: {reason}",
                source,
            )
    if omitted_diagnostics:
        diagnostics.append(
            Diagnostic(
                "usage.rust-budget",
                "warning",
                f"Omitted {omitted_diagnostics} additional Rust source diagnostics",
                SourceLocation(project.manifests[0]),
            )
        )
    return tuple(usages), tuple(diagnostics)
