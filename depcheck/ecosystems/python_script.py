"""PEP 723 text-profile metadata for independent script installation scopes."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import io
import re
import tomllib
import tokenize

from packaging.requirements import InvalidRequirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from depcheck.ecosystems.static import discover_files, read_text, StaticReadError
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)
from depcheck.source_locations import SourcePositions

_BLOCK = re.compile(
    r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$"
)


def _script_matches(content: str) -> list[re.Match[str]]:
    comments = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(content).readline):
            if token.type == tokenize.COMMENT and token.start[1] == 0:
                comments.add(token.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass  # Preserve valid metadata before a source syntax error; usage reports it.
    return [
        match
        for match in _BLOCK.finditer(content)
        if match["type"] == "script"
        and content.count("\n", 0, match.start()) + 1 in comments
    ]


def inline_script_files(
    root: Path,
    exclusions: tuple[str, ...] = (),
    *,
    paths: tuple[Path, ...] | None = None,
) -> tuple[Path, ...]:
    files = (
        paths
        if paths is not None
        else discover_files(
            root, suffixes=frozenset({".py"}), excluded_directories=exclusions
        )
    )
    selected = []
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        try:
            content = read_text(path)
        except StaticReadError:
            continue  # Source collector retains read diagnostics; not a parsed script scope.
        if "# /// script" in content and _script_matches(content):
            selected.append(path)
    return tuple(selected)


def parse_inline_script(path: Path) -> ManifestParseResult:
    diagnostics = []
    declarations = []
    source = SourceLocation(path)
    try:
        content = read_text(path)
        matches = _script_matches(content)
        if len(matches) != 1:
            raise ValueError(
                "A script scope requires exactly one closed script metadata block"
            )
        match = matches[0]
        embedded = "".join(
            line[2:] if line.startswith("# ") else line[1:]
            for line in match["content"].splitlines(keepends=True)
        )
        data = tomllib.loads(embedded)
        values = data.get("dependencies", [])
        if not isinstance(values, list) or len(values) > 2048:
            raise ValueError(
                "Inline dependencies must be an array within the 2048-entry budget"
            )
        python = data.get("requires-python")
        if python is not None:
            if not isinstance(python, str):
                raise ValueError("Inline requires-python must be a string")
            SpecifierSet(python)
        positions = SourcePositions.toml(path, embedded)
        base_line = content.count("\n", 0, match.start("content"))
        for index, value in enumerate(values):
            if not isinstance(value, str) or len(value) > 16384:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.script-invalid-requirement",
                        severity="error",
                        message="Inline dependency must be a bounded requirement string",
                        source=source,
                    )
                )
                continue
            location = positions.value("dependencies", index)
            if location.line is not None:
                location = SourceLocation(
                    path,
                    base_line + location.line,
                    (location.column + 2) if location.column is not None else None,
                )
            try:
                declaration = PythonRequirement.from_requirement(value, source=location)
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.script-invalid-requirement",
                        severity="error",
                        message=str(exc),
                        source=location,
                    )
                )
                continue
            declaration = replace(
                declaration,
                origin={
                    **declaration.origin,
                    "script": {
                        "format": "PEP-723",
                        "requires_python": python,
                        "installation": "unknown",
                        "metadata_profile": "textual-comment-block",
                    },
                },
            )
            declarations.append(declaration)
        if data.get("tool"):
            diagnostics.append(
                Diagnostic(
                    code="manifest.script-tool-uncollected",
                    severity="warning",
                    message="Inline tool configuration and runner-specific source/lock semantics are not evaluated; public registry identity remains unverified when source overrides may apply.",
                    source=source,
                )
            )
            declarations = [
                replace(
                    item,
                    origin={
                        **item.origin,
                        "public": None,
                        "kind": "script-tool-context-unknown",
                    },
                )
                for item in declarations
            ]
        unsupported = set(data) - {"dependencies", "requires-python", "tool"}
        if unsupported:
            diagnostics.append(
                Diagnostic(
                    code="manifest.script-fields-unsupported",
                    severity="warning",
                    message="Unknown inline script metadata fields: "
                    + ", ".join(sorted(unsupported)),
                    source=source,
                )
            )
    except (ValueError, InvalidSpecifier, StaticReadError, RecursionError) as exc:
        diagnostics.append(
            Diagnostic(
                code="manifest.script-invalid",
                severity="error",
                message=str(exc),
                source=source,
            )
        )
    diagnostics.append(
        Diagnostic(
            code="resolution.script-environment-unknown",
            severity="warning",
            message="PEP 723 declarations describe this script's independent requirements; interpreter selection, installation and adjacent runner locks are unknown.",
            source=source,
        )
    )
    return ManifestParseResult(
        declarations=tuple(declarations), diagnostics=tuple(diagnostics), files=(path,)
    )
