"""Bounded JavaScript tokenization and literal module loads."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from depcheck.ecosystems.frontend import ModuleLoad as _ModuleLoad


@dataclass(frozen=True, slots=True)
class _JsToken:
    kind: str
    value: str
    line: int
    column: int


def _lex_javascript(
    text: str,
    issues: list[tuple[int, int, str]] | None = None,
    *,
    start_line: int = 1,
    start_column: int = 1,
) -> tuple[tuple[_JsToken, ...], int]:
    """Tokenize only the bounded syntax needed for static module evidence."""
    tokens: list[_JsToken] = []
    incomplete = 0
    index = 0
    line = start_line
    column = start_column

    def uncertain(reason: str, issue_line: int, issue_column: int) -> None:
        nonlocal incomplete
        incomplete += 1
        if issues is not None and len(issues) < 5:
            issues.append((issue_line, issue_column, reason))

    def advance(count: int = 1) -> None:
        nonlocal index, line, column
        end = min(index + count, len(text))
        for character in text[index:end]:
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
        index = end

    while index < len(text):
        character = text[index]
        if character.isspace():
            advance()
            continue
        if index == 0 and text.startswith("#!", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("/*", index):
            token_line, token_column = line, column
            advance(2)
            closed = False
            while index < len(text):
                if text.startswith("*/", index):
                    advance(2)
                    closed = True
                    break
                advance()
            if not closed:
                uncertain("unterminated block comment", token_line, token_column)
            continue
        if character in {"'", '"'}:
            quote_character = character
            token_line = line
            token_column = column
            value: list[str] = []
            safe = True
            closed = False
            advance()
            while index < len(text):
                character = text[index]
                if character == quote_character:
                    advance()
                    closed = True
                    break
                if character in "\r\n":
                    break
                if character == "\\":
                    advance()
                    if index >= len(text):
                        break
                    escaped = text[index]
                    if escaped in {"\\", "'", '"', "/"}:
                        value.append(escaped)
                    else:
                        safe = False
                    advance()
                    continue
                value.append(character)
                advance()
            if not closed:
                uncertain("unterminated string", token_line, token_column)
                break
            if not safe:
                uncertain("unsupported string escape", token_line, token_column)
            if closed and safe:
                tokens.append(
                    _JsToken("string", "".join(value), token_line, token_column)
                )
            continue
        if character == "`":
            token_line, token_column = line, column
            advance()
            closed = False
            interpolated = False
            while index < len(text):
                if text[index] == "\\":
                    advance(2)
                    continue
                if text.startswith("${", index):
                    interpolated = True
                    uncertain("template interpolation is not parsed", line, column)
                    break
                if text[index] == "`":
                    advance()
                    closed = True
                    break
                advance()
            if interpolated:
                break
            if not closed:
                uncertain("unterminated template literal", token_line, token_column)
                break
            continue
        if character == "/" and _can_start_regex(tokens):
            token_line, token_column = line, column
            advance()
            closed = False
            in_character_class = False
            while index < len(text):
                character = text[index]
                if character == "\\":
                    advance(2)
                    continue
                if character in "\r\n":
                    break
                if character == "[":
                    in_character_class = True
                elif character == "]":
                    in_character_class = False
                elif character == "/" and not in_character_class:
                    advance()
                    while index < len(text) and (
                        text[index].isalnum() or text[index] in {"_", "$"}
                    ):
                        advance()
                    closed = True
                    break
                advance()
            if not closed:
                uncertain("unterminated regular expression", token_line, token_column)
                break
            continue
        if character == "<" and _looks_like_jsx_start(
            text,
            index,
            tokens[-1] if tokens else None,
        ):
            uncertain("JSX syntax is not parsed", line, column)
            break
        if character.isalpha() or character in {"_", "$"}:
            token_line = line
            token_column = column
            start = index
            while index < len(text) and (
                text[index].isalnum() or text[index] in {"_", "$"}
            ):
                advance()
            tokens.append(
                _JsToken("identifier", text[start:index], token_line, token_column)
            )
            continue
        tokens.append(_JsToken("punctuation", character, line, column))
        advance()
    return tuple(tokens), incomplete


def _can_start_regex(tokens: Sequence[_JsToken]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1]
    if previous.kind == "punctuation":
        return (
            previous.value in "([{=,:;!?&|+-*%^~<>"
            or previous.value == ")"
            and _closes_control_condition(tokens)
        )
    return previous.value in {
        "await",
        "case",
        "delete",
        "in",
        "instanceof",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }


def _closes_control_condition(tokens: Sequence[_JsToken]) -> bool:
    depth = 0
    for index in range(len(tokens) - 1, -1, -1):
        token = tokens[index]
        if token.value == ")":
            depth += 1
            continue
        if token.value != "(":
            continue
        depth -= 1
        if depth != 0:
            continue
        keyword = tokens[index - 1] if index else None
        return (
            keyword is not None
            and keyword.kind == "identifier"
            and keyword.value in {"catch", "for", "if", "switch", "while", "with"}
        )
    return False


def _looks_like_jsx_start(
    text: str,
    index: int,
    previous: _JsToken | None,
) -> bool:
    cursor = index + 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or not (text[cursor].isalpha() or text[cursor] == "/"):
        return False
    if previous is None:
        return True
    if previous.kind == "punctuation":
        return previous.value in "=([{,:;!&|?"
    return previous.value in {"return", "yield"}


def _module_loads(
    tokens: Sequence[_JsToken],
    dynamic_sources: list[tuple[int, int]] | None = None,
) -> tuple[tuple[_ModuleLoad, ...], int]:
    loads: list[_ModuleLoad] = []
    dynamic_count = 0
    seen: set[tuple[str, int, int, str]] = set()

    def dynamic(token: _JsToken) -> None:
        nonlocal dynamic_count
        dynamic_count += 1
        if dynamic_sources is not None and len(dynamic_sources) < 5:
            dynamic_sources.append((token.line, token.column))

    def add(token: _JsToken, kind: str) -> None:
        key = (token.value, token.line, token.column, kind)
        if key in seen:
            return
        seen.add(key)
        loads.append(_ModuleLoad(token.value, token.line, token.column, kind))

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {
            "export",
            "import",
            "require",
        }:
            continue
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.value == "require":
            if previous is not None and previous.value == ".":
                continue
            if following is None or following.value != "(":
                continue
            argument = tokens[index + 2] if index + 2 < len(tokens) else None
            closing = tokens[index + 3] if index + 3 < len(tokens) else None
            if (
                argument is not None
                and argument.kind == "string"
                and closing is not None
                and closing.value == ")"
            ):
                add(argument, "regular")
            else:
                dynamic(token)
            continue
        if token.value == "import":
            if following is not None and following.value == ".":
                continue
            if following is not None and following.value == "(":
                argument = tokens[index + 2] if index + 2 < len(tokens) else None
                closing = tokens[index + 3] if index + 3 < len(tokens) else None
                if (
                    argument is not None
                    and argument.kind == "string"
                    and closing is not None
                    and closing.value == ")"
                ):
                    add(argument, "dynamic")
                else:
                    dynamic(token)
                continue
            if following is not None and following.kind == "string":
                add(following, "regular")
                continue
        specifier = _from_specifier(tokens, index)
        if specifier is not None:
            add(specifier, "regular")
    return tuple(loads), dynamic_count


def _from_specifier(
    tokens: Sequence[_JsToken],
    start: int,
) -> _JsToken | None:
    opening = tokens[start]
    for index in range(start + 1, min(len(tokens), start + 257)):
        token = tokens[index]
        if token.value == ";":
            return None
        if (
            index > start + 1
            and token.kind == "identifier"
            and token.value in {"export", "import"}
        ):
            return None
        if (
            token.line > opening.line
            and token.kind == "identifier"
            and token.value
            in {"class", "const", "function", "if", "let", "return", "var"}
        ):
            return None
        if token.value != "from":
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        return (
            following if following is not None and following.kind == "string" else None
        )
    return None
