"""Bounded lexical C/C++ include evidence, without running a preprocessor."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass
import re

from depcheck.ecosystems.static import StaticReadError

_SPLICE = re.compile(r"\\\r?\n")
_UNSUPPORTED_TRANSLATION = re.compile(r"\?\?[=/'()!<>-]|\\[ \t]+\r?\n|\r(?!\n)")
_TOKEN = re.compile(
    r'(?<!\w)(?:u8|u|U|L)?R"|//|/\*|["\']|\n|%:|#|[A-Za-z_]\w*|(?:\d|\.\d)[\w.\']*'
)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_MAX_TOKENS = 100_000


@dataclass(frozen=True)
class CppInclude:
    reference: str
    delimiter: str
    offset: int
    conditional: bool


@dataclass(frozen=True)
class CppSourceGap:
    offset: int
    reason: str


def _skip_comments(text: str, offset: int) -> int:
    """Skip directive whitespace/comments; block-comment newlines stay inside it."""
    while offset < len(text):
        if text[offset] in " \t\v\f\r":
            offset += 1
        elif text.startswith("/*", offset):
            end = text.find("*/", offset + 2)
            if end < 0:
                raise StaticReadError("Unclosed C/C++ block comment")
            offset = end + 2
        elif text.startswith("//", offset):
            end = text.find("\n", offset + 2)
            return len(text) if end < 0 else end
        else:
            break
    return offset


def cpp_includes(original: str) -> Iterator[CppInclude | CppSourceGap]:
    # Compiler-dependent translation could change comment/directive boundaries.
    # Keep only its preceding evidence rather than choosing a compiler mode.
    if translation := _UNSUPPORTED_TRANSLATION.search(original):
        yield CppSourceGap(
            translation.start(), "Compiler-dependent C/C++ translation is uncollected"
        )
        original = original[: translation.start()]
    # Store one offset segment per splice, rather than one Python integer per
    # source character. Raw strings use the original body, where splicing is undone.
    pieces: list[str] = []
    starts, original_starts = [0], [0]
    last = length = 0
    for splice in _SPLICE.finditer(original):
        if len(starts) >= _MAX_TOKENS:
            raise StaticReadError("C/C++ line-splice budget exceeded")
        pieces.append(original[last : splice.start()])
        length += splice.start() - last
        starts.append(length)
        original_starts.append(splice.end())
        last = splice.end()
    pieces.append(original[last:])
    text = "".join(pieces)

    def physical(offset: int) -> int:
        segment = bisect_right(starts, offset) - 1
        return original_starts[segment] + offset - starts[segment]

    offset = depth = count = 0
    prefix = True
    ambiguous = False
    reported: set[str] = set()

    def gap(start: int, reason: str) -> Iterator[CppSourceGap]:
        if reason not in reported:
            reported.add(reason)
            yield CppSourceGap(physical(start), reason)

    while match := _TOKEN.search(text, offset):
        prefix &= not text[offset : match.start()].strip(" \t\v\f\r")
        offset = match.end()
        token = match.group()
        count += 1
        if count > _MAX_TOKENS:
            raise StaticReadError("C/C++ lexical token budget exceeded")
        if token == "\n":
            prefix = True
        elif token == "//":
            end = text.find("\n", offset)
            offset = len(text) if end < 0 else end
        elif token == "/*":
            end = text.find("*/", offset)
            if end < 0:
                raise StaticReadError("Unclosed C/C++ block comment")
            offset = end + 2
        elif token.endswith('R"'):
            opening = text.find("(", offset, offset + 17)
            delimiter = text[offset:opening] if opening >= 0 else ""
            if opening < 0 or any(c.isspace() or c in "\\()" for c in delimiter):
                raise StaticReadError("Unsupported C++ raw-string delimiter")
            original_start = physical(match.start())
            opening_length = opening + 1 - match.start()
            if (
                original[original_start : original_start + opening_length]
                != text[match.start() : opening + 1]
            ):
                raise StaticReadError("Spliced C++ raw-string opening is unsupported")
            closing = ")" + delimiter + '"'
            end = original.find(closing, original_start + opening_length)
            if end < 0:
                raise StaticReadError("Unclosed C++ raw string")
            end += len(closing)
            segment = bisect_right(original_starts, end) - 1
            offset = starts[segment] + end - original_starts[segment]
            prefix = False
        elif token in {'"', "'"}:
            while offset < len(text) and text[offset] != token:
                if text[offset] == "\n":
                    raise StaticReadError("Unclosed C/C++ quoted literal")
                offset += 2 if text[offset] == "\\" else 1
            if offset >= len(text):
                raise StaticReadError("Unclosed C/C++ quoted literal")
            offset += 1
            prefix = False
        elif token in {"#", "%:"} and prefix:
            prefix = False
            start = match.start()
            offset = _skip_comments(text, offset)
            name = _IDENTIFIER.match(text, offset)
            if name is None:
                continue
            offset = name.end()
            directive = name.group()
            if directive in {"if", "ifdef", "ifndef"}:
                depth += 1
                if depth > 64:
                    raise StaticReadError("C/C++ conditional depth budget exceeded")
            elif directive == "endif":
                if depth:
                    depth -= 1
                else:
                    ambiguous = True
                    yield from gap(start, "Unmatched C/C++ conditional directive")
            elif directive in {"else", "elif", "elifdef", "elifndef"} and not depth:
                ambiguous = True
                yield from gap(start, "Unmatched C/C++ conditional directive")
            elif directive in {"include_next", "import", "embed"}:
                yield from gap(start, "Unsupported C/C++ inclusion directive")
            elif directive == "include":
                offset = _skip_comments(text, offset)
                delimiter = text[offset : offset + 1]
                closing = ">" if delimiter == "<" else '"'
                line_end = text.find("\n", offset)
                line_end = len(text) if line_end < 0 else line_end
                end = (
                    text.find(closing, offset + 1, line_end)
                    if delimiter in {"<", '"'}
                    else -1
                )
                reference = text[offset + 1 : end] if end >= 0 else ""
                if (
                    not reference
                    or len(reference) > 65_536
                    or any(
                        c in reference for c in ("\n", "\r", "\\", '"', "'", "/*", "//")
                    )
                ):
                    yield from gap(
                        start,
                        "C/C++ macro or unsupported include operand is uncollected",
                    )
                    continue
                tail = _skip_comments(text, end + 1)
                offset = tail
                if tail < len(text) and text[tail] != "\n":
                    yield from gap(
                        start, "C/C++ include with trailing tokens is uncollected"
                    )
                    continue
                conditional = bool(depth or ambiguous)
                if conditional:
                    yield from gap(
                        start, "C/C++ preprocessor condition activation is unknown"
                    )
                yield CppInclude(reference, delimiter, physical(start), conditional)
        else:
            prefix = False
    if depth:
        yield from gap(max(0, len(text) - 1), "Unclosed C/C++ conditional directive")
