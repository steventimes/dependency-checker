"""Literal Astro regions and CSS imports; unsupported syntax remains explicit."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re

from depcheck.model import SourceLocation
from depcheck.source_locations import SourcePositions


@dataclass(frozen=True, slots=True)
class ModuleLoad:
    reference: str
    line: int
    column: int
    kind: str
    context: str = "module"


@dataclass(frozen=True, slots=True)
class SourceFragment:
    text: str
    offset: int
    context: str


@dataclass(frozen=True, slots=True)
class SourceIssue:
    code: str
    reason: str
    source: SourceLocation


def css_imports(
    text: str, positions: SourcePositions, offset: int = 0
) -> tuple[list[ModuleLoad], list[SourceIssue]]:
    loads: list[ModuleLoad] = []
    issues: list[SourceIssue] = []
    cursor = 0
    depth = 0

    def issue(start: int, reason: str) -> None:
        if len(issues) < 5:
            issues.append(
                SourceIssue(
                    "usage.unsupported-css-syntax", reason, positions.at(offset + start)
                )
            )

    def spaces() -> None:
        nonlocal cursor
        while cursor < len(text):
            if text[cursor].isspace():
                cursor += 1
            elif text.startswith("/*", cursor):
                end = text.find("*/", cursor + 2)
                if end < 0:
                    issue(cursor, "unterminated CSS comment")
                    cursor = len(text)
                else:
                    cursor = end + 2
            else:
                break

    def string(*, importing: bool = True) -> str | None:
        nonlocal cursor
        start = cursor
        quote = text[cursor]
        cursor += 1
        value: list[str] = []
        safe = True
        while cursor < len(text):
            char = text[cursor]
            cursor += 1
            if char == quote:
                if not safe and importing:
                    issue(start, "CSS string escapes are not resolved")
                return "".join(value) if safe else None
            if char in "\r\n":
                break
            if char == "\\":
                safe = False
                cursor += cursor < len(text)
            else:
                value.append(char)
        issue(start, "unterminated CSS string")
        return None

    while cursor < len(text):
        spaces()
        if cursor >= len(text):
            break
        char = text[cursor]
        if char in "\"'":
            string(importing=False)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                issue(cursor, "unbalanced CSS block")
                depth = 0
        if char != "@":
            cursor += 1
            continue
        start = cursor
        cursor += 1
        name_start = cursor
        while cursor < len(text) and (text[cursor].isalnum() or text[cursor] in "-_\\"):
            cursor += 1
        name = text[name_start:cursor].lower()
        if (
            name in {"use", "forward", "plugin", "config", "reference", "source"}
            or "\\" in name
        ):
            issue(start, f"CSS @{name} dependency semantics are not supported")
        if name != "import":
            continue
        if depth:
            issue(start, "nested CSS imports are not resolved")
            continue
        spaces()
        is_url = text[cursor : cursor + 4].lower() == "url("
        if is_url:
            cursor += 4
            spaces()
        reference_start = cursor
        value = None
        if cursor < len(text) and text[cursor] in "\"'":
            value = string()
        elif is_url:
            end = cursor
            while end < len(text) and not text[end].isspace() and text[end] != ")":
                end += 1
            value = text[cursor:end]
            cursor = end
            if not value or any(char in value for char in "\\\"'("):
                value = None
                issue(reference_start, "unsupported CSS URL syntax")
        else:
            issue(start, "CSS import is not a literal string or URL")
        spaces()
        if is_url:
            if cursor >= len(text) or text[cursor] != ")":
                issue(start, "unterminated CSS import URL")
                value = None
            else:
                cursor += 1
        if value is not None:
            source = positions.at(offset + reference_start)
            assert source.line is not None and source.column is not None
            loads.append(
                ModuleLoad(value, source.line, source.column, "regular", "css")
            )
    if depth:
        issue(len(text), "unclosed CSS block")
    return loads, issues


def astro_regions(
    text: str, positions: SourcePositions
) -> tuple[list[SourceFragment], list[ModuleLoad], list[SourceIssue]]:
    fragments: list[SourceFragment] = []
    issues: list[SourceIssue] = []
    start = 0
    opening = re.match(r"\A\ufeff?---[ \t]*\n", text)
    if opening:
        closing = re.search(r"^---[ \t]*(?:\n|$)", text[opening.end() :], re.MULTILINE)
        if closing is None:
            return (
                [],
                [],
                [
                    SourceIssue(
                        "usage.unsupported-astro-syntax",
                        "unclosed Astro frontmatter",
                        positions.at(0),
                    )
                ],
            )
        end = opening.end() + closing.start()
        fragments.append(
            SourceFragment(text[opening.end() : end], opening.end(), "module")
        )
        start = opening.end() + closing.end()
    parser = _AstroRegions(text[start:], positions, start, fragments, issues)
    parser.feed(text[start:])
    parser.close()
    if parser.block is not None:
        issues.append(
            SourceIssue(
                "usage.unsupported-astro-syntax",
                "unclosed Astro script/style block",
                positions.at(parser.block[0]),
            )
        )
    return fragments, parser.loads, issues


def component_regions(
    text: str, positions: SourcePositions
) -> tuple[list[SourceFragment], list[ModuleLoad], list[SourceIssue]]:
    fragments: list[SourceFragment] = []
    issues = [
        SourceIssue(
            "usage.unsupported-component-template",
            "Vue/Svelte template expressions, implicit framework imports and compilation are not collected; only bounded literal script/style regions are inspected",
            positions.at(0),
        )
    ]
    parser = _ComponentRegions(text, positions, 0, fragments, issues)
    parser.feed(text)
    parser.close()
    if parser.block is not None:
        parser.uncertain(parser.block[0], "unclosed component script/style block")
    return fragments, parser.loads, issues


class _AstroRegions(HTMLParser):
    def __init__(
        self,
        text: str,
        positions: SourcePositions,
        offset: int,
        fragments: list[SourceFragment],
        issues: list[SourceIssue],
    ) -> None:
        super().__init__(convert_charrefs=False)
        self.text = text
        self.positions = positions
        self.base_offset = offset
        self.line_starts = [0, *(i + 1 for i, char in enumerate(text) if char == "\n")]
        self.fragments = fragments
        self.issues = issues
        self.loads: list[ModuleLoad] = []
        self.block: tuple[int, str, str] | None = None
        self.stopped = False
        self.opaque: str | None = None

    def location(self) -> int:
        line, column = self.getpos()
        return self.base_offset + self.line_starts[line - 1] + column

    def uncertain(self, offset: int, reason: str) -> None:
        if len(self.issues) < 5:
            self.issues.append(
                SourceIssue(
                    "usage.unsupported-astro-syntax", reason, self.positions.at(offset)
                )
            )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.stopped or self.opaque is not None:
            return
        raw = self.get_starttag_text() or ""
        offset = self.location()
        if "{" in raw:
            self.uncertain(
                offset + raw.index("{"),
                "Astro template expressions and subsequent template regions are not parsed",
            )
            self.stopped = True
            return
        attributes = dict(attrs)
        if tag in {"textarea", "title"}:
            self.opaque = tag
            return
        if tag not in {"script", "style"}:
            return
        if not raw.startswith("<" + tag):
            self.uncertain(offset, "Astro Script/Style component bodies are not parsed")
            context = "skip"
        elif tag == "style" and (
            attributes.get("lang", "css") != "css" or "is:inline" in attributes
        ):
            self.uncertain(offset, "Astro style preprocessors are not parsed")
            context = "skip"
        elif tag == "script" and attributes.get("type", "module") not in {
            "module",
            "text/javascript",
            "application/javascript",
        }:
            context = "skip"
        elif (
            "is:inline" in attributes
            or tag == "script"
            and any(name != "src" for name in attributes)
        ):
            context = "browser"
        else:
            context = "css" if tag == "style" else "module"
        source = attributes.get("src")
        if source is not None and context != "skip":
            position = self.positions.at(offset)
            assert position.line is not None and position.column is not None
            self.loads.append(
                ModuleLoad(
                    source,
                    position.line,
                    position.column,
                    "regular",
                    "browser" if context == "browser" else "src",
                )
            )
        self.block = (offset + len(raw), tag, context)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.opaque is not None:
            if tag == self.opaque:
                self.opaque = None
            return
        if self.block is not None and tag == self.block[1]:
            offset, _, context = self.block
            if context != "skip":
                self.fragments.append(
                    SourceFragment(
                        self.positions.text[offset : self.location()], offset, context
                    )
                )
            self.block = None

    def handle_data(self, data: str) -> None:
        if not self.stopped and self.block is None and "{" in data:
            self.uncertain(
                self.location() + data.index("{"),
                "Astro template expressions and subsequent template regions are not parsed",
            )
            self.stopped = True


class _ComponentRegions(_AstroRegions):
    """Read top-level SFC blocks; stop after template expressions can hide markup."""

    depth = 0
    _VOID = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
    )

    def uncertain(self, offset: int, reason: str) -> None:
        if len(self.issues) < 5:
            self.issues.append(
                SourceIssue(
                    "usage.unsupported-component-syntax",
                    reason,
                    self.positions.at(offset),
                )
            )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.stopped:
            return
        if self.depth or tag not in {"script", "style"}:
            if tag not in self._VOID:
                self.depth += 1
            return
        attributes = dict(attrs)
        language = attributes.get("lang", "css" if tag == "style" else "js")
        allowed = (
            {"css"} if tag == "style" else {"js", "ts", "javascript", "typescript"}
        )
        unknown = set(attributes) - {
            "src",
            "lang",
            "setup",
            "context",
            "module",
            "scoped",
            "type",
        }
        if language not in allowed or unknown:
            self.uncertain(
                self.location(),
                "component preprocessor or custom block attributes are not parsed",
            )
            self.block = (
                self.location() + len(self.get_starttag_text() or ""),
                tag,
                "skip",
            )
            return
        super().handle_starttag(tag, [(k, v) for k, v in attrs if k in {"src", "type"}])
        if tag == "style" and attributes.get("src") is not None and self.loads:
            load = self.loads[-1]
            self.loads[-1] = ModuleLoad(
                load.reference, load.line, load.column, load.kind, "css"
            )

    def handle_endtag(self, tag: str) -> None:
        if self.block is not None:
            super().handle_endtag(tag)
        elif tag not in self._VOID:
            self.depth = max(0, self.depth - 1)
