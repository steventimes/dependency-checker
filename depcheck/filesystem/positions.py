"""Structural source positions alongside authoritative manifest parsing."""

from __future__ import annotations

import ast
import configparser
import json
import re
from bisect import bisect_right
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from tomlkit.container import Container
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import Array, InlineTable, Table
from tomlkit.parser import Parser

from depcheck.model import SourceLocation
from depcheck.profiling import count_work, measured

SourceKey = tuple[str | int, ...]
_TOML_CACHE_MAX_CHARACTERS = 256 * 1024
_TOML_READER: ContextVar[
    Callable[[type[SourcePositions], str, str], SourcePositions] | None
] = ContextVar("depcheck_toml_positions", default=None)


@contextmanager
def toml_position_scope() -> Iterator[None]:
    """Reuse bounded captured syntax only within one scan, never skip file I/O."""
    if _TOML_READER.get() is not None:
        yield
        return

    @lru_cache(maxsize=4)
    def parse(cls: type[SourcePositions], path: str, text: str) -> SourcePositions:
        count_work("parsing.toml-position-cache", misses=1)
        return cls._parse_toml(Path(path), text)

    reader = cast(Callable[[type[SourcePositions], str, str], SourcePositions], parse)
    token = _TOML_READER.set(reader)
    try:
        yield
    finally:
        _TOML_READER.reset(token)
        parse.cache_clear()


@measured("parsing.python-ast")
def parse_python_ast(text: str) -> ast.Module:
    """Parse captured text without CPython reopening a filename for errors."""
    return ast.parse(text, filename="")


class SourcePositions:
    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.text = text
        self.line_starts = [0, *(i + 1 for i, char in enumerate(text) if char == "\n")]
        self.keys: dict[SourceKey, int] = {}
        self.values: dict[SourceKey, int] = {}
        self._ast_columns: dict[int, tuple[list[int], list[int]]] = {}
        self._ast_line_starts: list[int] | None = None

    def at(self, offset: int | None) -> SourceLocation:
        if offset is None:
            return SourceLocation(self.path)
        line = bisect_right(self.line_starts, offset)
        return SourceLocation(self.path, line, offset - self.line_starts[line - 1] + 1)

    def key(self, *path: str | int) -> SourceLocation:
        return self.at(self.keys.get(path, self.values.get(path)))

    def value(self, *path: str | int) -> SourceLocation:
        return self.at(self.values.get(path, self.keys.get(path)))

    def ast_node(self, node: ast.AST | None) -> SourceLocation:
        """Convert UTF-8 byte columns, caching each source line's offsets."""
        line = getattr(node, "lineno", None)
        byte_column = getattr(node, "col_offset", None)
        if line is None or byte_column is None:
            return self.at(None)
        if self._ast_line_starts is None:
            self._ast_line_starts = (
                [0, *(match.end() for match in re.finditer(r"\r\n?|\n", self.text))]
                if "\r" in self.text
                else self.line_starts
            )
        if not 1 <= line <= len(self._ast_line_starts):
            return self.at(None)
        if line not in self._ast_columns:
            start = self._ast_line_starts[line - 1]
            end = (
                self._ast_line_starts[line]
                if line < len(self._ast_line_starts)
                else len(self.text)
            )
            text = self.text[start:end]
            ends: list[int] = []
            extras: list[int] = []
            if not text.isascii():
                byte = 0
                for index, char in enumerate(text):
                    size = len(char.encode("utf-8"))
                    byte += size
                    if size > 1:
                        ends.append(byte)
                        extras.append(byte - index - 1)
            self._ast_columns[line] = ends, extras
        ends, extras = self._ast_columns[line]
        index = bisect_right(ends, byte_column)
        column = byte_column - (extras[index - 1] if index else 0)
        return SourceLocation(self.path, line, column + 1)

    @classmethod
    def ini(
        cls,
        path: Path,
        text: str,
        config: configparser.ConfigParser,
        resolved_values: Mapping[tuple[str, str], str],
    ) -> SourcePositions:
        """Locate literal option lines only when ConfigParser confirms the value."""
        positions = cls(path, text)
        entries: dict[tuple[str, str], list[tuple[str, int]]] = {}
        section: str | None = None
        active: tuple[str, str] | None = None
        indent = 0
        offset = 0
        for raw in text.splitlines(keepends=True):
            value = raw.strip()
            leading = len(raw) - len(raw.lstrip())
            if value.startswith(("#", ";")):
                offset += len(raw)
                continue
            if not value:
                if active is not None:
                    entries[active].append(("", offset))
            elif active is not None and leading > indent:
                entries[active].append((value, offset + leading))
            elif match := config.SECTCRE.match(value):
                section = match["header"]
                active = None
            elif section is not None and (match := config.OPTCRE.match(value)):
                option = config.optionxform(match["option"].rstrip())
                active = section, option
                indent = leading
                raw_value = match["value"]
                start = (
                    offset
                    + leading
                    + match.start("value")
                    + len(raw_value)
                    - len(raw_value.lstrip())
                )
                entries[active] = [(raw_value.strip(), start)]
            else:
                active = None
            offset += len(raw)
        for key, lines in entries.items():
            if key not in resolved_values:
                continue
            rendered = "\n".join(value for value, _ in lines).rstrip()
            try:
                if (
                    config.get(*key, raw=True) != rendered
                    or resolved_values[key] != rendered
                ):
                    continue
            except configparser.Error:
                continue
            for index, (value, start) in enumerate(lines):
                if value:
                    positions.values[(*key, index)] = start
        return positions

    @classmethod
    def toml(cls, path: Path, text: str) -> SourcePositions:
        count_work("parsing.toml-position-cache", requests=1)
        reader = _TOML_READER.get()
        if reader is not None and len(text) <= _TOML_CACHE_MAX_CHARACTERS:
            # Windows Path equality folds case; locations retain lexical spelling.
            return reader(cls, str(path), text)
        count_work("parsing.toml-position-cache", uncached=1)
        return cls._parse_toml(path, text)

    @classmethod
    @measured("parsing.toml-positions")
    def _parse_toml(cls, path: Path, text: str) -> SourcePositions:
        positions = cls(path, text)
        parser = _PositionedTomlParser(text)
        try:
            document = parser.parse()
        except (TOMLKitError, RecursionError):
            # tomllib remains authoritative if a supported TOML form lacks spans.
            return positions

        pending: list[tuple[Any, SourceKey]] = [(document, ())]
        while pending:
            item, key = pending.pop()
            if id(item) in parser.value_offsets:
                positions.values[key] = parser.value_offsets[id(item)]
            if id(item) in parser.key_offsets:
                offset = parser.key_offsets[id(item)]
                positions.keys[key] = offset
                # Dotted keys explicitly spell these parent prefixes. Use
                # their first defining key, rather than guessing a table span.
                for depth in range(1, parser.dotted_depths.get(id(item), 0) + 1):
                    prefix = key[:-depth]
                    positions.keys.setdefault(prefix, offset)
            if isinstance(item, (Table, InlineTable)):
                pending.append((item.value, key))
            elif isinstance(item, Container):
                pending.extend(
                    (value, (*key, *(part.key for part in name)))
                    for name, value in reversed(item.body)
                    if name is not None
                )
            elif isinstance(item, Array):
                # Mapping/list access unwraps booleans; retain syntax Items
                # so repeated true/false literals keep distinct offsets.
                pending.extend(
                    (list.__getitem__(item, index), (*key, index))
                    for index in reversed(range(len(item)))
                )
            elif isinstance(item, list):
                pending.extend(
                    (value, (*key, index))
                    for index, value in reversed(list(enumerate(item)))
                )

        positions.keys.update(parser.table_offsets)
        return positions

    @classmethod
    def json_keys(
        cls,
        path: Path,
        text: str,
        sections: frozenset[str],
        *,
        max_depth: int = 1,
    ) -> SourcePositions:
        positions = cls(path, text)
        decoder = json.JSONDecoder()
        remaining = 100_000

        def skip_space(offset: int) -> int:
            while offset < len(text) and text[offset].isspace():
                offset += 1
            return offset

        def children(value: Any, offset: int, key: SourceKey, depth: int) -> None:
            if depth > min(max_depth, 16):
                return
            if isinstance(value, dict):
                object_keys(offset, key, depth)
            elif isinstance(value, list):
                array_values(offset, key, depth)

        def object_keys(offset: int, parent: SourceKey, depth: int) -> None:
            nonlocal remaining
            offset = skip_space(offset + 1)
            while offset < len(text) and text[offset] != "}":
                if remaining == 0:
                    return
                remaining -= 1
                key_offset = offset
                name, offset = decoder.raw_decode(text, offset)
                offset = skip_space(offset)
                value_offset = skip_space(offset + 1)
                value, offset = decoder.raw_decode(text, value_offset)
                key = (*parent, name)
                positions.keys[key] = key_offset
                positions.values[key] = value_offset
                if parent or name in sections:
                    children(value, value_offset, key, depth + 1)
                offset = skip_space(offset)
                if text[offset] == ",":
                    offset = skip_space(offset + 1)

        def array_values(offset: int, parent: SourceKey, depth: int) -> None:
            nonlocal remaining
            offset = skip_space(offset + 1)
            index = 0
            while offset < len(text) and text[offset] != "]":
                if remaining == 0:
                    return
                remaining -= 1
                value_offset = offset
                value, offset = decoder.raw_decode(text, offset)
                key = (*parent, index)
                positions.values[key] = value_offset
                children(value, value_offset, key, depth + 1)
                index += 1
                offset = skip_space(offset)
                if text[offset] == ",":
                    offset = skip_space(offset + 1)

        object_keys(skip_space(0), (), 0)
        if remaining == 0:
            # Unvisited keys may override prior spans under last-value semantics.
            positions.keys.clear()
            positions.values.clear()
        else:

            def retained(key: SourceKey, offset: int) -> bool:
                # A later repeated parent replaces its entire earlier subtree.
                return all(
                    offset >= positions.values[key[:depth]]
                    for depth in range(1, len(key))
                )

            positions.keys = {
                key: offset
                for key, offset in positions.keys.items()
                if retained(key, offset)
            }
            positions.values = {
                key: offset
                for key, offset in positions.values.items()
                if retained(key, offset)
            }
        return positions


class _PositionedTomlParser(Parser):
    """Keep offsets on parsed items, including dotted keys and array elements."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.value_offsets: dict[int, int] = {}
        self.key_offsets: dict[int, int] = {}
        self.dotted_depths: dict[int, int] = {}
        self.table_offsets: dict[SourceKey, int] = {}
        self.table_counts: dict[SourceKey, int] = {}
        self.text = text

    def _parse_value(self) -> Any:
        start = self._idx
        item = super()._parse_value()
        self.value_offsets[id(item)] = start
        return item

    def _parse_key_value(self, parse_comment: bool = False) -> Any:
        start = self._idx
        while start < len(self.text) and self.text[start] in " \t":
            start += 1
        key, item = super()._parse_key_value(parse_comment)
        self.key_offsets[id(item)] = start
        self.dotted_depths[id(item)] = sum(1 for _ in key) - 1
        return key, item

    def _parse_table(self, parent_name: Any = None, parent: Any = None) -> Any:
        start = self._idx
        is_array, name = self._peek_table()
        key: SourceKey = tuple(part.key for part in name)
        if is_array:
            index = self.table_counts.get(key, 0)
            self.table_counts[key] = index + 1
            key = (*key, index)
        self.table_offsets[key] = start
        return super()._parse_table(parent_name, parent)
