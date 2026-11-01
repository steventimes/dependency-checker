# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements. See NOTICE for copyright ownership.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Bounded ASCII adaptation of Apache Maven's ComparableVersion 3.10.0.

Source: apache/maven c43a36b8d67be7e0805a411bc0898af1a51f5472,
maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java.
Python integers replace the source's three numeric storage classes. Parsed
lists are frozen for hashing; no target code or Java process is executed.
"""

from __future__ import annotations

import re
from functools import total_ordering
from itertools import zip_longest
from typing import TypeAlias

_Part: TypeAlias = int | str | list["_Part"]
_Item: TypeAlias = int | str | tuple["_Item", ...]
_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


def _qualifier(value: str) -> tuple[int, str]:
    return (
        (_QUALIFIERS.index(value), "")
        if value in _QUALIFIERS
        else (len(_QUALIFIERS), value)
    )


def _string(value: str, followed_by_digit: bool = False) -> str:
    if followed_by_digit:
        value = {"a": "alpha", "b": "beta", "m": "milestone"}.get(value, value)
    return _ALIASES.get(value, value)


def _null(value: _Part) -> bool:
    return value in (0, "") if not isinstance(value, list) else not value


def _freeze(values: list[_Part]) -> tuple[_Item, ...]:
    return tuple(
        _freeze(value) if isinstance(value, list) else value for value in values
    )


def _parse(raw: str) -> tuple[_Item, ...]:
    if (
        not isinstance(raw, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,255}", raw) is None
    ):
        raise ValueError(
            "Maven ordering requires a bounded ASCII version, not a selector"
        )
    version = raw.lower()
    values: list[_Part] = []
    stack = [values]
    digits = False
    start = 0

    def descend() -> None:
        nonlocal values
        nested: list[_Part] = []
        values.append(nested)
        values = nested
        stack.append(values)

    def item(text: str) -> int | str:
        return int(text) if digits else _string(text)

    for index, character in enumerate(version):
        if character in ".-":
            values.append(0 if index == start else item(version[start:index]))
            start = index + 1
            if character == "-":
                descend()
        elif character.isdigit():
            if not digits and index > start:
                if values:
                    descend()
                values.append(_string(version[start:index], followed_by_digit=True))
                start = index
                descend()
            digits = True
        else:
            if digits and index > start:
                values.append(int(version[start:index]))
                start = index
                descend()
            digits = False
    if len(version) > start:
        if not digits and values:
            descend()
        values.append(item(version[start:]))
    for values in reversed(stack):
        for index in range(len(values) - 1, -1, -1):
            value = values[index]
            if _null(value):
                del values[index]
            elif not isinstance(value, list):
                break
    return _freeze(stack[0])


def _compare(left: _Item | None, right: _Item | None) -> int:
    if left is None:
        return 0 if right is None else -_compare(right, None)
    if right is None:
        if isinstance(left, int):
            return (left > 0) - (left < 0)
        if isinstance(left, str):
            return (_qualifier(left) > _qualifier("")) - (
                _qualifier(left) < _qualifier("")
            )
        for value in left:
            result = _compare(value, None)
            if result:
                return result
        return 0
    if isinstance(left, int):
        return (left > right) - (left < right) if isinstance(right, int) else 1
    if isinstance(left, str):
        if not isinstance(right, str):
            return -1
        return (_qualifier(left) > _qualifier(right)) - (
            _qualifier(left) < _qualifier(right)
        )
    if not isinstance(right, tuple):
        return -1 if isinstance(right, int) else 1
    for first, second in zip_longest(left, right):
        result = _compare(first, second)
        if result:
            return result
    return 0


@total_ordering
class MavenVersion:
    """ComparableVersion ordering and normalized equality within the input bound."""

    __slots__ = ("_items",)

    def __init__(self, raw: str):
        self._items = _parse(raw)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MavenVersion):
            return NotImplemented
        return self._items == other._items

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, MavenVersion):
            return NotImplemented
        return _compare(self._items, other._items) < 0

    def __hash__(self) -> int:
        return hash(self._items)
