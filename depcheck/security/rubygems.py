"""Bounded ASCII adaptation of RubyGems 3.6.9 Gem::Version ordering.

Source: ruby/rubygems 8a2a14d63da701e980f856d8772d273fd448b8a1,
lib/rubygems/version.rb. Copyright Chad Fowler, Rich Kilmer, Jim Weirich
and others; portions copyright Engine Yard and Andre Arko. MIT license,
reproduced in NOTICE. No Ruby runtime or target code is executed.

Only nonempty, unpadded strings of at most 256 characters are supported.
Version requirements and artifact platform suffixes are not interpreted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from itertools import zip_longest


@total_ordering
@dataclass(frozen=True, init=False)
class RubyGemsVersion:
    _segments: tuple[int | str, ...]

    def __init__(self, raw: str) -> None:
        if (
            not isinstance(raw, str)
            or len(raw) > 256
            or re.fullmatch(
                r"[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
                raw,
            )
            is None
        ):
            raise ValueError("RubyGems ordering requires a bounded ASCII version")
        version = raw.replace("-", ".pre.")
        # Match Gem::Version.canonical_segments, including zero numeric parts
        # before the first letter and after the last letter/dot anchor.
        version = re.sub(r"(?<=[A-Za-z.])[.0]+$", "", version)
        version = re.sub(r"(^|\.)[0.]+(?=[A-Za-z])", r"\1", version, count=1)
        segments = tuple(
            int(part) if part[0].isdigit() else part
            for part in re.findall(r"[0-9]+|[A-Za-z]+", version)
        )
        object.__setattr__(self, "_segments", segments)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RubyGemsVersion):
            return NotImplemented
        for left, right in zip_longest(self._segments, other._segments, fillvalue=0):
            if left == right:
                continue
            if isinstance(left, str):
                return left < right if isinstance(right, str) else True
            return left < right if isinstance(right, int) else False
        return False
