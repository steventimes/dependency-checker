"""Strict evidence input shared by format-specific readers.

File reads retain the repository boundary and bounded-I/O policy. Callers that
decode supplied bytes or streams retain their own format-specific size budgets.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from depcheck.filesystem import DEFAULT_MAX_BYTES, read_bytes, require_within_project


def read_evidence_json(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    raw, digest = read_evidence_bytes(root, relative)
    return parse_evidence_json(raw), digest


def read_evidence_bytes(
    root: Path, relative: str, *, max_bytes: int = DEFAULT_MAX_BYTES
) -> tuple[bytes, str]:
    """Capture bounded input under the explicit repository root before decoding."""
    path = Path(relative)
    if path.is_absolute():
        raise ValueError("Evidence path must be relative to the repository")
    candidate = root / path
    require_within_project(root, candidate, operation="read evidence input")
    raw = read_bytes(candidate, project_root=root, max_bytes=max_bytes)
    return raw, hashlib.sha256(raw).hexdigest()


def parse_evidence_json(raw: bytes) -> dict[str, Any]:
    """Decode bounded evidence bytes with unique keys and finite JSON values."""
    try:
        value = json.loads(raw, cls=_EvidenceJSONDecoder)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f"Invalid evidence JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Evidence JSON must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Evidence JSON keys must be unique")
        result[key] = value
    return result


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"Unsupported JSON constant {value}")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite")
    return number


class _EvidenceJSONDecoder(json.JSONDecoder):
    def __init__(self, *, unique_keys: bool = True) -> None:
        super().__init__(
            object_pairs_hook=_unique_object if unique_keys else None,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )

    def raw_decode(self, s: str, idx: int = 0) -> tuple[Any, int]:
        value, end = super().raw_decode(s, idx)
        pending = [value]
        while pending:
            item = pending.pop()
            if isinstance(item, str):
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ValueError(
                        "JSON strings and object keys must contain valid Unicode scalar values"
                    ) from exc
            elif isinstance(item, dict):
                pending.extend(item)
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        return value, end


def evidence_json_decoder(*, unique_keys: bool = True) -> json.JSONDecoder:
    """Decode successive JSON values; manifests may retain last-key-wins semantics."""
    return _EvidenceJSONDecoder(unique_keys=unique_keys)


def objects(value: Any, label: str, *, maximum: int = 20000) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or not all(isinstance(item, dict) for item in value)
    ):
        raise ValueError(f"{label} must be a bounded array of objects")
    return value


def text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 16384:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value
