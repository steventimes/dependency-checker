"""Strict evidence input shared by format-specific readers.

File reads retain the repository boundary and bounded-I/O policy. Callers that
decode supplied bytes or streams retain their own format-specific size budgets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from depcheck.bounded_io import read_bytes
from depcheck.path_policy import require_within_project


def read_evidence_json(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = Path(relative)
    if path.is_absolute():
        raise ValueError("Evidence path must be relative to the repository")
    candidate = root / path
    require_within_project(root, candidate, operation="read evidence JSON")
    raw = read_bytes(candidate)
    return parse_evidence_json(raw), hashlib.sha256(raw).hexdigest()


def parse_evidence_json(raw: bytes) -> dict[str, Any]:
    """Decode bounded evidence bytes with unique keys and finite JSON values."""
    try:
        value = json.loads(
            raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant
        )
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


def evidence_json_decoder() -> json.JSONDecoder:
    """Return the strict decoder for formats carrying successive JSON objects."""
    return json.JSONDecoder(
        object_pairs_hook=_unique_object, parse_constant=_invalid_constant
    )


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
