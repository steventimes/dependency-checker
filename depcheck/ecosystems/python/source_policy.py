"""Bounded uv source assertions, independent of transport or installation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.evidence.origins import python_origin, redact_source

_UV_SOURCE_ENTRIES = 1024
_UV_SOURCE_BYTES = 65_536
_UV_SOURCE_VALUE_BYTES = 8192
_UV_SOURCE_ALTERNATIVES = 128
_SOURCE_STRINGS = frozenset(
    {
        "git",
        "url",
        "path",
        "index",
        "registry",
        "rev",
        "branch",
        "tag",
        "subdirectory",
        "marker",
        "extra",
        "group",
    }
)
_SOURCE_BOOLEANS = frozenset({"editable", "package", "lfs"})
_SOURCE_KINDS = frozenset({"git", "url", "path", "index", "workspace", "registry"})


def source_assertion_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
    ).hexdigest()


def bounded_uv_sources(value: object) -> dict[str, tuple[str, object]] | None:
    """Keep canonical key collisions and invalid/bounded tables unresolved."""
    if not isinstance(value, dict) or len(value) > _UV_SOURCE_ENTRIES:
        return None
    try:
        if (
            len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode())
            > _UV_SOURCE_BYTES
        ):
            return None
        table = {}
        for name, source in value.items():
            normalized = str(canonicalize_name(name, validate=True))
            if normalized in table:
                return None
            table[normalized] = (name, source)
        return table
    except (TypeError, ValueError, RecursionError):
        return None


def uv_source_origin(value: object) -> dict[str, Any]:
    """Retain known literal fields; omit opaque data without choosing an alternative."""
    try:
        encoded = json.dumps(
            value, sort_keys=True, ensure_ascii=False, allow_nan=False
        ).encode()
        digest = hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return {
            "kind": "unknown",
            "public": False,
            "source_validation": "unverified",
            "details_omitted": True,
        }
    if len(encoded) > _UV_SOURCE_VALUE_BYTES:
        return {
            "kind": "unknown",
            "public": False,
            "source_validation": "unverified",
            "details_omitted": True,
            "source_assertion_sha256": digest,
        }
    alternatives = value if isinstance(value, list) else [value]
    omitted = False
    invalid = not alternatives or len(alternatives) > _UV_SOURCE_ALTERNATIVES
    projected: list[dict[str, Any]] = []
    if not invalid:
        for alternative in alternatives:
            fields: dict[str, Any] = {}
            if not isinstance(alternative, dict):
                omitted = invalid = True
                projected.append(fields)
                continue
            for key, item in alternative.items():
                if key in _SOURCE_STRINGS:
                    valid = isinstance(item, str) and bool(item.strip())
                elif key in _SOURCE_BOOLEANS:
                    valid = type(item) is bool
                elif key == "workspace":
                    valid = (isinstance(item, str) and bool(item.strip())) or type(
                        item
                    ) is bool
                else:
                    valid = False
                if valid:
                    fields[key] = item
                else:
                    omitted = True
                    if key in _SOURCE_STRINGS | _SOURCE_BOOLEANS | {"workspace"}:
                        invalid = True
            kinds = _SOURCE_KINDS.intersection(fields)
            if (
                len(kinds) != 1
                or "registry" in kinds
                or fields.get("workspace") is False
            ):
                invalid = True
            projected.append(fields)
    else:
        omitted = True
    assertion: object = (
        projected if isinstance(value, list) else projected[0] if projected else {}
    )
    origin = python_origin(assertion)
    if invalid:
        origin = {
            **origin,
            "kind": "unknown",
            "public": False,
            "source_validation": "unverified",
        }
    if omitted:
        origin["details_omitted"] = True
    if omitted or invalid or redact_source(value) != value:
        origin["source_assertion_sha256"] = digest
    return origin
