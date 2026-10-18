"""Shared static Java coordinate and diagnostic helpers."""

from __future__ import annotations

import re
from pathlib import Path

from depcheck.model import Diagnostic, SourceLocation

_PROPERTY = re.compile(r"\$\{([^}]+)\}")


def _valid_maven_coordinate(group: str, artifact: str) -> bool:
    return bool(group and artifact) and not (
        _PROPERTY.search(group) or _PROPERTY.search(artifact)
    )


def _is_exact_version(version: str) -> bool:
    dynamic_tokens = ("${", "+", "[", "]", "(", ")", ",")
    lowered = version.lower()
    return bool(version) and not (
        lowered in {"latest", "release"}
        or lowered.startswith("latest.")
        or lowered.endswith("-snapshot")
        or any(token in version for token in dynamic_tokens)
        or any(character.isspace() for character in version)
    )


def _diagnostic(
    code: str,
    message: str,
    path: Path | SourceLocation,
    *,
    severity: str = "error",
) -> Diagnostic:
    source = path if isinstance(path, SourceLocation) else SourceLocation(path)
    return Diagnostic(code, severity, message, source)
