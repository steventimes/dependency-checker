"""Shared Cargo input, coordinates and requirement comparisons."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import quote

from packaging.version import Version
from semver import Version as SemVersion

from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.static import StaticReadError, read_text
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import Diagnostic, PackageRef, SourceLocation

_SECTIONS = {
    "dependencies": "runtime",
    "dev-dependencies": "development",
    "build-dependencies": "build",
    "dev_dependencies": "development",
    "build_dependencies": "build",
}

_LEGACY_EDITIONS = frozenset({"2015", "2018", "2021"})

_NAME = re.compile(r"^[A-Za-z0-9_-]+$")

_NUMERIC = r"(?:0|[1-9][0-9]*)"

_REQUIREMENT_TOKEN = re.compile(
    rf"(\^|~|>=|<=|>|<|=)?\s*({_NUMERIC}(?:\.(?:{_NUMERIC}|\*)){{0,2}}|\*)"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)

_CRATES_IO = frozenset(
    {
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
        "registry+https://index.crates.io/",
    }
)


def _exact_version(value: str) -> bool:
    if not value.isascii():
        return False
    try:
        version = SemVersion.parse(value)
    except ValueError:
        return False
    return max(version.major, version.minor, version.patch) <= 2**64 - 1


@dataclass(frozen=True)
class _Document:
    data: dict[str, Any]
    positions: SourcePositions


def _read_document(root: Path, path: Path) -> _Document:
    if not _safe_path(root, path):
        raise StaticReadError(f"refusing outside or symlinked Cargo evidence: {path}")
    text = read_text(path)
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise StaticReadError(f"invalid TOML in {path}: {exc}") from exc
    return _Document(data, SourcePositions.toml(path, text))


def _safe_path(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
        if path.resolve().is_relative_to(root) is False:
            return False
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _local_path(root: Path, base: Path, value: str) -> Path | None:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or Path(value).is_absolute()
        or PureWindowsPath(value).drive
    ):
        return None
    candidate = base / value
    return candidate.resolve() if _safe_path(root, candidate) else None


def _package(name: str, registry: bool) -> PackageRef:
    purl = f"pkg:cargo/{quote(name, safe='')}" if registry else None
    return PackageRef("Cargo", name, name, purl)


def _table(data: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    table: Any = data
    for key in keys:
        table = table.get(key, {}) if isinstance(table, dict) else {}
    return table if isinstance(table, dict) else {}


def _metadata_value(value: Any) -> Any:
    # TOML dates and invalid extension values must remain serializable evidence.
    return json.loads(json.dumps(value, default=str))


def _error(code: str, message: str, path: Path | SourceLocation) -> Diagnostic:
    source = path if isinstance(path, SourceLocation) else SourceLocation(path)
    return Diagnostic(code, "error", message, source)


def _cargo_matches(raw: str, version: str) -> bool | None:
    # Reuse the stable semver intervals only after narrowing Cargo's grammar.
    # Cargo bare numeric requirements mean caret; npm's bare form differs.
    if (
        not raw
        or len(raw) > 256
        or len(version) > 128
        or "-" in raw
        or "-" in version
        or not _exact_version(version)
    ):
        return None
    tokens = []
    for part in raw.split(","):
        match = _REQUIREMENT_TOKEN.fullmatch(part.strip())
        if match is None:
            return None
        operator, value = match.groups()
        if any(
            int(component) > 2**64 - 1
            for component in value.split(".")
            if component != "*"
        ):
            return None
        if "*" in value:
            if operator or not re.fullmatch(r"\*|[0-9]+\.\*|[0-9]+\.[0-9]+\.\*", value):
                return None
        elif operator in {"=", ">", "<="} and len(value.split(".")) != 3:
            return None  # Partial comparisons differ from the shared npm helper.
        elif operator is None:
            operator = "^"
        tokens.append((operator or "") + value)
    intervals = EvidenceAnalyzer._semver_intervals(" ".join(tokens))
    if intervals is None:
        return None
    candidate = Version(version.split("+", 1)[0])
    return any(
        (lower is None or candidate > lower or candidate == lower and lower_inclusive)
        and (
            upper is None or candidate < upper or candidate == upper and upper_inclusive
        )
        for lower, lower_inclusive, upper, upper_inclusive in intervals
    )
