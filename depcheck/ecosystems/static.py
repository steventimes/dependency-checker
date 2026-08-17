from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".gradle",
        ".idea",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "bazel-bin",
        "bazel-out",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "out",
        "target",
        "vendor",
        "venv",
    }
)
DEFAULT_MAX_BYTES = 8 * 1024 * 1024


class StaticReadError(ValueError):
    """A repository file cannot be consumed safely as bounded static data."""


def discover_files(
    root: Path,
    *,
    names: frozenset[str] = frozenset(),
    suffixes: frozenset[str] = frozenset(),
    excluded_directories: Iterable[str] = (),
) -> tuple[Path, ...]:
    repository_root = Path(root).resolve()
    configured = tuple(Path(str(item)) for item in excluded_directories if str(item))
    found: list[Path] = []
    for current, directories, files in os.walk(
        repository_root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in DEFAULT_EXCLUDED_DIRECTORIES
            and not is_excluded(
                (current_path / directory).relative_to(repository_root),
                configured,
            )
            and not (current_path / directory).is_symlink()
            and _inside(repository_root, current_path / directory)
        )
        for filename in sorted(files):
            path = current_path / filename
            if path.is_symlink() or not _inside(repository_root, path):
                continue
            if names and filename in names:
                found.append(path)
            elif suffixes and path.suffix.lower() in suffixes:
                found.append(path)
    return tuple(found)


def exclusions_for(
    settings: Mapping[str, Any],
    project_root: Path = Path("."),
) -> tuple[str, ...]:
    raw = settings.get("excluded_directories", ())
    if isinstance(raw, str) or not isinstance(raw, Iterable):
        return ()
    root = Path(project_root)
    result: list[str] = []
    for value in raw:
        if not isinstance(value, str) or not value:
            continue
        path = Path(value)
        if len(path.parts) == 1 or root == Path("."):
            result.append(path.as_posix())
        elif root in path.parents:
            result.append(path.relative_to(root).as_posix())
    return tuple(result)


def is_excluded(
    relative_path: Path,
    excluded_directories: Iterable[str | Path],
) -> bool:
    configured = tuple(Path(str(item)) for item in excluded_directories)
    return _configured_exclusion(Path(relative_path), configured)


def read_text(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    candidate = Path(path)
    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise StaticReadError(f"cannot stat {candidate}: {exc}") from exc
    if size > max_bytes:
        raise StaticReadError(f"{candidate} exceeds {max_bytes} bytes")
    try:
        return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise StaticReadError(f"cannot read {candidate}: {exc}") from exc


def read_json(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path, max_bytes=max_bytes))
    except json.JSONDecodeError as exc:
        raise StaticReadError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StaticReadError(f"JSON root in {path} must be an object")
    return value


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _configured_exclusion(
    relative_path: Path,
    configured: tuple[Path, ...],
) -> bool:
    return any(
        (len(item.parts) == 1 and item.name in relative_path.parts)
        or relative_path == item
        or item in relative_path.parents
        for item in configured
    )
