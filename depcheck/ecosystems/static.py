from __future__ import annotations

from depcheck.profiling import measured

import json
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from depcheck.model import SourceLocation
from depcheck import bounded_io

DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".gradle",
        ".idea",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "bazel-bin",
        "bazel-out",
        "build",
        "coverage",
        "dist",
        "dist-packages",
        "node_modules",
        "out",
        "site-packages",
        "target",
        "vendor",
        "venv",
    }
)
DEFAULT_MAX_BYTES = bounded_io.DEFAULT_MAX_BYTES


class StaticReadError(ValueError):
    """A repository file cannot be consumed safely as bounded static data."""

    def __init__(self, message: str, *, source: SourceLocation | None = None) -> None:
        super().__init__(message)
        self.source = source


@measured("discovery.static")
def discover_files(
    root: Path,
    *,
    names: frozenset[str] = frozenset(),
    suffixes: frozenset[str] = frozenset(),
    excluded_directories: Iterable[str] = (),
) -> tuple[Path, ...]:
    repository_root = Path(root).resolve()
    configured = tuple(Path(str(item)) for item in excluded_directories if str(item))
    suffix_endings = tuple(suffixes)
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
            if filename not in names and not filename.lower().endswith(suffix_endings):
                continue
            path = current_path / filename
            if path.is_symlink() or not _inside(repository_root, path):
                continue
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
    try:
        content = bounded_io.read_bytes(path, max_bytes=max_bytes)
        return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError) as exc:
        raise StaticReadError(f"cannot read {path}: {exc}") from exc


def read_json(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    return parse_json(read_text(path, max_bytes=max_bytes), path)


@measured("parsing.json")
def parse_json(text: str, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StaticReadError(
            f"invalid JSON in {path}: {exc}",
            source=SourceLocation(path, exc.lineno, exc.colno),
        ) from exc
    except RecursionError as exc:
        raise StaticReadError(
            f"JSON nesting exceeds the parser limit in {path}"
        ) from exc
    if not isinstance(value, dict):
        raise StaticReadError(f"JSON root in {path} must be an object")
    return value


def _inside(root: Path, path: Path) -> bool:
    try:
        common = os.path.commonpath((path.resolve(), root))
    except (OSError, ValueError):
        return False
    return os.path.normcase(common) == os.path.normcase(str(root))


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
