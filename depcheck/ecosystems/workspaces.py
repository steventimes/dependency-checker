"""Conservative npm workspace membership for inherited pnpm evidence."""

from __future__ import annotations

from pathlib import Path
import re

from depcheck.ecosystems.commands import _safe_path
from depcheck.ecosystems.static import read_json, read_text
from depcheck.ecosystems.yaml_reader import read_lock_yaml


def pnpm_membership(
    root: Path, project_root: Path, lock: Path
) -> tuple[bool | None, tuple[Path, ...]]:
    parent = lock.parent
    workspace = parent / "pnpm-workspace.yaml"
    files = (workspace,) if workspace.exists() or workspace.is_symlink() else ()
    if project_root == parent:
        return True, files
    try:
        relative = project_root.relative_to(parent).as_posix()
        if not _safe_path(root, lock) or any(not _safe_path(root, p) for p in files):
            return None, files
        if files:
            data = read_lock_yaml(read_text(workspace))
            patterns = data.get("packages")
        else:
            data = read_json(parent / "package.json")
            patterns = data.get("workspaces")
            if isinstance(patterns, dict):
                patterns = patterns.get("packages")
        if patterns is not None:
            if not isinstance(patterns, list) or not all(
                isinstance(p, str) for p in patterns
            ):
                return None, files
            included = False
            for pattern in patterns:
                excluded = pattern.startswith("!")
                expression = _workspace_pattern(pattern[1:] if excluded else pattern)
                if expression is None:
                    return None, files
                if expression.fullmatch(relative):
                    if excluded:
                        return False, files
                    included = True
            return (included if files or not included else None), files
        data = read_lock_yaml(read_text(lock))
        importers = data.get("importers")
        if not isinstance(importers, dict):
            return None, files
        return (
            relative in importers if files or relative not in importers else None
        ), files
    except (OSError, ValueError, RecursionError):
        return None, files


def _workspace_pattern(pattern: str) -> re.Pattern[str] | None:
    pattern = pattern.removeprefix("./").rstrip("/")
    if not pattern or any(c in pattern for c in "{}[]\\()|") or pattern.startswith("/"):
        return None
    parts = pattern.split("/")
    if any(p in {"", ".", ".."} for p in parts):
        return None
    regex = ""
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            if last and regex.endswith("/"):
                regex = regex[:-1] + "(?:/.*)?"
            else:
                regex += ".*" if last else "(?:[^/]+/)*"
        else:
            regex += re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
            if not last:
                regex += "/"
    return re.compile(regex)
