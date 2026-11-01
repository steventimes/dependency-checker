"""Conservative npm workspace membership for inherited pnpm evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from depcheck.ecosystems.configuration.commands import _safe_path
from depcheck.ecosystems.configuration.yaml import read_lock_yaml
from depcheck.ecosystems.static import read_json, read_text


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
            if (
                not isinstance(patterns, list)
                or len(patterns) > 1024
                or not all(isinstance(p, str) for p in patterns)
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


@dataclass(frozen=True)
class _WorkspacePattern:
    parts: tuple[str, ...]

    def fullmatch(self, value: str) -> bool:
        # Dynamic programming, with an explicit work limit, avoids regex backtracking.
        if len(value) > 4096:
            raise ValueError("workspace path budget exhausted")
        components = value.split("/")
        work = 0
        active = {0}
        for part in self.parts:
            following: set[int] = set()
            if part == "**":
                for position in active:
                    work += len(components) + 1 - position
                    if work > 100_000:
                        raise ValueError("workspace matching budget exhausted")
                    following.update(range(position, len(components) + 1))
            else:
                for position in active:
                    if position == len(components):
                        continue
                    text = components[position]
                    states = {0}
                    for character in part:
                        work += len(text) + 1
                        if work > 100_000:
                            raise ValueError("workspace matching budget exhausted")
                        if character == "*":
                            states = (
                                set(range(min(states), len(text) + 1))
                                if states
                                else set()
                            )
                        else:
                            states = {
                                i + 1
                                for i in states
                                if i < len(text)
                                and (character == "?" or text[i] == character)
                            }
                    if len(text) in states:
                        following.add(position + 1)
            active = following
            if not active:
                return False
        return len(components) in active


def _workspace_pattern(pattern: str) -> _WorkspacePattern | None:
    pattern = pattern.removeprefix("./").rstrip("/")
    if (
        not pattern
        or len(pattern) > 4096
        or any(c in pattern for c in "{}[]\\()|")
        or pattern.startswith("/")
    ):
        return None
    parts = pattern.split("/")
    if any(p in {"", ".", ".."} for p in parts):
        return None
    return _WorkspacePattern(tuple(parts))
