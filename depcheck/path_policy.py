from __future__ import annotations

from pathlib import Path


class ProjectPathError(PermissionError):
    """文件访问目标越过调用方指定的权威项目根目录。"""


def require_within_project(
    project_root: Path,
    path: Path,
    *,
    operation: str,
) -> Path:
    """返回规范化路径；越过项目根（包括软链接逃逸）时拒绝访问。"""
    root = Path(project_root).resolve()
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProjectPathError(
            f"refusing to {operation} a path outside the project root"
        ) from exc
    return resolved
