from __future__ import annotations

from pathlib import Path
import shutil


class ProjectPathError(PermissionError):
    """文件访问目标越过调用方指定的权威项目根目录。"""


def external_path_executable(project_root: Path, name: str) -> str | None:
    """Resolve a PATH command, rejecting executables inside the target repository."""
    executable = shutil.which(name)
    if not executable:
        return None
    resolved = Path(executable).resolve()
    if resolved.is_relative_to(Path(project_root).resolve()):
        return None
    return str(resolved)


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


def default_index_path(project_root: Path) -> Path:
    """Default cache writes must not alias other files, even inside the root."""
    root = Path(project_root).resolve()
    cache = root / ".depcheck"
    path = cache / "index.sqlite3"
    if cache.is_symlink() or cache.resolve() != cache or path.is_symlink():
        raise ProjectPathError("refusing aliased default dependency cache")
    if path.exists() and path.stat().st_nlink > 1:
        raise ProjectPathError("refusing hard-linked default dependency cache")
    return require_within_project(
        root, path, operation="access default dependency cache"
    )
