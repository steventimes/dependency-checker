"""Bounded snapshots and atomic writes through pinned filesystem parents."""

from __future__ import annotations

import hashlib
import errno
import inspect
import io
import os
import secrets
import shutil
import stat
import tokenize
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, nullcontext
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Any, Callable, ParamSpec, TypeVar

from depcheck.profiling import count_work, measured


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


DEFAULT_MAX_BYTES = 8 * 1024 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024
_ROOT: ContextVar[Path | None] = ContextVar("depcheck_read_root", default=None)
_READ_RECEIPTS: ContextVar[dict[Path, str] | None] = ContextVar(
    "depcheck_read_receipts", default=None
)
_DIR_FD = os.open in os.supports_dir_fd
_P = ParamSpec("_P")
_R = TypeVar("_R")


def authorize_root(root: Path) -> Path:
    candidate = Path(os.path.abspath(root))
    authority = _ROOT.get()
    if authority is not None and not candidate.is_relative_to(authority):
        raise ProjectPathError("repository I/O scope cannot expand beyond its caller")
    return candidate


@contextmanager
def repository_reads(root: Path) -> Iterator[None]:
    root = authorize_root(root)
    token = _ROOT.set(root)
    try:
        yield
    finally:
        _ROOT.reset(token)


def repository_operation(
    parameter: str,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    """Bind I/O authority to an explicit repository/provider argument, never a file parent."""

    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            values = signature.bind(*args, **kwargs).arguments
            pieces = parameter.split(".")
            root: Any = values[pieces[0]]
            for piece in pieces[1:]:
                root = getattr(root, piece)
            # Ordinary callers authorize their selected canonical repository. MCP
            # carries an already-normalized startup authority that must not expand.
            root = Path(root) if parameter == "self._io_root" else Path(root).resolve()
            with repository_reads(root):
                return function(*args, **kwargs)

        return wrapped

    return decorate


class ReadLimitError(OSError):
    """The complete file cannot be consumed within its resource limit."""


class ContentChangedError(RuntimeError):
    """The guarded write target no longer matches its original snapshot."""


@contextmanager
def capture_reads() -> Iterator[dict[Path, str]]:
    receipts: dict[Path, str] = {}
    token = _READ_RECEIPTS.set(receipts)
    try:
        yield receipts
    finally:
        _READ_RECEIPTS.reset(token)


class PinnedParent:
    def __init__(self, path: Path, descriptor: int | None) -> None:
        self.path = path
        self.descriptor = descriptor

    def open(self, name: str, flags: int, mode: int = 0o600) -> int:
        if self.descriptor is not None:
            return os.open(
                name,
                flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                mode,
                dir_fd=self.descriptor,
            )
        from depcheck.filesystem.windows import open_file

        return open_file(self.path / name, flags)

    def replace(self, source: str, target: str) -> None:
        if self.descriptor is not None:
            os.replace(
                source, target, src_dir_fd=self.descriptor, dst_dir_fd=self.descriptor
            )
        else:
            os.replace(self.path / source, self.path / target)

    def unlink(self, name: str) -> None:
        if self.descriptor is not None:
            os.unlink(name, dir_fd=self.descriptor)
        else:
            (self.path / name).unlink()

    @contextmanager
    def publication_lock(self) -> Iterator[None]:
        """Exclude cooperating cache publishers without blocking readers."""
        if self.descriptor is None:
            from depcheck.filesystem.windows import lock_publication

            lock = lock_publication(self.path)
            try:
                yield
            finally:
                lock.close()
            return
        import fcntl

        descriptor = os.open(
            ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.descriptor
        )
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ContentChangedError(
                        "another dependency index publication is in progress; retry the refresh"
                    ) from exc
                raise
            yield
        finally:
            os.close(descriptor)


@contextmanager
def pinned_parent(
    path: Path,
    project_root: Path,
    *,
    create: bool = False,
    allow_aliases: bool = False,
    resolve_final: bool = True,
) -> Iterator[tuple[PinnedParent, str]]:
    root = authorize_root(project_root)
    original = Path(os.path.abspath(path))
    target = require_within_project(
        root,
        original if resolve_final else original.parent,
        operation="access repository data",
    )
    if not resolve_final:
        target = target / original.name
    if not allow_aliases and target != original:
        raise ProjectPathError("refusing aliased repository data")
    relative = target.parent.relative_to(root)
    with ExitStack() as stack:
        if os.name == "nt":
            from depcheck.filesystem.windows import lock_directory

            current = Path(root.anchor)
            for component in (*root.parts[1:], *relative.parts):
                handle = lock_directory(current)
                stack.callback(handle.close)
                current /= component
                if create:
                    current.mkdir(mode=0o700, exist_ok=True)
            handle = lock_directory(current)
            stack.callback(handle.close)
            yield PinnedParent(current, None), target.name
        else:
            if not hasattr(os, "O_NOFOLLOW") or not _DIR_FD:
                raise ProjectPathError(
                    "descriptor-relative filesystem access is unavailable"
                )
            flags = (
                getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY))
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
            )
            descriptor = os.open(root.anchor, flags)
            stack.callback(os.close, descriptor)
            for index, component in enumerate((*root.parts[1:], *relative.parts)):
                if create and index >= len(root.parts) - 1:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                descriptor = os.open(component, flags, dir_fd=descriptor)
                stack.callback(os.close, descriptor)
            yield PinnedParent(target.parent, descriptor), target.name


def read_descriptor(descriptor: int, path: Path, max_bytes: int) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ProjectPathError("repository evidence must be a regular file")
    if metadata.st_size > max_bytes:
        raise ReadLimitError(f"{path} exceeds {max_bytes} bytes")
    chunks: list[bytes] = []
    size = 0
    while size <= max_bytes:
        chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
    raise ReadLimitError(f"{path} exceeds {max_bytes} bytes")


@measured("io.read-bytes")
def read_bytes(
    path: Path,
    *,
    project_root: Path | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_aliases: bool = False,
) -> bytes:
    candidate = Path(path)
    if max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    root = Path(project_root) if project_root is not None else _ROOT.get()
    if root is None:
        root = (
            candidate.resolve().parent
        )  # Explicit path-only library caller authority.
    with pinned_parent(candidate, root, allow_aliases=allow_aliases) as (parent, name):
        descriptor = parent.open(name, os.O_RDONLY)
        try:
            content = read_descriptor(descriptor, candidate, max_bytes)
            count_work("io.work", reads=1, bytes=len(content))
            receipts = _READ_RECEIPTS.get()
            if receipts is not None:
                key = Path(os.path.abspath(candidate))
                digest = hashlib.sha256(content).hexdigest()
                if key in receipts and receipts[key] != digest:
                    raise ContentChangedError(
                        "repository evidence changed during scanning"
                    )
                if key in receipts:
                    count_work("io.work", repeated_captured_reads=1)
                receipts[key] = digest
            return content
        finally:
            os.close(descriptor)


def read_text(
    path: Path, *, project_root: Path | None = None, allow_aliases: bool = False
) -> str:
    # Match Path.read_text's universal-newline behavior.
    content = read_bytes(path, project_root=project_root, allow_aliases=allow_aliases)
    return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def read_python(
    path: Path, *, project_root: Path | None = None, allow_aliases: bool = False
) -> str:
    content = read_bytes(path, project_root=project_root, allow_aliases=allow_aliases)
    encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
    return content.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")


def atomic_write(
    path: Path,
    content: bytes,
    *,
    project_root: Path,
    max_bytes: int = DEFAULT_MAX_BYTES,
    expected_digest: str | None = None,
    expect_absent: bool = False,
    allow_aliases: bool = False,
    create_parent: bool = False,
    parent: PinnedParent | None = None,
) -> None:
    if expect_absent and expected_digest is not None:
        raise ValueError("expected absence and digest are mutually exclusive")
    if len(content) > max_bytes:
        raise ReadLimitError(f"{path} exceeds {max_bytes} bytes")
    anchor = (
        pinned_parent(
            path,
            project_root,
            create=create_parent,
            allow_aliases=allow_aliases,
            resolve_final=False,
        )
        if parent is None
        else nullcontext((parent, path.name))
    )
    with anchor as (parent, name):
        mode = 0o600
        try:
            descriptor = parent.open(name, os.O_RDONLY)
        except FileNotFoundError:
            if expected_digest is not None:
                raise ContentChangedError("file disappeared before atomic replacement")
        except OSError:
            if not allow_aliases or expect_absent:
                raise
            with pinned_parent(path, project_root, allow_aliases=True) as (
                resolved_parent,
                resolved_name,
            ):
                descriptor = resolved_parent.open(resolved_name, os.O_RDONLY)
                try:
                    current = read_descriptor(descriptor, path, max_bytes)
                    mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
                finally:
                    os.close(descriptor)
            if (
                expected_digest is not None
                and hashlib.sha256(current).hexdigest() != expected_digest
            ):
                raise ContentChangedError("file changed before atomic replacement")
        else:
            try:
                if expect_absent:
                    raise ContentChangedError("file appeared before atomic replacement")
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
                    raise ProjectPathError("refusing aliased atomic-write target")
                mode = stat.S_IMODE(metadata.st_mode)
                if expected_digest is not None:
                    current = read_descriptor(descriptor, path, max_bytes)
                    if hashlib.sha256(current).hexdigest() != expected_digest:
                        raise ContentChangedError(
                            "file changed before atomic replacement"
                        )
            finally:
                os.close(descriptor)
        temporary = ".depcheck-" + secrets.token_hex(16)
        descriptor = parent.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            try:
                handle = os.fdopen(descriptor, "wb")
            except BaseException:
                os.close(descriptor)
                raise
            with handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                if os.name == "nt":
                    from depcheck.filesystem.windows import set_file_mode

                    set_file_mode(handle.fileno(), mode)
                else:
                    os.fchmod(handle.fileno(), mode)
            if parent.descriptor is not None:
                with pinned_parent(
                    path, project_root, allow_aliases=allow_aliases, resolve_final=False
                ) as (current_parent, _name):
                    if current_parent.descriptor is None:
                        raise ProjectPathError("directory identity cannot be verified")
                    previous_parent_stat = os.fstat(parent.descriptor)
                    current_parent_stat = os.fstat(current_parent.descriptor)
                    if (previous_parent_stat.st_dev, previous_parent_stat.st_ino) != (
                        current_parent_stat.st_dev,
                        current_parent_stat.st_ino,
                    ):
                        raise ContentChangedError(
                            "parent directory changed before atomic replacement"
                        )
            parent.replace(temporary, name)
        finally:
            try:
                parent.unlink(temporary)
            except FileNotFoundError:
                pass
