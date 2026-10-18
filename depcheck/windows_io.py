"""Windows no-reparse opens and directory locks for repository I/O."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import stat
from typing import Any

from depcheck.path_policy import ProjectPathError


class _Attributes(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]


class _BasicInformation(ctypes.Structure):
    _fields_ = [
        ("creation", ctypes.c_int64),
        ("access", ctypes.c_int64),
        ("write", ctypes.c_int64),
        ("change", ctypes.c_int64),
        ("attributes", wintypes.DWORD),
    ]


def _api() -> Any:
    kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _open(
    path: Path, *, directory: bool, write: bool = False, create: bool = False
) -> tuple[Any, int]:
    kernel = _api()
    flags = 0x00200000 | (
        0x02000000 if directory else 0
    )  # OPEN_REPARSE_POINT, BACKUP_SEMANTICS
    access = 0 if directory else (0x40000000 if write else 0x80000000)
    # Omitting SHARE_DELETE pins each directory name against deletion/rename.
    handle = kernel.CreateFileW(
        str(path), access, 3 if directory else 1, None, 1 if create else 3, flags, None
    )
    if handle == ctypes.c_void_p(-1).value:
        raise getattr(ctypes, "WinError")(getattr(ctypes, "get_last_error")())
    try:
        attributes = _Attributes()
        if not kernel.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):
            raise getattr(ctypes, "WinError")(getattr(ctypes, "get_last_error")())
        if (
            attributes.attributes & 0x400
            or bool(attributes.attributes & 0x10) != directory
        ):
            raise ProjectPathError(
                "refusing reparse-point or unexpected Windows file type"
            )
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return kernel, handle


class DirectoryLock:
    def __init__(self, kernel: Any, handle: int) -> None:
        self.kernel = kernel
        self.handle = handle

    def close(self) -> None:
        self.kernel.CloseHandle(self.handle)


def lock_directory(path: Path) -> DirectoryLock:
    kernel, handle = _open(path, directory=True)
    return DirectoryLock(kernel, handle)


def open_file(path: Path, flags: int) -> int:
    import msvcrt

    kernel, handle = _open(
        path,
        directory=False,
        write=bool(flags & (os.O_WRONLY | os.O_RDWR)),
        create=bool(flags & os.O_CREAT),
    )
    try:
        return getattr(msvcrt, "open_osfhandle")(
            handle,
            (os.O_WRONLY if flags & os.O_WRONLY else os.O_RDONLY)
            | getattr(os, "O_BINARY"),
        )
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def set_file_mode(descriptor: int, mode: int) -> None:
    """Preserve Windows' read-only bit through the still-open temporary handle."""
    import msvcrt

    kernel = _api()
    handle = getattr(msvcrt, "get_osfhandle")(descriptor)
    information = _BasicInformation()
    if not kernel.GetFileInformationByHandleEx(
        handle, 0, ctypes.byref(information), ctypes.sizeof(information)
    ):
        raise getattr(ctypes, "WinError")(getattr(ctypes, "get_last_error")())
    if mode & stat.S_IWRITE:
        information.attributes &= ~1
        if not information.attributes:
            information.attributes = 0x80
    else:
        information.attributes &= ~0x80
        information.attributes |= 1
    if not kernel.SetFileInformationByHandle(
        handle, 0, ctypes.byref(information), ctypes.sizeof(information)
    ):
        raise getattr(ctypes, "WinError")(getattr(ctypes, "get_last_error")())
