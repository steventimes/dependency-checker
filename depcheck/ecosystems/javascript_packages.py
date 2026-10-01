"""Registry identities shared by npm and pnpm evidence collectors."""

from __future__ import annotations

import re
from urllib.parse import quote

from depcheck.ecosystems.static import StaticReadError
from depcheck.model import PackageRef

_PACKAGE = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def package_ref(name: str) -> PackageRef:
    return PackageRef(
        "npm", name.lower(), name, f"pkg:npm/{quote(name.lower(), safe='/')}"
    )


def registry_name(name: str) -> str:
    if not _PACKAGE.fullmatch(name) or name.startswith((".", "_")):
        raise StaticReadError(f"Invalid npm registry package name: {name!r}")
    return name


def exact_version(version: str) -> bool:
    return _VERSION.fullmatch(version) is not None


def dependency_identity(name: str, specifier: str) -> tuple[str, str]:
    if not specifier.startswith("npm:"):
        return name, specifier
    target = specifier[4:]
    package, separator, constraint = target.rpartition("@")
    if not separator or not package:
        package, constraint = target, "*"
    return registry_name(package), constraint or "*"
