"""Unexecuted patch/replace assertions and their qualified source matching."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from depcheck.ecosystems.rust.common import (
    _CRATES_IO,
    _NAME,
    _Document,
    _error,
    _exact_version,
)
from depcheck.evidence.origins import redact_source
from depcheck.model import DependencyDeclaration, Diagnostic, SourceLocation

_OVERRIDE_ENTRY_LIMIT = 10_000

_OVERRIDE_DETAIL_BYTES = 4096

_OVERRIDE_SOURCE_LIMIT = 2048


@dataclass(frozen=True)
class _CargoOverride:
    section: str
    name: str
    version: str | None
    source: str | None
    location: SourceLocation
    alias: str | None = None


@dataclass
class _CargoOverrides:
    by_name: dict[str, list[_CargoOverride]]
    unknown: bool = False


def _collect_overrides(
    document: _Document,
    diagnostics: list[Diagnostic],
    *,
    applicable: bool,
) -> _CargoOverrides:
    result = _CargoOverrides({})
    work = 0
    for section in ("patch", "replace"):
        if section not in document.data:
            continue
        location = document.positions.key(section)
        if not applicable:
            diagnostics.append(
                Diagnostic(
                    "configuration.cargo-overrides-ignored",
                    "warning",
                    f"Cargo {section} outside the workspace root is ignored; it does not change workspace resolution.",
                    location,
                )
            )
            continue
        table = document.data[section]
        if not isinstance(table, dict):
            diagnostics.append(
                _error("manifest.invalid", f"Cargo {section} must be a table", location)
            )
            diagnostics.append(
                _error(
                    "manifest.cargo-overrides-unsupported",
                    f"Cargo {section} override shape is not interpreted; affected scope is unknown.",
                    location,
                )
            )
            result.unknown = True
            continue
        groups = table.items() if section == "patch" else ((None, table),)
        for source, entries in groups:
            keys = (section, source) if source is not None else (section,)
            work += 1
            if work > _OVERRIDE_ENTRY_LIMIT:
                diagnostics.append(
                    _error(
                        "manifest.cargo-overrides-budget",
                        "Cargo override entry budget exceeded; remaining override scope and directness are unknown.",
                        document.positions.key(*keys),
                    )
                )
                result.unknown = True
                return result
            if not isinstance(entries, dict):
                diagnostics.append(
                    _error(
                        "manifest.invalid",
                        "Cargo patch source must contain a dependency table; override scope is unknown.",
                        document.positions.key(*keys),
                    )
                )
                result.unknown = True
                continue
            for alias, raw in entries.items():
                location = document.positions.key(*keys, alias)
                work += 1
                if work > _OVERRIDE_ENTRY_LIMIT:
                    diagnostics.append(
                        _error(
                            "manifest.cargo-overrides-budget",
                            "Cargo override entry budget exceeded; remaining override scope and directness are unknown.",
                            location,
                        )
                    )
                    result.unknown = True
                    return result
                name: Any = (
                    raw.get("package", alias) if isinstance(raw, dict) else alias
                )
                version = None
                target_source = source
                if section == "replace":
                    target_source, _, selector = alias.rpartition("#")
                    if not target_source:
                        target_source = None
                        selector = alias
                    match = re.fullmatch(r"([A-Za-z0-9_-]+)(?:@|:)(.+)", selector)
                    name = match[1] if match else None
                    version = match[2] if match else None
                valid = (
                    isinstance(raw, (str, dict))
                    and isinstance(name, str)
                    and _NAME.fullmatch(name) is not None
                    and (section != "replace" or _exact_version(version or ""))
                )
                if not valid:
                    result.unknown = True
                    diagnostics.append(
                        _error(
                            "manifest.invalid",
                            "Cargo override has an unsupported package selector or value shape; its affected scope is unknown.",
                            location,
                        )
                    )
                else:
                    result.by_name.setdefault(name, []).append(
                        _CargoOverride(
                            section,
                            name,
                            version,
                            target_source,
                            location,
                            alias if section == "patch" else None,
                        )
                    )
                diagnostics.append(
                    _error(
                        "manifest.cargo-overrides-unsupported",
                        f"Cargo {section} override is not interpreted; affected declaration-to-lock bindings remain unknown.",
                        location,
                    )
                )
    return result


def _override_source_matches(
    source: str | None, declaration: DependencyDeclaration
) -> bool | None:
    if source is None:
        return True  # An unqualified replace selector can refer to any source.
    if declaration.metadata.get("workspace-unresolved"):
        return None
    if (
        source == "crates-io"
        or source in _CRATES_IO
        or source
        in {
            "https://github.com/rust-lang/crates.io-index",
            "https://index.crates.io/",
        }
    ):
        if declaration.package.purl:
            return True
        if "git" in declaration.metadata or "path" in declaration.metadata:
            return False
        return None  # A named registry's URL is not collected here.
    if len(source) > _OVERRIDE_SOURCE_LIMIT:
        return None
    try:
        patched = urlsplit(source.removeprefix("git+"))
        if patched.scheme not in {"http", "https", "ssh", "git"} or not patched.netloc:
            return None
        if declaration.package.purl or "path" in declaration.metadata:
            return False
        git = declaration.metadata.get("git")
        if not isinstance(git, str) or len(git) > _OVERRIDE_SOURCE_LIMIT:
            return None
        requested = urlsplit(git)
        if (
            requested.scheme not in {"http", "https", "ssh", "git"}
            or not requested.netloc
        ):
            return None
        if _override_repo_key(patched) != _override_repo_key(requested):
            return False
        return True if source == git else None
    except ValueError:
        return None


def _override_repo_key(url: SplitResult) -> tuple[str, str | None, int | None, str]:
    # Cargo canonicalizes these repository spellings internally. This key only
    # prevents a false contradiction; it never establishes source identity.
    scheme, host, port = url.scheme, url.hostname, url.port
    if port == {"http": 80, "https": 443}.get(scheme):
        port = None
    path = url.path.removesuffix("/")
    if host == "github.com":
        scheme = "https"
        path = path.lower()
    return scheme, host, port, path.removesuffix(".git")


def _override_detail(root: Path, override: _CargoOverride) -> dict[str, Any] | None:
    if any(
        value is not None and len(value) > _OVERRIDE_SOURCE_LIMIT
        for value in (override.name, override.source, override.version, override.alias)
    ):
        return None
    detail = {
        "kind": override.section,
        "package": override.name,
        "location": override.location.to_dict(root),
        **(
            {"alias": redact_source(override.alias)}
            if override.alias is not None
            else {}
        ),
        **({"version": override.version} if override.version is not None else {}),
        **(
            {"patched_source": redact_source(override.source)}
            if override.source is not None
            else {}
        ),
    }
    return (
        detail if len(json.dumps(detail).encode()) <= _OVERRIDE_DETAIL_BYTES else None
    )
