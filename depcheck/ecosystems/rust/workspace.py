"""Bounded workspace membership, inheritance and edition evidence."""

from __future__ import annotations

from collections.abc import Mapping
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any

from depcheck.ecosystems.rust.common import (
    _LEGACY_EDITIONS,
    _SECTIONS,
    _Document,
    _error,
    _local_path,
    _table,
)
from depcheck.model import Diagnostic


def _workspace_for(
    root: Path, manifest: Path, documents: Mapping[Path, _Document]
) -> Path | None:
    document = documents.get(manifest)
    if document is None:
        return None
    if "workspace" in document.data:
        return manifest
    package = _package_table(document.data)
    explicit = package.get("workspace") if isinstance(package, dict) else None
    if isinstance(explicit, str):
        directory = _local_path(root, manifest.parent, explicit)
        candidate = directory / "Cargo.toml" if directory else None
        if (
            candidate is not None
            and candidate in documents
            and "workspace" in documents[candidate].data
        ):
            return candidate
        return None
    for directory in manifest.parent.parents:
        if not directory.is_relative_to(root):
            break
        candidate = directory / "Cargo.toml"
        workspace = documents.get(candidate)
        if workspace and "workspace" in workspace.data:
            relative = manifest.parent.relative_to(directory).as_posix()
            table = workspace.data["workspace"]
            if not isinstance(table, dict):
                return None
            if _matches(relative, table.get("exclude", [])):
                return None
            if _matches(relative, table.get("members", [])) or _path_member(
                root, manifest, candidate, documents
            ):
                return candidate
            return None
    return None


def _package_table(data: Mapping[str, Any]) -> Any:
    return data.get("package", data.get("project", {}))


def _cargo_edition(document: _Document, workspace: _Document | None) -> str | None:
    if "package" not in document.data and "project" not in document.data:
        return None  # Virtual workspaces have no package edition to default.
    package = _package_table(document.data)
    if not isinstance(package, dict):
        return None
    edition = package.get("edition", "2015")
    if (
        isinstance(edition, dict)
        and set(edition) == {"workspace"}
        and edition["workspace"] is True
    ):
        edition = (
            _table(workspace.data, "workspace", "package").get("edition")
            if workspace
            else None
        )
    return edition if isinstance(edition, str) else None


def _legacy_section(
    document: _Document, keys: tuple[str, ...], workspace: _Document | None
) -> dict[str, str] | None:
    name = keys[-1]
    canonical = name.replace("_", "-")
    parent = _table(document.data, *keys[:-1])
    if name == canonical or name not in parent:
        return None
    edition = _cargo_edition(document, workspace)
    if edition == "2024":
        status = "rejected"
    elif edition not in _LEGACY_EDITIONS:
        status = "edition-unknown"
    elif canonical in parent:
        status = "ignored"
    else:
        status = "accepted"
    return {
        "name": name,
        "canonical": canonical,
        "edition": edition
        if edition in _LEGACY_EDITIONS or edition == "2024"
        else "unknown",
        "status": status,
    }


def _matches(relative: str, patterns: Any) -> bool:
    if not isinstance(patterns, list):
        return False
    for pattern in patterns:
        if (
            not isinstance(pattern, str)
            or ".." in PurePosixPath(pattern).parts
            or pattern.startswith("/")
        ):
            continue
        left, right = PurePosixPath(relative).parts, PurePosixPath(pattern).parts
        positions = {0}
        for part in right:
            if part == "**" and positions:
                positions = set(range(min(positions), len(left) + 1))
            else:
                positions = {
                    i + 1
                    for i in positions
                    if i < len(left) and fnmatchcase(left[i], part)
                }
        if len(left) in positions:
            return True
    return False


def _path_member(
    root: Path, manifest: Path, workspace: Path, documents: Mapping[Path, _Document]
) -> bool:
    # Only follow statically discovered path dependencies; never walk target paths.
    members = {workspace}
    table = documents[workspace].data.get("workspace", {})
    for path in documents:
        if path.parent.is_relative_to(workspace.parent) and _matches(
            path.parent.relative_to(workspace.parent).as_posix(),
            table.get("members", []),
        ):
            members.add(path)
    pending = list(members)
    while pending:
        path = pending.pop()
        data = documents[path].data
        prefixes: list[tuple[str, ...]] = [()]
        prefixes.extend(("target", target) for target in _table(data, "target"))
        tables = [_table(data, "workspace", "dependencies")]
        for prefix in prefixes:
            for section in _SECTIONS:
                keys = (*prefix, section)
                legacy = _legacy_section(documents[path], keys, documents[workspace])
                if legacy is None or legacy["status"] == "accepted":
                    tables.append(_table(data, *keys))
        for dependencies in tables:
            for raw in dependencies.values() if isinstance(dependencies, dict) else ():
                if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
                    continue
                directory = _local_path(root, path.parent, raw["path"])
                child = directory / "Cargo.toml" if directory else None
                if (
                    child is None
                    or child not in documents
                    or child in members
                    or not child.parent.is_relative_to(workspace.parent)
                ):
                    continue
                if _matches(
                    child.parent.relative_to(workspace.parent).as_posix(),
                    table.get("exclude", []),
                ):
                    continue
                if "workspace" in documents[child].data:
                    continue
                members.add(child)
                pending.append(child)
    return manifest in members


def _workspace_diagnostics(
    root: Path,
    manifest: Path,
    document: _Document,
    diagnostics: list[Diagnostic],
    workspace_document: _Document | None,
) -> None:
    workspace = document.data.get("workspace", {})
    if not isinstance(workspace, dict):
        diagnostics.append(
            _error("manifest.invalid", "Cargo workspace must be a table", manifest)
        )
    else:
        for key in ("members", "exclude"):
            entries = workspace.get(key, [])
            if not isinstance(entries, list) or any(
                not isinstance(e, str) for e in entries
            ):
                diagnostics.append(
                    _error(
                        "manifest.invalid",
                        f"Cargo workspace {key} must be a string array",
                        manifest,
                    )
                )
                continue
            for entry in entries:
                if _local_path(root, manifest.parent, entry) is None:
                    diagnostics.append(
                        _error(
                            "manifest.workspace-outside-root",
                            f"Unsafe Cargo workspace {key} path: {entry!r}",
                            manifest,
                        )
                    )
    if "project" in document.data:
        edition = _cargo_edition(document, workspace_document)
        valid = (
            isinstance(document.data["project"], dict) and edition in _LEGACY_EDITIONS
        )
        diagnostics.append(
            Diagnostic(
                "configuration.cargo-legacy-package"
                if valid
                else "manifest.cargo-legacy-package",
                "warning" if valid else "error",
                "Legacy [project] is ignored because [package] is present."
                if valid and "package" in document.data
                else "Legacy [project] is a package table alias before edition 2024; its edition acceptance does not establish installation.",
                document.positions.key("project"),
            )
        )
    package = _package_table(document.data)
    if isinstance(package, dict) and "workspace" in package:
        entry = package["workspace"]
        if (
            not isinstance(entry, str)
            or _local_path(root, manifest.parent, entry) is None
        ):
            diagnostics.append(
                _error(
                    "manifest.workspace-outside-root",
                    f"Unsafe Cargo workspace path: {entry!r}",
                    manifest,
                )
            )
