from __future__ import annotations

from depcheck.bounded_io import repository_operation

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath, PureWindowsPath
import json
import re
import tomllib
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from packaging.version import Version
from semver import Version as SemVersion

from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.ecosystems.rust_source import collect_rust_references
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_text,
)
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    PackageRef,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
    VersionConstraint,
)
from depcheck.source_locations import SourcePositions

_SECTIONS = {
    "dependencies": "runtime",
    "dev-dependencies": "development",
    "build-dependencies": "build",
    "dev_dependencies": "development",
    "build_dependencies": "build",
}
_LEGACY_EDITIONS = frozenset({"2015", "2018", "2021"})
_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_LINK = re.compile(r"^([A-Za-z0-9_-]+)(?: ([^ ()]+))?(?: \((.+)\))?$")
_NUMERIC = r"(?:0|[1-9][0-9]*)"
_REQUIREMENT_TOKEN = re.compile(
    rf"(\^|~|>=|<=|>|<|=)?\s*({_NUMERIC}(?:\.(?:{_NUMERIC}|\*)){{0,2}}|\*)"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_CRATES_IO = frozenset(
    {
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
        "registry+https://index.crates.io/",
    }
)


def _exact_version(value: str) -> bool:
    if not value.isascii():
        return False
    try:
        version = SemVersion.parse(value)
    except ValueError:
        return False
    return max(version.major, version.minor, version.patch) <= 2**64 - 1


@dataclass(frozen=True)
class _Document:
    data: dict[str, Any]
    positions: SourcePositions


class CargoProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root.resolve()
        manifests = discover_files(
            root,
            names=frozenset({"Cargo.toml"}),
            excluded_directories=exclusions_for(context.settings),
        )
        documents: dict[Path, _Document] = {}
        for path in manifests:
            try:
                documents[path] = _read_document(root, path)
            except StaticReadError:
                pass  # Keep the project so collection reports the parse failure.
        projects = []
        for manifest in manifests:
            workspace = _workspace_for(root, manifest, documents)
            lock_root = workspace.parent if workspace else manifest.parent
            lock = lock_root / "Cargo.lock"
            relative_root = manifest.parent.relative_to(root)
            evidence = (manifest,) + (
                (workspace,) if workspace and workspace != manifest else ()
            )
            projects.append(
                ProjectUnit(
                    ProjectUnit.stable_id(relative_root, "Cargo", "cargo"),
                    relative_root,
                    "rust",
                    "Cargo",
                    "cargo",
                    tuple(path.relative_to(root) for path in evidence),
                    (lock.relative_to(root),)
                    if lock.exists() or lock.is_symlink()
                    else (),
                )
            )
        return tuple(
            sorted(projects, key=lambda p: (len(p.root.parts), p.root.as_posix()))
        )


class CargoEvidenceCollector:
    @repository_operation("context.repository_root")
    def collect(
        self, context: ProviderContext, project: ProjectUnit, pack: EcosystemPack
    ) -> EvidenceBundle:
        del pack
        root = context.repository_root.resolve()
        manifest = root / project.manifests[0]
        diagnostics: list[Diagnostic] = []
        declarations: list[DependencyDeclaration] = []
        documents: dict[Path, _Document] = {}
        for relative in project.manifests:
            path = root / relative
            try:
                documents[path] = _read_document(root, path)
            except StaticReadError as exc:
                diagnostics.append(_error("manifest.invalid", str(exc), path))
        document = documents.get(manifest)
        workspace: Path | None = None
        if document:
            workspace = next(
                (p for p in documents if "workspace" in documents[p].data), None
            )
            for path, item in documents.items():
                _workspace_diagnostics(
                    root,
                    path,
                    item,
                    diagnostics,
                    documents.get(workspace) if workspace else None,
                )
            package = _package_table(document.data)
            if (
                isinstance(package, dict)
                and "workspace" in package
                and workspace is None
            ):
                diagnostics.append(
                    _error(
                        "manifest.workspace-unresolved",
                        "Explicit Cargo workspace has no bounded workspace manifest",
                        manifest,
                    )
                )
            for section, scope in _SECTIONS.items():
                _collect_table(
                    root,
                    project,
                    document,
                    (section,),
                    scope,
                    None,
                    documents.get(workspace) if workspace else None,
                    declarations,
                    diagnostics,
                )
            targets = document.data.get("target", {})
            if not isinstance(targets, dict):
                diagnostics.append(
                    _error("manifest.invalid", "Cargo target must be a table", manifest)
                )
            else:
                for target, tables in targets.items():
                    if not isinstance(tables, dict):
                        diagnostics.append(
                            _error(
                                "manifest.invalid",
                                "Cargo target entry must be a table",
                                manifest,
                            )
                        )
                        continue
                    for section, scope in _SECTIONS.items():
                        _collect_table(
                            root,
                            project,
                            document,
                            ("target", target, section),
                            scope,
                            target,
                            documents.get(workspace) if workspace else None,
                            declarations,
                            diagnostics,
                        )
            if "workspace" in document.data:
                _collect_table(
                    root,
                    project,
                    document,
                    ("workspace", "dependencies"),
                    "runtime",
                    None,
                    None,
                    declarations,
                    diagnostics,
                    kind="constraint",
                )
            for section in ("patch", "replace"):
                if section in document.data:
                    diagnostics.append(
                        _error(
                            "manifest.cargo-overrides-unsupported",
                            f"Cargo {section} overrides are retained in the manifest but not interpreted.",
                            manifest,
                        )
                    )

        resolved: tuple[ResolvedDependency, ...] = ()
        if project.locks:
            lock = root / project.locks[0]
            try:
                resolved = _collect_lock(root, project, lock, declarations, diagnostics)
            except StaticReadError as exc:
                diagnostics.append(_error("lock.invalid", str(exc), lock))
        else:
            diagnostics.append(
                _error(
                    "resolution.lock-missing",
                    "No bounded Cargo.lock is available; manifest versions do not prove resolved crates.",
                    manifest,
                )
            )
        manifest_complete = not any(d.code.startswith("manifest.") for d in diagnostics)
        security_complete = (
            manifest_complete
            and bool(project.locks)
            and not any(d.code.startswith(("lock.", "security.")) for d in diagnostics)
        )
        source_files = tuple(
            p
            for p in discover_files(
                root / project.root,
                suffixes=frozenset({".rs"}),
                excluded_directories=exclusions_for(context.settings, project.root),
            )
            if not _in_child_project(p, root / project.root)
        )
        package_table = _package_table(document.data) if document else {}
        source_owner = (
            isinstance(package_table, dict)
            and isinstance(package_table.get("name"), str)
            and bool(_NAME.fullmatch(package_table["name"]))
            and document is not None
            and (
                "package" in document.data
                or (
                    _cargo_edition(
                        document, documents.get(workspace) if workspace else None
                    )
                    or ""
                )
                in _LEGACY_EDITIONS
            )
        )
        usages, source_diagnostics = collect_rust_references(
            project, declarations, source_files, source_owner=source_owner
        )
        diagnostics.extend(source_diagnostics)
        return EvidenceBundle(
            project,
            tuple(declarations),
            resolved,
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=(
                _status("manifest", manifest_complete),
                Capability(
                    "resolution",
                    CapabilityState.INCOMPLETE,
                    "Cargo.lock is a static superset; active features and targets are unknown",
                ),
                _status("security", security_complete),
                Capability(
                    "usage",
                    CapabilityState.INCOMPLETE,
                    "Literal Rust crate references only; target/cfg selection, macros and execution are unknown",
                ),
                Capability(
                    "mapping",
                    CapabilityState.INCOMPLETE,
                    "Cargo aliases supply inferred candidates; compiler/module binding is unknown",
                ),
            ),
            source_files=source_files,
            evidence_files=tuple(
                root / p for p in (*project.manifests, *project.locks)
            ),
        )


def create_cargo_pack() -> EcosystemPack:
    return EcosystemPack(
        "Cargo",
        CargoProjectDetector(),
        capabilities=frozenset(
            {"manifest", "resolution", "security", "sbom", "usage", "mapping"}
        ),
        collector=CargoEvidenceCollector(),
    )


def _read_document(root: Path, path: Path) -> _Document:
    if not _safe_path(root, path):
        raise StaticReadError(f"refusing outside or symlinked Cargo evidence: {path}")
    text = read_text(path)
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise StaticReadError(f"invalid TOML in {path}: {exc}") from exc
    return _Document(data, SourcePositions.toml(path, text))


def _safe_path(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
        if path.resolve().is_relative_to(root) is False:
            return False
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _local_path(root: Path, base: Path, value: str) -> Path | None:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or Path(value).is_absolute()
        or PureWindowsPath(value).drive
    ):
        return None
    candidate = base / value
    return candidate.resolve() if _safe_path(root, candidate) else None


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


def _collect_table(
    root: Path,
    project: ProjectUnit,
    document: _Document,
    keys: tuple[str, ...],
    scope: str,
    target: str | None,
    workspace: _Document | None,
    declarations: list[DependencyDeclaration],
    diagnostics: list[Diagnostic],
    *,
    kind: str = "direct",
) -> None:
    table: Any = document.data
    for key in keys:
        table = table.get(key, {}) if isinstance(table, dict) else None
    if not isinstance(table, dict):
        diagnostics.append(
            _error(
                "manifest.invalid",
                "Cargo dependency section must be a table",
                document.positions.key(*keys),
            )
        )
        return
    legacy = _legacy_section(document, keys, workspace)
    if legacy is not None:
        qualified = legacy["status"] not in {"accepted", "ignored"}
        diagnostics.append(
            Diagnostic(
                "manifest.cargo-legacy-section"
                if qualified
                else "configuration.cargo-legacy-section",
                "error" if qualified else "warning",
                f"Cargo section {legacy['name']!r} is {legacy['status']} for edition {legacy['edition']!r}; canonical spelling is {legacy['canonical']!r}. Non-accepted declarations remain configuration inventory.",
                document.positions.key(*keys),
            )
        )
        if legacy["status"] != "accepted":
            kind = "configuration"
    for alias, raw in table.items():
        source = document.positions.key(*keys, alias)
        if not _NAME.fullmatch(alias) or not isinstance(raw, (str, dict)):
            diagnostics.append(
                _error(
                    "manifest.invalid", f"Invalid Cargo dependency {alias!r}", source
                )
            )
            continue
        values = {"version": raw} if isinstance(raw, str) else dict(raw)
        metadata: dict[str, Any] = {"installation_name": alias, "group": keys[-1]}
        if legacy is not None:
            metadata["legacy_section"] = legacy
        if values.get("workspace") is True:
            inherited = (
                _table(workspace.data, "workspace", "dependencies").get(alias)
                if workspace
                else None
            )
            if workspace is None or not isinstance(inherited, (str, dict)):
                metadata["workspace-unresolved"] = True
                diagnostics.append(
                    _error(
                        "manifest.workspace-unresolved",
                        f"Cargo dependency {alias!r} has no bounded workspace definition",
                        source,
                    )
                )
            else:
                local = values
                values = (
                    {"version": inherited}
                    if isinstance(inherited, str)
                    else dict(inherited)
                )
                metadata["workspace_origin"] = workspace.positions.key(
                    "workspace", "dependencies", alias
                ).to_dict(root)
                metadata["workspace"] = True
                features = values.get("features", [])
                extra = local.get("features", [])
                if isinstance(features, list) and isinstance(extra, list):
                    values["features"] = (
                        list(dict.fromkeys((*features, *extra)))
                        if all(isinstance(v, str) for v in (*features, *extra))
                        else [*features, *extra]
                    )
                for key in ("optional", "default-features"):
                    if key in local:
                        if key == "default-features":
                            metadata["workspace-default-features"] = values.get(
                                key, True
                            )
                            if values.get(key, True) is True and local[key] is False:
                                diagnostics.append(
                                    _error(
                                        "manifest.cargo-feature-policy-unknown",
                                        f"Cargo inherited default-features for {alias!r} depends on edition and toolchain; both requests are preserved",
                                        source,
                                    )
                                )
                        values[key] = local[key]
                if set(local) - {
                    "workspace",
                    "features",
                    "optional",
                    "default-features",
                }:
                    diagnostics.append(
                        _error(
                            "manifest.invalid",
                            f"Cargo inherited dependency {alias!r} has unsupported overriding fields",
                            source,
                        )
                    )
        elif "workspace" in values:
            diagnostics.append(
                _error(
                    "manifest.invalid",
                    f"Cargo dependency {alias!r} must inherit with workspace=true",
                    source,
                )
            )
        name = values.get("package", alias)
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            diagnostics.append(
                _error(
                    "manifest.invalid",
                    f"Invalid Cargo package name for {alias!r}",
                    source,
                )
            )
            continue
        version = values.get("version", "")
        if not isinstance(version, str):
            diagnostics.append(
                _error(
                    "manifest.invalid", f"Invalid Cargo version for {alias!r}", source
                )
            )
            version = ""
        for key in (
            "git",
            "path",
            "registry",
            "rev",
            "tag",
            "branch",
            "features",
            "optional",
            "default-features",
        ):
            if key in values:
                metadata[key] = _metadata_value(values[key])
        known = {
            "version",
            "package",
            "workspace",
            "git",
            "path",
            "registry",
            "rev",
            "tag",
            "branch",
            "features",
            "optional",
            "default-features",
        }
        for key in values.keys() - known:
            metadata[key] = _metadata_value(values[key])
            diagnostics.append(
                _error(
                    "manifest.unsupported-expression",
                    f"Cargo dependency field {key!r} for {alias!r} is retained but not interpreted",
                    source,
                )
            )
        for key in ("git", "path", "registry", "rev", "tag", "branch"):
            if key in values and (not isinstance(values[key], str) or not values[key]):
                diagnostics.append(
                    _error(
                        "manifest.invalid",
                        f"Cargo {key} for {alias!r} must be a nonempty string",
                        source,
                    )
                )
        if target:
            metadata["target"] = target
        registry = not metadata.get("workspace-unresolved") and (
            not any(key in values for key in ("git", "path", "registry"))
            or values.get("registry") == "crates-io"
            and not any(key in values for key in ("git", "path"))
        )
        if "path" in values:
            base = (
                workspace.positions.path.parent
                if workspace is not None and metadata.get("workspace")
                else source.path.parent
            )
            path = values["path"]
            if not isinstance(path, str) or _local_path(root, base, path) is None:
                diagnostics.append(
                    _error(
                        "manifest.path-outside-root",
                        f"Unsafe Cargo dependency path for {alias!r}: {path!r}",
                        source,
                    )
                )
        if not registry:
            diagnostics.append(
                _error(
                    "security.cargo-source-unverified",
                    f"Cargo dependency {alias!r} uses path, Git, or alternate registry evidence; no crates.io coordinate is inferred",
                    source,
                )
            )
        if not version and registry and values.get("workspace") is not True:
            diagnostics.append(
                _error(
                    "manifest.invalid",
                    f"Cargo dependency {alias!r} has no version or source",
                    source,
                )
            )
        for key in ("optional", "default-features"):
            if key in values and not isinstance(values[key], bool):
                diagnostics.append(
                    _error(
                        "manifest.invalid",
                        f"Cargo {key} for {alias!r} must be boolean",
                        source,
                    )
                )
        if "features" in values and (
            not isinstance(values["features"], list)
            or any(not isinstance(v, str) for v in values["features"])
        ):
            diagnostics.append(
                _error(
                    "manifest.invalid",
                    f"Cargo features for {alias!r} must be a string array",
                    source,
                )
            )
        exact = version.strip()[1:].strip() if version.strip().startswith("=") else ""
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package(name, registry),
                VersionConstraint(
                    version, "cargo", f"={exact}" if _exact_version(exact) else None
                ),
                source,
                scope,
                kind,
                target,
                metadata,
            )
        )


def _collect_lock(
    root: Path,
    project: ProjectUnit,
    lock: Path,
    declarations: list[DependencyDeclaration],
    diagnostics: list[Diagnostic],
) -> tuple[ResolvedDependency, ...]:
    document = _read_document(root, lock)
    if document.data.get("version") not in (3, 4):
        raise StaticReadError("Only Cargo.lock versions 3 and 4 are supported")
    records = document.data.get("package", [])
    if not isinstance(records, list):
        raise StaticReadError("Cargo.lock package must be an array of tables")
    valid: list[tuple[dict[str, Any], SourceLocation, str]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        location = document.positions.key("package", index)
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("name"), str)
            or not _NAME.fullmatch(record["name"])
            or not isinstance(record.get("version"), str)
            or not _exact_version(record["version"])
        ):
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Cargo.lock package requires a crate name and exact version",
                    location,
                )
            )
            continue
        if any(
            key in record and not isinstance(record[key], str)
            for key in ("source", "checksum")
        ) or not isinstance(record.get("dependencies", []), list):
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Cargo.lock source, checksum, or dependencies have invalid types",
                    location,
                )
            )
            continue
        source = record.get("source", "path")
        instance = f"{source}#{record['name']}@{record['version']}"
        if instance in seen:
            diagnostics.append(
                _error(
                    "lock.invalid",
                    "Duplicate Cargo.lock package source/name/version",
                    location,
                )
            )
            continue
        seen.add(instance)
        valid.append((record, location, instance))
    direct: set[str] = set()
    for declaration in declarations:
        if declaration.kind != "direct":
            continue
        named = [(r, i) for r, _, i in valid if r["name"] == declaration.package.name]
        source_matches = [
            (_source_matches(declaration, r.get("source")), r, i) for r, i in named
        ]
        sourced = [(r, i) for matches, r, i in source_matches if matches is True]
        if (
            named
            and not sourced
            and all(matches is False for matches, _, _ in source_matches)
        ):
            diagnostics.append(
                _error(
                    "resolution.cargo-source-mismatch",
                    f"Cargo.lock has no source matching the declaration of {declaration.package.name!r}",
                    declaration.source,
                )
            )
        if not declaration.package.purl or not sourced:
            continue  # Git/path/alternate registry evidence stays qualified.
        range_matches = [
            (_cargo_matches(declaration.constraint.raw, r["version"]), i)
            for r, i in sourced
        ]
        direct_candidates = [i for matches, i in range_matches if matches is True]
        if any(matches is None for matches, _ in range_matches):
            diagnostics.append(
                _error(
                    "resolution.cargo-constraint-unknown",
                    f"Cargo range {declaration.constraint.raw!r} for {declaration.package.name!r} cannot be compared safely with lock evidence",
                    declaration.source,
                )
            )
        elif len(direct_candidates) == 1:
            direct.add(direct_candidates[0])
        elif len(direct_candidates) > 1:
            diagnostics.append(
                _error(
                    "resolution.cargo-direct-ambiguous",
                    f"Cargo declaration {declaration.package.name!r} has multiple registry lock candidates; directness is unknown",
                    declaration.source,
                )
            )
        else:
            diagnostics.append(
                _error(
                    "resolution.cargo-constraint-mismatch",
                    f"Cargo.lock versions for {declaration.package.name!r} do not satisfy its declared range {declaration.constraint.raw!r}",
                    declaration.source,
                )
            )
    resolved = []
    for record, location, instance in valid:
        source = record.get("source")
        registry = source in _CRATES_IO
        if not registry:
            diagnostics.append(
                _error(
                    "security.cargo-source-unverified",
                    f"Cargo.lock {record['name']} source {source or 'path/workspace'!r} has no verified crates.io coordinate",
                    location,
                )
            )
        links = []
        for reference in record.get("dependencies", []):
            match = _LINK.fullmatch(reference) if isinstance(reference, str) else None
            if match is None:
                diagnostics.append(
                    _error(
                        "lock.invalid",
                        "Invalid Cargo.lock dependency reference",
                        location,
                    )
                )
                continue
            name, version, dependency_source = match.groups()
            candidates = [
                (r, i)
                for r, _, i in valid
                if r["name"] == name
                and (version is None or r["version"] == version)
                and (dependency_source is None or r.get("source") == dependency_source)
            ]
            if len(candidates) == 1:
                candidate, target_instance = candidates[0]
                links.append(
                    ResolvedDependencyLink(
                        _package(name, candidate.get("source") in _CRATES_IO),
                        candidate["version"],
                        target_instance,
                    )
                )
            else:
                diagnostics.append(
                    _error(
                        "resolution.cargo-link-ambiguous",
                        f"Cargo.lock dependency {reference!r} resolves to {len(candidates)} instances; no edge target was inferred",
                        location,
                    )
                )
                links.append(ResolvedDependencyLink(_package(name, False), version))
        resolved.append(
            ResolvedDependency(
                project.project_id,
                _package(record["name"], registry),
                record["version"],
                location,
                direct=instance in direct,
                integrity=record.get("checksum"),
                dependencies=tuple(link.package for link in links),
                instance_id=instance,
                dependency_links=tuple(links),
            )
        )
    diagnostics.append(
        Diagnostic(
            "resolution.cargo-activation-unknown",
            "warning",
            "Cargo.lock records a workspace/feature/target superset; active features, platform conditions, and deployed crates are unknown.",
            SourceLocation(lock),
        )
    )
    return tuple(resolved)


def _package(name: str, registry: bool) -> PackageRef:
    purl = f"pkg:cargo/{quote(name, safe='')}" if registry else None
    return PackageRef("Cargo", name, name, purl)


def _source_matches(
    declaration: DependencyDeclaration, source: str | None
) -> bool | None:
    if declaration.package.purl:
        return source in _CRATES_IO
    git = declaration.metadata.get("git")
    if not isinstance(git, str):
        return None  # Lock entries do not locate path crates or named registries.
    if source is None or not source.startswith("git+"):
        return False
    try:
        declared, locked = urlsplit(git), urlsplit(source[4:])
        if (declared.scheme, declared.netloc, declared.path) != (
            locked.scheme,
            locked.netloc,
            locked.path,
        ):
            return False
        selectors = parse_qs(locked.query)
        return all(
            selectors.get(key) == [declaration.metadata[key]]
            for key in ("rev", "tag", "branch")
            if key in declaration.metadata
        )
    except ValueError:
        return None


def _cargo_matches(raw: str, version: str) -> bool | None:
    # Reuse the stable semver intervals only after narrowing Cargo's grammar.
    # Cargo bare numeric requirements mean caret; npm's bare form differs.
    if (
        not raw
        or len(raw) > 256
        or len(version) > 128
        or "-" in raw
        or "-" in version
        or not _exact_version(version)
    ):
        return None
    tokens = []
    for part in raw.split(","):
        match = _REQUIREMENT_TOKEN.fullmatch(part.strip())
        if match is None:
            return None
        operator, value = match.groups()
        if any(
            int(component) > 2**64 - 1
            for component in value.split(".")
            if component != "*"
        ):
            return None
        if "*" in value:
            if operator or not re.fullmatch(r"\*|[0-9]+\.\*|[0-9]+\.[0-9]+\.\*", value):
                return None
        elif operator in {"=", ">", "<="} and len(value.split(".")) != 3:
            return None  # Partial comparisons differ from the shared npm helper.
        elif operator is None:
            operator = "^"
        tokens.append((operator or "") + value)
    intervals = EvidenceAnalyzer._semver_intervals(" ".join(tokens))
    if intervals is None:
        return None
    candidate = Version(version.split("+", 1)[0])
    return any(
        (lower is None or candidate > lower or candidate == lower and lower_inclusive)
        and (
            upper is None or candidate < upper or candidate == upper and upper_inclusive
        )
        for lower, lower_inclusive, upper, upper_inclusive in intervals
    )


def _in_child_project(path: Path, project_root: Path) -> bool:
    directory = path.parent
    while directory != project_root and directory.is_relative_to(project_root):
        if (directory / "Cargo.toml").is_file():
            return True
        directory = directory.parent
    return False


def _table(data: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    table: Any = data
    for key in keys:
        table = table.get(key, {}) if isinstance(table, dict) else {}
    return table if isinstance(table, dict) else {}


def _metadata_value(value: Any) -> Any:
    # TOML dates and invalid extension values must remain serializable evidence.
    return json.loads(json.dumps(value, default=str))


def _error(code: str, message: str, path: Path | SourceLocation) -> Diagnostic:
    source = path if isinstance(path, SourceLocation) else SourceLocation(path)
    return Diagnostic(code, "error", message, source)


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
