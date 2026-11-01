"""Cargo discovery and collection orchestration, with literal manifest declarations."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from depcheck.ecosystems.registry import EcosystemPack, ProviderContext
from depcheck.ecosystems.rust.common import (
    _LEGACY_EDITIONS,
    _NAME,
    _SECTIONS,
    _Document,
    _error,
    _exact_version,
    _local_path,
    _metadata_value,
    _package,
    _read_document,
    _table,
)
from depcheck.ecosystems.rust.lock import _collect_lock
from depcheck.ecosystems.rust.overrides import _CargoOverrides, _collect_overrides
from depcheck.ecosystems.rust.source import collect_rust_references
from depcheck.ecosystems.rust.workspace import (
    _cargo_edition,
    _legacy_section,
    _package_table,
    _workspace_diagnostics,
    _workspace_for,
)
from depcheck.ecosystems.static import StaticReadError, discover_files, exclusions_for
from depcheck.evidence.origins import redact_source
from depcheck.filesystem import repository_operation
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    ProjectUnit,
    ResolvedDependency,
    VersionConstraint,
)


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
        overrides = _CargoOverrides({})
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
            for path, item in documents.items():
                collected = _collect_overrides(
                    item,
                    diagnostics,
                    applicable=path == (workspace or manifest),
                )
                overrides.by_name.update(collected.by_name)
                overrides.unknown |= collected.unknown

        resolved: tuple[ResolvedDependency, ...] = ()
        if project.locks:
            lock = root / project.locks[0]
            try:
                resolved = _collect_lock(
                    root, project, lock, declarations, diagnostics, overrides
                )
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
            tuple(
                replace(item, metadata=redact_source(dict(item.metadata)))
                for item in declarations
            ),
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


def _in_child_project(path: Path, project_root: Path) -> bool:
    directory = path.parent
    while directory != project_root and directory.is_relative_to(project_root):
        if (directory / "Cargo.toml").is_file():
            return True
        directory = directory.parent
    return False


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
