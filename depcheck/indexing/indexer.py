from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from depcheck.model import AnalysisReport, ScanResult
from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.config import DepcheckConfig, load_project_config
from depcheck.ecosystems import create_default_registry
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.model import EvidenceBundle, ProjectUnit
from depcheck.ecosystems.python import (
    adapt_python_bundle,
    create_python_pack,
    filter_python_manifest,
)
from depcheck.ecosystems.static import discover_files
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.ecosystems.python_manifest import PythonManifestCollector

from .models import INDEX_SCHEMA, IndexRefreshResult
from .store import IndexStore


_ECOSYSTEM_MANIFEST_NAMES = frozenset(
    {
        "CMakeLists.txt",
        "build.gradle",
        "build.gradle.kts",
        "conan.lock",
        "conanfile.py",
        "conanfile.txt",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "package.json",
        "pom.xml",
        "vcpkg-lock.json",
        "vcpkg.json",
    }
)
_ECOSYSTEM_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".go",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
    }
)


class RepositoryIndexer:
    """把易变的源码扫描结果转换为可复用的项目本地证据索引。"""

    def __init__(self, import_scanner: ImportScanner | None = None) -> None:
        self.import_scanner = import_scanner or ImportScanner()

    def refresh(
        self,
        project_root: Path,
        *,
        index_path: Path | None = None,
        ecosystems: tuple[str, ...] = (),
        project_ids: tuple[str, ...] = (),
    ) -> IndexRefreshResult:
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise ValueError(f"project root is not a directory: {root}")
        config = load_project_config(root)
        selected_ecosystems = _canonical_ecosystems(ecosystems)
        selected_projects = tuple(sorted(set(project_ids)))
        scope = _index_scope(selected_ecosystems, selected_projects)
        selection_digest = _mapping_digest(
            {
                "ecosystems": "\0".join(selected_ecosystems),
                "project_ids": "\0".join(selected_projects),
            }
        )
        if selected_ecosystems or selected_projects:
            return self._refresh_filtered(
                root,
                config,
                index_path=index_path,
                ecosystems=selected_ecosystems,
                project_ids=selected_projects,
                scope=scope,
                selection_digest=selection_digest,
            )
        import_scanner = (
            self.import_scanner
            if not config.excluded_directories
            else ImportScanner(config.excluded_directories)
        )
        config_digest = _config_digest(config)
        git_head = _git_head(root)
        resolved_index_path = (
            Path(index_path).resolve()
            if index_path is not None
            else root / ".depcheck" / "index.sqlite3"
        )
        existed_before = resolved_index_path.is_file()

        with IndexStore(root, index_path) as store:
            metadata = store.metadata()
            created = not existed_before or store.rebuilt
            previous_python = store.file_digests("python")
            python_paths = import_scanner.discover_files(root)
            python_by_relative = {_relative(root, path): path for path in python_paths}
            python_digests = {
                relative: _file_digest(path)
                for relative, path in python_by_relative.items()
            }
            topology_digest = _mapping_digest(
                {path: "python" for path in python_digests}
            )
            topology_changed = metadata.get("topology_digest") != topology_digest
            changed_python = {
                path
                for path, digest in python_digests.items()
                if topology_changed or previous_python.get(path) != digest
            }
            removed_python = set(previous_python) - set(python_digests)

            reporter = PythonManifestCollector(root, config.excluded_directories)
            discovered_manifests = {
                _relative(root, path) for path in reporter.find_dependency_file()
            }
            previous_manifests = store.file_digests("manifest")
            manifest_candidates = discovered_manifests | set(previous_manifests)
            candidate_manifest_digests = {
                path: _file_digest(root / path)
                for path in sorted(manifest_candidates)
                if (root / path).is_file()
            }
            manifest_changed = candidate_manifest_digests != previous_manifests
            ecosystem_digests = _ecosystem_digests(root, config)

            workspace_digest = _state_digest(
                python_digests,
                candidate_manifest_digests,
                config_digest,
                ecosystem_digests,
            )
            unchanged = (
                not created
                and not changed_python
                and not removed_python
                and not manifest_changed
                and metadata.get("workspace_digest") == workspace_digest
                and metadata.get("git_head", "") == (git_head or "")
                and metadata.get("config_digest") == config_digest
                and metadata.get("selection_digest") == selection_digest
            )
            if unchanged:
                return IndexRefreshResult(
                    index_path=store.path,
                    status="current",
                    scanned_python_files=0,
                    reused_python_files=len(python_digests),
                    parsed_manifest_files=0,
                    reused_manifest_files=len(candidate_manifest_digests),
                    removed_files=0,
                    complete=metadata.get("complete") == "true",
                    finding_count=int(metadata.get("finding_count", "0")),
                    diagnostic_count=int(metadata.get("diagnostic_count", "0")),
                    scope=scope,
                )

            changed_paths = [
                python_by_relative[path] for path in sorted(changed_python)
            ]
            changed_imports = import_scanner.scan_files(root, changed_paths)
            manifest_result = reporter.collect() if manifest_changed else None
            if manifest_result is not None:
                manifest_digests = {
                    _relative(root, path): _file_digest(path)
                    for path in manifest_result.files
                    if path.is_file()
                }
            else:
                manifest_digests = candidate_manifest_digests

            with store.transaction():
                store.remove_files(sorted(removed_python))
                for relative in sorted(changed_python):
                    absolute = python_by_relative[relative]
                    file_imports = tuple(
                        item
                        for item in changed_imports.imports
                        if item.source.path == absolute
                    )
                    diagnostics = tuple(
                        item
                        for item in changed_imports.diagnostics
                        if item.source is not None and item.source.path == absolute
                    )
                    store.replace_python_file(
                        relative,
                        python_digests[relative],
                        file_imports,
                        diagnostics,
                    )
                if manifest_result is not None:
                    store.replace_manifests(manifest_result, manifest_digests)

                cached_imports = store.load_imports()
                manifests = store.load_manifests()
                project_id = ProjectUnit.stable_id(Path("."), "PyPI", "python")
                relative_manifests = tuple(
                    Path(path) for path in sorted(manifest_digests)
                )
                project = ProjectUnit(
                    project_id=project_id,
                    root=Path("."),
                    language="python",
                    ecosystem="PyPI",
                    manager="python",
                    manifests=relative_manifests,
                    locks=tuple(
                        path
                        for path in relative_manifests
                        if path.name
                        in {"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"}
                    ),
                )
                pack = create_python_pack(
                    config.mapping_for("PyPI", project.project_id)
                )
                bundle = adapt_python_bundle(
                    root,
                    project,
                    pack,
                    filter_python_manifest(manifests, config.python_version),
                    cached_imports,
                )
                python_enabled = any(
                    item.lower() == "pypi" for item in config.enabled_ecosystems
                )
                has_python_evidence = bool(cached_imports.files or manifests.files)
                repository_reports = (
                    [EvidenceAnalyzer().analyze(bundle)]
                    if python_enabled and has_python_evidence
                    else []
                )
                repository_bundles = (
                    [bundle] if python_enabled and has_python_evidence else []
                )
                non_python_ecosystems = tuple(
                    item for item in config.enabled_ecosystems if item.lower() != "pypi"
                )
                if non_python_ecosystems:
                    non_python = RepositoryScanner().scan(
                        root,
                        RepositoryScanOptions(
                            security=False,
                            enabled_ecosystems=non_python_ecosystems,
                            ignored_packages=config.ignored_packages,
                        ),
                    )
                    repository_reports.append(_report_from_scan(non_python))
                    repository_bundles.extend(non_python.bundles)
                repository_report = _combine_reports(repository_reports)
                evidence_complete = all(
                    item.complete for item in repository_reports
                ) and all(
                    status.complete
                    for item in repository_bundles
                    for status in item.capabilities
                )
                repository_complete = evidence_complete and bool(
                    scope["repository_complete"]
                )
                final_workspace_digest = _state_digest(
                    python_digests,
                    manifest_digests,
                    config_digest,
                    ecosystem_digests,
                )
                store.replace_analysis(repository_report)
                store.replace_evidence(repository_bundles)
                store.set_metadata(
                    {
                        "schema": INDEX_SCHEMA,
                        "root": root.as_posix(),
                        "git_head": git_head or "",
                        "indexed_at": datetime.now(UTC).isoformat(),
                        "workspace_digest": final_workspace_digest,
                        "topology_digest": topology_digest,
                        "config_digest": config_digest,
                        "selection_digest": selection_digest,
                        "scope": json.dumps(scope, sort_keys=True),
                        "import_mapping": json.dumps(
                            dict(repository_report.import_mapping), sort_keys=True
                        ),
                        "complete": "true" if repository_complete else "false",
                        "status": (
                            "incomplete"
                            if not scope["repository_complete"]
                            else "error"
                            if not evidence_complete
                            else "fail"
                            if repository_report.findings
                            else "pass"
                        ),
                        "finding_count": str(len(repository_report.findings)),
                        "diagnostic_count": str(len(repository_report.diagnostics)),
                        "source_file_count": str(
                            len(
                                {
                                    _relative(root, path)
                                    for item in repository_bundles
                                    for path in item.source_files
                                }
                            )
                        ),
                        "python_file_count": str(
                            len(
                                {
                                    _relative(root, path)
                                    for item in repository_bundles
                                    if item.project.ecosystem.lower() == "pypi"
                                    for path in item.source_files
                                }
                            )
                        ),
                        "manifest_file_count": str(
                            len(
                                {
                                    path.as_posix()
                                    for item in repository_bundles
                                    for path in item.project.manifests
                                }
                            )
                        ),
                        "import_location_count": str(
                            sum(len(item.usages) for item in repository_bundles)
                        ),
                        "declaration_count": str(
                            sum(len(item.declarations) for item in repository_bundles)
                        ),
                    }
                )

            return IndexRefreshResult(
                index_path=store.path,
                status="created" if created else "updated",
                scanned_python_files=len(changed_python),
                reused_python_files=len(python_digests) - len(changed_python),
                parsed_manifest_files=(
                    len(manifest_result.files) if manifest_result is not None else 0
                ),
                reused_manifest_files=(
                    0 if manifest_result is not None else len(manifest_digests)
                ),
                removed_files=len(removed_python)
                + len(set(previous_manifests) - set(manifest_digests)),
                complete=repository_complete,
                finding_count=len(repository_report.findings),
                diagnostic_count=len(repository_report.diagnostics),
                scope=scope,
            )

    def _refresh_filtered(
        self,
        root: Path,
        config: DepcheckConfig,
        *,
        index_path: Path | None,
        ecosystems: tuple[str, ...],
        project_ids: tuple[str, ...],
        scope: dict[str, Any],
        selection_digest: str,
    ) -> IndexRefreshResult:
        options = RepositoryScanOptions(
            security=False,
            enabled_ecosystems=ecosystems if ecosystems else None,
            project_ids=project_ids,
            ignored_packages=config.ignored_packages,
        )
        result = RepositoryScanner().scan(root, options)
        bundles = result.bundles
        report = _report_from_scan(result)
        config_digest = _config_digest(config)
        file_digests = _bundle_file_digests(root, bundles)
        workspace_digest = _filtered_workspace_digest(
            file_digests,
            config_digest,
            selection_digest,
        )
        git_head = _git_head(root)
        source_files = {
            _relative(root, path) for bundle in bundles for path in bundle.source_files
        }
        python_files = {
            _relative(root, path)
            for bundle in bundles
            if bundle.project.ecosystem.lower() == "pypi"
            for path in bundle.source_files
        }
        manifest_files = {
            path.as_posix() for bundle in bundles for path in bundle.project.manifests
        }
        evidence_complete = result.capability("dependency_hygiene").complete and all(
            status.complete for bundle in bundles for status in bundle.capabilities
        )
        resolved_index_path = (
            Path(index_path).resolve()
            if index_path is not None
            else root / ".depcheck" / "index.sqlite3"
        )
        existed_before = resolved_index_path.is_file()

        with IndexStore(root, index_path) as store:
            metadata = store.metadata()
            created = not existed_before or store.rebuilt
            unchanged = (
                not created
                and metadata.get("workspace_digest") == workspace_digest
                and metadata.get("config_digest") == config_digest
                and metadata.get("selection_digest") == selection_digest
            )
            if unchanged:
                return IndexRefreshResult(
                    index_path=store.path,
                    status="current",
                    scanned_python_files=len(python_files),
                    reused_python_files=0,
                    parsed_manifest_files=len(manifest_files),
                    reused_manifest_files=0,
                    removed_files=0,
                    complete=False,
                    finding_count=int(metadata.get("finding_count", "0")),
                    diagnostic_count=int(metadata.get("diagnostic_count", "0")),
                    scope=scope,
                )

            with store.transaction():
                store.replace_analysis(report)
                store.replace_evidence(bundles)
                store.set_metadata(
                    {
                        "schema": INDEX_SCHEMA,
                        "root": root.as_posix(),
                        "git_head": git_head or "",
                        "indexed_at": datetime.now(UTC).isoformat(),
                        "workspace_digest": workspace_digest,
                        "topology_digest": "",
                        "config_digest": config_digest,
                        "selection_digest": selection_digest,
                        "scope": json.dumps(scope, sort_keys=True),
                        "import_mapping": json.dumps(
                            dict(report.import_mapping), sort_keys=True
                        ),
                        "complete": "false",
                        "evidence_complete": ("true" if evidence_complete else "false"),
                        "status": "incomplete",
                        "finding_count": str(len(report.findings)),
                        "diagnostic_count": str(len(report.diagnostics)),
                        "source_file_count": str(len(source_files)),
                        "python_file_count": str(len(python_files)),
                        "manifest_file_count": str(len(manifest_files)),
                        "import_location_count": str(
                            sum(len(bundle.usages) for bundle in bundles)
                        ),
                        "declaration_count": str(
                            sum(len(bundle.declarations) for bundle in bundles)
                        ),
                    }
                )

            return IndexRefreshResult(
                index_path=store.path,
                status="created" if created else "updated",
                scanned_python_files=len(python_files),
                reused_python_files=0,
                parsed_manifest_files=len(manifest_files),
                reused_manifest_files=0,
                removed_files=0,
                complete=False,
                finding_count=len(report.findings),
                diagnostic_count=len(report.diagnostics),
                scope=scope,
            )


class RepositoryIndex:
    """面向 CLI/MCP 的只读索引查询入口。"""

    def __init__(self, project_root: Path, *, index_path: Path | None = None) -> None:
        self.project_root = Path(project_root).resolve()
        self.index_path = (
            Path(index_path).resolve()
            if index_path is not None
            else self.project_root / ".depcheck" / "index.sqlite3"
        )

    def context(self) -> dict[str, Any]:
        if not self.index_path.is_file():
            return {
                "schema": INDEX_SCHEMA,
                "root": self.project_root.as_posix(),
                "index_path": self.index_path.as_posix(),
                "indexed": False,
                "indexed_at": None,
                "git_head": None,
                "stale": True,
                "stale_reasons": ["index-missing"],
                "complete": False,
                "status": "missing",
                "scope": {
                    "kind": "missing",
                    "repository_complete": False,
                    "ecosystems": [],
                    "project_ids": [],
                },
                "counts": {
                    "source_file_count": 0,
                    "python_file_count": 0,
                    "manifest_file_count": 0,
                    "import_location_count": 0,
                    "declaration_count": 0,
                    "finding_count": 0,
                    "diagnostic_count": 0,
                },
                "projects": [],
                "ecosystems": {},
                "incomplete_reasons": ["index-missing"],
                "index": {"schema": INDEX_SCHEMA, "indexed": False},
            }
        with IndexStore(self.project_root, self.index_path) as store:
            metadata = store.metadata()
            scope = _scope_from_metadata(metadata)
            current_digest: str | None
            if scope["repository_complete"]:
                current_digest = _current_workspace_digest(
                    self.project_root,
                    store.file_digests("manifest"),
                )
            else:
                current_digest = _current_filtered_workspace_digest(
                    self.project_root,
                    scope,
                )
            reasons: list[str] = []
            if metadata.get("workspace_digest") != current_digest:
                reasons.append("workspace-content")
            if scope["repository_complete"]:
                current_head = _git_head(self.project_root) or ""
                if metadata.get("git_head", "") != current_head:
                    reasons.append("git-head")
            projects = store.projects()
            incomplete_reasons = sorted(
                {
                    str(capability["reason"])
                    for project in projects
                    for capability in project["capabilities"].values()
                    if not capability["complete"] and capability["reason"]
                }
            )
            if not scope["repository_complete"]:
                incomplete_reasons.append("index-selection")
            return {
                "schema": metadata.get("schema"),
                "root": metadata.get("root"),
                "index_path": self.index_path.as_posix(),
                "indexed": True,
                "indexed_at": metadata.get("indexed_at"),
                "git_head": metadata.get("git_head") or None,
                "stale": bool(reasons),
                "stale_reasons": reasons,
                "complete": metadata.get("complete") == "true",
                "status": metadata.get("status"),
                "scope": scope,
                "projects": projects,
                "ecosystems": store.ecosystem_summary(),
                "incomplete_reasons": incomplete_reasons,
                "index": {
                    "schema": metadata.get("schema"),
                    "indexed": True,
                    "indexed_at": metadata.get("indexed_at"),
                },
                "counts": {
                    key: int(metadata.get(key, "0"))
                    for key in (
                        "source_file_count",
                        "python_file_count",
                        "manifest_file_count",
                        "import_location_count",
                        "declaration_count",
                        "finding_count",
                        "diagnostic_count",
                    )
                },
            }

    def findings(
        self, *, package: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        self._require_index()
        with IndexStore(self.project_root, self.index_path) as store:
            return store.findings(package=package, limit=limit)

    def dependencies(
        self,
        *,
        search: str | None = None,
        ecosystem: str | None = None,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self._require_index()
        with IndexStore(self.project_root, self.index_path) as store:
            return store.dependency_inventory(
                search=search,
                ecosystem=ecosystem,
                project_id=project_id,
                limit=limit,
            )

    def _require_index(self) -> None:
        if not self.index_path.is_file():
            raise FileNotFoundError(
                f"repository index does not exist: {self.index_path}"
            )


def _current_filtered_workspace_digest(
    root: Path,
    scope: dict[str, Any],
) -> str | None:
    config = load_project_config(root)
    ecosystems = tuple(str(item) for item in scope["ecosystems"])
    project_ids = tuple(str(item) for item in scope["project_ids"])
    try:
        result = RepositoryScanner().scan(
            root,
            RepositoryScanOptions(
                security=False,
                enabled_ecosystems=ecosystems if ecosystems else None,
                project_ids=project_ids,
                ignored_packages=config.ignored_packages,
            ),
        )
    except (KeyError, OSError, TypeError, ValueError):
        return None
    selection_digest = _mapping_digest(
        {
            "ecosystems": "\0".join(ecosystems),
            "project_ids": "\0".join(project_ids),
        }
    )
    return _filtered_workspace_digest(
        _bundle_file_digests(root, result.bundles),
        _config_digest(config),
        selection_digest,
    )


def _current_workspace_digest(root: Path, previous_manifests: dict[str, str]) -> str:
    config = load_project_config(root)
    scanner = ImportScanner(config.excluded_directories)
    python_digests = {
        _relative(root, path): _file_digest(path)
        for path in scanner.discover_files(root)
    }
    reporter = PythonManifestCollector(root, config.excluded_directories)
    discovered = {_relative(root, path) for path in reporter.find_dependency_file()}
    candidates = discovered | set(previous_manifests)
    manifest_digests = {
        path: _file_digest(root / path)
        for path in sorted(candidates)
        if (root / path).is_file()
    }
    return _state_digest(
        python_digests,
        manifest_digests,
        _config_digest(config),
        _ecosystem_digests(root, config),
    )


def _config_digest(config: DepcheckConfig) -> str:
    payload = asdict(config)
    payload["import_mapping"] = dict(sorted(config.import_mapping.items()))
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping_digest(values: dict[str, str]) -> str:
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _canonical_ecosystems(values: tuple[str, ...]) -> tuple[str, ...]:
    registry = create_default_registry()
    selected: dict[str, str] = {}
    for value in values:
        normalized = value.strip()
        if normalized:
            try:
                canonical = registry.get(normalized).ecosystem
            except KeyError as exc:
                raise ValueError(f"unknown ecosystem: {normalized}") from exc
            selected.setdefault(canonical.lower(), canonical)
    return tuple(selected[key] for key in sorted(selected))


def _index_scope(
    ecosystems: tuple[str, ...],
    project_ids: tuple[str, ...],
) -> dict[str, Any]:
    filtered = bool(ecosystems or project_ids)
    return {
        "kind": "filtered" if filtered else "repository",
        "repository_complete": not filtered,
        "ecosystems": list(ecosystems),
        "project_ids": list(project_ids),
    }


def _scope_from_metadata(metadata: dict[str, str]) -> dict[str, Any]:
    raw = metadata.get("scope")
    if raw is None:
        return _index_scope((), ())
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return _index_scope((), ())
    if not isinstance(decoded, dict):
        return _index_scope((), ())
    ecosystems = decoded.get("ecosystems", [])
    project_ids = decoded.get("project_ids", [])
    if not isinstance(ecosystems, list) or not all(
        isinstance(item, str) for item in ecosystems
    ):
        return _index_scope((), ())
    if not isinstance(project_ids, list) or not all(
        isinstance(item, str) for item in project_ids
    ):
        return _index_scope((), ())
    return _index_scope(tuple(ecosystems), tuple(project_ids))


def _bundle_file_digests(
    root: Path,
    bundles: tuple[EvidenceBundle, ...],
) -> dict[str, str]:
    candidates = {
        path
        for bundle in bundles
        for path in (
            *bundle.source_files,
            *bundle.evidence_files,
            *bundle.project.manifests,
            *bundle.project.locks,
        )
    }
    result: dict[str, str] = {}
    for path in candidates:
        candidate = Path(path) if Path(path).is_absolute() else root / path
        try:
            relative = candidate.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if candidate.is_file():
            result[relative] = _file_digest(candidate)
    return dict(sorted(result.items()))


def _filtered_workspace_digest(
    file_digests: dict[str, str],
    config_digest: str,
    selection_digest: str,
) -> str:
    return _mapping_digest(
        {
            **{f"selected:{key}": value for key, value in file_digests.items()},
            "config": config_digest,
            "selection": selection_digest,
        }
    )


def _state_digest(
    python_digests: dict[str, str],
    manifest_digests: dict[str, str],
    config_digest: str,
    ecosystem_digests: dict[str, str] | None = None,
) -> str:
    return _mapping_digest(
        {
            **{f"python:{key}": value for key, value in python_digests.items()},
            **{f"manifest:{key}": value for key, value in manifest_digests.items()},
            **{
                f"ecosystem:{key}": value
                for key, value in (ecosystem_digests or {}).items()
            },
            "config": config_digest,
        }
    )


def _ecosystem_digests(
    root: Path,
    config: DepcheckConfig,
) -> dict[str, str]:
    paths = discover_files(
        root,
        names=_ECOSYSTEM_MANIFEST_NAMES,
        suffixes=_ECOSYSTEM_SOURCE_SUFFIXES,
        excluded_directories=config.excluded_directories,
    )
    return {_relative(root, path): _file_digest(path) for path in paths}


def _report_from_scan(result: ScanResult) -> AnalysisReport:
    return AnalysisReport(
        findings=result.findings,
        diagnostics=result.diagnostics,
        import_mapping={
            usage.reference: usage.mapped_package.name
            for bundle in result.bundles
            for usage in bundle.usages
            if usage.mapped_package is not None
        },
    )


def _combine_reports(reports: list[AnalysisReport]) -> AnalysisReport:
    return AnalysisReport(
        findings=tuple(
            sorted(
                (finding for report in reports for finding in report.findings),
                key=lambda item: (item.code, item.package.sort_key, item.message),
            )
        ),
        diagnostics=tuple(
            diagnostic for report in reports for diagnostic in report.diagnostics
        ),
        import_mapping={
            reference: package
            for report in reports
            for reference, package in report.import_mapping.items()
        },
    )


def _relative(root: Path, path: Path) -> str:
    return Path(path).resolve().relative_to(root).as_posix()


def _git_head(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None
