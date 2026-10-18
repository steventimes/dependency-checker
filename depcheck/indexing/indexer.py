from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.bounded_io import repository_operation
from depcheck.config import DepcheckConfig, load_project_config
from depcheck.ecosystems import create_default_registry
from depcheck.ecosystems.python import _uv_workspace_root, named_component_roots
from depcheck.ecosystems.python_manifest import PythonManifestCollector
from depcheck.ecosystems.python_script import inline_script_files
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import ANALYSIS_REVISION as ANALYSIS_REVISION
from depcheck.model import ScanResult
from depcheck.path_policy import default_index_path, external_path_executable
from depcheck.profiling import measured

from .analysis import _report_from_scan, analyze_cached_evidence
from .fingerprints import (
    _bundle_file_digests,
    _config_digest,
    _ecosystem_digests,
    _filtered_workspace_digest,
    _freshness_unchanged,
    _manifest_digests,
    _mapping_digest,
    _state_digest,
    freshness_guard,
)
from .fingerprints import (
    _file_digest as _file_digest,
)
from .fingerprints import (
    _relative as _relative,
)
from .models import INDEX_SCHEMA, IndexRefreshResult
from .publication import evidence_metadata
from .store import IndexStore


class RepositoryIndexer:
    """把易变的源码扫描结果转换为可复用的项目本地证据索引。"""

    def __init__(self, import_scanner: ImportScanner | None = None) -> None:
        self.import_scanner = import_scanner or ImportScanner()

    @repository_operation("project_root")
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
        component_roots = named_component_roots(
            root,
            {
                "excluded_directories": config.excluded_directories,
                "python_roots": config.python_roots,
            },
        )
        if (
            selected_ecosystems
            or selected_projects
            or any(p != Path(".") for p in component_roots)
            or _uv_workspace_root(root, root) is not None
            or inline_script_files(root, config.excluded_directories)
        ):
            return self._refresh_filtered(
                root,
                config,
                index_path=index_path,
                ecosystems=selected_ecosystems,
                project_ids=selected_projects,
                scope=scope,
                selection_digest=selection_digest,
            )
        return self._refresh_incremental(
            root, config, index_path, scope, selection_digest
        )

    def _refresh_incremental(
        self,
        root: Path,
        config: DepcheckConfig,
        index_path: Path | None,
        scope: dict[str, Any],
        selection_digest: str,
    ) -> IndexRefreshResult:
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
                if topology_changed
                or metadata.get("config_digest") != config_digest
                or previous_python.get(path) != digest
            }
            removed_python = set(previous_python) - set(python_digests)

            reporter = PythonManifestCollector(root, config.excluded_directories)
            discovered_manifests = {
                _relative(root, path) for path in reporter.find_dependency_file()
            }
            previous_manifests = store.file_digests("manifest")
            manifest_candidates = discovered_manifests | set(previous_manifests)
            candidate_manifest_digests = _manifest_digests(
                root, manifest_candidates, config.excluded_directories
            )
            manifest_changed = (
                candidate_manifest_digests != previous_manifests
                or metadata.get("config_digest") != config_digest
            )
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
            # 按文件分组一次，避免每写入一个文件都遍历全部导入证据。
            imports_by_path = defaultdict(list)
            diagnostics_by_path = defaultdict(list)
            for item in changed_imports.imports:
                imports_by_path[item.source.path].append(item)
            for diagnostic in changed_imports.diagnostics:
                if diagnostic.source is not None:
                    diagnostics_by_path[diagnostic.source.path].append(diagnostic)
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
                    store.replace_python_file(
                        relative,
                        python_digests[relative],
                        tuple(imports_by_path[absolute]),
                        tuple(diagnostics_by_path[absolute]),
                    )
                if manifest_result is not None:
                    store.replace_manifests(manifest_result, manifest_digests)

                analysis = analyze_cached_evidence(
                    root, config, store, manifest_digests
                )
                repository_bundles = analysis.bundles
                repository_report = analysis.report
                coverage = analysis.coverage
                evidence_complete = analysis.complete
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
                        **evidence_metadata(
                            root, repository_report, repository_bundles
                        ),
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
                        "git_head": git_head or "",
                        "workspace_digest": final_workspace_digest,
                        "topology_digest": topology_digest,
                        "refresh_mode": "incremental",
                        "config_digest": config_digest,
                        "selection_digest": selection_digest,
                        "scope": json.dumps(scope, sort_keys=True),
                        "coverage": json.dumps(coverage, sort_keys=True),
                        "complete": "true" if repository_complete else "false",
                        "status": "incomplete"
                        if not scope["repository_complete"]
                        else "error"
                        if not evidence_complete
                        else "fail"
                        if repository_report.findings
                        else "pass",
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
        scan_result: ScanResult | None = None,
        scan_receipts: dict[Path, str] | None = None,
        scan_guard: str | None = None,
    ) -> IndexRefreshResult:
        freshness_cache_path = (
            Path(index_path).resolve()
            if index_path is not None
            else default_index_path(root)
        )
        captured_guard = freshness_guard(root, config, freshness_cache_path)
        options = RepositoryScanOptions(
            security=False,
            compatibility=False,
            enabled_ecosystems=ecosystems if ecosystems else None,
            project_ids=project_ids,
            ignored_packages=config.ignored_packages,
        )
        result = (
            scan_result
            if scan_result is not None
            else RepositoryScanner().scan(root, options)
        )
        bundles = result.bundles
        report = _report_from_scan(result)
        config_digest = _config_digest(config)
        file_digests = _bundle_file_digests(root, bundles)
        if scan_receipts is not None:
            # Compare the fingerprints being stored with the bytes used by the
            # scan. A separate check before fingerprinting leaves a race where
            # new bytes can be fingerprinted alongside the old analysis.
            changed = captured_guard != scan_guard
            for path, digest in scan_receipts.items():
                actual = file_digests.get(_relative(root, path))
                if actual is None:
                    actual = _file_digest(path)
                changed |= actual != digest
            if changed:
                raise RuntimeError(
                    "repository evidence changed during scanning; index was not replaced"
                )
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
                and (
                    not scope["repository_complete"]
                    or metadata.get("git_head", "") == (git_head or "")
                )
            )
            complete = bool(scope["repository_complete"] and evidence_complete)
            if unchanged:
                return IndexRefreshResult(
                    index_path=store.path,
                    status="current",
                    scanned_python_files=len(python_files),
                    reused_python_files=0,
                    parsed_manifest_files=len(manifest_files),
                    reused_manifest_files=0,
                    removed_files=0,
                    complete=complete,
                    finding_count=int(metadata.get("finding_count", "0")),
                    diagnostic_count=int(metadata.get("diagnostic_count", "0")),
                    scope=scope,
                )

            with store.transaction():
                store.replace_analysis(report)
                store.replace_evidence(bundles)
                store.set_metadata(
                    {
                        **evidence_metadata(root, report, bundles),
                        "source_file_count": str(len(source_files)),
                        "python_file_count": str(len(python_files)),
                        "manifest_file_count": str(len(manifest_files)),
                        "git_head": git_head or "",
                        "workspace_digest": workspace_digest,
                        "topology_digest": "",
                        "config_digest": config_digest,
                        "selection_digest": selection_digest,
                        "refresh_mode": "scan",
                        "freshness_guard": captured_guard
                        if captured_guard
                        == freshness_guard(root, config, freshness_cache_path)
                        else "",
                        "freshness_files": json.dumps(file_digests, sort_keys=True),
                        "scope": json.dumps(scope, sort_keys=True),
                        "coverage": json.dumps(
                            result.metadata["coverage"], sort_keys=True
                        ),
                        "complete": "true" if complete else "false",
                        "evidence_complete": "true" if evidence_complete else "false",
                        "status": "incomplete"
                        if not complete
                        else ("issues" if report.findings else "ok"),
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
                complete=complete,
                finding_count=len(report.findings),
                diagnostic_count=len(report.diagnostics),
                scope=scope,
            )

    @repository_operation("project_root")
    def refresh_from_scan(
        self,
        project_root: Path,
        result: ScanResult,
        receipts: dict[Path, str],
        guard: str,
    ) -> IndexRefreshResult:
        root = Path(project_root).resolve()
        if result.root != root:
            raise ValueError("scan result belongs to a different repository")
        config = load_project_config(root)
        return self._refresh_filtered(
            root,
            config,
            index_path=None,
            ecosystems=(),
            project_ids=(),
            scope=_index_scope((), ()),
            selection_digest=_mapping_digest({"ecosystems": "", "project_ids": ""}),
            scan_result=result,
            scan_receipts=receipts,
            scan_guard=guard,
        )


class RepositoryIndex:
    """面向 CLI/MCP 的只读索引查询入口。"""

    def __init__(self, project_root: Path, *, index_path: Path | None = None) -> None:
        self.project_root = Path(project_root).resolve()
        self.index_path = (
            Path(index_path).resolve()
            if index_path is not None
            else default_index_path(self.project_root)
        )

    @repository_operation("self.project_root")
    def context(self) -> dict[str, Any]:
        context = self._context()
        capabilities = create_default_registry().runtime_capabilities()
        context["runtime_capabilities"] = capabilities
        for project in context["projects"]:
            project["supported_capabilities"] = capabilities.get(
                project["ecosystem"], []
            )
        return context

    def _context(self) -> dict[str, Any]:
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
                "coverage": {"scope": "missing", "uncovered": []},
                "index": {"schema": INDEX_SCHEMA, "indexed": False},
            }
        with IndexStore(self.project_root, self.index_path, read_only=True) as store:
            metadata = store.metadata()
            scope = _scope_from_metadata(metadata)
            current_digest: str | None
            if scope["repository_complete"] and metadata.get("refresh_mode") != "scan":
                current_digest = _current_workspace_digest(
                    self.project_root,
                    store.file_digests("manifest"),
                )
            else:
                current_digest = _current_filtered_workspace_digest(
                    self.project_root,
                    scope,
                    metadata,
                    self.index_path,
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
            coverage = json.loads(metadata.get("coverage", '{"uncovered": []}'))
            incomplete_reasons.extend(
                entry["reason"] for entry in coverage.get("uncovered", [])
            )
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
                "incomplete_reasons": sorted(set(incomplete_reasons)),
                "coverage": coverage,
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
        with IndexStore(self.project_root, self.index_path, read_only=True) as store:
            return store.findings(package=package, limit=limit)

    @measured("query.dependencies")
    def dependencies(
        self,
        *,
        search: str | None = None,
        package: str | None = None,
        ecosystem: str | None = None,
        project_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        self._require_index()
        with IndexStore(self.project_root, self.index_path, read_only=True) as store:
            return store.dependency_inventory(
                search=search,
                package=package,
                ecosystem=ecosystem,
                project_id=project_id,
                limit=limit,
                offset=offset,
            )

    def dependency_origins(
        self, project_id: str, package: str, ecosystem: str, *, limit: int, depth: int
    ) -> dict[str, Any]:
        from depcheck.origins import dependency_origins

        self._require_index()
        with IndexStore(self.project_root, self.index_path, read_only=True) as store:
            return dependency_origins(
                project_id,
                package,
                ecosystem,
                store.dependency_graph(project_id),
                limit=limit,
                depth=depth,
            )

    def explanations(
        self,
        package: str,
        ecosystem: str | None,
        project_id: str | None,
        *,
        limit: int,
        origin_limit: int,
        origin_depth: int,
    ) -> list[dict[str, Any]]:
        from depcheck.origins import dependency_origins

        self._require_index()
        with IndexStore(self.project_root, self.index_path, read_only=True) as store:
            records = store.dependency_inventory(
                package=package, ecosystem=ecosystem, project_id=project_id, limit=limit
            )
            if len(records) == 1:
                record = records[0]
                record["origins"] = dependency_origins(
                    record["project_id"],
                    record["package"],
                    record["ecosystem"],
                    store.dependency_graph(record["project_id"]),
                    limit=origin_limit,
                    depth=origin_depth,
                )
            return records

    def _require_index(self) -> None:
        if not self.index_path.is_file():
            raise FileNotFoundError(
                f"repository index does not exist: {self.index_path}"
            )
        if self._context()["stale"]:
            raise RuntimeError(
                "repository index is stale; run 'depcheck index' before querying"
            )


def _current_filtered_workspace_digest(
    root: Path,
    scope: dict[str, Any],
    metadata: dict[str, str],
    index_path: Path,
) -> str | None:
    config = load_project_config(root)
    if _freshness_unchanged(root, config, metadata, index_path):
        return metadata.get("workspace_digest")
    ecosystems = tuple(str(item) for item in scope["ecosystems"])
    project_ids = tuple(str(item) for item in scope["project_ids"])
    try:
        result = RepositoryScanner().scan(
            root,
            RepositoryScanOptions(
                security=False,
                compatibility=False,
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
    manifest_digests = _manifest_digests(root, candidates, config.excluded_directories)
    return _state_digest(
        python_digests,
        manifest_digests,
        _config_digest(config),
        _ecosystem_digests(root, config),
    )


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


def _git_head(root: Path) -> str | None:
    executable = external_path_executable(root, "git")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None
