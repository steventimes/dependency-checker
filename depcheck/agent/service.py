from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.bounded_io import capture_reads, repository_operation
from depcheck.cmake_model import inspect_cmake_model
from depcheck.config import load_project_config
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.evidence_export import export_evidence
from depcheck.external_evidence import KINDS, inspect_external_evidence
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.indexing.fingerprints import freshness_guard
from depcheck.inventory_compare import compare_inventories
from depcheck.path_policy import default_index_path
from depcheck.python_calls import analyze_python_calls
from depcheck.sbom import inspect_sbom
from depcheck.security.evidence import inspect_security_evidence
from depcheck.security.offline import reevaluate_vulnerabilities
from depcheck.snapshots import compare_snapshots
from depcheck.supply_chain import (
    compare_package_behavior,
    compare_package_names,
    verify_registry_package,
)
from depcheck.update_planning import DependencyUpdatePlanner

from .gitnexus import GitNexusCompanion
from .paging import evidence_page


class DependencyAgentService:
    """供 CLI 与 MCP 共用的 agent 语义层，不包含传输协议细节。"""

    def __init__(
        self,
        project_root: Path,
        *,
        max_results: int = 50,
        code_index: GitNexusCompanion | None = None,
        authorized_root: Path | None = None,
    ) -> None:
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise ValueError(f"project root is not a directory: {root}")
        if max_results < 1:
            raise ValueError("max_results must be positive")
        self.project_root = root
        self._io_root = Path(authorized_root) if authorized_root is not None else root
        self.max_results = max_results
        self.code_index = code_index or GitNexusCompanion()

    @repository_operation("self._io_root")
    def index_repository(
        self,
        *,
        ecosystems: tuple[str, ...] = (),
        project_ids: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        result = RepositoryIndexer().refresh(
            self.project_root,
            ecosystems=ecosystems,
            project_ids=project_ids,
        )
        payload = asdict(result)
        payload["index_path"] = self._relative(result.index_path)
        payload["schema"] = "depcheck.agent.index-result.v1"
        return payload

    @repository_operation("self._io_root")
    def repository_context(self) -> dict[str, Any]:
        context = RepositoryIndex(self.project_root).context()
        context["code_index"] = self.code_index.inspect(self.project_root).to_dict()
        return context

    @repository_operation("self._io_root")
    def scan_repository(self) -> dict[str, Any]:
        with capture_reads() as receipts:
            guard = freshness_guard(
                self.project_root,
                load_project_config(self.project_root),
                default_index_path(self.project_root),
            )
            result = RepositoryScanner().scan(
                self.project_root,
                RepositoryScanOptions(security=False, compatibility=False),
            )
        payload = result.to_dict()
        findings = list(payload["findings"])
        payload["findings"] = findings[: self.max_results]
        payload["finding_count"] = len(findings)
        payload["truncated"] = len(findings) > self.max_results
        refreshed = RepositoryIndexer().refresh_from_scan(
            self.project_root, result, receipts, guard
        )
        payload["index"] = {
            **asdict(refreshed),
            "index_path": self._relative(refreshed.index_path),
            "schema": "depcheck.agent.index-result.v1",
        }
        payload["context"] = self.repository_context()
        return payload

    @repository_operation("self._io_root")
    def query_dependencies(
        self,
        query: str | None = None,
        *,
        search: str | None = None,
        ecosystem: str | None = None,
        project_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
        evidence_limit: int = 20,
        evidence_offset: int = 0,
    ) -> dict[str, Any]:
        if query is not None and search is not None:
            raise ValueError("query and search are aliases; provide only one")
        needle = search if search is not None else query
        effective_limit = self._limit(limit)
        records = RepositoryIndex(self.project_root).dependencies(
            search=needle,
            ecosystem=ecosystem,
            project_id=project_id,
            limit=effective_limit + 1,
            offset=offset,
        )
        truncated = len(records) > effective_limit
        return evidence_page(
            {
                "schema": "depcheck.agent.dependencies.v1",
                "query": needle,
                "ecosystem": ecosystem,
                "project_id": project_id,
                "count": min(len(records), effective_limit),
                "offset": offset,
                "next_offset": offset + effective_limit if truncated else None,
                "truncated": truncated,
                "dependencies": records[:effective_limit],
            },
            limit=evidence_limit,
            offset=evidence_offset,
        )

    @repository_operation("self._io_root")
    def _explain_dependency(
        self,
        package: str,
        *,
        ecosystem: str | None = None,
        project_id: str | None = None,
        origin_limit: int = 20,
        origin_depth: int = 32,
    ) -> dict[str, Any]:
        normalized = self._normalized_package(package, ecosystem)
        records = RepositoryIndex(self.project_root).explanations(
            package=normalized,
            ecosystem=ecosystem,
            project_id=project_id,
            limit=max(2, self.max_results),
            origin_limit=origin_limit,
            origin_depth=origin_depth,
        )
        matches = [
            record for record in records if self._package_matches(record, normalized)
        ]
        if not matches:
            return {
                "error": {
                    "code": "dependency.not-found",
                    "package": normalized,
                    "ecosystem": ecosystem,
                    "project_id": project_id,
                }
            }
        if len(matches) > 1:
            return {
                "error": {
                    "code": "dependency.ambiguous",
                    "package": normalized,
                    "choices": [self._identity(record) for record in matches],
                }
            }
        return {
            "schema": "depcheck.agent.dependency-explanation.v1",
            **matches[0],
        }

    @repository_operation("self._io_root")
    def explain_dependency(
        self,
        package: str,
        *,
        ecosystem: str | None = None,
        project_id: str | None = None,
        origin_limit: int = 20,
        origin_depth: int = 32,
        evidence_limit: int = 20,
        evidence_offset: int = 0,
    ) -> dict[str, Any]:
        return evidence_page(
            self._explain_dependency(
                package,
                ecosystem=ecosystem,
                project_id=project_id,
                origin_limit=origin_limit,
                origin_depth=origin_depth,
            ),
            limit=evidence_limit,
            offset=evidence_offset,
            derivation=True,
        )

    @repository_operation("self._io_root")
    def dependency_impact(
        self,
        package: str,
        *,
        ecosystem: str | None = None,
        project_id: str | None = None,
        origin_limit: int = 20,
        origin_depth: int = 32,
        evidence_limit: int = 20,
        evidence_offset: int = 0,
    ) -> dict[str, Any]:
        explanation = self._explain_dependency(
            package,
            ecosystem=ecosystem,
            project_id=project_id,
            origin_limit=origin_limit,
            origin_depth=origin_depth,
        )
        if "error" in explanation:
            return explanation
        usages = explanation["usages"]
        files = sorted({str(item["location"]["path"]) for item in usages})
        scopes: dict[str, int] = {}
        for item in usages:
            scope = str(item["scope"])
            scopes[scope] = scopes.get(scope, 0) + 1
        return evidence_page(
            {
                "schema": "depcheck.agent.dependency-impact.v1",
                "project_id": explanation["project_id"],
                "ecosystem": explanation["ecosystem"],
                "package": explanation["package"],
                "usage_count": len(usages),
                "usages": usages,
                "evidence_complete": explanation["evidence_complete"],
                "usage_complete": explanation["usage_complete"],
                "files": files,
                "scopes": dict(sorted(scopes.items())),
                "finding_codes": sorted(
                    {str(item["code"]) for item in explanation["findings"]}
                ),
                "code_graph": "dependency-evidence",
                "origins": explanation["origins"],
            },
            limit=evidence_limit,
            offset=evidence_offset,
        )

    @repository_operation("self._io_root")
    def inspect_dependency_sbom(
        self, sbom_file: str, *, limit: int | None = None, offset: int = 0
    ) -> dict[str, Any]:
        return inspect_sbom(
            self.project_root, sbom_file, limit=self._limit(limit), offset=offset
        )

    @repository_operation("self._io_root")
    def compare_inventories(
        self,
        before_file: str,
        after_file: str,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return compare_inventories(
            self.project_root,
            before_file,
            after_file,
            limit=self._limit(limit),
            offset=offset,
        )

    @repository_operation("self._io_root")
    def compare_package_behavior(
        self,
        before_file: str,
        after_file: str,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return compare_package_behavior(
            self.project_root,
            before_file,
            after_file,
            limit=self._limit(limit),
            offset=offset,
        )

    @repository_operation("self._io_root")
    def compare_package_names(
        self, package: str, references: list[str], ecosystem: str
    ) -> dict[str, Any]:
        return {
            "schema": "depcheck.package-name-signals.v1",
            "signals": compare_package_names(package, references, ecosystem),
            "maliciousness": "not-established",
            "automatic_replacement": False,
        }

    def verify_registry_package(
        self,
        ecosystem: str,
        package: str,
        *,
        version: str | None = None,
        allow_network: bool = False,
    ) -> dict[str, Any]:
        return verify_registry_package(
            ecosystem, package, version=version, allow_network=allow_network
        )

    @repository_operation("self._io_root")
    def analyze_python_calls(
        self, analysis_file: str, *, limit: int | None = None, offset: int = 0
    ) -> dict[str, Any]:
        return analyze_python_calls(
            self.project_root, analysis_file, limit=self._limit(limit), offset=offset
        )

    @repository_operation("self._io_root")
    def export_evidence(
        self,
        snapshot_file: str,
        kind: str,
        *,
        input_files: tuple[str, ...] = (),
        configuration_file: str | None = None,
    ) -> dict[str, Any]:
        return export_evidence(
            self.project_root,
            snapshot_file,
            kind=kind,
            input_files=input_files,
            configuration_file=configuration_file,
        )

    @repository_operation("self._io_root")
    def inspect_evidence(
        self,
        evidence_file: str,
        kind: str,
        *,
        artifact_file: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        effective_limit = self._limit(limit)
        if kind in KINDS:
            if artifact_file is not None:
                raise ValueError("artifact_file is supported only for attestations")
            return inspect_external_evidence(
                self.project_root,
                evidence_file,
                kind,
                limit=effective_limit,
                offset=offset,
            )
        if artifact_file is not None and kind != "attestation":
            raise ValueError("artifact_file is supported only for attestations")
        return inspect_security_evidence(
            self.project_root,
            evidence_file,
            kind,
            artifact_file=artifact_file,
            limit=effective_limit,
            offset=offset,
        )

    @repository_operation("self._io_root")
    def reevaluate_vulnerabilities(
        self,
        inventory_file: str,
        advisory_file: str,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return reevaluate_vulnerabilities(
            self.project_root,
            inventory_file,
            advisory_file,
            limit=self._limit(limit),
            offset=offset,
        )

    @repository_operation("self._io_root")
    def inspect_cmake_model(
        self,
        index_file: str,
        *,
        configuration: str | None = None,
        target: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return inspect_cmake_model(
            self.project_root,
            index_file,
            configuration=configuration,
            target=target,
            limit=self._limit(limit),
            offset=offset,
        )

    @repository_operation("self._io_root")
    def compare_dependency_snapshots(
        self,
        before_file: str,
        after_file: str,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> dict[str, Any]:
        return compare_snapshots(
            self.project_root,
            before_file,
            after_file,
            limit=self._limit(limit),
            offset=offset,
        )

    @repository_operation("self._io_root")
    def plan_dependency_updates(
        self,
        updates: dict[str, str],
        *,
        add_missing: bool = False,
        ecosystem: str | None = None,
        project_id: str | None = None,
        target_file: str | None = None,
        group: str | None = None,
    ) -> dict[str, Any]:
        return DependencyUpdatePlanner(self.project_root).plan(
            updates,
            add_missing=add_missing,
            ecosystem=ecosystem,
            project_id=project_id,
            target_file=target_file,
            group=group,
        )

    @staticmethod
    def _normalized_package(package: str, ecosystem: str | None) -> str:
        value = str(package).strip()
        if not value:
            raise ValueError("package must be non-empty")
        if ecosystem is not None and ecosystem.lower() == "pypi":
            return str(canonicalize_name(value))
        if ecosystem is not None and ecosystem.lower() == "cmake":
            return value.casefold()
        return value

    @staticmethod
    def _package_matches(record: dict[str, Any], package: str) -> bool:
        candidate = str(record["package"])
        if str(record["ecosystem"]).lower() == "pypi":
            return str(canonicalize_name(candidate)) == str(canonicalize_name(package))
        return candidate.lower() == package.lower()

    @staticmethod
    def _identity(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: record.get(key)
            for key in (
                "project_id",
                "ecosystem",
                "manager",
                "package",
                "display_name",
                "purl",
            )
        }

    def _limit(self, requested: int | None) -> int:
        if requested is None:
            return self.max_results
        if requested < 1:
            raise ValueError("limit must be positive")
        return min(requested, self.max_results)

    def _relative(self, path: Path) -> str:
        try:
            return Path(path).resolve().relative_to(self.project_root).as_posix()
        except ValueError:
            return Path(path).name
