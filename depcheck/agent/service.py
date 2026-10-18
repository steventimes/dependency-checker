from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.bounded_io import capture_reads, repository_operation
from depcheck.cmake_model import inspect_cmake_model
from depcheck.compatibility.pyproject_updater import PyprojectUpdater
from depcheck.compatibility.safe_updater import (
    RequirementsUpdater,
    RequirementUpdatePlan,
)
from depcheck.config import load_project_config
from depcheck.ecosystems import EcosystemRegistry, create_default_registry
from depcheck.ecosystems.python_manifest import PythonManifestCollector
from depcheck.ecosystems.static import is_excluded
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.evidence_export import export_evidence
from depcheck.external_evidence import KINDS, inspect_external_evidence
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.indexing.fingerprints import freshness_guard
from depcheck.inventory_compare import compare_inventories
from depcheck.path_policy import default_index_path, require_within_project
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
        payload = self._plan_dependency_updates(
            updates,
            add_missing=add_missing,
            ecosystem=ecosystem,
            project_id=project_id,
            target_file=target_file,
            group=group,
        )
        blockers = [
            d for d in payload.get("diagnostics", []) if d.get("severity") == "error"
        ]
        baseline: dict[str, Any] = {"security": "not-run"}
        if "error" in payload:
            blockers.append(payload["error"])
        elif not blockers:
            scan = RepositoryScanner().scan(
                self.project_root,
                RepositoryScanOptions(
                    security=False,
                    compatibility=False,
                    enabled_ecosystems=("PyPI",),
                    project_ids=(payload["project_id"],),
                ),
            )
            baseline["evidence_complete"] = scan.capability(
                "dependency_hygiene"
            ).complete
            baseline["coverage"] = scan.metadata["coverage"]
            if not baseline["evidence_complete"]:
                blockers.append({"code": "maintenance.evidence-incomplete"})
            resolved = {d.package.name for b in scan.bundles for d in b.resolved}
            if set(map(canonicalize_name, updates)) - resolved:
                blockers.append({"code": "maintenance.resolution-unknown"})
        plans = payload.get("plans", [])
        payload["handoff"] = {
            "status": "blocked" if blockers else ("ready" if plans else "no-change"),
            "blockers": blockers,
            "baseline": baseline,
            "groups": [
                {
                    "project_id": payload.get("project_id"),
                    "ecosystem": ecosystem or "PyPI",
                    "packages": sorted(updates),
                    "basis": "requested-together",
                    "coupling": "unknown",
                }
            ],
            "verification": [
                {"check": check, "status": "not-run"}
                for check in (
                    "package-manager-and-runtime-pins",
                    "locked-install",
                    "resolved-graph",
                    "focused-tests",
                    "project-checks",
                )
            ],
            "source_digests": [
                {"file": p["file"], "sha256": p["original_digest"]} for p in plans
            ],
        }
        return payload

    def _plan_dependency_updates(
        self,
        updates: dict[str, str],
        *,
        add_missing: bool = False,
        ecosystem: str | None = None,
        project_id: str | None = None,
        target_file: str | None = None,
        group: str | None = None,
    ) -> dict[str, Any]:
        if not updates:
            raise ValueError("updates must not be empty")
        if ecosystem is not None and ecosystem.lower() != "pypi":
            return self._unsupported_update(ecosystem, project_id)
        config = load_project_config(self.project_root)
        units = create_default_registry().discover(
            self.project_root,
            ("PyPI",),
            settings={"excluded_directories": config.excluded_directories},
        )
        selected = next((u for u in units if u.project_id == project_id), None)
        if project_id is not None and selected is None:
            return self._unsupported_update(ecosystem or "PyPI", project_id)
        if selected is None and target_file is not None:
            selected = EcosystemRegistry.owner_for(Path(target_file), units)
        if selected is None and len(units) > 1:
            return self._update_result(
                ecosystem,
                project_id,
                diagnostics=[
                    {
                        "code": "update.ambiguous-target",
                        "severity": "error",
                        "message": "Select the Python component before previewing updates",
                        "choices": [u.project_id for u in units],
                    }
                ],
            )
        if selected is None and len(units) == 1:
            selected = units[0]
        if selected is not None:
            project_id = selected.project_id
        normalized = {
            str(canonicalize_name(name)): str(specifier)
            for name, specifier in updates.items()
            if str(name).strip() and str(specifier).strip()
        }
        if len(normalized) != len(updates):
            raise ValueError("update names and specifiers must be non-empty")

        if group is not None and target_file is None:
            raise ValueError("group requires an explicit target_file")
        preview_root = (
            self.project_root / selected.root
            if selected is not None
            else self.project_root
        )
        updater = RequirementsUpdater(preview_root, allow_aliases=False)
        plans: list[dict[str, Any]] = []
        supported_targets: set[str] = set()
        reporter = PythonManifestCollector(
            self.project_root, config.excluded_directories
        )
        discovered = tuple(reporter.find_dependency_file())
        if selected is not None:
            discovered = tuple(
                p
                for p in discovered
                if EcosystemRegistry.owner_for(p.relative_to(self.project_root), units)
                == selected
                and EcosystemRegistry.owner_for(
                    p.resolve().relative_to(self.project_root), units
                )
                == selected
            )
        if target_file is not None:
            requested = Path(target_file)
            if requested.is_absolute():
                raise ValueError("target_file must be relative to the repository")
            target = require_within_project(
                self.project_root,
                self.project_root / requested,
                operation="read explicit update target",
            )
            if is_excluded(requested, config.excluded_directories) or is_excluded(
                target.relative_to(self.project_root), config.excluded_directories
            ):
                raise ValueError("target_file is excluded")
            if not target.is_file():
                raise ValueError("target_file must exist")
            supported_name = target.name == "pyproject.toml" or (
                target.name.startswith("requirements") and target.suffix == ".txt"
            )
            if not supported_name:
                return self._update_result(
                    ecosystem,
                    project_id,
                    diagnostics=[
                        {
                            "code": "update.unsupported-target",
                            "severity": "error",
                            "message": "Only pyproject.toml and requirements*.txt are preview targets",
                        }
                    ],
                )
            if target not in {path.resolve() for path in discovered}:
                raise ValueError(
                    "target_file is excluded or not a discovered Python manifest"
                )
            if target.name == "pyproject.toml":
                if add_missing:
                    return self._update_result(
                        ecosystem,
                        project_id,
                        diagnostics=[
                            {
                                "code": "update.unsupported-target",
                                "severity": "error",
                                "message": "pyproject previews do not add missing dependencies",
                            }
                        ],
                    )
                preview = PyprojectUpdater(preview_root, allow_aliases=False).plan(
                    self.project_root / requested, normalized, group=group
                )
                if preview.plan is not None:
                    plans.append(
                        {
                            **self._update_plan_payload(preview.plan),
                            "groups": list(preview.groups),
                        }
                    )
                return self._update_result(
                    ecosystem,
                    project_id,
                    plans=plans,
                    diagnostics=[
                        item.to_dict(self.project_root) for item in preview.diagnostics
                    ],
                )
            if group is not None:
                raise ValueError("group is only supported for pyproject.toml")
            discovered = (target,)
        for path in discovered:
            if not path.name.startswith("requirements") or path.suffix != ".txt":
                continue
            plan = updater.plan(path, normalized, add_missing=add_missing)
            supported_targets.update(plan.updated)
            supported_targets.update(plan.added)
            if plan.updated_content == plan.original_content:
                continue
            plans.append(self._update_plan_payload(plan))
        diagnostics = [
            item.to_dict(self.project_root) for item in reporter.discovery_diagnostics
        ]
        for package in sorted(normalized.keys() - supported_targets):
            diagnostics.append(
                {
                    "code": "update.unsupported-target",
                    "severity": "error",
                    "message": (
                        f"No supported requirements entry for {package!r}; "
                        "update previews support requirements*.txt version entries only."
                    ),
                }
            )
        return self._update_result(
            ecosystem, project_id, plans=plans, diagnostics=diagnostics
        )

    def _update_plan_payload(self, plan: RequirementUpdatePlan) -> dict[str, Any]:
        return {
            "file": self._relative(plan.file_path),
            "updated": plan.updated,
            "added": plan.added,
            "preview": plan.updated_content,
            "original_digest": plan.original_digest,
        }

    @staticmethod
    def _update_result(
        ecosystem: str | None,
        project_id: str | None,
        *,
        plans: list[dict[str, Any]] | None = None,
        diagnostics: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "schema": "depcheck.agent.update-plan.v1",
            "read_only": True,
            "ecosystem": ecosystem or "PyPI",
            "project_id": project_id or "pypi:python:.",
            "plans": plans if plans is not None else [],
            "diagnostics": diagnostics if diagnostics is not None else [],
        }

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

    @staticmethod
    def _unsupported_update(
        ecosystem: str,
        project_id: str | None,
    ) -> dict[str, Any]:
        return {
            "error": {
                "code": "capability.unsupported",
                "ecosystem": ecosystem,
                "project_id": project_id,
                "capability": "update_preview",
            },
            "diagnostics": [
                {
                    "code": "capability.unsupported",
                    "severity": "error",
                    "message": f"Update previews are unsupported for {ecosystem}/{project_id}.",
                }
            ],
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
