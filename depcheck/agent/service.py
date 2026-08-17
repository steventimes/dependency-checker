from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.compatibility.safe_updater import RequirementsUpdater
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.ecosystems.python_manifest import PythonManifestCollector

from .gitnexus import GitNexusCompanion


class DependencyAgentService:
    """供 CLI 与 MCP 共用的 agent 语义层，不包含传输协议细节。"""

    def __init__(
        self,
        project_root: Path,
        *,
        max_results: int = 50,
        code_index: GitNexusCompanion | None = None,
    ) -> None:
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise ValueError(f"project root is not a directory: {root}")
        if max_results < 1:
            raise ValueError("max_results must be positive")
        self.project_root = root
        self.max_results = max_results
        self.code_index = code_index or GitNexusCompanion()

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

    def repository_context(self) -> dict[str, Any]:
        context = RepositoryIndex(self.project_root).context()
        context["code_index"] = self.code_index.inspect(self.project_root).to_dict()
        return context

    def scan_repository(self) -> dict[str, Any]:
        result = RepositoryScanner().scan(
            self.project_root,
            RepositoryScanOptions(security=False),
        )
        payload = result.to_dict()
        findings = list(payload["findings"])
        payload["findings"] = findings[: self.max_results]
        payload["finding_count"] = len(findings)
        payload["truncated"] = len(findings) > self.max_results
        payload["index"] = self.index_repository()
        payload["context"] = self.repository_context()
        return payload

    def query_dependencies(
        self,
        query: str | None = None,
        *,
        search: str | None = None,
        ecosystem: str | None = None,
        project_id: str | None = None,
        limit: int | None = None,
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
        )
        truncated = len(records) > effective_limit
        return {
            "schema": "depcheck.agent.dependencies.v1",
            "query": needle,
            "ecosystem": ecosystem,
            "project_id": project_id,
            "count": min(len(records), effective_limit),
            "truncated": truncated,
            "dependencies": records[:effective_limit],
        }

    def explain_dependency(
        self,
        package: str,
        *,
        ecosystem: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = self._normalized_package(package, ecosystem)
        records = RepositoryIndex(self.project_root).dependencies(
            search=normalized,
            ecosystem=ecosystem,
            project_id=project_id,
            limit=self.max_results,
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

    def dependency_impact(
        self,
        package: str,
        *,
        ecosystem: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        explanation = self.explain_dependency(
            package,
            ecosystem=ecosystem,
            project_id=project_id,
        )
        if "error" in explanation:
            return explanation
        imports = explanation["imports"]
        files = sorted({str(item["location"]["path"]) for item in imports})
        scopes: dict[str, int] = {}
        for item in imports:
            scope = str(item["scope"])
            scopes[scope] = scopes.get(scope, 0) + 1
        return {
            "schema": "depcheck.agent.dependency-impact.v1",
            "project_id": explanation["project_id"],
            "ecosystem": explanation["ecosystem"],
            "package": explanation["package"],
            "usage_count": len(imports),
            "files": files,
            "scopes": dict(sorted(scopes.items())),
            "finding_codes": sorted(
                {str(item["code"]) for item in explanation["findings"]}
            ),
            "code_graph": "dependency-evidence",
        }

    def plan_dependency_updates(
        self,
        updates: dict[str, str],
        *,
        add_missing: bool = False,
        ecosystem: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        if not updates:
            raise ValueError("updates must not be empty")
        if ecosystem is not None and ecosystem.lower() != "pypi":
            return self._unsupported_update(ecosystem, project_id)
        if project_id is not None and project_id != "pypi:python:.":
            return self._unsupported_update(ecosystem or "unknown", project_id)
        normalized = {
            str(canonicalize_name(name)): str(specifier)
            for name, specifier in updates.items()
            if str(name).strip() and str(specifier).strip()
        }
        if len(normalized) != len(updates):
            raise ValueError("update names and specifiers must be non-empty")

        updater = RequirementsUpdater(self.project_root)
        plans: list[dict[str, Any]] = []
        reporter = PythonManifestCollector(self.project_root)
        for path in reporter.find_dependency_file():
            if not path.name.startswith("requirements") or path.suffix != ".txt":
                continue
            plan = updater.plan(path, normalized, add_missing=add_missing)
            if plan.updated_content == plan.original_content:
                continue
            plans.append(
                {
                    "file": self._relative(plan.file_path),
                    "updated": plan.updated,
                    "added": plan.added,
                    "preview": plan.updated_content,
                    "original_digest": plan.original_digest,
                }
            )
        return {
            "schema": "depcheck.agent.update-plan.v1",
            "read_only": True,
            "ecosystem": ecosystem or "PyPI",
            "project_id": project_id or "pypi:python:.",
            "plans": plans,
            "diagnostics": [
                item.to_dict(self.project_root)
                for item in reporter.discovery_diagnostics
            ],
        }

    @staticmethod
    def _normalized_package(package: str, ecosystem: str | None) -> str:
        value = str(package).strip()
        if not value:
            raise ValueError("package must be non-empty")
        if ecosystem is None or ecosystem.lower() == "pypi":
            return str(canonicalize_name(value))
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
            }
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
