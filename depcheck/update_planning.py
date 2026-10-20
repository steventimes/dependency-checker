"""Component-aware dependency update previews and qualified maintenance handoffs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

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
from depcheck.path_policy import require_within_project


class DependencyUpdatePlanner:
    """Read-only update planning for an already authorized repository root."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root

    def plan(
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

    def _relative(self, path: Path) -> str:
        try:
            return Path(path).resolve().relative_to(self.project_root).as_posix()
        except ValueError:
            return Path(path).name
