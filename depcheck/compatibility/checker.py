from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.compatibility.pypi_client import ReleaseMetadata
from depcheck.ecosystems.coverage import is_pylock_file
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

from .models import (
    CompatibilityConflict as CompatibilityConflict,
)
from .models import (
    CompatibilityGap as CompatibilityGap,
)
from .models import (
    CompatibilityReport as CompatibilityReport,
)
from .models import (
    PythonCompatibilityConflict as PythonCompatibilityConflict,
)
from .models import (
    RequirementConstraint as RequirementConstraint,
)
from .pypi_client import PyPIClient
from .resolver import resolve_manifest


class CompatibilityChecker:
    """Backtrack over public release metadata without installing target code."""

    MAX_RESOLUTION_ROUNDS = 1000

    def __init__(self, client: PyPIClient | None = None) -> None:
        self.client = client or PyPIClient()

    def check(self, declared_deps: dict[str, str | None]) -> CompatibilityReport:
        """将旧字典输入转换为依赖声明，再调用 check_detailed。"""
        declarations: list[PythonRequirement] = []
        for raw_name, raw_specifier in declared_deps.items():
            specifier = str(raw_specifier or "").strip()
            if specifier and specifier[0].isdigit():
                specifier = f"=={specifier}"
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        f"{raw_name}{specifier}",
                        source=SourceLocation(Path("<legacy-api>")),
                    )
                )
            except InvalidRequirement as exc:
                raise ValueError(
                    f"invalid declared dependency {raw_name!r}: {raw_specifier!r}"
                ) from exc
        return self.check_detailed(
            ManifestParseResult(declarations=tuple(declarations))
        )

    def suggest_updates(
        self,
        declared_deps: dict[str, str | None],
        constraints_only: bool = True,
    ) -> dict[str, str]:
        """返回报告中的版本建议，默认只包含直接声明的包。"""
        suggestions = self.check(declared_deps).suggestions
        if not constraints_only:
            return suggestions
        declared = {str(canonicalize_name(name)) for name in declared_deps}
        return {
            package: spec
            for package, spec in suggestions.items()
            if package in declared
        }

    def check_detailed(
        self,
        manifest: ManifestParseResult,
        *,
        python_version: str | None = None,
        dependency_groups: tuple[str, ...] = (),
    ) -> CompatibilityReport:
        from depcheck.ecosystems.python.collector import filter_python_manifest

        environment = self._target_environment(python_version)
        manifest = filter_python_manifest(manifest, environment["python_full_version"])
        if any(
            item.code
            in {
                "manifest.marker-evaluation-unknown",
                "resolution.pylock-activation-unknown",
                "manifest.pylock-unsupported",
            }
            or (
                item.source is not None
                and is_pylock_file(item.source.path)
                and item.severity == "error"
            )
            for item in manifest.diagnostics
        ):
            return CompatibilityReport(
                conflicts=[],
                missing=[],
                unconstrained=[],
                suggestions={},
                resolution_status="incomplete",
                diagnostics=list(manifest.diagnostics),
            )
        active = [item for item in manifest.declarations if item.group != "build"]
        locked = [item for item in active if item.kind == "locked"]
        conditional_locks = {
            item.source.path: item.source
            for item in locked
            if item.metadata.get("conditional")
            or item.origin.get("lock", {}).get("conditional")
        }
        if conditional_locks:
            return CompatibilityReport(
                conflicts=[],
                missing=[],
                unconstrained=[],
                suggestions={},
                resolution_status="incomplete",
                diagnostics=[
                    *manifest.diagnostics,
                    *(
                        Diagnostic(
                            code="compatibility.uv-lock-selection-unknown"
                            if source.path.name == "uv.lock"
                            else "compatibility.python-lock-selection-unknown",
                            severity="error",
                            message="Conditional Python lock candidates cannot seed one flat compatibility graph; environment, extras/group selection and installed activation are unknown.",
                            source=source,
                        )
                        for source in conditional_locks.values()
                    ),
                ],
            )

        available_groups = {item.group for item in active if item.kind == "direct"}
        unknown = set(dependency_groups) - available_groups
        if unknown:
            raise ValueError(
                "Unknown dependency group selection: " + ", ".join(sorted(unknown))
            )
        selected_groups = {"runtime", *dependency_groups}
        selected = [
            item
            for item in active
            if item.group in selected_groups or item.kind == "constraint"
        ]
        report = resolve_manifest(
            ReleaseMetadata(self.client),
            manifest,
            selected,
            environment,
            max_rounds=self.MAX_RESOLUTION_ROUNDS,
        )
        return replace(
            report,
            resolution={
                **report.resolution,
                "selected_groups": sorted(selected_groups),
                "unselected_groups": sorted(available_groups - selected_groups),
                "selection_basis": "runtime plus explicitly requested groups; installed selection unknown",
            },
        )

    @staticmethod
    def _target_environment(python_version: str | None) -> dict[str, str]:
        environment = default_environment()
        if python_version:
            try:
                parsed = Version(python_version)
            except InvalidVersion as exc:
                raise ValueError(f"invalid Python version: {python_version}") from exc
            environment["python_version"] = f"{parsed.major}.{parsed.minor}"
            environment["python_full_version"] = str(parsed)
        return environment

    @staticmethod
    def _extract_exact_version(specifier: str | None) -> str | None:
        """保留旧辅助方法，供既有集成平滑迁移。"""
        if not specifier:
            return None
        value = specifier.strip()
        if value.startswith("==") and "," not in value and "*" not in value:
            return value[2:]
        return None
