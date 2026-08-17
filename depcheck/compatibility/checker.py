from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import NormalizedName, canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .pypi_client import PyPIClient, PyPIFetchResult


@dataclass(frozen=True)
class CompatibilityConflict:
    package: str
    declared: str | None
    required: str
    required_by: str


@dataclass(frozen=True)
class CompatibilityGap:
    package: str
    required: str
    required_by: str


@dataclass(frozen=True)
class PythonCompatibilityConflict:
    package: str
    version: str
    requires_python: str
    current_python: str


@dataclass(frozen=True)
class CompatibilityReport:
    conflicts: list[CompatibilityConflict]
    missing: list[CompatibilityGap]
    unconstrained: list[CompatibilityGap]
    suggestions: dict[str, str]
    python_conflicts: list[PythonCompatibilityConflict] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    selected_versions: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


@dataclass(frozen=True)
class RequirementConstraint:
    source: str
    specifier: SpecifierSet


class CompatibilityChecker:
    """依据发布元数据迭代解析完整依赖图，并显式区分冲突与扫描失败。"""

    MAX_RESOLUTION_ROUNDS = 100

    def __init__(self, client: PyPIClient | None = None) -> None:
        self.client = client or PyPIClient()

    def check(self, declared_deps: dict[str, str | None]) -> CompatibilityReport:
        """兼容旧字典接口，但统一委托给证据化解析器。"""
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
        """返回解析报告的安全建议；默认不把传递包升级为直接依赖。"""
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
    ) -> CompatibilityReport:
        environment = self._target_environment(python_version)
        current_python = environment["python_full_version"]
        active = [
            item
            for item in manifest.declarations
            if item.group != "build"
            and item.kind != "constraint"
            and item.is_active(environment)
        ]
        direct = [item for item in active if item.kind == "direct"]
        locked = [item for item in active if item.kind == "locked"]

        direct_constraints: defaultdict[NormalizedName, list[RequirementConstraint]] = (
            defaultdict(list)
        )
        direct_extras: defaultdict[NormalizedName, set[str]] = defaultdict(set)
        for item in direct:
            direct_constraints[canonicalize_name(item.name)].append(
                RequirementConstraint("project manifest", item.specifier)
            )
            direct_extras[canonicalize_name(item.name)].update(item.extras)

        diagnostics: list[Diagnostic] = []
        seed_conflicts: list[CompatibilityConflict] = []
        selected: dict[NormalizedName, str] = {}
        fixed_versions: set[NormalizedName] = set()

        # 锁文件代表实际安装状态，优先于范围声明；多个锁定版本本身就是冲突。
        for item in locked:
            if not item.pinned_version:
                continue
            package = canonicalize_name(item.name)
            existing = selected.get(package)
            if existing is not None and existing != item.pinned_version:
                seed_conflicts.append(
                    CompatibilityConflict(
                        package=str(package),
                        declared=f"=={existing},=={item.pinned_version}",
                        required="single resolved version",
                        required_by="lockfiles",
                    )
                )
                continue
            selected[package] = item.pinned_version
            fixed_versions.add(package)

        for item in direct:
            if not item.pinned_version:
                continue
            package = canonicalize_name(item.name)
            if package not in selected:
                selected[package] = item.pinned_version
            fixed_versions.add(package)

        extras: dict[NormalizedName, set[str]] = {
            package: set(values) for package, values in direct_extras.items()
        }
        seen_states: set[tuple[object, ...]] = set()
        final_conflicts = list(seed_conflicts)
        final_suggestions: dict[str, str] = {}
        final_metadata: dict[NormalizedName, Mapping[str, Any]] = {}

        for _round in range(self.MAX_RESOLUTION_ROUNDS):
            state = self._resolution_state(selected, extras)
            if state in seen_states:
                self._append_diagnostic(
                    diagnostics,
                    Diagnostic(
                        code="compatibility.resolution-cycle",
                        severity="error",
                        message="兼容性解析在候选版本之间循环，无法得到稳定结果",
                    ),
                )
                break
            seen_states.add(state)

            metadata: dict[NormalizedName, Mapping[str, Any]] = {}
            transitive: defaultdict[NormalizedName, list[RequirementConstraint]] = (
                defaultdict(list)
            )
            next_extras: dict[NormalizedName, set[str]] = {
                package: set(values) for package, values in direct_extras.items()
            }

            for package, version in sorted(
                selected.items(), key=lambda item: str(item[0])
            ):
                info = self._metadata_info(package, version, diagnostics)
                if info is None:
                    continue
                metadata[package] = info
                for raw_requirement in info.get("requires_dist", []) or []:
                    try:
                        requirement = Requirement(str(raw_requirement))
                    except (InvalidRequirement, TypeError) as exc:
                        self._append_diagnostic(
                            diagnostics,
                            Diagnostic(
                                code="pypi.invalid-requires-dist",
                                severity="warning",
                                message=f"无法解析 {package} 的依赖元数据：{exc}",
                            ),
                        )
                        continue
                    if not self._marker_applies(
                        requirement,
                        environment,
                        extras.get(package, set()),
                    ):
                        continue
                    target = canonicalize_name(requirement.name)
                    transitive[target].append(
                        RequirementConstraint(str(package), requirement.specifier)
                    )
                    next_extras.setdefault(target, set()).update(requirement.extras)

            next_selected = dict(selected)
            round_conflicts = list(seed_conflicts)
            round_suggestions: dict[str, str] = {}
            packages = set(direct_constraints) | set(transitive)
            for package in sorted(packages, key=str):
                constraints = [
                    *direct_constraints.get(package, []),
                    *transitive.get(package, []),
                ]
                combined = self._combine_specifiers(constraints)
                current = selected.get(package)

                if current is not None and package in fixed_versions:
                    if not combined.contains(current, prereleases=True):
                        round_conflicts.append(
                            self._conflict(package, current, combined, constraints)
                        )
                        candidate = self._candidate(package, combined, diagnostics)
                        if candidate is not None:
                            round_suggestions[str(package)] = f"=={candidate}"
                    continue

                candidate = self._candidate(package, combined, diagnostics)
                if candidate is None:
                    round_conflicts.append(
                        self._conflict(package, current, combined, constraints)
                    )
                    continue
                next_selected[package] = candidate

            final_conflicts = self._dedupe_conflicts(round_conflicts)
            final_suggestions = round_suggestions
            final_metadata = metadata
            if next_selected == selected and next_extras == extras:
                break
            selected = next_selected
            extras = next_extras
        else:
            self._append_diagnostic(
                diagnostics,
                Diagnostic(
                    code="compatibility.resolution-limit",
                    severity="error",
                    message=(
                        f"兼容性解析超过 {self.MAX_RESOLUTION_ROUNDS} 轮，"
                        "依赖图可能不稳定"
                    ),
                ),
            )

        python_conflicts = self._python_conflicts(
            selected,
            final_metadata,
            current_python,
            diagnostics,
        )
        return CompatibilityReport(
            conflicts=final_conflicts,
            missing=[],
            unconstrained=[],
            suggestions=final_suggestions,
            python_conflicts=python_conflicts,
            diagnostics=diagnostics,
            selected_versions={str(key): value for key, value in selected.items()},
        )

    def _candidate(
        self,
        package: NormalizedName,
        specifier: SpecifierSet,
        diagnostics: list[Diagnostic],
    ) -> str | None:
        versions, diagnostic = self._available_versions_detailed(str(package))
        if diagnostic is not None:
            self._append_diagnostic(diagnostics, diagnostic)
            return None
        return self._find_best_version(versions, specifier)

    def _metadata_info(
        self,
        package: NormalizedName,
        version: str,
        diagnostics: list[Diagnostic],
    ) -> Mapping[str, Any] | None:
        result = self._fetch_metadata(str(package), version)
        if result.diagnostic is not None:
            self._append_diagnostic(diagnostics, result.diagnostic)
            return None
        data = result.data or {}
        info = data.get("info")
        if not isinstance(info, dict):
            self._append_diagnostic(
                diagnostics,
                Diagnostic(
                    code="pypi.invalid-response",
                    severity="error",
                    message=f"PyPI 元数据缺少 info 对象：{package}=={version}",
                ),
            )
            return None
        return info

    def _available_versions_detailed(
        self,
        package: str,
    ) -> tuple[list[str], Diagnostic | None]:
        result = self._fetch_metadata(package)
        if result.diagnostic is not None:
            return [], result.diagnostic
        data = result.data or {}
        releases = data.get("releases")
        if not isinstance(releases, dict):
            return [], Diagnostic(
                code="pypi.invalid-response",
                severity="error",
                message=f"PyPI releases 不是对象：{package}",
            )

        versions: list[str] = []
        for raw, files in releases.items():
            if not isinstance(files, list) or not files:
                continue
            if any(
                isinstance(file_data, dict) and not file_data.get("yanked", False)
                for file_data in files
            ):
                versions.append(str(raw))
        return versions, None

    def _fetch_metadata(
        self,
        package: str,
        version: str | None = None,
    ) -> PyPIFetchResult:
        fetch = getattr(self.client, "fetch_metadata", None)
        if callable(fetch):
            return fetch(package, version)
        legacy_fetch = getattr(self.client, "get_metadata", None)
        if callable(legacy_fetch):
            data = legacy_fetch(package, version)
            if isinstance(data, dict):
                return PyPIFetchResult(data)
        return PyPIFetchResult(
            None,
            Diagnostic(
                code="pypi.metadata-unavailable",
                severity="error",
                message=f"无法读取 PyPI 元数据：{package}",
            ),
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
    def _resolution_state(
        selected: Mapping[NormalizedName, str],
        extras: Mapping[NormalizedName, set[str]],
    ) -> tuple[object, ...]:
        versions = tuple(
            sorted((str(name), version) for name, version in selected.items())
        )
        active_extras = tuple(
            sorted(
                (str(name), tuple(sorted(values))) for name, values in extras.items()
            )
        )
        return versions, active_extras

    @staticmethod
    def _combine_specifiers(
        requirements: Sequence[RequirementConstraint],
    ) -> SpecifierSet:
        return SpecifierSet(
            ",".join(
                str(requirement.specifier)
                for requirement in requirements
                if str(requirement.specifier)
            )
        )

    @staticmethod
    def _find_best_version(
        versions: Sequence[str],
        specifier: SpecifierSet,
    ) -> str | None:
        parsed: list[Version] = []
        for raw in versions:
            try:
                parsed.append(Version(raw))
            except InvalidVersion:
                continue

        allow_prereleases = specifier.prereleases is True
        for version in sorted(parsed, reverse=True):
            if version.is_prerelease and not allow_prereleases:
                continue
            if specifier.contains(version, prereleases=allow_prereleases):
                return str(version)
        return None

    @staticmethod
    def _extract_exact_version(specifier: str | None) -> str | None:
        """保留旧辅助方法，供既有集成平滑迁移。"""
        if not specifier:
            return None
        value = specifier.strip()
        if value.startswith("==") and "," not in value and "*" not in value:
            return value[2:]
        return None

    @staticmethod
    def _marker_applies(
        requirement: Requirement,
        environment: dict[str, str],
        extras: set[str],
    ) -> bool:
        if requirement.marker is None:
            return True
        return any(
            requirement.marker.evaluate({**environment, "extra": extra})
            for extra in ("", *sorted(extras))
        )

    @staticmethod
    def _conflict(
        package: NormalizedName,
        selected: str | None,
        combined: SpecifierSet,
        constraints: Sequence[RequirementConstraint],
    ) -> CompatibilityConflict:
        sources = sorted({item.source for item in constraints if str(item.specifier)})
        return CompatibilityConflict(
            package=str(package),
            declared=f"=={selected}" if selected is not None else None,
            required=str(combined) or "a published release",
            required_by=", ".join(sources) or "project manifest",
        )

    @staticmethod
    def _dedupe_conflicts(
        conflicts: Sequence[CompatibilityConflict],
    ) -> list[CompatibilityConflict]:
        unique: list[CompatibilityConflict] = []
        seen: set[tuple[object, ...]] = set()
        for item in conflicts:
            key = (item.package, item.declared, item.required, item.required_by)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    @staticmethod
    def _append_diagnostic(
        diagnostics: list[Diagnostic],
        diagnostic: Diagnostic,
    ) -> None:
        key = (diagnostic.code, diagnostic.severity, diagnostic.message)
        if not any(
            (item.code, item.severity, item.message) == key for item in diagnostics
        ):
            diagnostics.append(diagnostic)

    def _python_conflicts(
        self,
        selected: Mapping[NormalizedName, str],
        metadata: Mapping[NormalizedName, Mapping[str, Any]],
        current_python: str,
        diagnostics: list[Diagnostic],
    ) -> list[PythonCompatibilityConflict]:
        conflicts: list[PythonCompatibilityConflict] = []
        for package, info in sorted(metadata.items(), key=lambda item: str(item[0])):
            requires_python = info.get("requires_python")
            if not requires_python:
                continue
            try:
                python_specifier = SpecifierSet(str(requires_python))
            except InvalidSpecifier as exc:
                self._append_diagnostic(
                    diagnostics,
                    Diagnostic(
                        code="pypi.invalid-requires-python",
                        severity="warning",
                        message=f"无法解析 {package} 的 requires_python：{exc}",
                    ),
                )
                continue
            if not python_specifier.contains(current_python, prereleases=True):
                conflicts.append(
                    PythonCompatibilityConflict(
                        package=str(package),
                        version=selected[package],
                        requires_python=str(requires_python),
                        current_python=current_python,
                    )
                )
        return conflicts
