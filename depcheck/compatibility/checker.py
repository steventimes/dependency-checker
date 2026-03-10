from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, List, DefaultDict
from collections import defaultdict
import logging

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name, NormalizedName
from packaging.version import Version, InvalidVersion

from .pypi_client import PyPIClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompatibilityConflict:
    package: str
    declared: Optional[str]
    required: str
    required_by: str


@dataclass(frozen=True)
class CompatibilityGap:
    package: str
    required: str
    required_by: str


@dataclass(frozen=True)
class CompatibilityReport:
    conflicts: List[CompatibilityConflict]
    missing: List[CompatibilityGap]
    unconstrained: List[CompatibilityGap]
    suggestions: Dict[str, str]


@dataclass(frozen=True)
class RequirementConstraint:
    source: str
    specifier: SpecifierSet


class CompatibilityChecker:
    def __init__(self, client: Optional[PyPIClient] = None) -> None:
        self.client = client or PyPIClient()

    def check(self, declared_deps: Dict[str, Optional[str]]) -> CompatibilityReport:
        normalized: Dict[NormalizedName, Optional[str]] = {
            canonicalize_name(name): spec
            for name, spec in declared_deps.items()
        }
        constraints = self._collect_constraints(normalized)

        conflicts: List[CompatibilityConflict] = []
        missing: List[CompatibilityGap] = []
        unconstrained: List[CompatibilityGap] = []

        for package, reqs in constraints.items():
            combined = self._combine_specifiers(reqs)
            required_spec = str(combined) if str(combined) else ""
            declared_spec = normalized.get(package)

            if package not in normalized:
                for req in reqs:
                    if str(req.specifier):
                        missing.append(
                            CompatibilityGap(
                                package=package,
                                required=str(req.specifier),
                                required_by=req.source,
                            )
                        )
                continue

            if declared_spec is None:
                if required_spec:
                    for req in reqs:
                        if str(req.specifier):
                            unconstrained.append(
                                CompatibilityGap(
                                    package=package,
                                    required=str(req.specifier),
                                    required_by=req.source,
                                )
                            )
                continue

            if not self._is_compatible(package, declared_spec, combined):
                for req in reqs:
                    if str(req.specifier):
                        conflicts.append(
                            CompatibilityConflict(
                                package=package,
                                declared=declared_spec,
                                required=str(req.specifier),
                                required_by=req.source,
                            )
                        )

        suggestions = self._suggest_fixes(constraints, normalized, conflicts, missing, unconstrained)

        return CompatibilityReport(
            conflicts=conflicts,
            missing=missing,
            unconstrained=unconstrained,
            suggestions=suggestions,
        )

    def suggest_updates(
        self, declared_deps: Dict[str, Optional[str]], constraints_only: bool = True
    ) -> Dict[str, str]:
        normalized: Dict[NormalizedName, Optional[str]] = {
            canonicalize_name(name): spec
            for name, spec in declared_deps.items()
        }
        constraints = self._collect_constraints(normalized)
        updates: Dict[str, str] = {}

        for package, reqs in constraints.items():
            if constraints_only and package not in normalized:
                continue
            combined = self._combine_specifiers(reqs)
            if not str(combined):
                continue
            latest = self._latest_compatible_version(package, combined)
            if latest:
                updates[package] = f"=={latest}"

        return updates

    def _collect_constraints(
        self, declared: Dict[NormalizedName, Optional[str]]
    ) -> DefaultDict[NormalizedName, List[RequirementConstraint]]:
        constraints: DefaultDict[NormalizedName, List[RequirementConstraint]] = defaultdict(list)

        for package, spec in declared.items():
            metadata = self._fetch_metadata(package, spec)
            if not metadata:
                continue

            requires = metadata.get("info", {}).get("requires_dist") or []
            for entry in requires:
                try:
                    req = Requirement(entry)
                except Exception:
                    continue

                if req.marker and not req.marker.evaluate():
                    continue

                name = canonicalize_name(req.name)
                constraints[name].append(
                    RequirementConstraint(source=package, specifier=req.specifier)
                )

        return constraints

    def _fetch_metadata(self, package: NormalizedName, spec: Optional[str]) -> Optional[Dict]:
        version = self._extract_exact_version(spec)
        return self.client.get_metadata(package, version)

    @staticmethod
    def _extract_exact_version(spec: Optional[str]) -> Optional[str]:
        if not spec:
            return None
        cleaned = spec.strip()
        if cleaned.startswith("==") and "," not in cleaned:
            return cleaned[2:]
        return None

    @staticmethod
    def _combine_specifiers(reqs: List[RequirementConstraint]) -> SpecifierSet:
        joined = ",".join(
            str(req.specifier) for req in reqs if str(req.specifier)
        )
        return SpecifierSet(joined)

    def _is_compatible(
        self, package: str, declared_spec: str, required: SpecifierSet
    ) -> bool:
        combined = SpecifierSet(
            ",".join(
                spec for spec in [declared_spec, str(required)] if spec
            )
        )
        return self._has_compatible_version(package, combined)

    def _has_compatible_version(self, package: str, spec: SpecifierSet) -> bool:
        versions = self.client.get_versions(package)
        return self._find_best_version(versions, spec) is not None

    def _latest_compatible_version(
        self, package: str, spec: SpecifierSet
    ) -> Optional[str]:
        versions = self.client.get_versions(package)
        return self._find_best_version(versions, spec)

    @staticmethod
    def _find_best_version(
        versions: List[str], spec: SpecifierSet
    ) -> Optional[str]:
        parsed: List[Version] = []
        for raw in versions:
            try:
                parsed.append(Version(raw))
            except InvalidVersion:
                continue
        for version in sorted(parsed, reverse=True):
            if spec.contains(version, prereleases=True):
                return str(version)
        return None

    def _suggest_fixes(
        self,
        constraints: DefaultDict[NormalizedName, List[RequirementConstraint]],
        declared: Dict[NormalizedName, Optional[str]],
        conflicts: List[CompatibilityConflict],
        missing: List[CompatibilityGap],
        unconstrained: List[CompatibilityGap],
    ) -> Dict[str, str]:
        suggestions: Dict[str, str] = {}
        affected = {
            canonicalize_name(item.package)
            for item in conflicts + missing + unconstrained
        }
        for package in affected:
            reqs = constraints.get(package, [])
            combined = self._combine_specifiers(reqs)
            if not str(combined):
                continue
            latest = self._latest_compatible_version(package, combined)
            if latest:
                suggestions[package] = f"=={latest}"
        return suggestions
