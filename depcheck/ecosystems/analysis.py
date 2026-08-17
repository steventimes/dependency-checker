from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from depcheck.model import AnalysisReport, Finding, PackageIdentity
from depcheck.model import Diagnostic, SourceLocation
from depcheck.model import (
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    UsageEvidence,
)

DependencyKey = tuple[str, str, str]
_SEMVER_EXACT = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SEMVER_PRERELEASE = re.compile(r"(?<![0-9A-Za-z])v?\d+\.\d+\.\d+-[0-9A-Za-z]")


class EvidenceAnalyzer:
    """Produce hygiene findings only from sufficiently strong mappings."""

    def analyze(self, bundle: EvidenceBundle) -> AnalysisReport:
        declarations = self._declarations_by_key(bundle.declarations)
        resolved = {
            item.package.key(item.project_id)
            for item in bundle.resolved
            if item.version
        }
        qualified = self._qualified_usages_by_key(bundle.usages)
        inferred = {
            item.mapped_package.key(item.project_id)
            for item in bundle.usages
            if item.mapped_package is not None
            and item.mapping_confidence is MappingConfidence.INFERRED
        }
        unknown_count = sum(
            item.mapping_confidence is MappingConfidence.UNKNOWN
            for item in bundle.usages
        )

        findings = self._usage_findings(qualified, declarations)
        if unknown_count == 0:
            findings.extend(self._unused_findings(declarations, qualified, inferred))
        findings.extend(self._unpinned_findings(declarations, resolved))
        declaration_findings, declaration_diagnostics = self._declaration_findings(
            declarations
        )
        findings.extend(declaration_findings)
        findings.sort(key=lambda item: (item.code, item.package.sort_key, item.message))

        diagnostics = list(bundle.diagnostics)
        diagnostics.extend(declaration_diagnostics)
        if unknown_count:
            diagnostics.append(
                Diagnostic(
                    code="mapping.unresolved",
                    severity="warning",
                    message=(
                        f"{unknown_count} source references could not be mapped safely."
                    ),
                )
            )

        import_mapping = {
            item.reference: item.mapped_package.name
            for item in bundle.usages
            if item.mapped_package is not None
        }
        return AnalysisReport(
            findings=tuple(findings),
            diagnostics=tuple(diagnostics),
            import_mapping=import_mapping,
        )

    @staticmethod
    def _declarations_by_key(
        declarations: Sequence[DependencyDeclaration],
    ) -> dict[DependencyKey, list[DependencyDeclaration]]:
        grouped: dict[DependencyKey, list[DependencyDeclaration]] = {}
        for item in declarations:
            if item.kind != "direct" or item.scope == "build":
                continue
            grouped.setdefault(item.package.key(item.project_id), []).append(item)
        return grouped

    @staticmethod
    def _qualified_usages_by_key(
        usages: Sequence[UsageEvidence],
    ) -> dict[DependencyKey, list[UsageEvidence]]:
        grouped: dict[DependencyKey, list[UsageEvidence]] = {}
        for item in usages:
            if (
                item.mapped_package is None
                or not item.mapping_confidence.qualifies_for_hygiene
            ):
                continue
            grouped.setdefault(
                item.mapped_package.key(item.project_id),
                [],
            ).append(item)
        return grouped

    def _usage_findings(
        self,
        usages: Mapping[DependencyKey, list[UsageEvidence]],
        declarations: Mapping[DependencyKey, list[DependencyDeclaration]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, evidence in usages.items():
            declared = declarations.get(key, [])
            package = evidence[0].mapped_package
            if package is None:
                continue
            if not declared:
                optional_only = all(item.kind == "optional" for item in evidence)
                findings.append(
                    Finding(
                        code="dependency.missing",
                        package=PackageIdentity(
                            key[0], package.ecosystem, package.name, purl=package.purl
                        ),
                        severity="warning" if optional_only else "error",
                        message=f"Used package '{package.name}' is not declared.",
                        locations=self._usage_locations(evidence),
                        details={
                            "project_id": key[0],
                            "ecosystem": package.ecosystem,
                            "mapping_confidence": sorted(
                                {item.mapping_confidence.value for item in evidence}
                            ),
                            "optional": optional_only,
                        },
                    )
                )
                continue

            incompatible = [
                usage
                for usage in evidence
                if not any(
                    self._scope_accepts(usage, declaration) for declaration in declared
                )
            ]
            if incompatible:
                findings.append(
                    Finding(
                        code="dependency.scope-mismatch",
                        package=PackageIdentity(
                            key[0], package.ecosystem, package.name, purl=package.purl
                        ),
                        severity="error",
                        message=(
                            f"Package '{package.name}' is declared only in an "
                            "incompatible dependency scope."
                        ),
                        locations=self._usage_locations(incompatible),
                        details={
                            "project_id": key[0],
                            "ecosystem": package.ecosystem,
                            "declared_scopes": sorted(
                                {item.scope for item in declared}
                            ),
                        },
                    )
                )
        return findings

    @staticmethod
    def _unused_findings(
        declarations: Mapping[DependencyKey, list[DependencyDeclaration]],
        usages: Mapping[DependencyKey, list[UsageEvidence]],
        inferred: set[DependencyKey],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, declared in declarations.items():
            if key in usages or key in inferred:
                continue
            package = declared[0].package
            findings.append(
                Finding(
                    code="dependency.unused",
                    package=PackageIdentity(
                        key[0], package.ecosystem, package.name, purl=package.purl
                    ),
                    severity="warning",
                    message=(
                        f"Declared package '{package.name}' has no qualified "
                        "usage evidence."
                    ),
                    locations=tuple(item.source for item in declared),
                    details={
                        "project_id": key[0],
                        "ecosystem": package.ecosystem,
                    },
                )
            )
        return findings

    @staticmethod
    def _scope_accepts(
        usage: UsageEvidence,
        declaration: DependencyDeclaration,
    ) -> bool:
        if usage.kind == "optional":
            return declaration.scope != "build"
        if usage.scope == "runtime":
            return declaration.scope in {"runtime", "peer", "host"}
        if usage.scope == "test":
            return declaration.scope in {
                "runtime",
                "development",
                "test",
                "optional",
            }
        if usage.scope == "build":
            return declaration.scope in {"runtime", "development", "build"}
        return declaration.scope != "build"

    @classmethod
    def _unpinned_findings(
        cls,
        declarations: Mapping[DependencyKey, list[DependencyDeclaration]],
        resolved: set[DependencyKey],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, direct in declarations.items():
            if key in resolved or not direct:
                continue
            supported = [
                item
                for item in direct
                if item.constraint.scheme.lower()
                in {"pep440", "semver", "go", "maven", "conan", "vcpkg"}
            ]
            if not supported or any(cls._exact_version(item) for item in supported):
                continue
            package = direct[0].package
            findings.append(
                Finding(
                    code="dependency.unpinned",
                    package=PackageIdentity(
                        key[0], package.ecosystem, package.name, purl=package.purl
                    ),
                    severity="warning",
                    message=f"Direct package '{package.name}' has no exact version pin.",
                    locations=tuple(item.source for item in direct),
                    details={"project_id": key[0], "ecosystem": package.ecosystem},
                )
            )
        return findings

    @classmethod
    def _declaration_findings(
        cls,
        declarations: Mapping[DependencyKey, list[DependencyDeclaration]],
    ) -> tuple[list[Finding], list[Diagnostic]]:
        findings: list[Finding] = []
        diagnostics: list[Diagnostic] = []
        for key, direct in declarations.items():
            if len(direct) < 2:
                continue
            package = direct[0].package
            details = {"project_id": key[0], "ecosystem": package.ecosystem}
            locations = tuple(item.source for item in direct)
            findings.append(
                Finding(
                    code="declaration.duplicate",
                    package=PackageIdentity(
                        key[0], package.ecosystem, package.name, purl=package.purl
                    ),
                    severity="warning",
                    message=f"Package '{package.name}' is declared multiple times.",
                    locations=locations,
                    details=details,
                )
            )
            exact = {
                version
                for item in direct
                if (version := cls._exact_version(item)) is not None
            }
            schemes = {item.constraint.scheme.lower() for item in direct}
            conflict: bool | None
            if len(exact) > 1:
                conflict = True
            elif len(schemes) != 1:
                conflict = None
            else:
                scheme = next(iter(schemes))
                if scheme == "pep440":
                    conflict = cls._pep440_conflict(direct)
                elif scheme == "semver":
                    conflict = cls._range_conflict(direct, cls._semver_intervals)
                elif scheme == "maven":
                    conflict = cls._range_conflict(direct, cls._maven_intervals)
                elif len(exact) == len(direct):
                    conflict = False
                else:
                    conflict = None
            if conflict:
                findings.append(
                    Finding(
                        code="declaration.conflict",
                        package=PackageIdentity(
                            key[0], package.ecosystem, package.name, purl=package.purl
                        ),
                        severity="error",
                        message=f"Package '{package.name}' has incompatible declarations.",
                        locations=locations,
                        details={
                            **details,
                            "constraints": [item.constraint.raw for item in direct],
                        },
                    )
                )
            elif conflict is None:
                diagnostics.append(
                    Diagnostic(
                        code="analysis.constraint-intersection-unknown",
                        severity="error",
                        message=(
                            f"Cannot prove whether duplicate constraints for "
                            f"{package.name} have a common version."
                        ),
                        source=direct[0].source,
                    )
                )
        return findings, diagnostics

    @staticmethod
    def _exact_version(declaration: DependencyDeclaration) -> object | None:
        constraint = declaration.constraint
        raw = (constraint.normalized or constraint.raw).strip()
        scheme = constraint.scheme.lower()
        if not raw:
            return None
        if scheme == "pep440":
            try:
                items = list(SpecifierSet(raw))
            except InvalidSpecifier:
                return None
            if len(items) != 1:
                return None
            item = items[0]
            if item.operator not in {"==", "==="} or "*" in item.version:
                return None
            try:
                return Version(item.version)
            except InvalidVersion:
                return None
        if scheme in {"semver", "go"}:
            match = _SEMVER_EXACT.fullmatch(raw)
            if match is None:
                return None
            major, minor, patch, prerelease = match.groups()
            return (
                scheme,
                int(major),
                int(minor),
                int(patch),
                prerelease or "",
            )
        if scheme == "maven":
            lowered = raw.lower()
            dynamic = (
                lowered in {"latest", "release"}
                or lowered.startswith("latest.")
                or lowered.endswith("-snapshot")
                or any(token in raw for token in ("${", "+", "[", "]", "(", ")", ","))
                or any(character.isspace() for character in raw)
            )
            return None if dynamic else ("maven", raw)
        if scheme == "conan":
            range_tokens = ("<", ">", "=", "~", "^", "*", "|", ",", "[", "]", "(", ")")
            if any(token in raw for token in range_tokens) or any(
                character.isspace() for character in raw
            ):
                return None
            return ("conan", raw)
        if scheme == "vcpkg":
            # Current vcpkg declarations carry only explicit override versions.
            return ("vcpkg", raw)
        return None

    @classmethod
    def _pep440_conflict(
        cls,
        declarations: Sequence[DependencyDeclaration],
    ) -> bool | None:
        if len(declarations) < 2:
            return False
        sets: list[SpecifierSet] = []
        for declaration in declarations:
            raw = (
                declaration.constraint.normalized or declaration.constraint.raw
            ).strip()
            try:
                sets.append(SpecifierSet(raw))
            except InvalidSpecifier:
                return None

        exact = {
            version
            for item in declarations
            if (version := cls._exact_version(item)) is not None
        }
        if exact:
            return any(
                not all(
                    specifiers.contains(version, prereleases=True)
                    for specifiers in sets
                )
                for version in exact
            )

        lower: tuple[Version, bool] | None = None
        upper: tuple[Version, bool] | None = None
        for specifiers in sets:
            for item in specifiers:
                if item.operator not in {">", ">=", "<", "<="}:
                    continue
                try:
                    version = Version(item.version)
                except InvalidVersion:
                    return None
                inclusive = item.operator in {">=", "<="}
                if item.operator.startswith(">"):
                    if lower is None or version > lower[0]:
                        lower = (version, inclusive)
                    elif version == lower[0]:
                        lower = (version, lower[1] and inclusive)
                else:
                    if upper is None or version < upper[0]:
                        upper = (version, inclusive)
                    elif version == upper[0]:
                        upper = (version, upper[1] and inclusive)
        if lower is None or upper is None:
            return False
        return lower[0] > upper[0] or (
            lower[0] == upper[0] and not (lower[1] and upper[1])
        )

    @classmethod
    def _range_conflict(
        cls,
        declarations: Sequence[DependencyDeclaration],
        parser: Any,
    ) -> bool | None:
        parsed = [
            parser((item.constraint.normalized or item.constraint.raw).strip())
            for item in declarations
        ]
        if any(item is None for item in parsed):
            return None
        candidates = list(parsed[0] or ())
        for alternatives in parsed[1:]:
            candidates = [
                intersection
                for left in candidates
                for right in alternatives or ()
                if (intersection := cls._interval_intersection(left, right)) is not None
            ]
            if not candidates:
                return True
        return False

    @classmethod
    def _semver_intervals(
        cls,
        raw: str,
    ) -> tuple[tuple[Version | None, bool, Version | None, bool], ...] | None:
        if _SEMVER_PRERELEASE.search(raw):
            return None
        alternatives: list[tuple[Version | None, bool, Version | None, bool]] = []
        for segment in raw.split("||"):
            segment = segment.strip()
            if not segment:
                return None
            if " - " in segment:
                parts = segment.split(" - ")
                if len(parts) != 2:
                    return None
                lower = cls._semver_floor(parts[0])
                upper_bound = cls._semver_hyphen_upper(parts[1])
                if lower is None or upper_bound is None:
                    return None
                upper, upper_inclusive = upper_bound
                alternatives.append((lower, True, upper, upper_inclusive))
                continue
            interval = (None, False, None, False)
            for token in segment.replace(",", " ").split():
                token_interval = cls._semver_token_interval(token)
                if token_interval is None:
                    return None
                intersected = cls._interval_intersection(interval, token_interval)
                if intersected is None:
                    return ()
                interval = intersected
            alternatives.append(interval)
        return tuple(alternatives)

    @classmethod
    def _semver_token_interval(
        cls,
        token: str,
    ) -> tuple[Version | None, bool, Version | None, bool] | None:
        if token in {"*", "x", "X"}:
            return (None, False, None, False)
        if token.startswith("^"):
            value = token[1:]
            if "-" in value:
                return None
            lower = cls._semver_floor(value)
            if lower is None:
                return None
            release = lower.release + (0, 0, 0)
            major, minor, patch = release[:3]
            parts = value.lstrip("v").split(".")
            if len(parts) == 1 or major:
                upper = Version(f"{major + 1}.0.0")
            elif len(parts) == 2 or minor:
                upper = Version(f"0.{minor + 1}.0")
            else:
                upper = Version(f"0.0.{patch + 1}")
            return (lower, True, upper, False)
        if token.startswith("~"):
            value = token.lstrip("~>")
            lower = cls._semver_floor(value)
            if lower is None:
                return None
            parts = value.lstrip("v").split(".")
            upper = (
                Version(f"{lower.release[0] + 1}.0.0")
                if len(parts) == 1
                else Version(f"{lower.release[0]}.{lower.release[1] + 1}.0")
            )
            return (lower, True, upper, False)
        comparison = re.fullmatch(r"(>=|<=|>|<|=)?(.+)", token)
        if comparison is None:
            return None
        operator, value = comparison.groups()
        if operator is not None and "-" in value:
            return None
        wildcard = re.fullmatch(
            r"v?(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?",
            value,
        )
        if operator is None and wildcard is not None:
            major, minor, patch = wildcard.groups()
            if minor is None or minor in {"x", "X", "*"}:
                return (
                    Version(f"{major}.0.0"),
                    True,
                    Version(f"{int(major) + 1}.0.0"),
                    False,
                )
            if patch is None or patch in {"x", "X", "*"}:
                return (
                    Version(f"{major}.{minor}.0"),
                    True,
                    Version(f"{major}.{int(minor) + 1}.0"),
                    False,
                )
        version = cls._semver_floor(value)
        if version is None:
            return None
        if operator in {None, "="}:
            return (version, True, version, True)
        if operator == ">=":
            return (version, True, None, False)
        if operator == ">":
            return (version, False, None, False)
        if operator == "<=":
            return (None, False, version, True)
        return (None, False, version, False)

    @staticmethod
    def _semver_floor(raw: str) -> Version | None:
        value = raw.strip().lstrip("v")
        if not re.fullmatch(
            r"\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
            value,
        ):
            return None
        core, separator, suffix = value.partition("-")
        parts = core.split(".")
        core = ".".join((*parts, *("0" for _ in range(3 - len(parts)))))
        try:
            return Version(core + (separator + suffix if separator else ""))
        except InvalidVersion:
            return None

    @classmethod
    def _semver_hyphen_upper(
        cls,
        raw: str,
    ) -> tuple[Version, bool] | None:
        value = raw.strip().lstrip("v")
        if "-" in value or "+" in value:
            return None
        if not re.fullmatch(r"\d+(?:\.\d+){0,2}", value):
            return None
        upper = cls._semver_floor(value)
        if upper is None:
            return None
        parts = value.split(".")
        if len(parts) == 3:
            return upper, True
        major, minor = (upper.release + (0, 0))[:2]
        if len(parts) == 2:
            return Version(f"{major}.{minor + 1}.0"), False
        return Version(f"{major + 1}.0.0"), False

    @staticmethod
    def _maven_intervals(
        raw: str,
    ) -> tuple[tuple[Version | None, bool, Version | None, bool], ...] | None:
        match = re.fullmatch(r"^(\[|\()([^,]*),([^,]*)(\]|\))$", raw)
        if match is not None:
            opening, lower_raw, upper_raw, closing = match.groups()
            try:
                lower = Version(lower_raw.strip()) if lower_raw.strip() else None
                upper = Version(upper_raw.strip()) if upper_raw.strip() else None
            except InvalidVersion:
                return None
            return ((lower, opening == "[", upper, closing == "]"),)
        try:
            return ((Version(raw), True, Version(raw), True),)
        except InvalidVersion:
            return None

    @staticmethod
    def _interval_intersection(
        left: tuple[Version | None, bool, Version | None, bool],
        right: tuple[Version | None, bool, Version | None, bool],
    ) -> tuple[Version | None, bool, Version | None, bool] | None:
        lower, lower_inclusive = left[0], left[1]
        if right[0] is not None and (lower is None or right[0] > lower):
            lower, lower_inclusive = right[0], right[1]
        elif right[0] is not None and right[0] == lower:
            lower_inclusive = lower_inclusive and right[1]
        upper, upper_inclusive = left[2], left[3]
        if right[2] is not None and (upper is None or right[2] < upper):
            upper, upper_inclusive = right[2], right[3]
        elif right[2] is not None and right[2] == upper:
            upper_inclusive = upper_inclusive and right[3]
        if (
            lower is not None
            and upper is not None
            and (
                lower > upper
                or (lower == upper and not (lower_inclusive and upper_inclusive))
            )
        ):
            return None
        return (lower, lower_inclusive, upper, upper_inclusive)

    @staticmethod
    def _usage_locations(
        usages: Sequence[UsageEvidence],
    ) -> tuple[SourceLocation, ...]:
        return tuple(item.source for item in usages)
