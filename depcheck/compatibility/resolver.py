"""Bounded metadata resolution. This is not an installer or an API check.

Extras have separate criteria coupled to an exact base version. This lets a
new extra invalidate a previous choice without keeping dependencies from a
discarded branch. Requires-Python participates in the same backtracking graph.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from resolvelib import AbstractProvider, BaseReporter, Resolver
from resolvelib.resolvers import ResolutionImpossible, ResolutionTooDeep

from depcheck.model import Diagnostic, ManifestParseResult, PythonRequirement

from .metadata import ReleaseMetadata
from .models import (
    CompatibilityConflict,
    CompatibilityReport,
    PythonCompatibilityConflict,
    append_diagnostic,
)

PYTHON = "@python"


@dataclass(frozen=True)
class _Requirement:
    name: str
    specifier: str = ""
    extras: tuple[str, ...] = ()
    source: str = "project manifest"
    dependencies: bool = True

    @property
    def identifier(self) -> str:
        return self.name + (f"[{','.join(self.extras)}]" if self.extras else "")


@dataclass(frozen=True)
class _Candidate:
    name: str
    version: str
    extras: tuple[str, ...] = ()
    dependencies: bool = True

    @property
    def identifier(self) -> str:
        return self.name + (f"[{','.join(self.extras)}]" if self.extras else "")


class _Incomplete(Exception):
    pass


class _Provider(AbstractProvider[_Requirement, _Candidate, str]):
    MAX_REQUESTS = 256
    MAX_PACKAGES = 512
    MAX_VERSIONS = 10000
    MAX_DEPENDENCIES = 2048
    MAX_REQUIREMENTS = 20000

    def __init__(
        self,
        metadata: ReleaseMetadata,
        environment: dict[str, str],
        constraints: dict[str, list[_Requirement]],
        blocked: set[str],
        diagnostics: list[Diagnostic],
    ) -> None:
        self.release_metadata = metadata
        self.environment = environment
        self.constraints = constraints
        self.blocked = blocked
        self.diagnostics = diagnostics
        self.preferred: dict[str, str] = {}
        self.versions: dict[str, list[str]] = {}
        self.metadata: dict[tuple[str, str], Mapping[str, Any]] = {}
        self.requests = 0
        self.requirement_count = 0
        self.dependency_cache: dict[_Candidate, tuple[_Requirement, ...]] = {}

    def stop(self, code: str, message: str) -> Any:
        append_diagnostic(
            self.diagnostics, Diagnostic(code=code, severity="error", message=message)
        )
        raise _Incomplete(message)

    def request(self) -> None:
        if self.requests >= self.MAX_REQUESTS:
            self.stop(
                "compatibility.metadata-budget",
                "Metadata request budget exhausted; satisfiability is unknown.",
            )
        self.requests += 1

    def identify(self, requirement_or_candidate: _Requirement | _Candidate) -> str:
        return requirement_or_candidate.identifier

    def get_preference(
        self,
        identifier: str,
        resolutions: Mapping[str, _Candidate],
        candidates: Mapping[str, Iterator[_Candidate]],
        information: Mapping[str, Iterator[Any]],
        backtrack_causes: Sequence[Any],
    ) -> tuple[int, int, str]:
        requirements = [item.requirement for item in information[identifier]]
        pinned = any(self._exact(item.specifier) is not None for item in requirements)
        return (identifier != PYTHON, not pinned, identifier)

    @staticmethod
    def _exact(specifier: str) -> str | None:
        for item in SpecifierSet(specifier):
            if item.operator in {"==", "==="} and "*" not in item.version:
                return item.version
        return None

    def find_matches(
        self,
        identifier: str,
        requirements: Mapping[str, Iterator[_Requirement]],
        incompatibilities: Mapping[str, Iterator[_Candidate]],
    ) -> list[_Candidate]:
        requested = list(requirements[identifier])
        name = requested[0].name
        if name in self.blocked:
            self.stop(
                "compatibility.source-unverified",
                f"{name}: a declared non-public or ambiguous source cannot be replaced by a public homonym.",
            )
        requested = [*requested, *self.constraints.get(name, [])]
        excluded = set(incompatibilities[identifier])
        combined = SpecifierSet(
            ",".join(item.specifier for item in requested if item.specifier)
        )
        exact = self._exact(str(combined))
        if name == PYTHON:
            versions = [self.environment["python_full_version"]]
        elif exact is not None:
            versions = [exact]
        else:
            if name not in self.versions:
                if len(self.versions) >= self.MAX_PACKAGES:
                    self.stop(
                        "compatibility.package-budget",
                        "Package candidate budget exhausted.",
                    )
                self.request()
                versions, diagnostic = self.release_metadata.versions(name)
                if diagnostic is not None:
                    self.diagnostics.append(diagnostic)
                    raise _Incomplete(diagnostic.message)
                if len(versions) > self.MAX_VERSIONS:
                    self.stop(
                        "compatibility.candidate-budget",
                        f"{name}: release domain exceeds the candidate budget.",
                    )
                parsed: list[tuple[Version, str]] = []
                for raw in versions:
                    try:
                        parsed.append((Version(raw), raw))
                    except InvalidVersion:
                        continue
                self.versions[name] = [raw for _, raw in sorted(parsed, reverse=True)]
            versions = self.versions[name]
        dependencies = any(item.dependencies for item in requested)
        matches: list[_Candidate] = []
        for version in versions:
            try:
                parsed_version = Version(version)
            except InvalidVersion:
                self.stop(
                    "compatibility.unsupported-version",
                    f"{name}: non-PEP-440 exact version cannot be resolved.",
                )
            if (
                parsed_version.is_prerelease
                and not combined.prereleases
                and name != PYTHON
            ):
                continue
            candidate = _Candidate(name, version, requested[0].extras, dependencies)
            if candidate not in excluded and all(
                self.is_satisfied_by(item, candidate) for item in requested
            ):
                matches.append(candidate)
        preferred = self.preferred.get(name)
        if preferred:
            matches.sort(key=lambda item: Version(item.version) != Version(preferred))
        return matches

    def is_satisfied_by(self, requirement: _Requirement, candidate: _Candidate) -> bool:
        return (
            requirement.name == candidate.name
            and (not requirement.extras or requirement.extras == candidate.extras)
            and (not requirement.dependencies or candidate.dependencies)
            and SpecifierSet(requirement.specifier).contains(
                candidate.version, prereleases=True
            )
        )

    def get_dependencies(self, candidate: _Candidate) -> tuple[_Requirement, ...]:
        if candidate in self.dependency_cache:
            return self.dependency_cache[candidate]
        if candidate.name == PYTHON or not candidate.dependencies:
            return ()
        key = (candidate.name, candidate.version)
        if key not in self.metadata:
            self.request()
            info = self.release_metadata.info(
                canonicalize_name(candidate.name), candidate.version, self.diagnostics
            )
            if info is None:
                raise _Incomplete("Release metadata unavailable")
            for field, expected in (
                ("name", candidate.name),
                ("version", candidate.version),
            ):
                value = info.get(field)
                if value is None:
                    continue
                try:
                    matches = (
                        canonicalize_name(value) == expected
                        if field == "name"
                        else Version(value) == Version(expected)
                    )
                except (TypeError, InvalidVersion):
                    matches = False
                if not matches:
                    self.stop(
                        "pypi.metadata-identity-mismatch",
                        f"{candidate.name}=={candidate.version}: {field} does not match the queried release.",
                    )
            self.metadata[key] = info
        info = self.metadata[key]
        source = f"{candidate.identifier}=={candidate.version}"
        dependencies: list[_Requirement] = []
        if candidate.extras:
            dependencies.append(
                _Requirement(
                    candidate.name,
                    f"=={candidate.version}",
                    source=source,
                    dependencies=False,
                )
            )
        raw_python = info.get("requires_python")
        if raw_python is not None:
            try:
                if not isinstance(raw_python, str):
                    raise InvalidSpecifier("requires_python must be a string")
                python_spec = str(SpecifierSet(raw_python))
            except InvalidSpecifier as exc:
                self.stop("pypi.invalid-requires-python", f"{source}: {exc}")
            if python_spec:
                dependencies.append(_Requirement(PYTHON, python_spec, source=source))
        raw_dependencies = info.get("requires_dist")
        if raw_dependencies is None:
            raw_dependencies = []
        if not isinstance(raw_dependencies, list):
            self.stop(
                "pypi.invalid-requires-dist",
                f"{source}: requires_dist must be an array.",
            )
        if len(raw_dependencies) > self.MAX_DEPENDENCIES:
            self.stop(
                "compatibility.dependency-budget",
                f"{source}: dependency metadata exceeds the entry budget.",
            )
        for raw in raw_dependencies:
            try:
                if not isinstance(raw, str) or len(raw) > 16384:
                    raise InvalidRequirement("Requirement must be a bounded string")
                parsed = Requirement(raw)
            except InvalidRequirement as exc:
                self.stop("pypi.invalid-requires-dist", f"{source}: {exc}")
            try:
                applies = _marker_applies(
                    parsed, self.environment, set(candidate.extras)
                )
            except (
                UndefinedComparison,
                UndefinedEnvironmentName,
                InvalidVersion,
            ) as exc:
                self.stop("pypi.invalid-requires-dist-marker", f"{source}: {exc}")
            if not applies:
                continue
            if parsed.url:
                self.stop(
                    "compatibility.source-unverified",
                    f"{source}: direct URL dependency {parsed.name} is outside the public metadata model.",
                )
            dependencies.append(
                _Requirement(
                    str(canonicalize_name(parsed.name)),
                    str(parsed.specifier),
                    tuple(
                        sorted(
                            {str(canonicalize_name(extra)) for extra in parsed.extras}
                        )
                    ),
                    source,
                )
            )
        self.requirement_count += len(dependencies)
        if self.requirement_count > self.MAX_REQUIREMENTS:
            self.stop(
                "compatibility.requirement-budget",
                "Total dependency metadata budget exhausted.",
            )
        result = tuple(dependencies)
        self.dependency_cache[candidate] = result
        return result


def resolve_manifest(
    metadata: ReleaseMetadata,
    manifest: ManifestParseResult,
    active: list[PythonRequirement],
    environment: dict[str, str],
    *,
    max_rounds: int = 1000,
) -> CompatibilityReport:
    diagnostics = list(manifest.diagnostics)
    blocked = {
        str(canonicalize_name(item.name))
        for item in active
        if item.origin.get("public") is not True
    }
    constraints: dict[str, list[_Requirement]] = defaultdict(list)
    roots: list[_Requirement] = [
        _Requirement(PYTHON, f"=={environment['python_full_version']}")
    ]
    relaxed: list[_Requirement] = list(roots)
    locked: dict[str, str] = {}
    for item in active:
        name = str(canonicalize_name(item.name))
        script = item.origin.get("script", {})
        requires_python = (
            script.get("requires_python") if isinstance(script, Mapping) else None
        )
        if requires_python and not SpecifierSet(requires_python).contains(
            environment["python_full_version"], prereleases=True
        ):
            append_diagnostic(
                diagnostics,
                Diagnostic(
                    code="compatibility.script-python-conflict",
                    severity="error",
                    message=f"{item.source.path}: script requires Python {requires_python}; selected metadata environment is {environment['python_full_version']}.",
                    source=item.source,
                ),
            )
        if name in blocked:
            append_diagnostic(
                diagnostics,
                Diagnostic(
                    code="compatibility.source-unverified",
                    severity="error",
                    message=f"{name}: public release metadata cannot establish this source's compatibility.",
                    source=item.source,
                ),
            )
            continue
        requirement = _Requirement(
            name,
            str(item.specifier),
            tuple(sorted({str(canonicalize_name(extra)) for extra in item.extras})),
            f"{item.kind}: {item.source.path}",
        )
        if item.kind == "constraint":
            constraints[name].append(requirement)
        elif item.kind == "locked" and item.pinned_version:
            roots.append(requirement)
            relaxed.append(_Requirement(name, source=requirement.source))
            locked[name] = item.pinned_version
        elif item.kind == "direct":
            roots.append(requirement)
            relaxed.append(requirement)
    provider = _Provider(metadata, environment, constraints, blocked, diagnostics)
    selected: dict[str, str] = {}
    conflicts: list[CompatibilityConflict] = []
    python_conflicts: list[PythonCompatibilityConflict] = []
    suggestions: dict[str, str] = {}
    status = "incomplete"

    def solve(requirements: list[_Requirement]) -> dict[str, str]:
        result = Resolver(provider, BaseReporter()).resolve(
            requirements, max_rounds=max_rounds
        )
        return {
            candidate.name: candidate.version
            for candidate in result.mapping.values()
            if candidate.name != PYTHON
        }

    try:
        if len(roots) + sum(map(len, constraints.values())) > provider.MAX_REQUIREMENTS:
            provider.stop(
                "compatibility.requirement-budget", "Root requirement budget exhausted."
            )
        try:
            selected = solve(roots)
            status = "resolved"
        except ResolutionImpossible as exc:
            status = "unsatisfiable"
            for cause in exc.causes:
                requirement = cause.requirement
                if requirement.name == PYTHON and cause.parent is not None:
                    parent = cause.parent
                    python_conflict = PythonCompatibilityConflict(
                        parent.name,
                        parent.version,
                        requirement.specifier,
                        environment["python_full_version"],
                    )
                    if python_conflict not in python_conflicts:
                        python_conflicts.append(python_conflict)
                    continue
                if requirement.name == PYTHON:
                    continue
                related = [r for r in roots if r.name == requirement.name]
                conflict = CompatibilityConflict(
                    requirement.name,
                    ",".join(r.specifier for r in related) or None,
                    requirement.specifier or "a published release",
                    requirement.source,
                )
                if conflict not in conflicts:
                    conflicts.append(conflict)
            if locked:
                provider.preferred = locked
                try:
                    update = solve(relaxed)
                    suggestions = {
                        name: f"=={version}"
                        for name, version in update.items()
                        if name in locked and Version(locked[name]) != Version(version)
                    }
                except ResolutionImpossible:
                    pass
    except ResolutionTooDeep:
        diagnostics.append(
            Diagnostic(
                code="compatibility.resolution-limit",
                severity="error",
                message=f"Backtracking exceeded {max_rounds} rounds; satisfiability is unknown.",
            )
        )
        if status != "unsatisfiable":
            status = "incomplete"
    except _Incomplete:
        if status != "unsatisfiable":
            status = "incomplete"
    if any(item.severity == "error" for item in diagnostics):
        status = "incomplete"
    return CompatibilityReport(
        conflicts=conflicts,
        missing=[],
        unconstrained=[],
        suggestions=suggestions,
        python_conflicts=python_conflicts,
        diagnostics=diagnostics,
        selected_versions=selected,
        resolution_status=status,
        resolution={
            "algorithm": "resolvelib-backtracking",
            "model": "public-release-metadata-single-environment",
            "objective": "prefer-highest-eligible; lock-relaxation-prefers-recorded-versions",
            "optimality": "not-established",
            "metadata_requests": provider.requests,
            "max_metadata_requests": provider.MAX_REQUESTS,
            "max_rounds": max_rounds,
            "installation_status": "not-checked",
            "artifact_compatibility_status": "not-checked",
            "api_compatibility_status": "not-checked",
        },
    )


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
