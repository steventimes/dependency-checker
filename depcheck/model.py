from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


class CapabilityState(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    state: CapabilityState
    reason: str | None = None

    @property
    def complete(self) -> bool:
        return self.state is CapabilityState.COMPLETE

    def to_dict(self) -> dict[str, str]:
        result = {"state": self.state.value}
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    project_id: str
    ecosystem: str
    name: str
    version: str | None = None
    instance: str | None = None
    purl: str | None = field(default=None, compare=False)

    @property
    def coordinates(self) -> tuple[str, str, str, str | None, str | None]:
        return (
            self.project_id,
            self.ecosystem,
            self.name,
            self.version,
            self.instance,
        )

    @property
    def sort_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.project_id,
            self.ecosystem.lower(),
            self.name,
            self.version or "",
            self.instance or "",
        )

    def to_dict(self) -> dict[str, str]:
        result = {
            "project_id": self.project_id,
            "ecosystem": self.ecosystem,
            "package": self.name,
        }
        if self.version is not None:
            result["version"] = self.version
        if self.instance is not None:
            result["instance"] = self.instance
        if self.purl is not None:
            result["purl"] = self.purl
        return result


class MappingConfidence(StrEnum):
    EXACT = "exact"
    CONFIGURED = "configured"
    INFERRED = "inferred"
    UNKNOWN = "unknown"

    @property
    def qualifies_for_hygiene(self) -> bool:
        return self in {self.EXACT, self.CONFIGURED}


@dataclass(frozen=True, slots=True)
class PackageRef:
    ecosystem: str
    name: str
    display_name: str
    purl: str | None = None

    def key(self, project_id: str) -> tuple[str, str, str]:
        return (project_id, self.ecosystem.lower(), self.name)

    def to_dict(self) -> dict[str, str]:
        result = {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "display_name": self.display_name,
        }
        if self.purl is not None:
            result["purl"] = self.purl
        return result


@dataclass(frozen=True, slots=True)
class VersionConstraint:
    raw: str
    scheme: str
    normalized: str | None = None


@dataclass(frozen=True, slots=True)
class ProjectUnit:
    project_id: str
    root: Path
    language: str
    ecosystem: str
    manager: str
    manifests: tuple[Path, ...] = field(default_factory=tuple)
    locks: tuple[Path, ...] = field(default_factory=tuple)

    @staticmethod
    def stable_id(relative_root: Path, ecosystem: str, manager: str) -> str:
        root = relative_root.as_posix() or "."
        return f"{ecosystem.lower()}:{manager.lower()}:{root}"


@dataclass(frozen=True, slots=True)
class DependencyDeclaration:
    project_id: str
    package: PackageRef
    constraint: VersionConstraint
    source: SourceLocation
    scope: str = "runtime"
    kind: str = "direct"
    marker: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResolvedDependencyLink:
    package: PackageRef
    version: str | None = None
    instance_id: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedDependency:
    project_id: str
    package: PackageRef
    version: str
    source: SourceLocation
    direct: bool = False
    integrity: str | None = None
    dependencies: tuple[PackageRef, ...] = field(default_factory=tuple)
    instance_id: str | None = None
    dependency_links: tuple[ResolvedDependencyLink, ...] = field(default_factory=tuple)

    @property
    def identity(self) -> PackageIdentity:
        return PackageIdentity(
            self.project_id,
            self.package.ecosystem,
            self.package.name,
            self.version,
            self.instance_id,
            self.package.purl,
        )


@dataclass(frozen=True, slots=True)
class UsageEvidence:
    project_id: str
    language: str
    reference: str
    source: SourceLocation
    scope: str = "runtime"
    kind: str = "regular"
    mapped_package: PackageRef | None = None
    mapping_confidence: MappingConfidence = MappingConfidence.UNKNOWN
    mapping_reason: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    project: ProjectUnit
    declarations: tuple[DependencyDeclaration, ...] = field(default_factory=tuple)
    resolved: tuple[ResolvedDependency, ...] = field(default_factory=tuple)
    usages: tuple[UsageEvidence, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    capabilities: tuple[Capability, ...] = field(default_factory=tuple)
    source_files: tuple[Path, ...] = field(default_factory=tuple)
    evidence_files: tuple[Path, ...] = field(default_factory=tuple)

    def to_dict(self, repository_root: Path) -> dict[str, Any]:
        return {
            "project": {
                "project_id": self.project.project_id,
                "root": self.project.root.as_posix(),
                "language": self.project.language,
                "ecosystem": self.project.ecosystem,
                "manager": self.project.manager,
                "manifests": [
                    _relative(path, repository_root) for path in self.project.manifests
                ],
                "locks": [
                    _relative(path, repository_root) for path in self.project.locks
                ],
            },
            "declarations": [
                {
                    "project_id": item.project_id,
                    "package": item.package.to_dict(),
                    "constraint": {
                        "raw": item.constraint.raw,
                        "scheme": item.constraint.scheme,
                        "normalized": item.constraint.normalized,
                    },
                    "location": item.source.to_dict(repository_root),
                    "scope": item.scope,
                    "kind": item.kind,
                    "marker": item.marker,
                    "metadata": dict(item.metadata),
                }
                for item in self.declarations
            ],
            "resolved": [
                {
                    "identity": item.identity.to_dict(),
                    "location": item.source.to_dict(repository_root),
                    "direct": item.direct,
                    "integrity": item.integrity,
                    "dependencies": [
                        package.to_dict() for package in item.dependencies
                    ],
                    "dependency_links": [
                        {
                            "package": link.package.to_dict(),
                            "version": link.version,
                            "instance_id": link.instance_id,
                        }
                        for link in item.dependency_links
                    ],
                }
                for item in self.resolved
            ],
            "usages": [
                {
                    "project_id": item.project_id,
                    "language": item.language,
                    "reference": item.reference,
                    "location": item.source.to_dict(repository_root),
                    "scope": item.scope,
                    "kind": item.kind,
                    "mapped_package": (
                        item.mapped_package.to_dict()
                        if item.mapped_package is not None
                        else None
                    ),
                    "mapping_confidence": item.mapping_confidence.value,
                    "mapping_reason": item.mapping_reason,
                }
                for item in self.usages
            ],
            "diagnostics": [item.to_dict(repository_root) for item in self.diagnostics],
            "capabilities": {item.name: item.to_dict() for item in self.capabilities},
            "source_files": [
                _relative(path, repository_root) for path in self.source_files
            ],
            "evidence_files": [
                _relative(path, repository_root) for path in self.evidence_files
            ],
        }


def _relative(path: Path, repository_root: Path) -> str:
    try:
        return path.resolve().relative_to(repository_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


@dataclass(frozen=True, slots=True)
class SourceLocation:
    path: Path
    line: int | None = None
    column: int | None = None

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        path = self.path
        if root is not None:
            try:
                path = path.resolve().relative_to(root.resolve())
            except ValueError:
                pass
        result: dict[str, Any] = {"path": path.as_posix()}
        if self.line is not None:
            result["line"] = self.line
        if self.column is not None:
            result["column"] = self.column
        return result


@dataclass(frozen=True, slots=True)
class PythonRequirement:
    name: str
    display_name: str
    raw_requirement: str
    specifier: SpecifierSet
    marker: Marker | None
    extras: tuple[str, ...]
    source: SourceLocation
    group: str = "runtime"
    kind: str = "direct"

    @classmethod
    def from_requirement(
        cls,
        raw_requirement: str,
        *,
        source: SourceLocation,
        group: str = "runtime",
        kind: str = "direct",
    ) -> PythonRequirement:
        parsed = Requirement(raw_requirement.strip())
        return cls(
            name=str(canonicalize_name(parsed.name)),
            display_name=parsed.name,
            raw_requirement=raw_requirement.strip(),
            specifier=parsed.specifier,
            marker=parsed.marker,
            extras=tuple(sorted(parsed.extras)),
            source=source,
            group=group,
            kind=kind,
        )

    def is_active(self, environment: Mapping[str, str] | None = None) -> bool:
        return self.marker is None or self.marker.evaluate(
            environment=dict(environment) if environment else None
        )

    @property
    def pinned_version(self) -> str | None:
        items = list(self.specifier)
        if len(items) != 1:
            return None
        item = items[0]
        if item.operator not in {"==", "==="} or "*" in item.version:
            return None
        return item.version


@dataclass(frozen=True, slots=True)
class ManifestParseResult:
    declarations: tuple[PythonRequirement, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    files: tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ImportEvidence:
    module: str
    source: SourceLocation
    scope: str = "runtime"
    kind: str = "regular"


@dataclass(frozen=True, slots=True)
class ImportScanResult:
    imports: tuple[ImportEvidence, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    files: tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    severity: str
    message: str
    source: SourceLocation | None = None

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.source is not None:
            result["location"] = self.source.to_dict(root)
        return result


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    package: PackageIdentity
    severity: str
    message: str
    locations: tuple[SourceLocation, ...] = field(default_factory=tuple)
    details: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        return {
            "code": self.code,
            "identity": self.package.to_dict(),
            "severity": self.severity,
            "message": self.message,
            "locations": [location.to_dict(root) for location in self.locations],
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    import_mapping: Mapping[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)

    @property
    def status(self) -> str:
        if not self.complete:
            return "incomplete"
        return "fail" if self.findings else "pass"

    @property
    def risk_count(self) -> int:
        return len(self.findings)

    def to_dict(self, root: Path | None = None) -> dict[str, Any]:
        return {
            "status": self.status,
            "complete": self.complete,
            "risk_count": self.risk_count,
            "diagnostic_count": len(self.diagnostics),
            "findings": [item.to_dict(root) for item in self.findings],
            "diagnostics": [item.to_dict(root) for item in self.diagnostics],
            "import_mapping": dict(sorted(self.import_mapping.items())),
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    root: Path
    capabilities: tuple[Capability, ...]
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    diagnostics: tuple[Diagnostic, ...] = field(default_factory=tuple)
    bundles: tuple[EvidenceBundle, ...] = field(default_factory=tuple)
    vulnerabilities: Mapping[PackageIdentity, tuple[Mapping[str, Any], ...]] = field(
        default_factory=dict
    )
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def capability(self, name: str) -> Capability:
        return next(item for item in self.capabilities if item.name == name)

    @property
    def complete(self) -> bool:
        return all(capability.complete for capability in self.capabilities) and not any(
            diagnostic.severity == "error" for diagnostic in self.diagnostics
        )

    @property
    def risk_count(self) -> int:
        return len(self.findings)

    @property
    def status(self) -> str:
        if not self.complete:
            return "incomplete"
        return "fail" if self.findings else "pass"

    def to_dict(self) -> dict[str, Any]:
        counts = Counter(finding.code for finding in self.findings)
        source_files = sorted(
            {
                _relative(path, self.root)
                for bundle in self.bundles
                for path in bundle.source_files
            }
        )
        manifest_files = sorted(
            {
                path.as_posix()
                for bundle in self.bundles
                for path in bundle.project.manifests
            }
        )
        resolved = [
            {
                "identity": item.identity.to_dict(),
                "direct": item.direct,
                "integrity": item.integrity,
                "dependencies": [
                    {
                        "ecosystem": link.package.ecosystem,
                        "package": link.package.name,
                        "version": link.version,
                        "instance": link.instance_id,
                    }
                    for link in item.dependency_links
                ],
            }
            for bundle in self.bundles
            for item in bundle.resolved
        ]
        projects = [
            {
                "project_id": bundle.project.project_id,
                "root": bundle.project.root.as_posix(),
                "language": bundle.project.language,
                "ecosystem": bundle.project.ecosystem,
                "manager": bundle.project.manager,
                "manifests": [path.as_posix() for path in bundle.project.manifests],
                "locks": [path.as_posix() for path in bundle.project.locks],
                "source_file_count": len(bundle.source_files),
                "declaration_count": len(bundle.declarations),
                "resolved_count": len(bundle.resolved),
                "usage_count": len(bundle.usages),
                "capabilities": {
                    item.name: item.to_dict() for item in bundle.capabilities
                },
            }
            for bundle in self.bundles
        ]
        ecosystems: dict[str, dict[str, int]] = {}
        for bundle in self.bundles:
            summary = ecosystems.setdefault(
                bundle.project.ecosystem,
                {
                    "project_count": 0,
                    "declaration_count": 0,
                    "resolved_count": 0,
                    "usage_count": 0,
                    "source_file_count": 0,
                },
            )
            summary["project_count"] += 1
            summary["declaration_count"] += len(bundle.declarations)
            summary["resolved_count"] += len(bundle.resolved)
            summary["usage_count"] += len(bundle.usages)
            summary["source_file_count"] += len(bundle.source_files)

        return {
            "schema": "depcheck.scan.v1",
            "summary": {
                "status": self.status,
                "complete": self.complete,
                "risk_count": self.risk_count,
                "diagnostic_count": len(self.diagnostics),
                "counts": dict(sorted(counts.items())),
            },
            "capabilities": {
                capability.name: capability.to_dict()
                for capability in self.capabilities
            },
            "findings": [finding.to_dict(self.root) for finding in self.findings],
            "diagnostics": [
                diagnostic.to_dict(self.root) for diagnostic in self.diagnostics
            ],
            "inventory": {
                "source_file_count": len(source_files),
                "source_files": source_files,
                "manifest_file_count": len(manifest_files),
                "manifest_files": manifest_files,
                "declaration_count": sum(
                    len(bundle.declarations) for bundle in self.bundles
                ),
                "resolved_count": len(resolved),
                "resolved_dependencies": resolved,
                "usage_count": sum(len(bundle.usages) for bundle in self.bundles),
            },
            "projects": projects,
            "ecosystems": ecosystems,
            "vulnerabilities": [
                {
                    "identity": identity.to_dict(),
                    "issues": [dict(issue) for issue in issues],
                }
                for identity, issues in sorted(
                    self.vulnerabilities.items(),
                    key=lambda item: item[0].sort_key,
                )
            ],
            "metadata": dict(self.metadata),
        }
