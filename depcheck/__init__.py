"""Canonical public API for depcheck."""

from .engine import RepositoryScanner, RepositoryScanOptions
from .model import (
    AnalysisReport,
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    Finding,
    PackageIdentity,
    PackageRef,
    ProjectUnit,
    ResolvedDependency,
    ScanResult,
    SourceLocation,
    UsageEvidence,
    VersionConstraint,
)

from ._version import __version__

__all__ = [
    "AnalysisReport",
    "Capability",
    "CapabilityState",
    "DependencyDeclaration",
    "Diagnostic",
    "EvidenceBundle",
    "Finding",
    "PackageIdentity",
    "PackageRef",
    "ProjectUnit",
    "RepositoryScanOptions",
    "RepositoryScanner",
    "ResolvedDependency",
    "ScanResult",
    "SourceLocation",
    "UsageEvidence",
    "VersionConstraint",
    "__version__",
]
