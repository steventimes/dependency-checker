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

__version__ = "0.4.0"

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
