"""Package-neutral evidence and ecosystem provider boundaries."""

from collections.abc import Mapping

from depcheck.ecosystems.base import (
    EcosystemPack,
    EvidenceCollector,
    ManifestProvider,
    ProjectDetector,
    ProviderContext,
    ResolutionProvider,
    UsageMapper,
    UsageProvider,
)
from depcheck.model import (
    Capability,
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    PackageRef,
    ProjectUnit,
    ResolvedDependency,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.ecosystems.registry import EcosystemRegistry


def create_default_registry(
    import_mapping: Mapping[str, str] | None = None,
) -> EcosystemRegistry:
    """Create a fresh registry containing all built-in packs available in M0."""
    from depcheck.ecosystems.javascript import create_npm_pack
    from depcheck.ecosystems.go import create_go_pack
    from depcheck.ecosystems.java import create_maven_pack
    from depcheck.ecosystems.cpp import create_conan_pack, create_vcpkg_pack
    from depcheck.ecosystems.python import create_python_pack

    registry = EcosystemRegistry()
    registry.register(create_python_pack(import_mapping))
    registry.register(create_npm_pack())
    registry.register(create_go_pack())
    registry.register(create_maven_pack())
    registry.register(create_conan_pack())
    registry.register(create_vcpkg_pack())
    return registry


__all__ = [
    "Capability",
    "DependencyDeclaration",
    "EcosystemPack",
    "EvidenceCollector",
    "EcosystemRegistry",
    "EvidenceBundle",
    "ManifestProvider",
    "MappingConfidence",
    "PackageRef",
    "ProjectDetector",
    "ProjectUnit",
    "ProviderContext",
    "ResolutionProvider",
    "ResolvedDependency",
    "UsageEvidence",
    "UsageMapper",
    "UsageProvider",
    "VersionConstraint",
    "create_default_registry",
]
