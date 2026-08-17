from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from depcheck.model import (
    DependencyDeclaration,
    EvidenceBundle,
    ProjectUnit,
    ResolvedDependency,
    UsageEvidence,
)


@dataclass(frozen=True, slots=True)
class ProviderContext:
    """Read-only repository context shared by stateless providers."""

    repository_root: Path
    settings: Mapping[str, Any] = field(default_factory=dict)


class ProjectDetector(Protocol):
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        raise NotImplementedError


class ManifestProvider(Protocol):
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[DependencyDeclaration, ...]:
        raise NotImplementedError


class ResolutionProvider(Protocol):
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[ResolvedDependency, ...]:
        raise NotImplementedError


class UsageProvider(Protocol):
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[UsageEvidence, ...]:
        raise NotImplementedError


class UsageMapper(Protocol):
    def map(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        usage: UsageEvidence,
    ) -> UsageEvidence:
        raise NotImplementedError


class EvidenceCollector(Protocol):
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class EcosystemPack:
    """A composed registration; unsupported providers remain explicit."""

    ecosystem: str
    detector: ProjectDetector
    manifest_provider: ManifestProvider | None = None
    resolution_provider: ResolutionProvider | None = None
    usage_provider: UsageProvider | None = None
    usage_mapper: UsageMapper | None = None
    capabilities: frozenset[str] = field(default_factory=frozenset)
    collector: EvidenceCollector | None = None
