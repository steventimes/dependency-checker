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


class EcosystemRegistry:
    """Deterministic registry for independently composed ecosystem packs."""

    def __init__(self) -> None:
        self._packs: dict[str, EcosystemPack] = {}

    def register(self, pack: EcosystemPack) -> None:
        key = pack.ecosystem.lower()
        if key in self._packs:
            raise ValueError(f"ecosystem already registered: {pack.ecosystem}")
        self._packs[key] = pack

    def get(self, ecosystem: str) -> EcosystemPack:
        try:
            return self._packs[ecosystem.lower()]
        except KeyError as exc:
            raise KeyError(f"unknown ecosystem: {ecosystem}") from exc

    def runtime_capabilities(self) -> dict[str, list[str]]:
        return {
            pack.ecosystem: sorted(pack.capabilities)
            for _, pack in sorted(self._packs.items())
        }

    def discover(
        self,
        repository_root: Path,
        enabled: tuple[str, ...] | None = None,
        *,
        settings: Mapping[str, Any] | None = None,
    ) -> tuple[ProjectUnit, ...]:
        selected = (
            {item.lower() for item in enabled}
            if enabled is not None
            else set(self._packs)
        )
        context = ProviderContext(
            Path(repository_root).resolve(),
            settings or {},
        )
        units = [
            unit
            for key in sorted(selected)
            for unit in self.get(key).detector.detect(context)
        ]
        return tuple(
            sorted(
                units,
                key=lambda unit: (
                    len(unit.root.parts),
                    unit.root.as_posix(),
                    unit.project_id,
                ),
            )
        )

    @staticmethod
    def owner_for(
        relative_path: Path,
        projects: tuple[ProjectUnit, ...],
    ) -> ProjectUnit | None:
        path = Path(relative_path)
        candidates = [unit for unit in projects if _contains(unit.root, path)]
        return max(
            candidates,
            key=lambda unit: len(unit.root.parts),
            default=None,
        )


def _contains(project_root: Path, path: Path) -> bool:
    root = Path(project_root)
    if root == Path("."):
        return not path.is_absolute() and ".." not in path.parts
    return path == root or root in path.parents
