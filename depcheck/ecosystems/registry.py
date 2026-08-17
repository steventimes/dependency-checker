from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.model import ProjectUnit


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
