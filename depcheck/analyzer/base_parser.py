from abc import ABC, abstractmethod
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement


class BaseDependencyParser(ABC):
    def __init__(self, path: Path):
        self.path = Path(path)

    @staticmethod
    def parse_line(line: str) -> tuple[str, str | None]:
        """
        Parses a dependency string into a (name, version) tuple.
        """
        line = line.strip()
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            return "", None

        name = requirement.name.strip().lower()
        specifier = str(requirement.specifier)
        version = (
            BaseDependencyParser._normalize_version(specifier) if specifier else None
        )
        return name, version

    @staticmethod
    def _normalize_version(raw_version: str) -> str | None:
        """Return a clean version string without comparator prefixes."""
        version = raw_version.strip().lstrip("=<>!~").strip()
        return version or None

    @abstractmethod
    def parse(self) -> dict[str, str | None]:
        raise NotImplementedError
