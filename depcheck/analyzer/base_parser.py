from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional, Tuple

from packaging.requirements import Requirement

class BaseDependencyParser(ABC):
    
    def __init__(self, path: Path):
        self.path = Path(path)
    
    @staticmethod
    def parse_line(line: str) -> Tuple[str, Optional[str]]:
        """
        Parses a dependency string into a (name, version) tuple.
        """
        line = line.strip()
        try:
            requirement = Requirement(line)
        except Exception:
            return "", None

        operators = ["==", ">=", "<=", "~=", "!=", "<", ">", "="]
        
        for op in operators:
            if op in line:
                parts = line.split(op, 1)
                name = parts[0].split("[", 1)[0].strip().lower()
                version = BaseDependencyParser._normalize_version(parts[1])
                return name, version

        return line.split("[", 1)[0].strip().lower(), None

    @staticmethod
    def _normalize_version(raw_version: str) -> Optional[str]:
        """Return a clean version string without comparator prefixes."""
        version = raw_version.strip().lstrip("=<>!~").strip()
        return version or None

    @abstractmethod
    def parse(self) -> Dict[str, Optional[str]]:
        raise NotImplementedError
