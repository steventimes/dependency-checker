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

        specifier = str(requirement.specifier) if requirement.specifier else None
        return requirement.name.strip().lower(), specifier

    @abstractmethod
    def parse(self) -> Dict[str, Optional[str]]:
        raise NotImplementedError
