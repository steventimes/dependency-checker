from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional, Tuple

class BaseDependencyParser(ABC):
    
    def __init__(self, path: Path):
        self.path = Path(path)
    
    @staticmethod
    def parse_line(line: str) -> Tuple[str, Optional[str]]:
        """
        Parses a dependency string into a (name, version) tuple.
        """
        line = line.strip()
        
        if ";" in line:
            line = line.split(";")[0].strip()

        operators = ["==", ">=", "<=", "~=", "!=", "<", ">"]
        
        for op in operators:
            if op in line:
                parts = line.split(op, 1)
                name = parts[0].strip().lower()
                version = parts[1].strip()
                return name, version
        
        return line.lower(), None

    @abstractmethod
    def parse(self) -> Dict[str, Optional[str]]:
        raise NotImplementedError