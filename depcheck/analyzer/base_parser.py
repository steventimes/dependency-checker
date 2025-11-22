from abc import ABC
from pathlib import Path
from typing import Dict, Optional
class BaseDependencyParser(ABC):
    
    def __init__(self, path: Path):
        self.path = Path(path)
    
    @classmethod
    def parse(self) -> Dict[str, Optional[str]]:
        raise NotImplementedError