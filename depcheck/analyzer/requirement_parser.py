from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional
import logging

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class RequirementParser(BaseDependencyParser):

    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        
        if not self.path.exists():
            logger.warning(f"Requirements file not found: {self.path}")
            return deps
        
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if not line:
                        continue
                    
                    name, version = self.parse_line(line)
                    if name:
                        deps[name] = version
                        
        except Exception as e:
            logger.error(f"Error parsing requirements file {self.path}: {e}")
                    
        return deps