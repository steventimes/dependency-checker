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
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    version_found = False
                    for sign in ["==", ">=", "<=", "~=", "!=", "<", ">"]:
                        if sign in line:
                            name, version = line.split(sign, 1)
                            deps[name.strip().lower()] = version.strip()
                            version_found = True
                            break
                    
                    if not version_found:
                        deps[line.lower()] = None
        except Exception as e:
            logger.error(f"Error parsing requirements file {self.path}: {e}")
                    
        return deps