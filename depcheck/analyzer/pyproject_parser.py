from __future__ import annotations
from typing import Dict, Optional
from pathlib import Path
import tomllib
import logging

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class PyProjectParser(BaseDependencyParser):
    
    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        
        if not self.path.exists():
            logger.warning(f"pyproject.toml not found: {self.path}")
            return deps
        
        try:
            data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml {self.path}: {e}")
            return deps
        
        projects = data.get("project")
        if not projects:
            logger.info(f"No 'project' section found in {self.path}")
            return deps
        
        dep_list = projects.get("dependencies", [])
        for line in dep_list:
            line = line.strip()
            
            version_found = False
            for sign in ["==", ">=", "<=", "~=", "!=", "<", ">"]:
                if sign in line:
                    name, version = line.split(sign, 1)
                    deps[name.strip().lower()] = version.strip()
                    version_found = True
                    break
            
            if not version_found:
                deps[line.lower()] = None
                
        return deps