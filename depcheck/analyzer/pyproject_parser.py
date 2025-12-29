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
        
        optional_deps = projects.get("optional-dependencies", {})
        for group_name, group_deps in optional_deps.items():
            dep_list.extend(group_deps)
        for line in dep_list:
            if not isinstance(line, str):
                continue
                
            name, version = self.parse_line(line)
            if name:
                deps[name] = version
            
        return deps