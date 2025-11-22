from __future__ import annotations
from typing import Dict, Optional
from pathlib import Path
import tomllib

from .base_parser import BaseDependencyParser

class PyProjectParser(BaseDependencyParser):
    
    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        
        if not self.path.exists():
            return deps
        
        try:
            data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return deps
        
        projects = data.get("project")
        if not projects:
            return deps
        
        dep_list = projects.get("dependencies", [])
        for line in dep_list:
                line = line.strip()
                
                for sign in ["==", ">=", "<=", "~=", "!=", "<", ">"]:
                    if sign in line:
                        name, version = line.split(sign, 1)
                        deps[name.strip().lower()] = f"{sign}{version.strip()}"
                        break
                else:
                    deps[line.lower()] = None
        return deps