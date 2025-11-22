from __future__ import annotations
from typing import Dict, Optional
from pathlib import Path
import configparser

from .base_parser import BaseDependencyParser

class SetipCfgParser(BaseDependencyParser):
    
    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        if not self.path.exists():
            return deps
        
        config = configparser.ConfigParser()
        try:
            config.read(self.path)
        except Exception:
            return deps
        
        if "options" not in config or "install_requires" not in config["options"]:
            return deps
        
        requires = config["options"]["install_requires"].splitlines()
        for line in requires:
            line = line.strip()
            if not line:
                continue
            
            for sign in ["==", ">=", "<=", "~=", "!=", "<", ">"]:
                if sign in line:
                    name, version = line.split(sign, 1)
                    deps[name.strip().lower()] = f"{sign}{version.strip()}"
                    break
                else:
                    deps[line.lower()] = None
                    
        return deps