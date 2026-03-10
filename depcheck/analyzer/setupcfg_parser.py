from __future__ import annotations
from typing import Dict, Optional
import configparser
import logging

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class SetupCfgParser(BaseDependencyParser):
    
    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        if not self.path.exists():
            logger.warning(f"setup.cfg not found: {self.path}")
            return deps
        
        config = configparser.ConfigParser()
        try:
            config.read(self.path)
        except Exception as e:
            logger.error(f"Error parsing setup.cfg {self.path}: {e}")
            return deps
        
        if "options" not in config or "install_requires" not in config["options"]:
            logger.info(f"No install_requires found in {self.path}")
            return deps
        
        requires = config["options"]["install_requires"].splitlines()
        for line in requires:
            line = line.strip()
            if not line:
                continue
            
            name, version = self.parse_line(line)
            if name:
                deps[name] = version
                
        return deps