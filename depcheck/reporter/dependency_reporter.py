from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional, List, Type

from ..analyzer.base_parser import BaseDependencyParser
from ..analyzer.requirement_parser import RequirementParser
from ..analyzer.pyproject_parser import PyProjectParser
from ..analyzer.setupcfg_parser import SetipCfgParser

parser_map: Dict[str, Type[BaseDependencyParser]] = {
    "requirement.txt": RequirementParser,
    "pyproject.toml": PyProjectParser,
    "setup.cfg": SetipCfgParser,
}

class DependencyReporter:
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        
    def find_dependency_file(self) -> List[Path]:
        found_files: List[Path] = []
        
        for filename in parser_map.keys():
            file = self.project_root / filename
            if file.exists():
                found_files.append(file)
                
        return found_files
    
    def parse_all(self) -> Dict[str, Optional[str]]:
        dependency_files = self.find_dependency_file()
        all_deps: Dict[str, Optional[str]] = {}
        
        for file_path in dependency_files:
            parser_class = parser_map[file_path.name]
            parser = parser_class(file_path)
            
            try:
                deps = parser.parse()
            except Exception:
                deps = {}
                
            all_deps.update(deps)
            
        return all_deps
    
    def generate_report(self) -> str:
        
        deps = self.parse_all()
        if not deps:
            return "No dependency files found."
        
        lines = []
        for pkg, version in sorted(deps.items()):
            if version:
                lines.append(f"{pkg}{version}")
            else:
                lines.append(f"{pkg}(no version)")
        return "\n".join(lines)