from __future__ import annotations
from pathlib import Path
from typing import Dict, Optional, List, Type
import logging

from ..analyzer.base_parser import BaseDependencyParser
from ..analyzer.requirement_parser import RequirementParser
from ..analyzer.pyproject_parser import PyProjectParser
from ..analyzer.setupcfg_parser import SetupCfgParser
from ..analyzer.pip_install_parser import PipInstallParser

logger = logging.getLogger(__name__)

parser_map: Dict[str, Type[BaseDependencyParser]] = {
    "requirements.txt": RequirementParser,
    "pyproject.toml": PyProjectParser,
    "setup.cfg": SetupCfgParser,
    "Dockerfile": PipInstallParser,
    "dockerfile": PipInstallParser,
    "Makefile": PipInstallParser,
    "makefile": PipInstallParser,
    "CMakeLists.txt": PipInstallParser,
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
                logger.info(f"Found dependency file: {file}")

        for file in sorted(self.project_root.glob("requirements*.txt")):
            if file not in found_files:
                found_files.append(file)
                logger.info(f"Found dependency file: {file}")
                
        if not found_files:
            logger.warning(f"No dependency files found in {self.project_root}")
                
        return found_files
    
    def parse_all(self) -> Dict[str, Optional[str]]:
        dependency_files = self.find_dependency_file()
        all_deps: Dict[str, Optional[str]] = {}
        
        for file_path in dependency_files:
            parser_class = self._get_parser(file_path)
            parser = parser_class(file_path)
            
            try:
                deps = parser.parse()
                all_deps.update(deps)
                logger.info(f"Parsed {len(deps)} dependencies from {file_path.name}")
            except Exception as e:
                logger.error(f"Failed to parse {file_path}: {e}")
                
        return all_deps

    def _get_parser(self, file_path: Path) -> Type[BaseDependencyParser]:
        if file_path.name in parser_map:
            return parser_map[file_path.name]
        if file_path.name.startswith("requirements") and file_path.suffix == ".txt":
            return RequirementParser
        raise KeyError(f"Unsupported dependency file: {file_path}")
    
    def generate_report(self) -> str:
        deps = self.parse_all()
        if not deps:
            return "No dependency files found."
        
        lines = []
        for pkg, version in sorted(deps.items()):
            if version:
                lines.append(f"{pkg}=={version}")
            else:
                lines.append(f"{pkg} (no version)")
        return "\n".join(lines)
