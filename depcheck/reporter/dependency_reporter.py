from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, Optional, List, Type
import logging

from ..analyzer.base_parser import BaseDependencyParser
from ..analyzer.requirement_parser import RequirementParser
from ..analyzer.pyproject_parser import PyProjectParser
from ..analyzer.setupcfg_parser import SetupCfgParser
from ..analyzer.pip_install_parser import PipInstallParser

logger = logging.getLogger(__name__)

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}

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
        self.last_dependency_files: List[Path] = []
        
    def find_dependency_file(self) -> List[Path]:
        found_files: List[Path] = []
        seen: set[Path] = set()

        for dirpath, dirnames, filenames in os.walk(self.project_root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_dir(dirname)
            ]
            current_dir = Path(dirpath)
            filename_set = set(filenames)

            for filename in sorted(parser_map.keys()):
                if filename in filename_set:
                    self._append_dependency_file(current_dir / filename, found_files, seen)

            for filename in sorted(name for name in filename_set if name.startswith("requirements") and name.endswith(".txt")):
                self._append_dependency_file(current_dir / filename, found_files, seen)
                
        if not found_files:
            logger.warning(f"No dependency files found in {self.project_root}")

        self.last_dependency_files = found_files
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

    def _append_dependency_file(self, file_path: Path, found_files: List[Path], seen: set[Path]) -> None:
        if file_path in seen:
            return
        seen.add(file_path)
        found_files.append(file_path)
        logger.info(f"Found dependency file: {file_path}")

    def _should_ignore_dir(self, name: str) -> bool:
        return name.startswith(".") or name in IGNORED_DIRECTORIES
    
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
