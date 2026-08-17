from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)
from depcheck.path_policy import ProjectPathError, require_within_project

from ..analyzer.base_parser import BaseDependencyParser
from ..analyzer.lockfile_parser import LockfileParser
from ..analyzer.pip_install_parser import PipInstallParser
from ..analyzer.pipfile_parser import PipfileParser
from ..analyzer.pyproject_parser import PyProjectParser
from ..analyzer.requirement_parser import RequirementParser
from ..analyzer.setup_py_parser import SetupPyParser
from ..analyzer.setupcfg_parser import SetupCfgParser

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

parser_map: dict[str, type[BaseDependencyParser]] = {
    "requirements.txt": RequirementParser,
    "pyproject.toml": PyProjectParser,
    "setup.cfg": SetupCfgParser,
    "setup.py": SetupPyParser,
    "Pipfile": PipfileParser,
    "uv.lock": LockfileParser,
    "poetry.lock": LockfileParser,
    "pdm.lock": LockfileParser,
    "Pipfile.lock": LockfileParser,
    "Dockerfile": PipInstallParser,
    "dockerfile": PipInstallParser,
    "Makefile": PipInstallParser,
    "makefile": PipInstallParser,
    "CMakeLists.txt": PipInstallParser,
}


class PythonManifestCollector:
    def __init__(
        self,
        project_root: Path,
        excluded_directories: Iterable[str] = (),
    ):
        self.project_root = Path(project_root).resolve()
        self.excluded_directories = tuple(excluded_directories)
        self.last_dependency_files: list[Path] = []
        self.discovery_diagnostics: list[Diagnostic] = []

    def find_dependency_file(self) -> list[Path]:
        found_files: list[Path] = []
        seen: set[Path] = set()
        self.discovery_diagnostics = []

        for dirpath, dirnames, filenames in os.walk(self.project_root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_path(
                    Path(dirpath) / dirname,
                )
            ]
            current_dir = Path(dirpath)
            filename_set = set(filenames)

            for filename in sorted(parser_map.keys()):
                if filename in filename_set:
                    self._append_dependency_file(
                        current_dir / filename, found_files, seen
                    )

            for filename in sorted(
                name
                for name in filename_set
                if name.startswith("requirements") and name.endswith(".txt")
            ):
                self._append_dependency_file(current_dir / filename, found_files, seen)

        if not found_files:
            logger.warning(f"No dependency files found in {self.project_root}")

        self.last_dependency_files = found_files
        return found_files

    def parse_all(self) -> dict[str, str | None]:
        all_deps: dict[str, str | None] = {}
        for item in self.collect().declarations:
            if item.kind in {"constraint", "locked"} or item.group == "build":
                continue
            all_deps[item.name] = BaseDependencyParser._normalize_version(
                str(item.specifier)
            )
        return all_deps

    def collect(self) -> ManifestParseResult:
        """解析并聚合所有清单，同时保留来源和失败诊断。"""
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        files: list[Path] = []
        seen_declarations: set[tuple[object, ...]] = set()
        seen_files: set[Path] = set()

        for file_path in self.find_dependency_file():
            parser_type = self._get_parser(file_path)
            parser = (
                parser_type(file_path, project_root=self.project_root)
                if parser_type is RequirementParser
                else parser_type(file_path)
            )
            try:
                detailed = getattr(parser, "parse_detailed", None)
                if detailed is None:
                    continue
                result = detailed()
            # 聚合边界把未知解析器故障转成“不完整”诊断，避免单文件终止全项目。
            except Exception as exc:  # noqa: BLE001
                diagnostics.append(
                    Diagnostic(
                        code="manifest.parser-error",
                        severity="error",
                        message=f"解析器异常：{exc}",
                    )
                )
                continue

            diagnostics.extend(result.diagnostics)
            for parsed_file in result.files:
                resolved = parsed_file.resolve()
                if resolved not in seen_files:
                    seen_files.add(resolved)
                    files.append(parsed_file)
            for item in result.declarations:
                key = (
                    item.name,
                    item.raw_requirement,
                    item.group,
                    item.kind,
                    item.source.path.resolve(),
                    item.source.line,
                )
                if key not in seen_declarations:
                    seen_declarations.add(key)
                    declarations.append(item)

        diagnostics[:0] = self.discovery_diagnostics
        self.last_dependency_files = files
        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=tuple(files),
        )

    def _get_parser(self, file_path: Path) -> type[BaseDependencyParser]:
        if file_path.name in parser_map:
            return parser_map[file_path.name]
        if file_path.name.startswith("requirements") and file_path.suffix == ".txt":
            return RequirementParser
        raise KeyError(f"Unsupported dependency file: {file_path}")

    def _append_dependency_file(
        self, file_path: Path, found_files: list[Path], seen: set[Path]
    ) -> None:
        try:
            require_within_project(
                self.project_root,
                file_path,
                operation="discover requirements",
            )
        except ProjectPathError:
            self.discovery_diagnostics.append(
                Diagnostic(
                    code="manifest.outside-project-root",
                    severity="error",
                    message="依赖清单越过项目根目录，已拒绝读取",
                    source=SourceLocation(file_path),
                )
            )
            return
        if file_path in seen:
            return
        seen.add(file_path)
        found_files.append(file_path)
        logger.info(f"Found dependency file: {file_path}")

    def _should_ignore_dir(self, name: str) -> bool:
        return name.startswith(".") or name in IGNORED_DIRECTORIES

    def _should_ignore_path(self, path: Path) -> bool:
        if self._should_ignore_dir(path.name):
            return True
        from depcheck.ecosystems.static import is_excluded

        return is_excluded(
            path.relative_to(self.project_root),
            self.excluded_directories,
        )

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
