from __future__ import annotations

import logging
import os
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from depcheck.ecosystems.coverage import is_pylock_file
from depcheck.ecosystems.python.parsers import BaseDependencyParser
from depcheck.ecosystems.python.parsers.lock import LockfileParser
from depcheck.ecosystems.python.parsers.pip_commands import PipInstallParser
from depcheck.ecosystems.python.parsers.pipfile import PipfileParser
from depcheck.ecosystems.python.parsers.pyproject import PyProjectParser
from depcheck.ecosystems.python.parsers.pylock import PylockParser
from depcheck.ecosystems.python.parsers.requirements import RequirementParser
from depcheck.ecosystems.python.parsers.setup import SetupCfgParser, SetupPyParser
from depcheck.filesystem import (
    ContentChangedError,
    ProjectPathError,
    repository_operation,
    require_within_project,
)
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

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
    "dist-packages",
    "node_modules",
    "site-packages",
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
    "pylock.toml": PylockParser,
    "Pipfile.lock": LockfileParser,
    "Dockerfile": PipInstallParser,
    "dockerfile": PipInstallParser,
    "Makefile": PipInstallParser,
    "makefile": PipInstallParser,
    "CMakeLists.txt": PipInstallParser,
}


def is_requirements_file(path: Path) -> bool:
    candidate = Path(path)
    stem = candidate.stem.lower()
    return candidate.suffix.lower() in {".txt", ".lock"} and (
        stem.startswith("requirements") or stem.endswith("-requirements")
    )


class PythonManifestCollector:
    def __init__(
        self,
        project_root: Path,
        excluded_directories: Iterable[str] = (),
        *,
        configuration_root: Path | None = None,
        configuration_start: Path | None = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.excluded_directories = tuple(excluded_directories)
        self.configuration_root = Path(
            configuration_root or self.project_root
        ).resolve()
        self.configuration_start = configuration_start
        if not self.project_root.is_relative_to(self.configuration_root):
            raise ValueError(
                "Python collection must remain inside its configuration boundary"
            )
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

            for filename in sorted(set(parser_map) | {"uv.toml"}):
                if filename in filename_set:
                    self._append_dependency_file(
                        current_dir / filename, found_files, seen
                    )

            for filename in sorted(
                name
                for name in filename_set
                if is_requirements_file(Path(name)) or is_pylock_file(Path(name))
            ):
                self._append_dependency_file(current_dir / filename, found_files, seen)

        if not found_files:
            logger.debug("No Python dependency files found in %s", self.project_root)

        self.last_dependency_files = found_files
        return found_files

    def parse_all(self) -> dict[str, str | None]:
        all_deps: dict[str, str | None] = {}
        for item in self.collect().declarations:
            if (
                item.kind in {"constraint", "locked", "environment"}
                or item.group == "build"
            ):
                continue
            all_deps[item.name] = BaseDependencyParser._normalize_version(
                str(item.specifier)
            )
        return all_deps

    @repository_operation("self.configuration_root")
    def collect(self) -> ManifestParseResult:
        """解析并聚合所有清单，同时保留来源和失败诊断。"""
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        files: list[Path] = []
        seen_declarations: Counter[tuple[object, ...]] = Counter()
        seen_files: set[Path] = set()
        positions: dict[tuple[object, ...], list[int]] = {}
        origins: dict[tuple[object, ...], dict] = {}
        index_policies: dict[Path, dict] = {}
        uv_policies: dict[Path, dict] = {}

        for file_path in self.find_dependency_file():
            if file_path.name == "uv.toml":
                # A configuration control is an input, not another dependency parser.
                files.append(file_path)
                seen_files.add(file_path.resolve())
                continue
            parser_type = self._get_parser(file_path)
            parser = (
                parser_type(file_path, project_root=self.project_root)
                if parser_type is RequirementParser
                else parser_type(
                    file_path,
                    configuration_root=self.configuration_root,
                    configuration_start=self.configuration_start,
                )
                if parser_type is PyProjectParser
                else parser_type(file_path)
            )
            try:
                detailed = getattr(parser, "parse_detailed", None)
                if detailed is None:
                    continue
                result = detailed()
            except ContentChangedError:
                raise
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
            if (
                isinstance(parser, PyProjectParser)
                and parser.uv_policy.source is not None
            ):
                uv_policies[file_path.parent.resolve()] = parser.uv_policy.metadata(
                    self.configuration_root
                )
            if isinstance(parser, PyProjectParser) and parser.index_origin is not None:
                index_policies[file_path.parent.resolve()] = {
                    "kind": "unknown",
                    "public": False,
                    "assertion": {
                        "index_policy_unverified": True,
                        "configuration_file": file_path.relative_to(
                            self.project_root
                        ).as_posix(),
                        **(
                            {
                                "uv_index_policy": parser.uv_policy.metadata(
                                    self.configuration_root
                                )
                            }
                            if parser.uv_policy.source is not None
                            else {}
                        ),
                    },
                }
            for parsed_file in result.files:
                resolved = parsed_file.resolve()
                if resolved not in seen_files:
                    seen_files.add(resolved)
                    files.append(parsed_file)
            occurrences: Counter[tuple[object, ...]] = Counter()
            for item in result.declarations:
                key = (
                    item.name,
                    item.raw_requirement,
                    item.group,
                    item.kind,
                    item.source.path.resolve(),
                    item.source.line,
                    item.source.column,
                )
                occurrences[key] += 1
                previous = origins.get(key)
                if previous is not None and previous != item.origin:
                    assertions = previous.get("contexts", [previous])
                    origin = {
                        "kind": "multiple-contexts",
                        "public": previous.get("public") is True
                        and item.origin.get("public") is True,
                        "contexts": [*assertions, dict(item.origin)],
                    }
                    item = replace(item, origin=origin)
                    for position in positions.get(key, []):
                        declarations[position] = replace(
                            declarations[position], origin=origin
                        )
                origins[key] = dict(item.origin)
                if occurrences[key] > seen_declarations[key]:
                    positions.setdefault(key, []).append(len(declarations))
                    declarations.append(item)
            # Retain a parser result's multiplicity, without adding it again
            # when the same physical declaration is reached from another entry file.
            seen_declarations |= occurrences

        diagnostics[:0] = self.discovery_diagnostics
        declarations = [
            replace(
                item,
                metadata={
                    **item.metadata,
                    "inherited_source_policy": index_policies[
                        item.source.path.parent.resolve()
                    ],
                },
            )
            if item.metadata.get("python_kind") == "lock-record"
            and item.source.path.parent.resolve() in index_policies
            else item
            for item in declarations
        ]
        self.last_dependency_files = files
        declarations = [
            replace(
                item,
                metadata={
                    **item.metadata,
                    "uv_index_policy": uv_policies[item.source.path.parent.resolve()],
                },
            )
            if item.metadata.get("lock_format") == "uv"
            and item.source.path.parent.resolve() in uv_policies
            else item
            for item in declarations
        ]
        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=tuple(files),
        )

    def _get_parser(self, file_path: Path) -> type[BaseDependencyParser]:
        if file_path.name in parser_map:
            return parser_map[file_path.name]
        if is_pylock_file(file_path):
            return PylockParser
        if is_requirements_file(file_path):
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
