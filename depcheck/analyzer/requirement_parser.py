from __future__ import annotations

import logging
import re
from pathlib import Path

from packaging.requirements import InvalidRequirement

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)
from depcheck.path_policy import ProjectPathError, require_within_project

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class RequirementParser(BaseDependencyParser):
    _INCLUDE_RE = re.compile(
        r"^(?P<option>-r|--requirement|-c|--constraint)(?:\s+|=)(?P<path>.+)$"
    )

    def __init__(self, path: Path, *, project_root: Path | None = None) -> None:
        super().__init__(path)
        self.project_root = (
            Path(project_root).resolve()
            if project_root is not None
            else self.path.parent.resolve()
        )

    def parse(self) -> dict[str, str | None]:
        """返回旧版扁平结果；新代码应使用 parse_detailed。"""
        deps: dict[str, str | None] = {}
        for item in self.parse_detailed().declarations:
            if item.kind == "constraint":
                continue
            deps[item.name] = self._normalize_version(str(item.specifier))
        return deps

    def parse_detailed(self) -> ManifestParseResult:
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        files: list[Path] = []
        visited: set[Path] = set()
        active: set[Path] = set()

        self._parse_file(
            self.path,
            group=self._group_for_filename(self.path.name),
            kind="direct",
            declarations=declarations,
            diagnostics=diagnostics,
            files=files,
            visited=visited,
            active=active,
            include_source=None,
        )
        return ManifestParseResult(
            tuple(declarations), tuple(diagnostics), tuple(files)
        )

    def _parse_file(
        self,
        path: Path,
        *,
        group: str,
        kind: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        files: list[Path],
        visited: set[Path],
        active: set[Path],
        include_source: SourceLocation | None,
    ) -> None:
        try:
            resolved = require_within_project(
                self.project_root,
                path,
                operation="read requirements",
            )
        except ProjectPathError:
            diagnostics.append(
                Diagnostic(
                    code=(
                        "manifest.include-outside-project-root"
                        if include_source is not None
                        else "manifest.outside-project-root"
                    ),
                    severity="error",
                    message="requirements 文件越过项目根目录，已拒绝读取",
                    source=include_source or SourceLocation(path),
                )
            )
            return
        if resolved in active:
            diagnostics.append(
                Diagnostic(
                    code="manifest.include-cycle",
                    severity="error",
                    message=f"requirements 文件存在循环引用：{path}",
                    source=include_source or SourceLocation(path),
                )
            )
            return
        if resolved in visited:
            return
        if not path.is_file():
            diagnostics.append(
                Diagnostic(
                    code="manifest.include-not-found",
                    severity="error",
                    message=f"引用的依赖文件不存在：{path}",
                    source=include_source or SourceLocation(path),
                )
            )
            return

        visited.add(resolved)
        active.add(resolved)
        files.append(path)
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            diagnostics.append(
                Diagnostic(
                    code="manifest.read-error",
                    severity="error",
                    message=f"无法读取依赖文件：{exc}",
                    source=SourceLocation(path),
                )
            )
            active.remove(resolved)
            return

        for line_number, raw_line in self._logical_lines(content):
            stripped = self._strip_comment(raw_line).strip()
            if not stripped:
                continue

            include = self._INCLUDE_RE.match(stripped)
            if include:
                target_text = include.group("path").strip().strip("\"'")
                option = include.group("option")
                child_kind = "constraint" if option in {"-c", "--constraint"} else kind
                target = Path(target_text)
                if target.is_absolute() or ".." in target.parts:
                    diagnostics.append(
                        Diagnostic(
                            code="manifest.include-outside-project-root",
                            severity="error",
                            message=(
                                "requirements include 必须是项目根目录内且不含父目录穿越的相对路径"
                            ),
                            source=SourceLocation(path, line=line_number),
                        )
                    )
                    continue
                self._parse_file(
                    path.parent / target,
                    group=group,
                    kind=child_kind,
                    declarations=declarations,
                    diagnostics=diagnostics,
                    files=files,
                    visited=visited,
                    active=active,
                    include_source=SourceLocation(path, line=line_number),
                )
                continue

            # 其余 pip 选项不是包声明；详细模式只诊断真正的声明错误。
            if stripped.startswith("-"):
                continue

            source = SourceLocation(path, line=line_number)
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        stripped,
                        source=source,
                        group=group,
                        kind=kind,
                    )
                )
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-requirement",
                        severity="error",
                        message=f"无效依赖声明：{exc}",
                        source=source,
                    )
                )

        active.remove(resolved)

    @staticmethod
    def _logical_lines(content: str) -> list[tuple[int, str]]:
        """合并反斜杠续行，同时保留首行位置。"""
        logical: list[tuple[int, str]] = []
        buffer = ""
        start_line = 1
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not buffer:
                start_line = line_number
            current = line.rstrip()
            if current.endswith("\\"):
                buffer += current[:-1] + " "
                continue
            logical.append((start_line, buffer + current))
            buffer = ""
        if buffer:
            logical.append((start_line, buffer))
        return logical

    @staticmethod
    def _strip_comment(line: str) -> str:
        stripped = line.lstrip()
        if stripped.startswith("#"):
            return ""
        # URL 中的 # 片段不是注释，仅移除由空白引出的行内注释。
        return re.split(r"\s+#", line, maxsplit=1)[0]

    @staticmethod
    def _group_for_filename(filename: str) -> str:
        lowered = filename.lower()
        if any(token in lowered for token in ("dev", "test", "lint", "quality")):
            return "dev"
        return "runtime"
