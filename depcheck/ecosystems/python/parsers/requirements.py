from __future__ import annotations

import logging
import re
import shlex
from dataclasses import replace
from pathlib import Path

from packaging.requirements import InvalidRequirement

from depcheck.ecosystems.python.parsers import BaseDependencyParser
from depcheck.evidence.origins import python_origin, redact_source
from depcheck.filesystem import ProjectPathError, read_text, require_within_project
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class RequirementParser(BaseDependencyParser):
    _INCLUDE_RE = re.compile(
        r"^(?P<option>--requirement|--constraint)(?:\s+|=)(?P<path>.+)$|^(?P<short>-r|-c)(?:=|\s*)(?P<short_path>.+)$"
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
        visited: set[tuple[Path, str, str]] = set()
        active: set[Path] = set()
        directives: list[dict[str, object]] = []

        self._parse_file(
            self.path,
            group=self._group_for_filename(self.path.name),
            kind="locked" if self.path.suffix.lower() == ".lock" else "direct",
            declarations=declarations,
            diagnostics=diagnostics,
            files=files,
            visited=visited,
            active=active,
            include_source=None,
            directives=directives,
        )
        if any(item.severity == "error" for item in diagnostics):
            directives.append({"option": "incomplete-input", "value": None})
        if directives:
            public = all(
                item["option"] == "--index-url"
                and python_origin({"registry": item["value"]})["public"]
                for item in directives
            )
            origin = {
                "kind": "requirements-index",
                "public": public,
                "assertion": redact_source(directives),
            }
            declarations = [
                replace(item, origin=origin)
                if item.origin.get("kind") == "registry"
                else item
                for item in declarations
            ]
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
        visited: set[tuple[Path, str, str]],
        active: set[Path],
        include_source: SourceLocation | None,
        directives: list[dict[str, object]],
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
        context = (resolved, group, kind)
        if context in visited:
            return
        if len(visited) >= 512 or len(active) >= 64:
            diagnostics.append(
                Diagnostic(
                    code="manifest.include-budget",
                    severity="error",
                    message="Requirements include budget exhausted",
                    source=include_source,
                )
            )
            directives.append({"option": "unknown", "value": None})
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

        visited.add(context)
        active.add(resolved)
        if path not in files:
            files.append(path)
        try:
            content = read_text(
                path, project_root=self.project_root, allow_aliases=True
            )
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
                target_text = (
                    (include.group("path") or include.group("short_path"))
                    .strip()
                    .strip("\"'")
                )
                option = include.group("option") or include.group("short")
                child_kind = "constraint" if option in {"-c", "--constraint"} else kind
                target = Path(target_text)
                if target.is_absolute():
                    diagnostics.append(
                        Diagnostic(
                            code="manifest.include-outside-project-root",
                            severity="error",
                            message=(
                                "requirements include 必须是项目根目录内的相对路径"
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
                    directives=directives,
                )
                continue

            # 其余 pip 选项不是包声明；详细模式只诊断真正的声明错误。
            if stripped.startswith("-"):
                try:
                    parts = shlex.split(stripped)
                except ValueError:
                    parts = []
                sources = self._source_options(parts)
                for option, value in sources:
                    if len(directives) >= 1024:
                        directives.append({"option": "budget-exhausted", "value": None})
                        diagnostics.append(
                            Diagnostic(
                                code="manifest.source-budget",
                                severity="error",
                                message="Requirements source option budget exhausted",
                                source=SourceLocation(path, line_number),
                            )
                        )
                        break
                    directives.append(
                        {
                            "option": option,
                            "value": value,
                            "path": str(path),
                            "line": line_number,
                        }
                    )
                continue

            stripped = re.sub(
                r"(?:\s+--hash(?:=|\s+)[A-Za-z0-9_-]+:[A-Fa-f0-9]+)+\s*$",
                "",
                stripped,
            )
            source = SourceLocation(path, line=line_number)
            try:
                requirement = PythonRequirement.from_requirement(
                    stripped,
                    source=source,
                    group=group,
                    kind=kind,
                )
                if kind == "locked" and requirement.pinned_version is None:
                    diagnostics.append(
                        Diagnostic(
                            code="manifest.invalid-lock-entry",
                            severity="error",
                            message="Compiled requirements locks require exact registry versions",
                            source=source,
                        )
                    )
                else:
                    declarations.append(requirement)
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-requirement",
                        severity="error",
                        message=redact_source(f"无效依赖声明：{exc}"),
                        source=source,
                    )
                )

        active.remove(resolved)

    @staticmethod
    def _source_options(parts: list[str]) -> list[tuple[str, str | None]]:
        """Read every option; unsupported syntax cannot assert default PyPI."""
        source_options = {
            "--index-url",
            "--extra-index-url",
            "--no-index",
            "--find-links",
        }
        value_options = {
            "--trusted-host",
            "--no-binary",
            "--only-binary",
            "--use-feature",
            "--use-deprecated",
            "--config-settings",
        }
        flag_options = {
            "--pre",
            "--require-hashes",
            "--prefer-binary",
            "--use-pep517",
            "--no-use-pep517",
        }
        known = source_options | value_options | flag_options
        results: list[tuple[str, str | None]] = []
        if not parts:
            return [("unsupported-option", None)]
        index = 0
        while index < len(parts):
            token = parts[index]
            option, separator, attached = token.partition("=")
            if token.startswith(("-i", "-f")) and not token.startswith("--"):
                option, attached = (
                    ("--index-url" if token[1] == "i" else "--find-links"),
                    token[2:],
                )
            elif option.startswith("--") and option not in known:
                matches = [name for name in known if name.startswith(option)]
                option = matches[0] if len(matches) == 1 else "unsupported-option"
            if option not in known:
                results.append(("unsupported-option", None))
                index += 1
                continue
            value = attached or None
            if option in value_options or option in source_options - {"--no-index"}:
                if (
                    value is None
                    and not separator
                    and index + 1 < len(parts)
                    and not parts[index + 1].startswith("-")
                ):
                    index += 1
                    value = parts[index]
                if value is None:
                    results.append(("unsupported-option", None))
            elif separator:
                results.append(("unsupported-option", None))
            if option in source_options:
                results.append((option, value))
            index += 1
        return results

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
        if lowered.startswith("build-") or "-build" in lowered:
            return "build"
        if any(token in lowered for token in ("dev", "test", "lint", "quality")):
            return "dev"
        return "runtime"
