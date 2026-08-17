from __future__ import annotations

import logging
import re
import shlex
from collections.abc import Iterable
from typing import ClassVar

from packaging.requirements import InvalidRequirement

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class PipInstallParser(BaseDependencyParser):
    _PIP_INSTALL_RE = re.compile(
        r"(?:^|\s)(?:python\s+-m\s+)?pip(?:3)?\s+install\s+(?P<args>.+)",
        re.IGNORECASE,
    )
    _SKIP_NEXT: ClassVar[set[str]] = {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
    }

    def parse(self) -> dict[str, str | None]:
        deps: dict[str, str | None] = {}
        if not self.path.exists():
            logger.warning(f"Dependency hint file not found: {self.path}")
            return deps

        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            logger.error(f"Error parsing dependency hints {self.path}: {exc}")
            return deps

        for line in self._combine_lines(text.splitlines()):
            match = self._PIP_INSTALL_RE.search(self._strip_comments(line).strip())
            if match:
                self._merge_deps(deps, self._parse_args(match.group("args")))
        return deps

    def parse_detailed(self) -> ManifestParseResult:
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        if not self.path.is_file():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"依赖提示文件不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.read-error",
                        severity="error",
                        message=f"无法读取依赖提示文件：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        for line_number, line in self._combine_lines_with_numbers(text.splitlines()):
            match = self._PIP_INSTALL_RE.search(self._strip_comments(line).strip())
            if not match:
                continue
            for token in self._requirement_tokens(match.group("args")):
                try:
                    declarations.append(
                        PythonRequirement.from_requirement(
                            token,
                            source=SourceLocation(self.path, line=line_number),
                            group="hint",
                            kind="hint",
                        )
                    )
                except InvalidRequirement as exc:
                    diagnostics.append(
                        Diagnostic(
                            code="manifest.invalid-requirement",
                            severity="warning",
                            message=f"无法解析 pip install 参数 {token!r}：{exc}",
                            source=SourceLocation(self.path, line=line_number),
                        )
                    )

        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _combine_lines(self, lines: Iterable[str]) -> list[str]:
        return [line for _, line in self._combine_lines_with_numbers(lines)]

    def _combine_lines_with_numbers(
        self, lines: Iterable[str]
    ) -> list[tuple[int, str]]:
        combined: list[tuple[int, str]] = []
        buffer = ""
        start_line = 1
        for line_number, line in enumerate(lines, start=1):
            if not buffer:
                start_line = line_number
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            if buffer:
                combined.append((start_line, buffer + stripped))
                buffer = ""
            else:
                combined.append((line_number, stripped))
        if buffer:
            combined.append((start_line, buffer))
        return combined

    def _strip_comments(self, line: str) -> str:
        return line.split("#", 1)[0]

    def _parse_args(self, args: str) -> dict[str, str | None]:
        deps: dict[str, str | None] = {}
        for token in self._requirement_tokens(args):
            name, version = self.parse_line(token)
            if name and (name not in deps or (deps[name] is None and version)):
                deps[name] = version
        return deps

    def _requirement_tokens(self, args: str) -> list[str]:
        try:
            tokens = shlex.split(args, posix=True)
        except ValueError:
            tokens = args.split()

        results: list[str] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in self._SKIP_NEXT:
                skip_next = True
                continue
            if token.startswith(("-", "./", "../", "/")):
                continue

            lower = token.lower()
            if (
                "git+" in lower
                or lower.startswith(("http://", "https://"))
                or "@" in token
            ):
                continue
            name, _ = self.parse_line(token)
            if name:
                results.append(token)
        return results

    def _merge_deps(
        self, base: dict[str, str | None], incoming: dict[str, str | None]
    ) -> None:
        for name, version in incoming.items():
            if name not in base or (base[name] is None and version):
                base[name] = version
