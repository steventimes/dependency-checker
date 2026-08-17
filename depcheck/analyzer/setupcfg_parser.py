from __future__ import annotations

import configparser
import logging

from packaging.requirements import InvalidRequirement

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class SetupCfgParser(BaseDependencyParser):
    def parse(self) -> dict[str, str | None]:
        deps: dict[str, str | None] = {}
        for item in self.parse_detailed().declarations:
            deps[item.name] = self._normalize_version(str(item.specifier))
        return deps

    def parse_detailed(self) -> ManifestParseResult:
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        if not self.path.exists():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"setup.cfg 不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )

        config = configparser.ConfigParser()
        try:
            with self.path.open(encoding="utf-8") as handle:
                config.read_file(handle)
        except (OSError, UnicodeError, configparser.Error) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-setup-cfg",
                        severity="error",
                        message=f"无法解析 setup.cfg：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        if config.has_option("options", "install_requires"):
            self._append_lines(
                config.get("options", "install_requires"),
                "runtime",
                declarations,
                diagnostics,
            )
        if config.has_section("options.extras_require"):
            for group, value in config.items("options.extras_require"):
                self._append_lines(
                    value,
                    f"optional:{group}",
                    declarations,
                    diagnostics,
                )

        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _append_lines(
        self,
        value: str,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        for raw_line in value.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        line,
                        source=SourceLocation(self.path),
                        group=group,
                    )
                )
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-requirement",
                        severity="error",
                        message=f"无效依赖声明 {line!r}：{exc}",
                        source=SourceLocation(self.path),
                    )
                )
