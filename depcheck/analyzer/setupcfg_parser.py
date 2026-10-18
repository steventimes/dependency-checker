from __future__ import annotations

import configparser
import logging

from packaging.requirements import InvalidRequirement
from depcheck.source_locations import SourcePositions

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
            text = self._read_text()
            config.read_string(text)
            runtime = (
                config.get("options", "install_requires")
                if config.has_option("options", "install_requires")
                else None
            )
            extras = (
                config.items("options.extras_require")
                if config.has_section("options.extras_require")
                else []
            )
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

        resolved = (
            {("options", "install_requires"): runtime} if runtime is not None else {}
        )
        resolved.update(
            {("options.extras_require", group): value for group, value in extras}
        )
        positions = SourcePositions.ini(self.path, text, config, resolved)
        if runtime is not None:
            self._append_lines(
                runtime,
                "runtime",
                declarations,
                diagnostics,
                positions,
                "options",
                "install_requires",
            )
        if extras:
            for group, value in extras:
                self._append_lines(
                    value,
                    f"optional:{group}",
                    declarations,
                    diagnostics,
                    positions,
                    "options.extras_require",
                    group,
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
        positions: SourcePositions,
        section: str,
        option: str,
    ) -> None:
        for index, raw_line in enumerate(value.splitlines()):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        line,
                        source=positions.value(section, option, index),
                        group=group,
                    )
                )
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-requirement",
                        severity="error",
                        message=f"无效依赖声明 {line!r}：{exc}",
                        source=positions.value(section, option, index),
                    )
                )
