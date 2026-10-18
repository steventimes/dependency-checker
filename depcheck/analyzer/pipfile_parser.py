from __future__ import annotations

import tomllib

from packaging.requirements import InvalidRequirement
from depcheck.source_locations import SourcePositions
from depcheck.python_sources import PipenvSources

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser


class PipfileParser(BaseDependencyParser):
    """解析 Pipenv 的直接依赖；本地/VCS 条目不送入远端版本查询。"""

    def parse(self) -> dict[str, str | None]:
        return {
            item.name: self._normalize_version(str(item.specifier))
            for item in self.parse_detailed().declarations
            if item.kind == "direct"
        }

    def parse_detailed(self) -> ManifestParseResult:
        if not self.path.is_file():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"Pipfile 不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )
        try:
            text = self._read_text()
            data = tomllib.loads(text)
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-toml",
                        severity="error",
                        message=f"无法解析 Pipfile：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        positions = SourcePositions.toml(self.path, text)
        sources = PipenvSources(data.get("source"))
        for section, group in (("packages", "runtime"), ("dev-packages", "dev")):
            values = data.get(section, {}) if isinstance(data, dict) else {}
            if not isinstance(values, dict):
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-dependency-table",
                        severity="error",
                        message=f"Pipfile 的 [{section}] 必须是表",
                        source=positions.key(section),
                    )
                )
                continue
            for name, value in values.items():
                self._append_entry(
                    str(name),
                    value,
                    group,
                    declarations,
                    diagnostics,
                    source=positions.key(section, str(name)),
                    origin=sources.origin(value),
                )

        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _append_entry(
        self,
        name: str,
        value: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        *,
        source: SourceLocation,
        origin: dict,
    ) -> None:
        extras: tuple[str, ...] = ()
        marker = ""
        kind = "direct"
        if isinstance(value, str):
            version = "" if value.strip() in {"", "*"} else value.strip()
        elif isinstance(value, dict):
            extras_value = value.get("extras", [])
            if isinstance(extras_value, list):
                extras = tuple(sorted(str(item) for item in extras_value))
            marker_value = value.get("markers")
            if isinstance(marker_value, str) and marker_value.strip():
                marker = f"; {marker_value.strip()}"
            version_value = value.get("version", "")
            version = (
                ""
                if not isinstance(version_value, str)
                or version_value.strip() in {"", "*"}
                else version_value.strip()
            )
            if any(key in value for key in ("path", "file", "git", "url")):
                kind = "local"
                version = ""
        else:
            diagnostics.append(
                self._invalid(f"Pipfile 条目 {name!r} 必须是字符串或表", source)
            )
            return

        rendered_extras = f"[{','.join(extras)}]" if extras else ""
        requirement = f"{name}{rendered_extras}{version}{marker}"
        try:
            declarations.append(
                PythonRequirement.from_requirement(
                    requirement,
                    source=source,
                    group=group,
                    kind=kind,
                    origin=origin,
                )
            )
        except InvalidRequirement as exc:
            diagnostics.append(
                self._invalid(f"无效 Pipfile 依赖 {requirement!r}：{exc}", source)
            )

    def _invalid(
        self, message: str, source: SourceLocation | None = None
    ) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-requirement",
            severity="error",
            message=message,
            source=source or SourceLocation(self.path),
        )
