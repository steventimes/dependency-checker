from __future__ import annotations

import tomllib

from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import InvalidName, canonicalize_name

from depcheck.ecosystems.python.parsers import BaseDependencyParser
from depcheck.evidence.origins import PipenvSources
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

_NON_CATEGORY_SECTIONS = frozenset(
    {"build-system", "pipenv", "requires", "scripts", "source"}
)
_MAX_PIPFILE_PACKAGES = 20_000
_MARKER_KEYS = (
    "os_name",
    "sys_platform",
    "platform_machine",
    "platform_python_implementation",
    "platform_release",
    "platform_system",
    "platform_version",
    "python_version",
    "python_full_version",
    "implementation_name",
    "implementation_version",
)


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
        sections = [
            "packages",
            "dev-packages",
            *(
                section
                for section in data
                if section not in _NON_CATEGORY_SECTIONS
                and section not in {"packages", "dev-packages"}
            ),
        ]
        package_index = 0
        for section in sections:
            category_kind = (
                "default"
                if section == "packages"
                else "develop"
                if section == "dev-packages"
                else "custom"
            )
            group = (
                "runtime"
                if category_kind == "default"
                else "dev"
                if category_kind == "develop"
                else f"pipenv:{section}"
            )
            values = data.get(section, {})
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
                if package_index == _MAX_PIPFILE_PACKAGES:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.pipfile-package-limit",
                            "error",
                            f"Pipfile inventory is limited to {_MAX_PIPFILE_PACKAGES} declarations; additional entries were omitted",
                            positions.key(section, str(name)),
                        )
                    )
                    return ManifestParseResult(
                        declarations=tuple(declarations),
                        diagnostics=tuple(diagnostics),
                        files=(self.path,),
                    )
                package_index += 1
                self._append_entry(
                    str(name),
                    value,
                    group,
                    declarations,
                    diagnostics,
                    source=positions.key(section, str(name)),
                    origin=sources.origin(value),
                    metadata={
                        "python_kind": "pipenv-declaration",
                        "pipenv_category": section,
                        "category_kind": category_kind,
                        "activation": "unknown",
                    },
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
        metadata: dict,
    ) -> None:
        try:
            canonicalize_name(name, validate=True)
        except InvalidName as exc:
            diagnostics.append(
                self._invalid(f"无效 Pipfile 包名 {name!r}：{exc}", source)
            )
            return
        extras: tuple[str, ...] = ()
        marker = ""
        kind = "direct"
        if isinstance(value, str):
            version = "" if value.strip() in {"", "*"} else value.strip()
        elif isinstance(value, dict):
            extras_value = value.get("extras", [])
            if not isinstance(extras_value, list) or any(
                not isinstance(item, str) or not item.strip() for item in extras_value
            ):
                diagnostics.append(
                    self._invalid(
                        f"Pipfile 条目 {name!r} 的 extras 必须是字符串数组", source
                    )
                )
                return
            extras = tuple(sorted(extras_value))
            marker_parts = []
            for key in ("markers", *_MARKER_KEYS):
                if key not in value:
                    continue
                marker_value = value[key]
                if not isinstance(marker_value, str) or not marker_value.strip():
                    diagnostics.append(
                        self._invalid(
                            f"Pipfile 条目 {name!r} 的 {key} 必须是非空字符串", source
                        )
                    )
                    return
                expression = (
                    marker_value.strip()
                    if key == "markers"
                    else f"{key} {marker_value.strip()}"
                )
                try:
                    marker_parts.append(str(Marker(expression)))
                except (InvalidMarker, RecursionError) as exc:
                    diagnostics.append(
                        self._invalid(
                            f"无效 Pipfile 条件 {name!r}.{key}：{exc}", source
                        )
                    )
                    return
            if marker_parts:
                marker = "; " + (
                    marker_parts[0]
                    if len(marker_parts) == 1
                    else " and ".join(f"({part})" for part in marker_parts)
                )
            version_value = value.get("version", "")
            if not isinstance(version_value, str):
                diagnostics.append(
                    self._invalid(
                        f"Pipfile 条目 {name!r} 的 version 必须是字符串", source
                    )
                )
                return
            version = (
                "" if version_value.strip() in {"", "*"} else version_value.strip()
            )
            if any(key in value for key in ("path", "file", "git", "url")):
                kind = "local"
                version = ""
        else:
            diagnostics.append(
                self._invalid(f"Pipfile 条目 {name!r} 必须是字符串或表", source)
            )
            return

        if version and not version.startswith(("<", ">", "=", "!", "~")):
            version = f"=={version}"
        try:
            SpecifierSet(version)
        except InvalidSpecifier as exc:
            diagnostics.append(
                self._invalid(f"无效 Pipfile 版本 {version!r}：{exc}", source)
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
                    metadata=metadata,
                )
            )
        except (InvalidRequirement, RecursionError) as exc:
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
