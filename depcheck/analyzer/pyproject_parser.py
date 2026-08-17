from __future__ import annotations

import tomllib
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from packaging.requirements import InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser


class PyProjectParser(BaseDependencyParser):
    """统一读取 PEP 621、PEP 735、Poetry 与 PDM 依赖声明。"""

    def parse(self) -> dict[str, str | None]:
        deps: dict[str, str | None] = {}
        for item in self.parse_detailed().declarations:
            if item.group == "build" or item.kind not in {"direct", "local"}:
                continue
            deps[item.name] = self._normalize_version(str(item.specifier))
        return deps

    def parse_detailed(self) -> ManifestParseResult:
        source = SourceLocation(self.path)
        if not self.path.is_file():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"pyproject.toml 不存在：{self.path}",
                        source=source,
                    ),
                )
            )
        try:
            data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-toml",
                        severity="error",
                        message=f"无法解析 pyproject.toml：{exc}",
                        source=source,
                    ),
                ),
                files=(self.path,),
            )

        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        self._parse_pep_tables(data, declarations, diagnostics)
        self._parse_poetry(data, declarations, diagnostics)
        self._parse_pdm(data, declarations, diagnostics)
        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _parse_pep_tables(
        self,
        data: Mapping[str, Any],
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        project = data.get("project")
        if isinstance(project, dict):
            self._append_requirements(
                project.get("dependencies", []), "runtime", declarations, diagnostics
            )
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, values in optional.items():
                    self._append_requirements(
                        values,
                        f"optional:{group}",
                        declarations,
                        diagnostics,
                    )

        build_system = data.get("build-system")
        if isinstance(build_system, dict):
            self._append_requirements(
                build_system.get("requires", []), "build", declarations, diagnostics
            )

        groups = data.get("dependency-groups")
        if isinstance(groups, dict):
            for group in groups:
                self._append_dependency_group(
                    str(group),
                    target_group=str(group),
                    groups=groups,
                    declarations=declarations,
                    diagnostics=diagnostics,
                    active=(),
                )

    def _parse_poetry(
        self,
        data: Mapping[str, Any],
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        tool = data.get("tool")
        poetry = tool.get("poetry") if isinstance(tool, dict) else None
        if not isinstance(poetry, dict):
            return

        extras_by_dependency: dict[str, list[str]] = defaultdict(list)
        poetry_extras = poetry.get("extras", {})
        if isinstance(poetry_extras, dict):
            for extra, dependencies in poetry_extras.items():
                if not isinstance(dependencies, list):
                    continue
                for dependency in dependencies:
                    extras_by_dependency[
                        str(canonicalize_name(str(dependency)))
                    ].append(str(extra))

        dependencies = poetry.get("dependencies", {})
        if isinstance(dependencies, dict):
            for name, value in dependencies.items():
                if str(name).lower() == "python":
                    continue
                optional_group = extras_by_dependency.get(
                    str(canonicalize_name(str(name))), []
                )
                if optional_group:
                    group = f"optional:{optional_group[0]}"
                elif self._poetry_optional(value):
                    group = "optional:poetry"
                else:
                    group = "runtime"
                self._append_poetry_entry(
                    str(name), value, group, declarations, diagnostics
                )

        legacy_dev = poetry.get("dev-dependencies", {})
        if isinstance(legacy_dev, dict):
            for name, value in legacy_dev.items():
                self._append_poetry_entry(
                    str(name), value, "dev:dev", declarations, diagnostics
                )

        poetry_groups = poetry.get("group", {})
        if isinstance(poetry_groups, dict):
            for group, settings in poetry_groups.items():
                values = (
                    settings.get("dependencies") if isinstance(settings, dict) else None
                )
                if not isinstance(values, dict):
                    continue
                for name, value in values.items():
                    self._append_poetry_entry(
                        str(name),
                        value,
                        f"dev:{group}",
                        declarations,
                        diagnostics,
                    )

    def _parse_pdm(
        self,
        data: Mapping[str, Any],
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        tool = data.get("tool")
        pdm = tool.get("pdm") if isinstance(tool, dict) else None
        if not isinstance(pdm, dict):
            return
        groups = pdm.get("dev-dependencies", {})
        if isinstance(groups, dict):
            for group, values in groups.items():
                self._append_requirements(
                    values,
                    f"dev:{group}",
                    declarations,
                    diagnostics,
                )

    def _append_requirements(
        self,
        values: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if not isinstance(values, list):
            diagnostics.append(
                Diagnostic(
                    code="manifest.invalid-dependency-list",
                    severity="error",
                    message=f"依赖组 {group} 必须是数组",
                    source=SourceLocation(self.path),
                )
            )
            return
        for value in values:
            if not isinstance(value, str):
                diagnostics.append(self._invalid(group, repr(value), "必须是字符串"))
                continue
            self._append_requirement(value, group, "direct", declarations, diagnostics)

    def _append_poetry_entry(
        self,
        name: str,
        value: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if isinstance(value, list):
            for item in value:
                self._append_poetry_entry(name, item, group, declarations, diagnostics)
            return

        extras: tuple[str, ...] = ()
        marker = ""
        kind = "direct"
        if isinstance(value, str):
            version = value.strip()
        elif isinstance(value, dict):
            if any(key in value for key in ("path", "git", "url")):
                kind = "local"
                version = ""
            else:
                raw_version = value.get("version", "")
                version = str(raw_version).strip() if raw_version is not None else ""
            raw_extras = value.get("extras", [])
            if isinstance(raw_extras, list):
                extras = tuple(sorted(str(item) for item in raw_extras))
            raw_marker = value.get("markers")
            if isinstance(raw_marker, str) and raw_marker.strip():
                marker = f"; {raw_marker.strip()}"
        else:
            diagnostics.append(
                self._invalid(group, name, "Poetry 条目必须是字符串或表")
            )
            return

        if version in {"", "*"}:
            version = ""
        elif kind == "direct":
            converted = self._convert_poetry_constraint(version)
            if converted is None:
                diagnostics.append(
                    self._invalid(group, f"{name}{version}", "版本约束无效")
                )
                return
            version = converted
        rendered_extras = f"[{','.join(extras)}]" if extras else ""
        self._append_requirement(
            f"{name}{rendered_extras}{version}{marker}",
            group,
            kind,
            declarations,
            diagnostics,
        )

    def _append_requirement(
        self,
        requirement: str,
        group: str,
        kind: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        try:
            declarations.append(
                PythonRequirement.from_requirement(
                    requirement,
                    source=SourceLocation(self.path),
                    group=group,
                    kind=kind,
                )
            )
        except InvalidRequirement as exc:
            diagnostics.append(self._invalid(group, requirement, str(exc)))

    def _append_dependency_group(
        self,
        group: str,
        *,
        target_group: str,
        groups: Mapping[str, Any],
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        active: tuple[str, ...],
    ) -> None:
        if group in active:
            diagnostics.append(
                Diagnostic(
                    code="manifest.group-cycle",
                    severity="error",
                    message=f"dependency-groups 存在循环引用：{' -> '.join((*active, group))}",
                    source=SourceLocation(self.path),
                )
            )
            return
        values = groups.get(group)
        if not isinstance(values, list):
            diagnostics.append(
                Diagnostic(
                    code="manifest.invalid-dependency-list",
                    severity="error",
                    message=f"依赖组 {group} 必须是数组",
                    source=SourceLocation(self.path),
                )
            )
            return
        for value in values:
            if isinstance(value, str):
                self._append_requirements(
                    [value], f"dev:{target_group}", declarations, diagnostics
                )
            elif isinstance(value, dict) and isinstance(
                value.get("include-group"), str
            ):
                self._append_dependency_group(
                    value["include-group"],
                    target_group=target_group,
                    groups=groups,
                    declarations=declarations,
                    diagnostics=diagnostics,
                    active=(*active, group),
                )
            else:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-group-entry",
                        severity="error",
                        message=f"依赖组 {group} 含有无效条目",
                        source=SourceLocation(self.path),
                    )
                )

    @staticmethod
    def _poetry_optional(value: object) -> bool:
        return isinstance(value, dict) and value.get("optional") is True

    @staticmethod
    def _convert_poetry_constraint(value: str) -> str | None:
        if value.startswith("^"):
            return PyProjectParser._caret_constraint(value[1:])
        if value.startswith("~") and not value.startswith("~="):
            return PyProjectParser._tilde_constraint(value[1:])
        return value

    @staticmethod
    def _caret_constraint(raw: str) -> str | None:
        try:
            version = Version(raw)
        except InvalidVersion:
            return None
        release = (*version.release, 0, 0, 0)
        major, minor, patch = release[:3]
        if major:
            upper = f"{major + 1}.0"
        elif minor:
            upper = f"0.{minor + 1}.0"
        else:
            upper = f"0.0.{patch + 1}"
        return f">={version},<{upper}"

    @staticmethod
    def _tilde_constraint(raw: str) -> str | None:
        try:
            version = Version(raw)
        except InvalidVersion:
            return None
        if len(version.release) <= 1:
            upper = f"{version.major + 1}.0"
        else:
            upper = f"{version.major}.{version.minor + 1}"
        return f">={version},<{upper}"

    def _invalid(self, group: str, value: str, reason: str) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-requirement",
            severity="error",
            message=f"依赖组 {group} 的声明 {value!r} 无效：{reason}",
            source=SourceLocation(self.path),
        )
