from __future__ import annotations

import tomllib
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version
from depcheck.source_locations import SourceKey, SourcePositions

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser
from depcheck.bounded_io import DEFAULT_MAX_BYTES

_GROUP_MAX_ENTRIES = 20_000
_GROUP_MAX_DEPTH = 64
_GROUP_MAX_DIAGNOSTICS = 64


@dataclass
class _GroupBudget:
    entries: int
    bytes: int
    exhausted: bool = False


class PyProjectParser(BaseDependencyParser):
    """统一读取 PEP 621、PEP 735、Poetry 与 PDM 依赖声明。"""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.positions = SourcePositions(self.path, "")

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
            text = self._read_text()
            data = tomllib.loads(text)
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

        self.positions = SourcePositions.toml(self.path, text)
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        tool = data.get("tool", {})
        if not isinstance(tool, dict):
            diagnostics.append(self._invalid_table("tool"))
            tool = {}
        uv = tool.get("uv", {})
        if not isinstance(uv, dict):
            diagnostics.append(self._invalid_table("tool.uv"))
            uv = {}
        self._parse_pep_tables(data, declarations, diagnostics, uv=uv)
        self._parse_poetry(data, declarations, diagnostics)
        self._parse_pdm(data, declarations, diagnostics)
        from dataclasses import replace
        from depcheck.python_sources import python_origin

        index_config = {
            manager: config[key]
            for manager, key in (
                ("uv", "index"),
                ("poetry", "source"),
                ("pdm", "source"),
            )
            if isinstance(config := tool.get(manager), dict) and config.get(key)
        }
        if index_config:
            declarations = [
                replace(
                    item, origin=python_origin({"configured_indexes": index_config})
                )
                if item.origin.get("public") is True
                else item
                for item in declarations
            ]
        sources = uv.get("sources", {}) if isinstance(uv, dict) else {}
        if isinstance(sources, dict):
            sources = {str(canonicalize_name(k)): v for k, v in sources.items()}
            declarations = [
                replace(item, origin=python_origin(sources[item.name]))
                if item.name in sources
                else item
                for item in declarations
            ]
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
        *,
        uv: Mapping[str, Any],
    ) -> None:
        project = data.get("project", {})
        if isinstance(project, dict):
            dynamic = project.get("dynamic", [])
            if not isinstance(dynamic, list) or not all(
                isinstance(item, str) for item in dynamic
            ):
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-dynamic-fields",
                        severity="error",
                        message="project.dynamic 必须是字符串数组",
                        source=self.positions.key("project", "dynamic"),
                    )
                )
            else:
                for field in ("dependencies", "optional-dependencies"):
                    if field in dynamic:
                        diagnostics.append(
                            Diagnostic(
                                code="manifest.dynamic-pyproject",
                                severity="error",
                                message=f"project.{field} 是动态依赖，无法静态解析",
                                source=self.positions.key("project", "dynamic"),
                            )
                        )
            self._append_requirements(
                project.get("dependencies", []),
                "runtime",
                declarations,
                diagnostics,
                key=("project", "dependencies"),
            )
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, values in optional.items():
                    self._append_requirements(
                        values,
                        f"optional:{group}",
                        declarations,
                        diagnostics,
                        key=("project", "optional-dependencies", str(group)),
                    )
            else:
                diagnostics.append(self._invalid_table("project.optional-dependencies"))
        else:
            diagnostics.append(self._invalid_table("project"))

        build_system = data.get("build-system", {})
        if isinstance(build_system, dict):
            self._append_requirements(
                build_system.get("requires", []),
                "build",
                declarations,
                diagnostics,
                key=("build-system", "requires"),
            )
        else:
            diagnostics.append(self._invalid_table("build-system"))

        groups = data.get("dependency-groups", {})
        budget = _GroupBudget(_GROUP_MAX_ENTRIES, DEFAULT_MAX_BYTES)
        names: dict[str, list[str]] = defaultdict(list)
        if isinstance(groups, dict):
            group_diagnostics: list[Diagnostic] = []
            valid: list[str] = []
            for group in groups:
                source = self.positions.key("dependency-groups", group)
                if not self._take_group_budget(
                    budget, 128 + len(group.encode("utf-8")), source, group_diagnostics
                ):
                    break
                try:
                    normalized = str(canonicalize_name(group, validate=True))
                except InvalidName:
                    group_diagnostics.append(
                        Diagnostic(
                            "manifest.invalid-group-name",
                            "error",
                            "Dependency group name is invalid.",
                            source,
                        )
                    )
                    continue
                names[normalized].append(group)
                valid.append(group)
            for aliases in names.values():
                if len(aliases) > 1:
                    source = self.positions.key("dependency-groups", aliases[1])
                    if not self._take_group_budget(
                        budget, 128, source, group_diagnostics
                    ):
                        break
                    group_diagnostics.append(
                        Diagnostic(
                            "manifest.group-ambiguous",
                            "error",
                            "Dependency group names collide after normalization; no include target is chosen.",
                            source,
                        )
                    )
            for group in valid:
                self._append_dependency_group(
                    group,
                    target_group=f"dev:{group}",
                    groups=groups,
                    names=names,
                    declarations=declarations,
                    diagnostics=group_diagnostics,
                    active=(),
                    budget=budget,
                )
            diagnostics.extend(group_diagnostics)
        else:
            diagnostics.append(self._invalid_table("dependency-groups"))
        self._append_uv_legacy(uv, names, budget, declarations, diagnostics)

    def _append_uv_legacy(
        self,
        uv: Mapping[str, Any],
        names: Mapping[str, list[str]],
        budget: _GroupBudget,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if "dev-dependencies" not in uv:
            return
        key = ("tool", "uv", "dev-dependencies")
        values = uv["dev-dependencies"]
        if not isinstance(values, list):
            diagnostics.append(
                Diagnostic(
                    "manifest.invalid-dependency-list",
                    "error",
                    "tool.uv.dev-dependencies must be an array of requirement strings.",
                    self.positions.value(*key),
                )
            )
            return
        targets = names.get("dev", [])
        group = "dev:" + (targets[0] if len(targets) == 1 else "dev")
        # uv appends these requirements after standard group flattening. They
        # contribute to dev itself, not to groups that include the standard dev.
        for index, value in enumerate(values):
            source = self.positions.value(*key, index)
            size = (
                256 + len(group.encode("utf-8")) + len(str(self.path).encode("utf-8"))
            )
            if isinstance(value, str):
                size += len(value.encode("utf-8"))
            if not self._take_group_budget(budget, size, source, diagnostics):
                return
            if isinstance(value, str):
                self._append_requirement(
                    value, group, "direct", declarations, diagnostics, source
                )
            else:
                diagnostics.append(
                    Diagnostic(
                        "manifest.invalid-dependency-entry",
                        "error",
                        "tool.uv.dev-dependencies entries must be requirement strings; group includes are unsupported here.",
                        source,
                    )
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
                    str(name),
                    value,
                    group,
                    declarations,
                    diagnostics,
                    key=("tool", "poetry", "dependencies", str(name)),
                )

        legacy_dev = poetry.get("dev-dependencies", {})
        if isinstance(legacy_dev, dict):
            for name, value in legacy_dev.items():
                self._append_poetry_entry(
                    str(name),
                    value,
                    "dev:dev",
                    declarations,
                    diagnostics,
                    key=("tool", "poetry", "dev-dependencies", str(name)),
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
                        key=(
                            "tool",
                            "poetry",
                            "group",
                            str(group),
                            "dependencies",
                            str(name),
                        ),
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
                    key=("tool", "pdm", "dev-dependencies", str(group)),
                )

    def _append_requirements(
        self,
        values: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        *,
        key: SourceKey,
    ) -> None:
        if not isinstance(values, list):
            diagnostics.append(
                Diagnostic(
                    code="manifest.invalid-dependency-list",
                    severity="error",
                    message=f"依赖组 {group} 必须是数组",
                    source=self.positions.key(*key),
                )
            )
            return
        for index, value in enumerate(values):
            source = self.positions.value(*key, index)
            if not isinstance(value, str):
                diagnostics.append(
                    self._invalid(group, repr(value), "必须是字符串", source)
                )
                continue
            self._append_requirement(
                value, group, "direct", declarations, diagnostics, source
            )

    def _append_poetry_entry(
        self,
        name: str,
        value: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        *,
        key: SourceKey,
    ) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._append_poetry_entry(
                    name, item, group, declarations, diagnostics, key=(*key, index)
                )
            return

        source = self.positions.key(*key)
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
                self._invalid(group, name, "Poetry 条目必须是字符串或表", source)
            )
            return

        if version in {"", "*"}:
            version = ""
        elif kind == "direct":
            converted = self._convert_poetry_constraint(version)
            if converted is None:
                diagnostics.append(
                    self._invalid(group, f"{name}{version}", "版本约束无效", source)
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
            source,
        )

    def _append_requirement(
        self,
        requirement: str,
        group: str,
        kind: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        source: SourceLocation,
    ) -> None:
        try:
            declarations.append(
                PythonRequirement.from_requirement(
                    requirement,
                    source=source,
                    group=group,
                    kind=kind,
                )
            )
        except InvalidRequirement as exc:
            diagnostics.append(self._invalid(group, requirement, str(exc), source))

    def _append_dependency_group(
        self,
        group: str,
        *,
        target_group: str,
        groups: Mapping[str, Any],
        names: Mapping[str, list[str]],
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        active: tuple[str, ...],
        budget: _GroupBudget,
        include_source: SourceLocation | None = None,
    ) -> None:
        if budget.exhausted:
            return
        if group in active:
            diagnostics.append(
                Diagnostic(
                    code="manifest.group-cycle",
                    severity="error",
                    message="Cyclic dependency group include: "
                    + " -> ".join(name[:80] for name in (*active, group)),
                    source=include_source
                    or self.positions.key("dependency-groups", group),
                )
            )
            return
        if len(active) >= _GROUP_MAX_DEPTH:
            diagnostics.append(
                Diagnostic(
                    code="manifest.group-limit",
                    severity="error",
                    message="dependency-groups nesting exceeds 64 levels",
                    source=include_source
                    or self.positions.key("dependency-groups", group),
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
                    source=include_source
                    or self.positions.key("dependency-groups", group),
                )
            )
            return
        for index, value in enumerate(values):
            source = self.positions.value("dependency-groups", group, index)
            literal = (
                value
                if isinstance(value, str)
                else value.get("include-group", "")
                if isinstance(value, dict)
                else ""
            )
            size = (
                256
                + len(target_group.encode("utf-8"))
                + len(str(self.path).encode("utf-8"))
            )
            if isinstance(literal, str):
                size += len(literal.encode("utf-8"))
            if not self._take_group_budget(budget, size, source, diagnostics):
                return
            if isinstance(value, str):
                self._append_requirement(
                    value,
                    target_group,
                    "direct",
                    declarations,
                    diagnostics,
                    source,
                )
            elif (
                isinstance(value, dict)
                and value.keys() == {"include-group"}
                and isinstance(value.get("include-group"), str)
            ):
                include_source = self.positions.value(
                    "dependency-groups", group, index, "include-group"
                )
                try:
                    normalized = str(
                        canonicalize_name(value["include-group"], validate=True)
                    )
                except InvalidName:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.invalid-group-name",
                            "error",
                            "Included dependency group name is invalid.",
                            include_source,
                        )
                    )
                    continue
                candidates = names.get(normalized, [])
                if len(candidates) != 1:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.group-ambiguous"
                            if candidates
                            else "manifest.group-not-found",
                            "error",
                            "Included dependency group has no unique normalized target.",
                            include_source,
                        )
                    )
                    continue
                self._append_dependency_group(
                    candidates[0],
                    target_group=target_group,
                    groups=groups,
                    names=names,
                    declarations=declarations,
                    diagnostics=diagnostics,
                    active=(*active, group),
                    budget=budget,
                    include_source=include_source,
                )
            else:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-group-entry",
                        severity="error",
                        message=f"依赖组 {group} 含有无效条目",
                        source=source,
                    )
                )

    @staticmethod
    def _take_group_budget(
        budget: _GroupBudget,
        size: int,
        source: SourceLocation,
        diagnostics: list[Diagnostic],
    ) -> bool:
        if budget.exhausted:
            return False
        budget.entries -= 1
        budget.bytes -= size
        if (
            budget.entries < 0
            or budget.bytes < 0
            or len(diagnostics) >= _GROUP_MAX_DIAGNOSTICS
        ):
            budget.exhausted = True
            diagnostics.append(
                Diagnostic(
                    "manifest.group-limit",
                    "error",
                    "Dependency group expansion reached its entry, context or diagnostic budget; retained evidence is incomplete.",
                    source,
                )
            )
            return False
        return True

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

    def _invalid(
        self, group: str, value: str, reason: str, source: SourceLocation | None = None
    ) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-requirement",
            severity="error",
            message=f"依赖组 {group} 的声明 {value!r} 无效：{reason}",
            source=source or SourceLocation(self.path),
        )

    def _invalid_table(self, field: str) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-dependency-table",
            severity="error",
            message=f"{field} 必须是表",
            source=self.positions.key(*field.split(".")),
        )
