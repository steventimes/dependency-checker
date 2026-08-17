from __future__ import annotations

import json
import tomllib

from packaging.requirements import InvalidRequirement
from packaging.version import InvalidVersion, Version

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser


class LockfileParser(BaseDependencyParser):
    """只读取锁文件中的已解析版本，绝不把传递包当成直接声明。"""

    def parse(self) -> dict[str, str | None]:
        return {
            item.name: item.pinned_version
            for item in self.parse_detailed().declarations
            if item.pinned_version
        }

    def parse_detailed(self) -> ManifestParseResult:
        if not self.path.is_file():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"锁文件不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )

        try:
            if self.path.name == "Pipfile.lock":
                data = json.loads(self.path.read_text(encoding="utf-8"))
            else:
                data = tomllib.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-lockfile",
                        severity="error",
                        message=f"无法解析锁文件：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        if self.path.name == "Pipfile.lock":
            self._parse_pipfile(data, declarations, diagnostics)
        else:
            self._parse_toml_lock(data, declarations, diagnostics)
        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _parse_toml_lock(
        self,
        data: object,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        packages = data.get("package", []) if isinstance(data, dict) else []
        if not isinstance(packages, list):
            diagnostics.append(self._invalid("锁文件的 package 必须是数组"))
            return
        for item in packages:
            if not isinstance(item, dict):
                diagnostics.append(self._invalid("锁文件包含非对象 package 条目"))
                continue
            group = "lock"
            category = item.get("category")
            groups = item.get("groups")
            if isinstance(category, str):
                group = f"lock:{category}"
            elif isinstance(groups, list) and groups:
                group = f"lock:{','.join(sorted(str(value) for value in groups))}"
            self._append(
                item.get("name"), item.get("version"), group, declarations, diagnostics
            )

    def _parse_pipfile(
        self,
        data: object,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if not isinstance(data, dict):
            diagnostics.append(self._invalid("Pipfile.lock 顶层必须是对象"))
            return
        for section, group in (("default", "lock:runtime"), ("develop", "lock:dev")):
            packages = data.get(section, {})
            if not isinstance(packages, dict):
                diagnostics.append(
                    self._invalid(f"Pipfile.lock 的 {section} 必须是对象")
                )
                continue
            for name, item in packages.items():
                version = item.get("version") if isinstance(item, dict) else item
                self._append(name, version, group, declarations, diagnostics)

    def _append(
        self,
        name: object,
        version: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if not isinstance(name, str) or not isinstance(version, str):
            diagnostics.append(self._invalid("锁文件条目缺少 name 或 version"))
            return
        cleaned = version.strip()
        cleaned = cleaned.removeprefix("==")
        try:
            Version(cleaned)
            declarations.append(
                PythonRequirement.from_requirement(
                    f"{name}=={cleaned}",
                    source=SourceLocation(self.path),
                    group=group,
                    kind="locked",
                )
            )
        except (InvalidVersion, InvalidRequirement) as exc:
            diagnostics.append(
                self._invalid(f"无效锁定版本 {name!r}={version!r}：{exc}")
            )

    def _invalid(self, message: str) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-lock-entry",
            severity="warning",
            message=message,
            source=SourceLocation(self.path),
        )
