from __future__ import annotations

import json
import tomllib
from collections import Counter
from typing import Any

from packaging.requirements import InvalidRequirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from depcheck.python_sources import python_origin, PipenvSources
from depcheck.source_locations import SourcePositions

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser

_MAX_UV_PACKAGES = 20_000


def _uv_marker_list(value: Any) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _uv_has_conditions(value: Any) -> bool:
    pending = [value]
    nodes = 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 1024:
            return True
        if isinstance(item, dict):
            if any(
                key
                in {
                    "marker",
                    "resolution-markers",
                    "supported-markers",
                    "required-markers",
                    "conflicts",
                    "extra",
                    "extras",
                    "optional-dependencies",
                    "dev-dependencies",
                    "dependency-groups",
                    "default-groups",
                    "group-requires-python",
                }
                and value
                for key, value in item.items()
            ):
                return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _uv_bounded_context(
    value: dict[str, Any], budget: int
) -> tuple[dict[str, Any], bool, int]:
    if budget <= 0:
        return {}, True, 0
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        if size <= budget:
            return value, False, size
    except (TypeError, ValueError, RecursionError):
        pass
    return {}, True, 0


class LockfileParser(BaseDependencyParser):
    """只读取锁文件中的已解析版本，绝不把传递包当成直接声明。"""

    def parse(self) -> dict[str, str | None]:
        versions: dict[str, set[str]] = {}
        conditional: set[str] = set()
        for item in self.parse_detailed().declarations:
            if item.pinned_version:
                versions.setdefault(item.name, set()).add(item.pinned_version)
            if item.origin.get("lock", {}).get("conditional"):
                conditional.add(item.name)
        return {
            name: next(iter(values))
            if len(values) == 1 and name not in conditional
            else None
            for name, values in versions.items()
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
            text = self._read_text()
            if self.path.name == "Pipfile.lock":
                data = json.loads(text, object_pairs_hook=self._unique_object)
                positions = (
                    SourcePositions.json_keys(
                        self.path, text, frozenset({"default", "develop"})
                    )
                    if isinstance(data, dict)
                    else SourcePositions(self.path, text)
                )
            else:
                data = tomllib.loads(text)
                positions = SourcePositions.toml(self.path, text)
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
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
            self._parse_pipfile(data, declarations, diagnostics, positions)
        else:
            self._parse_toml_lock(data, declarations, diagnostics, positions)
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
        positions: SourcePositions,
    ) -> None:
        packages = data.get("package", []) if isinstance(data, dict) else []
        if not isinstance(packages, list):
            diagnostics.append(self._invalid("锁文件的 package 必须是数组"))
            return
        if self.path.name == "uv.lock" and len(packages) > _MAX_UV_PACKAGES:
            diagnostics.append(
                Diagnostic(
                    "manifest.uv-lock-package-limit",
                    "error",
                    f"uv lock package inventory is limited to {_MAX_UV_PACKAGES} entries; additional packages were omitted",
                    SourceLocation(self.path),
                )
            )
            packages = packages[:_MAX_UV_PACKAGES]
        contexts = (
            self._uv_contexts(data, packages, diagnostics, positions)
            if self.path.name == "uv.lock" and isinstance(data, dict)
            else {}
        )
        for index, item in enumerate(packages):
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
            origin = python_origin(
                item.get("source"), implicit_public=self.path.name != "uv.lock"
            )
            if index in contexts:
                origin["lock"] = contexts[index]
            self._append(
                item.get("name"),
                item.get("version"),
                group,
                declarations,
                diagnostics,
                origin=origin,
                source=positions.value("package", index, "name"),
            )

    def _uv_contexts(
        self,
        data: dict[str, Any],
        packages: list[Any],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
    ) -> dict[int, dict[str, Any]]:
        root_keys = (
            "version",
            "revision",
            "requires-python",
            "resolution-markers",
            "supported-markers",
            "required-markers",
            "conflicts",
        )
        package_keys = (
            "resolution-markers",
            "dependencies",
            "optional-dependencies",
            "dev-dependencies",
            "dependency-groups",
            "default-groups",
            "group-requires-python",
        )
        root = {key: data[key] for key in root_keys if key in data}
        values = {
            index: {key: item[key] for key in package_keys if key in item}
            for index, item in enumerate(packages)
            if isinstance(item, dict)
        }
        names = Counter(
            canonicalize_name(item["name"])
            for item in packages
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        conditional = (
            bool(diagnostics)
            or any(count > 1 for count in names.values())
            or _uv_has_conditions(root)
            or any(_uv_has_conditions(value) for value in values.values())
        )
        problems: list[Diagnostic] = []
        omitted = 0

        def problem(code: str, source: SourceLocation, message: str) -> None:
            nonlocal omitted
            if len(problems) < 31:
                problems.append(Diagnostic(code, "error", message, source))
            else:
                omitted += 1

        for key, value in root.items():
            valid = True
            if key == "version":
                valid = type(value) is int and value == 1
            elif key == "revision":
                valid = type(value) is int and value >= 0
            elif key == "requires-python":
                valid = (
                    isinstance(value, str)
                    and bool(value.strip())
                    and len(value) <= 4096
                )
                if valid:
                    try:
                        SpecifierSet(value)
                    except (RecursionError, ValueError):
                        valid = False
            elif key.endswith("markers"):
                valid = _uv_marker_list(value)
            elif key == "conflicts":
                valid = isinstance(value, list)
            if not valid:
                problem(
                    "manifest.uv-lock-context-invalid",
                    positions.value(key),
                    f"Unsupported uv lock context field: {key}",
                )
        for index, value in values.items():
            markers = value.get("resolution-markers")
            if "resolution-markers" in value and not _uv_marker_list(markers):
                problem(
                    "manifest.uv-lock-context-invalid",
                    positions.value("package", index, "resolution-markers"),
                    "uv package resolution-markers must be an array of non-empty strings",
                )
            for key in (
                "dependencies",
                "optional-dependencies",
                "dev-dependencies",
                "dependency-groups",
            ):
                if key not in value:
                    continue
                dependencies = value[key]
                groups = (
                    [dependencies]
                    if key == "dependencies"
                    else (
                        list(dependencies.values())
                        if isinstance(dependencies, dict)
                        else [None]
                    )
                )
                if not all(
                    isinstance(group, list)
                    and all(
                        isinstance(entry, dict)
                        and isinstance(entry.get("name"), str)
                        and entry["name"]
                        for entry in group
                    )
                    for group in groups
                ):
                    problem(
                        "manifest.uv-lock-context-invalid",
                        positions.value("package", index, key),
                        f"Unsupported uv lock dependency assertion shape: {key}",
                    )
        conditional = conditional or bool(problems) or bool(omitted)
        budget = 256 * 1024
        contexts = {}
        root, root_omitted, root_size = _uv_bounded_context(root, 8192)
        if root_omitted:
            problem(
                "resolution.uv-lock-context-limit",
                SourceLocation(self.path),
                "uv root lock context exceeds the supported JSON/depth/byte budget",
            )
        limited = root_omitted
        for index, value in values.items():
            retained, clipped, size = _uv_bounded_context(
                value, min(8192, max(0, budget - root_size - 256))
            )
            clipped = clipped or root_omitted or budget < root_size + size + 256
            if clipped:
                context = {"root": {}, "package": {}, "details_omitted": True}
                if not limited:
                    problem(
                        "resolution.uv-lock-context-limit",
                        positions.value("package", index, "name"),
                        "uv lock context was omitted by the supported JSON/depth/byte budget",
                    )
                    limited = True
            else:
                context = {"root": root, "package": retained}
                budget -= root_size + size + 256
            contexts[index] = {
                **context,
                "format": "uv",
                "package_index": index,
                "conditional": conditional or clipped,
                "activation": "unknown",
            }
        if conditional or limited:
            diagnostics.append(
                Diagnostic(
                    "resolution.uv-lock-selection-unknown",
                    "warning",
                    "uv lock conditions are inventory assertions; environment, extras/group selection and installed activation are unknown",
                    SourceLocation(self.path),
                )
            )
        diagnostics.extend(problems)
        if omitted:
            diagnostics.append(
                Diagnostic(
                    "resolution.uv-lock-diagnostic-limit",
                    "error",
                    f"{omitted} additional uv lock context diagnostics were omitted",
                    SourceLocation(self.path),
                )
            )
        return contexts

    def _parse_pipfile(
        self,
        data: object,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
    ) -> None:
        if not isinstance(data, dict):
            diagnostics.append(self._invalid("Pipfile.lock 顶层必须是对象"))
            return
        metadata = data.get("_meta", {})
        sources = PipenvSources(
            metadata.get("sources")
            if isinstance(metadata, dict)
            else {"invalid-meta": True}
        )
        for section, group in (("default", "lock:runtime"), ("develop", "lock:dev")):
            packages = data.get(section, {})
            if not isinstance(packages, dict):
                diagnostics.append(
                    self._invalid(f"Pipfile.lock 的 {section} 必须是对象")
                )
                continue
            for name, item in packages.items():
                version = item.get("version") if isinstance(item, dict) else item
                self._append(
                    name,
                    version,
                    group,
                    declarations,
                    diagnostics,
                    origin=sources.origin(item),
                    source=positions.key(section, str(name)),
                )

    def _append(
        self,
        name: object,
        version: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        origin: dict | None = None,
        source: SourceLocation | None = None,
    ) -> None:
        if not isinstance(name, str) or not isinstance(version, str):
            diagnostics.append(self._invalid("锁文件条目缺少 name 或 version", source))
            return
        cleaned = version.strip()
        cleaned = cleaned.removeprefix("==")
        try:
            Version(cleaned)
            declarations.append(
                PythonRequirement.from_requirement(
                    f"{name}=={cleaned}",
                    source=source or SourceLocation(self.path),
                    group=group,
                    kind="locked",
                    origin=origin,
                )
            )
        except (InvalidVersion, InvalidRequirement) as exc:
            diagnostics.append(
                self._invalid(f"无效锁定版本 {name!r}={version!r}：{exc}", source)
            )

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Pipfile.lock keys must be unique")
            value[key] = item
        return value

    def _invalid(
        self, message: str, source: SourceLocation | None = None
    ) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-lock-entry",
            severity="error",
            message=message,
            source=source or SourceLocation(self.path),
        )
