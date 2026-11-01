from __future__ import annotations

import json
import tomllib
from collections import Counter
from typing import Any

from packaging.requirements import InvalidRequirement
from packaging.specifiers import SpecifierSet
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.ecosystems.python.parsers import BaseDependencyParser
from depcheck.evidence.input import parse_evidence_json
from depcheck.evidence.origins import PipenvSources, python_origin, redact_source
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

_MAX_UV_PACKAGES = 20_000
_MAX_TOML_PACKAGES = 20_000
_MAX_PIPFILE_PACKAGES = 20_000


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
    value: dict[str, Any], budget: int, *, redacted_size: bool = False
) -> tuple[dict[str, Any], bool, int]:
    if budget <= 0:
        return {}, True, 0
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        if size > budget:
            return {}, True, 0
        if redacted_size:
            size = max(
                size,
                len(
                    json.dumps(
                        redact_source(value), ensure_ascii=False, allow_nan=False
                    ).encode("utf-8")
                ),
            )
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
            if item.metadata.get("conditional") or item.origin.get("lock", {}).get(
                "conditional"
            ):
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
                data = parse_evidence_json(text.encode("utf-8"))
                positions = SourcePositions.json_keys(
                    self.path, text, frozenset(data) - {"_meta"}
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
        limit = _MAX_UV_PACKAGES if self.path.name == "uv.lock" else _MAX_TOML_PACKAGES
        if len(packages) > limit:
            diagnostics.append(
                Diagnostic(
                    "manifest.uv-lock-package-limit"
                    if self.path.name == "uv.lock"
                    else "manifest.lock-package-limit",
                    "error",
                    f"Lock package inventory is limited to {limit} entries; additional packages were omitted",
                    SourceLocation(self.path),
                )
            )
            packages = packages[:limit]
        contexts = (
            self._uv_contexts(data, packages, diagnostics, positions)
            if self.path.name == "uv.lock" and isinstance(data, dict)
            else self._legacy_contexts(data, packages, diagnostics)
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
            context = contexts.get(index, {})
            if self.path.name == "uv.lock" and context:
                origin["lock"] = contexts[index]
            metadata = {
                "python_kind": "lock-record",
                "lock_format": self.path.stem,
                "package_index": index,
                "context": {
                    "root": context.get("root", {}),
                    "package": context.get("package", {}),
                },
                "conditional": context.get("conditional", False),
                "activation": "unknown",
                **({"details_omitted": True} if context.get("details_omitted") else {}),
            }
            self._append(
                item.get("name"),
                item.get("version"),
                group,
                declarations,
                diagnostics,
                origin=origin,
                metadata=metadata,
                source=positions.value("package", index, "name"),
            )

    def _legacy_contexts(
        self,
        data: object,
        packages: list[Any],
        diagnostics: list[Diagnostic],
    ) -> dict[int, dict[str, Any]]:
        """Preserve lock occurrences and selection assertions without activating them."""
        header = data.get("metadata", {}) if isinstance(data, dict) else {}
        root_keys = (
            "lock-version",
            "lock_version",
            "python-versions",
            "groups",
            "strategy",
            "content-hash",
            "content_hash",
        )
        root = (
            {key: header[key] for key in root_keys if key in header}
            if isinstance(header, dict)
            else {}
        )
        package_keys = (
            "source",
            "category",
            "groups",
            "optional",
            "extras",
            "marker",
            "markers",
            "python-versions",
            "requires_python",
            "dependencies",
        )
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
        conditional = any(count > 1 for count in names.values()) or any(
            any(
                value.get(key)
                for key in (
                    "category",
                    "groups",
                    "optional",
                    "extras",
                    "marker",
                    "markers",
                    "python-versions",
                    "requires_python",
                )
            )
            for value in values.values()
        )
        budget = 256 * 1024
        root, root_omitted, root_size = _uv_bounded_context(root, 8192)
        limited = root_omitted
        contexts = {}
        for index, value in values.items():
            retained, clipped, size = _uv_bounded_context(
                value, min(8192, max(0, budget - root_size - 256))
            )
            clipped = clipped or root_omitted or budget < root_size + size + 256
            if clipped:
                context = {"root": {}, "package": {}, "details_omitted": True}
                limited = True
            else:
                context = {"root": root, "package": retained}
                budget -= root_size + size + 256
            contexts[index] = {**context, "conditional": conditional or clipped}
        if limited:
            diagnostics.append(
                Diagnostic(
                    "resolution.python-lock-context-limit",
                    "error",
                    "Python lock context exceeded its byte/depth budget; retained occurrences have qualified metadata omissions.",
                    SourceLocation(self.path),
                )
            )
        if conditional or limited:
            diagnostics.append(
                Diagnostic(
                    "resolution.python-lock-selection-unknown",
                    "warning",
                    "Python lock groups, extras and environment conditions are inventory assertions; selected installation scope remains unknown.",
                    SourceLocation(self.path),
                )
            )
        return contexts

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
            "manifest",
        )
        package_keys = (
            "source",
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
        if not isinstance(metadata, dict):
            diagnostics.append(
                self._invalid(
                    "Pipfile.lock 的 _meta 必须是对象", positions.key("_meta")
                )
            )
        sources = PipenvSources(
            metadata.get("sources")
            if isinstance(metadata, dict)
            else {"invalid-meta": True}
        )
        budget = 256 * 1024
        limited = False
        package_index = 0
        root, root_omitted, root_size = _uv_bounded_context(
            {"_meta": metadata}, 8192, redacted_size=True
        )
        for section, packages in data.items():
            if section == "_meta":
                continue
            category_kind = (
                "default"
                if section == "default"
                else "develop"
                if section == "develop"
                else "custom"
            )
            group = (
                "lock:runtime"
                if category_kind == "default"
                else "lock:dev"
                if category_kind == "develop"
                else f"lock:pipenv:{section}"
            )
            if not isinstance(packages, dict):
                diagnostics.append(
                    self._invalid(
                        f"Pipfile.lock 的 {section} 必须是对象", positions.key(section)
                    )
                )
                continue
            for name, item in packages.items():
                source = positions.key(section, str(name))
                if package_index == _MAX_PIPFILE_PACKAGES:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.lock-package-limit",
                            "error",
                            f"Pipfile.lock inventory is limited to {_MAX_PIPFILE_PACKAGES} entries; additional packages were omitted",
                            source,
                        )
                    )
                    return
                package = (
                    {key: value for key, value in item.items() if key != "hashes"}
                    if isinstance(item, dict)
                    else {"version": item}
                )
                artifact_metadata: dict[str, Any] = {}
                if isinstance(item, dict) and "hashes" in item:
                    artifact_metadata["omitted_package_fields"] = ["hashes"]
                    hashes = item["hashes"]
                    if isinstance(hashes, list) and all(
                        isinstance(value, str) and bool(value.strip())
                        for value in hashes
                    ):
                        artifact_metadata["artifact_hash_count"] = len(hashes)
                    else:
                        diagnostics.append(
                            self._invalid(
                                "Pipfile.lock hashes must be an array of non-empty strings; artifact hashes are not imported or verified",
                                source,
                            )
                        )
                context: dict[str, Any]
                if root_omitted or budget <= root_size + 256:
                    context, clipped, size = {}, True, 0
                else:
                    context, clipped, size = _uv_bounded_context(
                        {
                            "root": root,
                            "package": package,
                        },
                        min(8192, max(0, budget - 256)),
                        redacted_size=True,
                    )
                if clipped:
                    context = {"root": {}, "package": {}}
                    if not limited:
                        diagnostics.append(
                            Diagnostic(
                                "resolution.python-lock-context-limit",
                                "error",
                                "Pipfile.lock context exceeded its byte/depth budget; retained occurrences have qualified metadata omissions.",
                                source,
                            )
                        )
                        limited = True
                else:
                    budget -= size + 256
                pointer = "/" + "/".join(
                    str(value).replace("~", "~0").replace("/", "~1")
                    for value in (section, name)
                )
                lock_metadata = {
                    "python_kind": "lock-record",
                    "lock_format": "pipfile",
                    "package_index": package_index,
                    "source_pointer": pointer,
                    "pipenv_category": section,
                    "category_kind": category_kind,
                    "context": context,
                    "conditional": True,
                    "activation": "unknown",
                    **artifact_metadata,
                    **({"details_omitted": True} if clipped else {}),
                }
                if package_index == 0:
                    diagnostics.append(
                        Diagnostic(
                            "resolution.python-lock-selection-unknown",
                            "warning",
                            "Pipfile.lock categories, extras and environment conditions are inventory assertions; selected installation scope remains unknown.",
                            SourceLocation(self.path),
                        )
                    )
                package_index += 1
                version = item.get("version") if isinstance(item, dict) else item
                origin = sources.origin(item)
                try:
                    canonicalize_name(name, validate=True)
                except InvalidName as exc:
                    diagnostics.append(
                        self._invalid(f"无效 Pipfile.lock 包名 {name!r}：{exc}", source)
                    )
                    continue
                if (
                    version is None
                    and isinstance(item, dict)
                    and any(key in item for key in ("git", "path", "file", "url"))
                ):
                    try:
                        declarations.append(
                            PythonRequirement.from_requirement(
                                str(name),
                                source=source,
                                group=group,
                                kind="locked",
                                origin=origin,
                                metadata=lock_metadata,
                            )
                        )
                    except InvalidRequirement as exc:
                        diagnostics.append(
                            self._invalid(
                                f"无效 Pipfile.lock 包名 {name!r}：{exc}", source
                            )
                        )
                    else:
                        diagnostics.append(
                            Diagnostic(
                                "resolution.pipenv-version-unknown",
                                "warning",
                                "Pipfile.lock local or VCS record has no resolved package version; its source assertion does not establish a public release identity.",
                                source,
                            )
                        )
                    continue
                self._append(
                    name,
                    version,
                    group,
                    declarations,
                    diagnostics,
                    origin=origin,
                    metadata=lock_metadata,
                    source=source,
                )

    def _append(
        self,
        name: object,
        version: object,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        origin: dict | None = None,
        metadata: dict | None = None,
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
                    metadata=metadata,
                )
            )
        except (InvalidVersion, InvalidRequirement) as exc:
            diagnostics.append(
                self._invalid(f"无效锁定版本 {name!r}={version!r}：{exc}", source)
            )

    def _invalid(
        self, message: str, source: SourceLocation | None = None
    ) -> Diagnostic:
        return Diagnostic(
            code="manifest.invalid-lock-entry",
            severity="error",
            message=message,
            source=source or SourceLocation(self.path),
        )
