from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depcheck.policy_codes import VALID_FAIL_ON


class ConfigurationError(ValueError):
    """项目配置无法安全解释时抛出的操作错误。"""


_LEGACY_ALLOWED_KEYS = {
    "compatibility",
    "fail-on",
    "ignore-packages",
    "import-map",
    "python-version",
    "security",
}
_NEUTRAL_ALLOWED_KEYS = _LEGACY_ALLOWED_KEYS | {
    "enabled-ecosystems",
    "excluded-directories",
    "mappings",
}
DEFAULT_ECOSYSTEMS = ("PyPI", "npm", "Go", "Maven", "Conan", "vcpkg")


@dataclass(frozen=True, slots=True)
class DepcheckConfig:
    """项目级默认值；命令行显式参数可以在边界处覆盖它们。"""

    security: bool = True
    compatibility: bool = False
    ignored_packages: tuple[str, ...] = field(default_factory=tuple)
    import_mapping: Mapping[str, str] = field(default_factory=dict)
    python_version: str | None = None
    fail_on: tuple[str, ...] = field(default_factory=tuple)
    enabled_ecosystems: tuple[str, ...] = DEFAULT_ECOSYSTEMS
    excluded_directories: tuple[str, ...] = field(default_factory=tuple)
    scoped_mappings: Mapping[
        str,
        Mapping[str, Mapping[str, str]],
    ] = field(default_factory=dict)

    def mapping_for(self, ecosystem: str, project_id: str) -> dict[str, str]:
        result: dict[str, str] = {}
        if ecosystem.lower() == "pypi":
            result.update(
                {key.lower(): value for key, value in self.import_mapping.items()}
            )
        projects = next(
            (
                value
                for key, value in self.scoped_mappings.items()
                if key.lower() == ecosystem.lower()
            ),
            {},
        )
        result.update(
            {
                str(key).lower(): str(value)
                for key, value in projects.get(project_id, {}).items()
            }
        )
        return result


def load_project_config(project_root: Path) -> DepcheckConfig:
    """优先加载中立配置；缺失时回退到旧 Python 配置。"""
    root = Path(project_root)
    neutral_path = root / ".depcheck.toml"
    if neutral_path.is_file():
        return _parse_config(
            _load_toml(neutral_path),
            source=".depcheck.toml",
            allowed_keys=_NEUTRAL_ALLOWED_KEYS,
            default_ecosystems=DEFAULT_ECOSYSTEMS,
        )

    legacy_path = root / "pyproject.toml"
    if not legacy_path.is_file():
        return DepcheckConfig()

    document = _load_toml(legacy_path)
    legacy = _legacy_table(document)
    tool = document.get("tool", {})
    if isinstance(tool, Mapping) and "depcheck" not in tool:
        return DepcheckConfig()
    return _parse_config(
        legacy,
        source="tool.depcheck",
        allowed_keys=_LEGACY_ALLOWED_KEYS,
        default_ecosystems=("PyPI",),
    )


def _load_toml(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise ConfigurationError(f"{path.name} must contain a TOML table")
    return document


def _legacy_table(document: Mapping[str, Any]) -> Mapping[str, Any]:
    tool = document.get("tool", {})
    if not isinstance(tool, Mapping):
        raise ConfigurationError("[tool] must be a table")
    raw = tool.get("depcheck", {})
    if not isinstance(raw, Mapping):
        raise ConfigurationError("[tool.depcheck] must be a table")
    return raw


def _parse_config(
    raw: Mapping[str, Any],
    *,
    source: str,
    allowed_keys: set[str],
    default_ecosystems: tuple[str, ...],
) -> DepcheckConfig:
    unknown_keys = sorted(set(raw) - allowed_keys)
    if unknown_keys:
        raise ConfigurationError(f"{source} unknown key: {unknown_keys[0]}")

    security = _boolean(raw, "security", True, source)
    compatibility = _boolean(raw, "compatibility", False, source)
    ignored = _string_sequence(raw, "ignore-packages", source)
    fail_on = _string_sequence(raw, "fail-on", source)
    normalized_fail_on = tuple(item.lower() for item in fail_on)
    unknown_fail_on = sorted(set(normalized_fail_on) - VALID_FAIL_ON)
    if unknown_fail_on:
        raise ConfigurationError(
            f"{source} unknown fail-on value: {unknown_fail_on[0]}"
        )
    python_version = _optional_string(raw, "python-version", source)
    import_mapping = _string_mapping(raw, "import-map", source)
    enabled = _string_sequence(
        raw,
        "enabled-ecosystems",
        source,
        default=default_ecosystems,
    )
    excluded = _string_sequence(raw, "excluded-directories", source)
    _validate_exclusions(excluded, source)
    scoped_mappings = _scoped_mappings(raw, source)
    return DepcheckConfig(
        security=security,
        compatibility=compatibility,
        ignored_packages=tuple(item.lower() for item in ignored),
        import_mapping={key.lower(): value for key, value in import_mapping.items()},
        python_version=python_version,
        fail_on=normalized_fail_on,
        enabled_ecosystems=_unique_case_insensitive(enabled),
        excluded_directories=excluded,
        scoped_mappings=scoped_mappings,
    )


def _boolean(
    values: Mapping[str, Any],
    key: str,
    default: bool,
    source: str,
) -> bool:
    value = values.get(key, default)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{source}.{key} must be a boolean")
    return value


def _optional_string(
    values: Mapping[str, Any],
    key: str,
    source: str,
) -> str | None:
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{source}.{key} must be a non-empty string")
    return value.strip()


def _string_sequence(
    values: Mapping[str, Any],
    key: str,
    source: str,
    *,
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    value = values.get(key, default)
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ConfigurationError(f"{source}.{key} must be an array of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigurationError(f"{source}.{key} must contain non-empty strings")
        result.append(item.strip())
    return tuple(result)


def _string_mapping(
    values: Mapping[str, Any],
    key: str,
    source: str,
) -> dict[str, str]:
    value = values.get(key, {})
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{source}.{key} must be a table")
    return _validate_string_mapping(value, f"{source}.{key}")


def _validate_string_mapping(
    value: Mapping[object, object],
    source: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        if (
            not isinstance(raw_key, str)
            or not raw_key.strip()
            or not isinstance(raw_value, str)
            or not raw_value.strip()
        ):
            raise ConfigurationError(
                f"{source} keys and values must be non-empty strings"
            )
        result[raw_key.strip()] = raw_value.strip()
    return result


def _scoped_mappings(
    values: Mapping[str, Any],
    source: str,
) -> dict[str, dict[str, dict[str, str]]]:
    raw = values.get("mappings", {})
    if not isinstance(raw, Mapping):
        raise ConfigurationError(f"{source}.mappings must be a table")
    result: dict[str, dict[str, dict[str, str]]] = {}
    for ecosystem, projects in raw.items():
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            raise ConfigurationError(
                f"{source}.mappings ecosystem names must be non-empty strings"
            )
        if not isinstance(projects, Mapping):
            raise ConfigurationError(
                f"{source}.mappings.{ecosystem} must be a project table"
            )
        project_result: dict[str, dict[str, str]] = {}
        for project_id, mapping in projects.items():
            if not isinstance(project_id, str) or not project_id.strip():
                raise ConfigurationError(
                    f"{source}.mappings.{ecosystem} project IDs must be non-empty strings"
                )
            if not isinstance(mapping, Mapping):
                raise ConfigurationError(
                    f"{source}.mappings.{ecosystem}.{project_id} must be a table"
                )
            project_result[project_id.strip()] = _validate_string_mapping(
                mapping,
                f"{source}.mappings.{ecosystem}.{project_id}",
            )
        result[ecosystem.strip()] = project_result
    return result


def _validate_exclusions(excluded: Sequence[str], source: str) -> None:
    for item in excluded:
        path = Path(item)
        if path.is_absolute() or ".." in path.parts:
            raise ConfigurationError(
                f"{source}.excluded-directories must contain relative repository paths"
            )


def _unique_case_insensitive(values: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return tuple(result)
