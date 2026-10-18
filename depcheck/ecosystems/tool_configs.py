"""Collect bounded literal tool configuration without loading target modules."""

from __future__ import annotations

import configparser
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import shlex
import tomllib
from typing import Any
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from depcheck.ecosystems.commands import _safe_path
from depcheck.ecosystems.javascript_packages import registry_name
from depcheck.ecosystems.registry import EcosystemRegistry
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    is_excluded,
    read_text,
)
from depcheck.model import (
    Capability,
    CapabilityState,
    Diagnostic,
    EvidenceBundle,
    MappingConfidence,
    ProjectUnit,
    SourceLocation,
    UsageEvidence,
)
from depcheck.source_locations import SourcePositions

_JSONC = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/')
_TRAILING = re.compile(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])')
_PYTEST_PLUGINS = {
    "pytest_mock": "pytest-mock",
    "pytest_cov": "pytest-cov",
    "pytest_asyncio": "pytest-asyncio",
    "xdist": "pytest-xdist",
}
_PYTEST_FILES = frozenset(
    {"pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"}
)


def discover_tool_config_files(
    root: Path, settings: dict[str, Any] | None = None
) -> tuple[Path, ...]:
    candidates = discover_files(
        root,
        names=_PYTEST_FILES | {"pnpm-workspace.yaml"},
        suffixes=frozenset({".json"}),
        excluded_directories=exclusions_for(settings or {}),
    )
    paths = {
        p
        for p in candidates
        if p.name in _PYTEST_FILES
        or p.name == "pnpm-workspace.yaml"
        or (p.name.startswith("tsconfig") and p.suffix == ".json")
    }
    pending = [
        (p, 0) for p in paths if p.name.startswith("tsconfig") and p.suffix == ".json"
    ]
    visited: set[Path] = set()
    while pending:
        path, depth = pending.pop()
        if path in visited or depth >= 32:
            continue
        visited.add(path)
        try:
            data = json.loads(
                _jsonc_text(read_text(path)), object_pairs_hook=_unique_object
            )
            extend = data.get("extends", []) if isinstance(data, dict) else []
            values = [extend] if isinstance(extend, str) else extend
            for value in values if isinstance(values, list) else []:
                if isinstance(value, str) and value.startswith("."):
                    target = Path(os.path.abspath(path.parent / value))
                    if not target.suffix:
                        target = target.with_suffix(".json")
                    if (
                        _safe_path(root, target)
                        and target.is_file()
                        and not is_excluded(
                            target.relative_to(root), exclusions_for(settings or {})
                        )
                    ):
                        paths.add(target)
                        pending.append((target, depth + 1))
        except (OSError, ValueError, RecursionError):
            continue
    for name in ("tsconfig.json", *_PYTEST_FILES):
        if (root / name).is_symlink():
            paths.add(root / name)
    return tuple(sorted(paths))


def apply_tool_config_usage(
    bundle: EvidenceBundle,
    root: Path,
    projects: tuple[ProjectUnit, ...],
    settings: dict[str, Any] | None = None,
) -> EvidenceBundle:
    collector = _ConfigCollector(bundle, root, projects, settings or {})
    if bundle.project.ecosystem.lower() == "npm":
        for path in discover_tool_config_files(
            root / bundle.project.root,
            {
                "excluded_directories": exclusions_for(
                    settings or {}, bundle.project.root
                )
            },
        ):
            if (
                path.name.startswith("tsconfig")
                and path.suffix == ".json"
                and collector.owns(path)
            ):
                collector.typescript(path, ())
    elif bundle.project.ecosystem.lower() == "pypi":
        for path in discover_tool_config_files(
            root / bundle.project.root,
            {
                "excluded_directories": exclusions_for(
                    settings or {}, bundle.project.root
                )
            },
        ):
            if path.name in _PYTEST_FILES and collector.owns(path):
                collector.pytest(path)
    else:
        return bundle
    capabilities = bundle.capabilities
    if collector.incomplete:
        capabilities = tuple(
            Capability(
                c.name,
                CapabilityState.INCOMPLETE,
                "Tool configuration evidence is incomplete",
            )
            if c.name in {"usage", "mapping"}
            else c
            for c in capabilities
        )
    return replace(
        bundle,
        usages=tuple(collector.usages),
        diagnostics=tuple(collector.diagnostics),
        evidence_files=tuple(collector.files),
        capabilities=capabilities,
    )


class _ConfigCollector:
    def __init__(
        self,
        bundle: EvidenceBundle,
        root: Path,
        projects: tuple[ProjectUnit, ...],
        settings: dict[str, Any],
    ) -> None:
        self.bundle, self.root, self.projects, self.settings = (
            bundle,
            root,
            projects,
            settings,
        )
        self.usages = list(bundle.usages)
        self.diagnostics = list(bundle.diagnostics)
        self.files = list(bundle.evidence_files)
        self.visited: set[Path] = set()
        self.incomplete = False
        self.custom_type_roots = False

    def owns(self, path: Path) -> bool:
        units = tuple(
            p for p in self.projects if p.ecosystem == self.bundle.project.ecosystem
        )
        owner = EcosystemRegistry.owner_for(path.relative_to(self.root), units)
        return owner == self.bundle.project

    def problem(self, message: str, source: SourceLocation) -> None:
        self.incomplete = True
        diagnostic = Diagnostic("configuration.unsupported", "warning", message, source)
        if diagnostic not in self.diagnostics:
            self.diagnostics.append(diagnostic)

    def read(self, path: Path) -> str:
        if not _safe_path(self.root, path) or is_excluded(
            path.relative_to(self.root), exclusions_for(self.settings)
        ):
            raise StaticReadError("Configuration path is unsafe or excluded")
        if path not in self.files:
            self.files.append(path)
        return read_text(path)

    def usage(
        self,
        reference: str,
        package: str,
        scope: str,
        source: SourceLocation,
        field: str,
    ) -> None:
        declared = [
            d
            for d in self.bundle.declarations
            if d.kind == "direct"
            and (d.metadata.get("installation_name") or d.package.name) == package
        ]
        if not declared:
            self.problem(
                f"{field} reference {reference!r} has no verified declared package owner",
                source,
            )
            return
        usage = UsageEvidence(
            self.bundle.project.project_id,
            self.bundle.project.language,
            reference,
            source,
            scope=scope,
            kind="configuration",
            mapped_package=declared[0].package,
            mapping_confidence=MappingConfidence.EXACT,
            mapping_reason=f"Literal {field} maps {reference!r} to declared {package!r}; this is configuration, not proof of execution.",
        )
        if usage not in self.usages:
            self.usages.append(usage)

    def typescript(self, path: Path, ancestors: tuple[Path, ...]) -> None:
        source = SourceLocation(path)
        try:
            if path in ancestors or len(ancestors) >= 32 or len(self.visited) >= 128:
                raise StaticReadError(
                    "TypeScript configuration cycle or traversal limit"
                )
            if path in self.visited:
                return
            self.visited.add(path)
            text = self.read(path)
            text = _JSONC.sub(
                lambda m: (
                    m[0]
                    if m[0].startswith('"')
                    else "".join("\n" if c == "\n" else " " for c in m[0])
                ),
                text,
            )
            text = _TRAILING.sub(
                lambda m: m[0] if m[0].startswith('"') else " " + m[0][1:], text
            )
            data = json.loads(text, object_pairs_hook=_unique_object)
            if not isinstance(data, dict):
                raise StaticReadError("TypeScript configuration must be an object")
            positions = SourcePositions.json_keys(
                path, text, frozenset({"compilerOptions"})
            )
            extend = data.get("extends", [])
            if isinstance(extend, str):
                extend = [extend]
            if not isinstance(extend, list):
                raise StaticReadError("TypeScript extends must contain literal strings")
            for value in extend:
                source = positions.value("extends")
                if not isinstance(value, str) or not value:
                    raise StaticReadError(
                        "TypeScript extends must contain literal strings"
                    )
                if value.startswith("."):
                    target = Path(os.path.abspath(path.parent / value))
                    if not target.suffix:
                        target = target.with_suffix(".json")
                    self.typescript(target, (*ancestors, path))
                else:
                    self.usage(
                        value, _npm_name(value), "build", source, "tsconfig.extends"
                    )
                    # Package-provided contents are outside static source coverage.
                    self.problem(
                        "Package-provided TypeScript configuration contents are not collected",
                        source,
                    )
            options = data.get("compilerOptions", {})
            if not isinstance(options, dict):
                raise StaticReadError("TypeScript compilerOptions must be an object")
            if "typeRoots" in options:
                self.custom_type_roots = True
                self.problem(
                    "Custom TypeScript typeRoots are not resolved",
                    positions.value("compilerOptions", "typeRoots"),
                )
            for field in ("types", "plugins"):
                if field == "types" and self.custom_type_roots:
                    continue
                source = positions.value("compilerOptions", field)
                values = options.get(field, [])
                if not isinstance(values, list):
                    raise StaticReadError(f"TypeScript {field} must be an array")
                for value in values:
                    name = (
                        value.get("name")
                        if field == "plugins" and isinstance(value, dict)
                        else value
                    )
                    if not isinstance(name, str) or not name:
                        raise StaticReadError(
                            f"TypeScript {field} must contain literal package names"
                        )
                    package = _npm_name(name)
                    if field == "types":
                        package = "@types/" + (
                            package[1:].replace("/", "__")
                            if package.startswith("@")
                            else package
                        )
                    self.usage(
                        name,
                        package,
                        "build",
                        source,
                        f"tsconfig.compilerOptions.{field}",
                    )
            if "jsxImportSource" in options:
                source = positions.value("compilerOptions", "jsxImportSource")
                name = options["jsxImportSource"]
                if not isinstance(name, str):
                    raise StaticReadError(
                        "TypeScript jsxImportSource must be a literal package"
                    )
                self.usage(
                    name,
                    _npm_name(name),
                    "unknown",
                    source,
                    "tsconfig.compilerOptions.jsxImportSource",
                )
                self.problem(
                    "JSX emit and bundler context do not establish dependency scope",
                    source,
                )
            if options.get("importHelpers") is True:
                source = positions.value("compilerOptions", "importHelpers")
                self.usage(
                    "tslib",
                    "tslib",
                    "unknown",
                    source,
                    "tsconfig.compilerOptions.importHelpers",
                )
                self.problem(
                    "Helper emit and bundler context do not establish dependency scope",
                    source,
                )
        except (OSError, ValueError, RecursionError) as exc:
            self.problem(str(exc), source)

    def pytest(self, path: Path) -> None:
        source = SourceLocation(path)
        try:
            text = self.read(path)
            if path.suffix == ".toml":
                data = (
                    tomllib.loads(text)
                    .get("tool", {})
                    .get("pytest", {})
                    .get("ini_options", {})
                )
                source = SourcePositions.toml(path, text).value(
                    "tool", "pytest", "ini_options", "addopts"
                )
            else:
                parser = configparser.ConfigParser(interpolation=None)
                parser.read_string(text)
                section = "tool:pytest" if path.name == "setup.cfg" else "pytest"
                data = dict(parser[section]) if parser.has_section(section) else {}
            if not isinstance(data, dict):
                raise StaticReadError("pytest configuration must be a table")
            required = data.get("required_plugins", [])
            if isinstance(required, str):
                required = shlex.split(required)
            if not isinstance(required, list) or not all(
                isinstance(v, str) for v in required
            ):
                raise StaticReadError(
                    "pytest required_plugins must contain literal requirements"
                )
            for value in required:
                requirement = Requirement(value)
                location = (
                    SourcePositions.toml(path, text).value(
                        "tool", "pytest", "ini_options", "required_plugins"
                    )
                    if path.suffix == ".toml"
                    else source
                )
                self.usage(
                    value,
                    str(canonicalize_name(requirement.name)),
                    "test",
                    location,
                    "pytest.required_plugins",
                )
                if requirement.marker is not None:
                    self.problem(
                        "pytest required_plugins contains an unevaluated environment marker",
                        location,
                    )
            value = data.get("addopts", "")
            tokens = shlex.split(value) if isinstance(value, str) else value
            if not isinstance(tokens, list) or not all(
                isinstance(t, str) for t in tokens
            ):
                raise StaticReadError("pytest addopts must be literal strings")
            if len(tokens) > 4096:
                raise StaticReadError("pytest addopts exceeds the token limit")
            for index, token in enumerate(tokens):
                if token == "-p":
                    if index + 1 == len(tokens):
                        raise StaticReadError(
                            "pytest -p requires a literal plugin name"
                        )
                    name = tokens[index + 1]
                elif token.startswith("-p") and len(token) > 2:
                    name = token[2:]
                else:
                    continue
                if name.startswith("no:"):
                    continue
                package = _PYTEST_PLUGINS.get(name)
                if package is None:
                    self.problem(
                        f"pytest plugin {name!r} has no verified distribution mapping",
                        source,
                    )
                else:
                    self.usage(name, package, "test", source, "pytest.addopts")
        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            RecursionError,
            configparser.Error,
        ) as exc:
            self.problem(str(exc), source)


def _jsonc_text(text: str) -> str:
    text = _JSONC.sub(
        lambda m: (
            m[0]
            if m[0].startswith('"')
            else "".join("\n" if c == "\n" else " " for c in m[0])
        ),
        text,
    )
    return _TRAILING.sub(
        lambda m: m[0] if m[0].startswith('"') else " " + m[0][1:], text
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StaticReadError("Configuration JSON keys must be unique")
        result[key] = value
    return result


def _npm_name(value: str) -> str:
    parts = value.split("/")
    return registry_name("/".join(parts[:2]) if value.startswith("@") else parts[0])
