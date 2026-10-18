"""Bounded command evidence from configuration, without executing commands."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import json
from pathlib import Path
import re
import shlex
from typing import Any

import yaml

from depcheck.ecosystems.registry import EcosystemRegistry
from depcheck.ecosystems.static import (
    StaticReadError,
    exclusions_for,
    is_excluded,
    read_text,
)
from depcheck.ecosystems.yaml_reader import _LockLoader
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

_PYTHON_COMMANDS = {
    "pytest": ("pytest", "test"),
    "ruff": ("ruff", "test"),
    "mypy": ("mypy", "test"),
    "sphinx-build": ("sphinx", "build"),
    "mkdocs": ("mkdocs", "build"),
}
_NPM_COMMANDS = {
    "vitest": ("vitest", "test"),
    "jest": ("jest", "test"),
    "eslint": ("eslint", "test"),
    "prettier": ("prettier", "test"),
    "tsc": ("typescript", "test"),
    "vite": ("vite", "build"),
    "webpack": ("webpack", "build"),
    "vitepress": ("vitepress", "build"),
}
_PYTHON_MODULES = {
    "pytest": ("pytest", "test"),
    "ruff": ("ruff", "test"),
    "mypy": ("mypy", "test"),
    "sphinx": ("sphinx", "build"),
    "sphinx.cmd.build": ("sphinx", "build"),
    "mkdocs": ("mkdocs", "build"),
}
_SHELL_COMMANDS = frozenset(
    {
        "echo",
        "printf",
        "pwd",
        "true",
        "false",
        "exit",
        "test",
        "mkdir",
        "ls",
        "cat",
        "cp",
        "mv",
        "rm",
        "touch",
    }
)
_UV_FLAGS = frozenset({"--frozen", "--locked", "--offline", "--no-sync"})
_DYNAMIC = re.compile(r"[$`|&;<>()\\*?\[\]{}]")
_PYTHON = re.compile(r"python(?:3(?:\.\d+)?)?\Z")
_MAX_COMMANDS = 4096
_MAX_COMMAND_LENGTH = 16_384
_MAX_SCRIPTS = 512


def discover_command_files(
    repository_root: Path, settings: Mapping[str, Any] | None = None
) -> tuple[Path, ...]:
    """Return direct workflow YAML files, including rejected symlink candidates.

    The candidates also belong in freshness inventory. Symlinked directories
    are never traversed; collection diagnoses them without reading their data.
    """
    root = Path(repository_root).resolve()
    directory = root / ".github" / "workflows"
    if is_excluded(Path(".github/workflows"), exclusions_for(settings or {})):
        return ()
    if not _safe_path(root, directory) or not directory.is_dir():
        return ()
    try:
        return tuple(
            sorted(
                (
                    path
                    for path in directory.iterdir()
                    if path.suffix.lower() in {".yml", ".yaml"}
                    and (path.is_file() or path.is_symlink())
                ),
                key=lambda path: path.name,
            )
        )
    except OSError:
        return ()


def apply_command_usage(
    bundle: EvidenceBundle,
    repository_root: Path,
    projects: tuple[ProjectUnit, ...],
    settings: Mapping[str, Any] | None = None,
) -> EvidenceBundle:
    """Add exact mappings for fixed, directly declared tools in static commands."""
    if bundle.project.ecosystem.lower() not in {"pypi", "npm"}:
        return bundle
    collector = _CommandCollector(bundle, Path(repository_root).resolve(), projects)
    if bundle.project.ecosystem.lower() == "npm":
        collector.package_scripts()
    directory = collector.root / ".github" / "workflows"
    excluded = is_excluded(Path(".github/workflows"), exclusions_for(settings or {}))
    if not excluded and not _safe_path(collector.root, directory):
        collector.problem(
            "command.invalid",
            "Workflow directory is symlinked or outside the repository.",
            SourceLocation(directory),
        )
    for path in discover_command_files(collector.root, settings):
        collector.workflow(path)
    return collector.result()


class _CommandCollector:
    def __init__(
        self, bundle: EvidenceBundle, root: Path, projects: tuple[ProjectUnit, ...]
    ) -> None:
        self.bundle = bundle
        self.root = root
        self.projects = projects
        self.usages = list(bundle.usages)
        self.diagnostics = list(bundle.diagnostics)
        self.files = list(bundle.evidence_files)
        self.scripts: dict[str, tuple[str, SourceLocation]] = {}
        self.incomplete = False
        self.command_count = 0

    def problem(self, code: str, message: str, source: SourceLocation) -> None:
        self.incomplete = True
        diagnostic = Diagnostic(code, "warning", message, source)
        if diagnostic not in self.diagnostics:
            self.diagnostics.append(diagnostic)

    def result(self) -> EvidenceBundle:
        capabilities = list(self.bundle.capabilities)
        if self.incomplete:
            capability = Capability(
                "usage",
                CapabilityState.INCOMPLETE,
                "Static command configuration has unsupported or ambiguous evidence.",
            )
            capabilities = [
                capability if item.name == "usage" else item for item in capabilities
            ]
            if not any(item.name == "usage" for item in capabilities):
                capabilities.append(capability)
        return replace(
            self.bundle,
            usages=tuple(self.usages),
            diagnostics=tuple(self.diagnostics),
            capabilities=tuple(capabilities),
            evidence_files=tuple(self.files),
        )

    def package_scripts(self) -> None:
        path = self.root / self.bundle.project.root / "package.json"
        try:
            if not _safe_path(self.root, path):
                raise StaticReadError(
                    "Package script manifest is symlinked or outside the repository"
                )
            text = read_text(path)
            document = json.loads(text, object_pairs_hook=_unique_object)
            if not isinstance(document, dict):
                raise StaticReadError("Package script manifest must be a JSON object")
            scripts = document.get("scripts", {})
            if not isinstance(scripts, dict) or len(scripts) > _MAX_SCRIPTS:
                raise StaticReadError("Package scripts must be a bounded object")
            positions = SourcePositions.json_keys(path, text, frozenset({"scripts"}))
            for name, command in scripts.items():
                source = positions.value("scripts", name)
                if not isinstance(command, str) or not name:
                    self.problem(
                        "command.invalid",
                        "Package script names must be non-empty and commands must be strings.",
                        source,
                    )
                    continue
                self.scripts[name] = (command, source)
        except (StaticReadError, ValueError, RecursionError) as exc:
            self.problem(
                "command.invalid",
                str(exc),
                getattr(exc, "source", None) or SourceLocation(path),
            )
            return
        if path not in self.files:
            self.files.append(path)
        for name, (command, source) in self.scripts.items():
            self.command(
                command,
                source,
                self.root / self.bundle.project.root,
                (name,),
                f"package.json scripts.{name}",
            )

    def workflow(self, path: Path) -> None:
        try:
            if not _safe_path(self.root, path):
                raise StaticReadError(
                    "Workflow file is symlinked or outside the repository"
                )
            if path not in self.files:
                self.files.append(path)
            document, positions = _read_workflow(path)
            defaults = _run_defaults(document)
            jobs = document.get("jobs", {})
            if not isinstance(jobs, dict):
                raise StaticReadError("Workflow jobs must be a mapping")
            for name, job in jobs.items():
                if not isinstance(job, dict):
                    raise StaticReadError("Workflow jobs must contain mappings")
                job_defaults = {**defaults, **_run_defaults(job)}
                steps = job.get("steps", [])
                if not isinstance(steps, list):
                    raise StaticReadError("Workflow steps must be an array")
                for index, step in enumerate(steps):
                    if not isinstance(step, dict):
                        raise StaticReadError("Workflow steps must contain mappings")
                    if "run" not in step:
                        continue
                    key = ("jobs", name, "steps", index, "run")
                    source = positions.get(key, SourceLocation(path))
                    command = step["run"]
                    if not isinstance(command, str):
                        self.problem(
                            "command.invalid",
                            "Workflow run must be a literal string.",
                            source,
                        )
                        continue
                    raw_directory = step.get(
                        "working-directory", job_defaults.get("working-directory", ".")
                    )
                    directory_source = positions.get(
                        (*key[:-1], "working-directory"), source
                    )
                    if (
                        not isinstance(raw_directory, str)
                        or _DYNAMIC.search(raw_directory)
                        or not raw_directory
                    ):
                        self.problem(
                            "command.invalid",
                            "Workflow working-directory must be a literal repository path.",
                            directory_source,
                        )
                        continue
                    directory = self.root / raw_directory
                    if not _safe_path(self.root, directory) or not directory.is_dir():
                        self.problem(
                            "command.invalid",
                            "Workflow working-directory is unavailable, symlinked, or outside the repository.",
                            directory_source,
                        )
                        continue
                    shell = step.get("shell", job_defaults.get("shell"))
                    if shell is not None and shell not in {"bash", "sh"}:
                        self.problem(
                            "command.unsupported",
                            "Only portable literal bash/sh run commands are supported.",
                            source,
                        )
                        continue
                    self.command(
                        command,
                        source,
                        directory.resolve(),
                        (),
                        f"workflow jobs.{name}.steps[{index}].run",
                    )
        except (StaticReadError, ValueError, RecursionError) as exc:
            self.problem(
                "command.invalid",
                str(exc),
                getattr(exc, "source", None) or SourceLocation(path),
            )

    def command(
        self,
        value: str,
        source: SourceLocation,
        directory: Path,
        chain: tuple[str, ...],
        field: str,
    ) -> None:
        units = tuple(
            item
            for item in self.projects
            if item.ecosystem.lower() == self.bundle.project.ecosystem.lower()
        )
        owner = EcosystemRegistry.owner_for(directory.relative_to(self.root), units)
        if owner is None or owner.project_id != self.bundle.project.project_id:
            return
        if len(value) > _MAX_COMMAND_LENGTH:
            self.problem(
                "command.unsupported",
                "Command exceeds the static length limit.",
                source,
            )
            return
        lines = [
            line.strip()
            for line in value.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if any(
            _DYNAMIC.search(line) or re.match(r"(?:cd|pushd|popd)(?:\s|$)", line)
            for line in lines
        ):
            self.problem(
                "command.unsupported",
                "Shell operators, expansion, globbing, or changing working-directory cannot be mapped statically.",
                source,
            )
            return
        for line in lines:
            self.command_count += 1
            if self.command_count > _MAX_COMMANDS:
                self.problem(
                    "command.unsupported",
                    "Command configuration exceeds the static command limit.",
                    source,
                )
                return
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError as exc:
                self.problem(
                    "command.unsupported", f"Malformed literal command: {exc}", source
                )
                continue
            if tokens:
                self.tokens(tokens, source, directory, chain, field)

    def tokens(
        self,
        tokens: list[str],
        source: SourceLocation,
        directory: Path,
        chain: tuple[str, ...],
        field: str,
    ) -> None:
        executable = tokens[0]
        if executable == "uv":
            if len(tokens) > 1 and tokens[1] in {"sync", "lock", "pip"}:
                return
            if len(tokens) < 3 or tokens[1] != "run":
                self.problem(
                    "command.unsupported",
                    "Only the bounded uv run wrapper is supported.",
                    source,
                )
                return
            index = 2
            while index < len(tokens) and tokens[index].startswith("-"):
                if tokens[index] in _UV_FLAGS:
                    index += 1
                elif (
                    tokens[index] == "--extra"
                    and index + 1 < len(tokens)
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", tokens[index + 1])
                ):
                    index += 2
                else:
                    self.problem(
                        "command.unsupported",
                        "Unsupported uv run option or dynamic environment selection.",
                        source,
                    )
                    return
            if index == len(tokens) or tokens[index] in {"uv", "uvx"}:
                self.problem(
                    "command.unsupported",
                    "uv run requires one supported literal command.",
                    source,
                )
                return
            tokens = tokens[index:]
            executable = tokens[0]
        if executable in {"npm", "pnpm", "yarn"}:
            if self.bundle.project.ecosystem.lower() != "npm" or not self.owns(
                directory, "npm", source
            ):
                return
            if len(tokens) > 1 and tokens[1] in {
                "install",
                "ci",
                "add",
                "remove",
                "uninstall",
            }:
                return
            if (
                len(tokens) < 3
                or tokens[1] != "run"
                or (len(tokens) > 3 and tokens[3] != "--")
            ):
                self.problem(
                    "command.unsupported",
                    "Only literal npm/pnpm/yarn run SCRIPT references are supported.",
                    source,
                )
                return
            name = tokens[2]
            if name in chain or len(chain) >= 16:
                self.problem(
                    "command.script-cycle",
                    "Package script reference is cyclic or exceeds the static recursion limit.",
                    source,
                )
                return
            if name not in self.scripts:
                self.problem(
                    "command.unmapped",
                    f"Package script {name!r} has no local definition.",
                    source,
                )
                return
            value, target_source = self.scripts[name]
            self.command(
                value,
                target_source,
                self.root / self.bundle.project.root,
                (*chain, name),
                f"package.json scripts.{name}",
            )
            return
        ecosystem = None
        mapping = None
        if _PYTHON.fullmatch(executable):
            ecosystem = "pypi"
            if len(tokens) >= 3 and tokens[1] == "-m":
                mapping = _PYTHON_MODULES.get(tokens[2])
                if tokens[2] in {"pip", "ensurepip"}:
                    return
            elif (
                len(tokens) >= 2
                and not tokens[1].startswith("-")
                and _local_script(self.root, directory, tokens[1], {".py"})
            ):
                return
            else:
                self.problem(
                    "command.unsupported",
                    "Python wrapper requires a fixed module or a local literal script.",
                    source,
                )
                return
        elif executable in _PYTHON_COMMANDS:
            ecosystem, mapping = "pypi", _PYTHON_COMMANDS[executable]
        elif executable in _NPM_COMMANDS:
            ecosystem, mapping = "npm", _NPM_COMMANDS[executable]
        elif executable in _SHELL_COMMANDS or executable in {"pip", "pip3"}:
            return
        elif (
            executable == "node"
            and len(tokens) >= 2
            and _local_script(self.root, directory, tokens[1], {".js", ".mjs", ".cjs"})
        ):
            return
        elif executable in {
            "npx",
            "uvx",
            "env",
            "bash",
            "sh",
            "cmd",
            "powershell",
            "pwsh",
        }:
            self.problem(
                "command.unsupported",
                "Execution wrapper cannot be mapped with the supported static grammar.",
                source,
            )
            return
        if ecosystem is not None and self.bundle.project.ecosystem.lower() != ecosystem:
            return
        if not self.owns(
            directory, ecosystem or self.bundle.project.ecosystem.lower(), source
        ):
            return
        if mapping is None:
            self.problem(
                "command.unmapped",
                f"Literal command {executable!r} has no fixed dependency mapping.",
                source,
            )
            return
        package, scope = mapping
        declared = next(
            (
                item
                for item in self.bundle.declarations
                if item.kind == "direct"
                and item.scope != "build"
                and item.package.name == package
            ),
            None,
        )
        if declared is None:
            return
        usage = UsageEvidence(
            project_id=self.bundle.project.project_id,
            language=self.bundle.project.language,
            reference=tokens[2] if _PYTHON.fullmatch(executable) else executable,
            source=source,
            scope=scope,
            kind="command",
            mapped_package=declared.package,
            mapping_confidence=MappingConfidence.EXACT,
            mapping_reason=f"Static configuration in {field} maps {executable!r} to directly declared {package!r}; this is not evidence of command execution.",
        )
        if usage not in self.usages:
            self.usages.append(usage)

    def owns(self, directory: Path, ecosystem: str, source: SourceLocation) -> bool:
        units = tuple(
            item for item in self.projects if item.ecosystem.lower() == ecosystem
        )
        owner = EcosystemRegistry.owner_for(directory.relative_to(self.root), units)
        if owner is None or owner.project_id != self.bundle.project.project_id:
            return False
        if ecosystem == "pypi":
            manifests = [
                path if path.is_absolute() else self.root / path
                for path in owner.manifests
                if path not in owner.locks
                and path.suffix != ".lock"
                and path.name != "pip_install.sh"
            ]
            roots = {path.parent for path in manifests}
            if len(roots) > 1:
                self.problem(
                    "command.owner-ambiguous",
                    "Independent Python component manifests cannot share static command usage.",
                    source,
                )
                return False
            component = next(iter(roots), self.root / owner.root)
            if directory != component and component not in directory.parents:
                self.problem(
                    "command.owner-ambiguous",
                    "The command working-directory does not identify the Python component.",
                    source,
                )
                return False
        return True


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise StaticReadError("Package script JSON mapping keys must be unique")
        result[name] = value
    return result


def _run_defaults(document: Mapping[str, Any]) -> dict[str, Any]:
    defaults = document.get("defaults", {})
    if not isinstance(defaults, dict) or not isinstance(defaults.get("run", {}), dict):
        raise StaticReadError("Workflow defaults.run must be a mapping")
    return defaults.get("run", {})


def _read_workflow(
    path: Path,
) -> tuple[dict[str, Any], dict[tuple[Any, ...], SourceLocation]]:
    loader = _LockLoader(read_text(path))
    try:
        node = loader.get_single_node()
        if node is None:
            raise StaticReadError("Workflow YAML must contain a mapping")
        document = loader.construct_document(node)
        if not isinstance(document, dict):
            raise StaticReadError("Workflow YAML root must be a mapping")
        positions: dict[tuple[Any, ...], SourceLocation] = {}

        def visit(current: Any, key: tuple[Any, ...]) -> None:
            positions[key] = SourceLocation(
                path, current.start_mark.line + 1, current.start_mark.column + 1
            )
            if isinstance(current, yaml.MappingNode):
                for name, value in current.value:
                    visit(value, (*key, name.value))
            elif isinstance(current, yaml.SequenceNode):
                for index, value in enumerate(current.value):
                    visit(value, (*key, index))

        visit(node, ())
        return document, positions
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        raise StaticReadError(f"Invalid workflow YAML: {exc}") from exc
    finally:
        loader.dispose()


def _safe_path(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        path.resolve().relative_to(root)
        return not any(
            item.is_symlink()
            for item in (path, *path.parents)
            if item != root and root in item.parents
        )
    except (OSError, ValueError, RuntimeError):
        return False


def _local_script(root: Path, directory: Path, value: str, suffixes: set[str]) -> bool:
    path = directory / value
    return (
        not Path(value).is_absolute()
        and path.suffix in suffixes
        and _safe_path(root, path)
        and path.is_file()
    )
