"""Literal pyproject environment/task assertions; never execute or interpolate them."""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any

from packaging.requirements import InvalidRequirement

from depcheck.filesystem.positions import SourceKey, SourcePositions
from depcheck.model import Diagnostic, PythonRequirement, SourceLocation

_MAX_ITEMS = 4096
_MAX_ENVIRONMENTS = 128


@dataclass(frozen=True)
class PythonTask:
    command: str
    source: SourceLocation
    field: str
    environment: str | None = None


@dataclass(frozen=True)
class PythonTaskConfiguration:
    requirements: tuple[PythonRequirement, ...]
    tasks: tuple[PythonTask, ...]
    diagnostics: tuple[Diagnostic, ...]


def collect_python_tasks(
    data: dict[str, Any], positions: SourcePositions
) -> PythonTaskConfiguration:
    collector = _Collector(positions)
    tool = data.get("tool", {})
    if isinstance(tool, dict):
        if "hatch" in tool:
            collector.hatch(tool["hatch"])
        if "poe" in tool:
            collector.poe(tool["poe"])
    return PythonTaskConfiguration(
        tuple(collector.requirements),
        tuple(collector.tasks),
        tuple(collector.diagnostics),
    )


class _Collector:
    def __init__(self, positions: SourcePositions) -> None:
        self.positions = positions
        self.requirements: list[PythonRequirement] = []
        self.tasks: list[PythonTask] = []
        self.diagnostics: list[Diagnostic] = []
        self.remaining = _MAX_ITEMS
        self.exhausted = False

    def problem(self, message: str, key: SourceKey, *, error: bool = False) -> None:
        if len(self.diagnostics) < 64:
            self.diagnostics.append(
                Diagnostic(
                    "configuration.python-task-unsupported",
                    "error" if error else "warning",
                    message,
                    self.positions.value(*key),
                )
            )

    def take(self, key: SourceKey) -> bool:
        if self.remaining <= 0:
            if not self.exhausted:
                self.problem(
                    "Python task configuration reached its shared item limit.",
                    key,
                    error=True,
                )
                self.exhausted = True
            return False
        self.remaining -= 1
        return True

    def hatch(self, config: Any) -> None:
        key = ("tool", "hatch")
        if not isinstance(config, dict):
            self.problem("Hatch configuration must be a table.", key, error=True)
            return
        environments = config.get("envs", {})
        if not isinstance(environments, dict) or len(environments) > _MAX_ENVIRONMENTS:
            self.problem(
                "Hatch environments must be a bounded table.",
                (*key, "envs"),
                error=True,
            )
            return
        for name, environment in environments.items():
            env_key = (*key, "envs", name)
            if not self.take(env_key):
                break
            if not name or len(name) > 128 or not isinstance(environment, dict):
                self.problem(
                    "Hatch environment names and tables must be bounded.",
                    env_key,
                    error=True,
                )
                continue
            context = f"hatch:{name}"
            template = environment.get("template", "default")
            if not isinstance(template, str) or not template or len(template) > 128:
                self.problem(
                    "Hatch template must be a bounded name.",
                    (*env_key, "template"),
                    error=True,
                )
                template = "[unsupported]"
            if "detached" in environment and not isinstance(
                environment["detached"], bool
            ):
                self.problem(
                    "Hatch detached must be a boolean.",
                    (*env_key, "detached"),
                    error=True,
                )
            # Preserve physical declarations. Inherited activation is deliberately
            # not flattened into this environment or the application's requirements.
            for field in ("dependencies", "extra-dependencies"):
                values = environment.get(field, [])
                if not isinstance(values, list):
                    self.problem(
                        "Hatch environment dependencies must be arrays.",
                        (*env_key, field),
                        error=True,
                    )
                    continue
                for index, value in enumerate(values):
                    item_key = (*env_key, field, index)
                    if not self.take(item_key):
                        break
                    if (
                        not isinstance(value, str)
                        or len(value) > 16384
                        or any(c in value for c in "{}$")
                    ):
                        self.problem(
                            "Hatch dependency context formatting is not evaluated.",
                            item_key,
                            error=True,
                        )
                        continue
                    try:
                        self.requirements.append(
                            PythonRequirement.from_requirement(
                                value,
                                source=self.positions.value(*item_key),
                                group=context,
                                kind="environment",
                                origin={
                                    "kind": "hatch-environment",
                                    "public": False,
                                    "activation": "unknown",
                                    "assertion": {
                                        "environment": name,
                                        "template": template,
                                        "source_selection": "unverified",
                                        "source_configuration_fields": [
                                            field
                                            for field in (
                                                "sources",
                                                "env-vars",
                                                "env-include",
                                                "env-exclude",
                                            )
                                            if field in environment
                                        ],
                                    },
                                },
                            )
                        )
                    except InvalidRequirement:
                        self.problem(
                            "Invalid literal Hatch environment requirement.",
                            item_key,
                            error=True,
                        )
            scripts = environment.get("scripts", {})
            if not isinstance(scripts, dict):
                self.problem("Hatch scripts must be a table.", (*env_key, "scripts"))
                continue
            # A default environment with content may contribute inherited scripts,
            # dependencies and overrides. Keep those relationships unresolved.
            self_referential = environment.get("detached") is True or template == name
            inherited = not self_referential and (
                template != "default" or bool(environments.get("default"))
            )
            if inherited:
                self.problem(
                    "Hatch template inheritance is retained but not expanded.", env_key
                )
            expanded_options = any(
                field in environment
                for field in (
                    "matrix",
                    "overrides",
                    "extra-scripts",
                    "features",
                    "dependency-groups",
                )
            )
            if expanded_options:
                self.problem(
                    "Hatch matrix, overrides, extra scripts and selected project groups are not expanded.",
                    env_key,
                )
            external = any(field in config for field in ("config", "env"))
            if external:
                self.problem("External Hatch configuration is not evaluated.", key)
            if inherited or expanded_options or external:
                continue
            for script, value in scripts.items():
                if self.exhausted:
                    break
                task_key = (*env_key, "scripts", script)
                commands = value if isinstance(value, list) else [value]
                for index, command in enumerate(commands):
                    source_key = (
                        (*task_key, index) if isinstance(value, list) else task_key
                    )
                    if not self.take(source_key):
                        break
                    if isinstance(command, str):
                        try:
                            tokens = shlex.split(command)
                        except ValueError:
                            tokens = []
                        if tokens and tokens[0] in scripts:
                            self.problem(
                                "Hatch script aliases are not expanded into executable mappings.",
                                source_key,
                            )
                            continue
                    self.add_task(
                        command,
                        source_key,
                        f"tool.hatch.envs.{name}.scripts.{script}",
                        context,
                    )

    def poe(self, config: Any) -> None:
        key = ("tool", "poe")
        if not isinstance(config, dict):
            self.problem("Poe configuration must be a table.", key, error=True)
            return
        tasks = config.get("tasks", {})
        if not isinstance(tasks, dict):
            self.problem("Poe tasks must be a table.", (*key, "tasks"), error=True)
            return
        # These options can change ownership, command arguments, or environments.
        if any(
            field in config
            for field in (
                "include",
                "env",
                "envfile",
                "cwd",
                "executor",
                "default_task_type",
                "default_task_options",
            )
        ):
            self.problem(
                "Poe includes, environment, defaults and executor overrides are not evaluated.",
                key,
            )
            return
        for name, task in tasks.items():
            task_key: SourceKey = (*key, "tasks", name)
            if not self.take(task_key):
                break
            if not name.strip() or len(name) > 128:
                self.problem("Poe task names must be non-empty and bounded.", task_key)
                continue
            if isinstance(task, str):
                command = task
            elif (
                isinstance(task, dict)
                and task.keys() <= {"cmd", "help"}
                and "cmd" in task
            ):
                command = task["cmd"]
                task_key = (*task_key, "cmd")
            else:
                self.problem(
                    "Only literal Poe cmd tasks without execution overrides are supported.",
                    task_key,
                )
                continue
            if isinstance(command, str) and ("\n" in command or "\r" in command):
                self.problem(
                    "Multiline Poe cmd syntax is not interpreted as separate commands.",
                    task_key,
                )
                continue
            self.add_task(command, task_key, f"tool.poe.tasks.{name}")

    def add_task(
        self, value: Any, key: SourceKey, field: str, environment: str | None = None
    ) -> None:
        if not isinstance(value, str) or not value.strip() or len(value) > 16384:
            self.problem(
                "Task command must be a non-empty bounded literal string.", key
            )
            return
        self.tasks.append(
            PythonTask(value, self.positions.value(*key), field, environment)
        )
