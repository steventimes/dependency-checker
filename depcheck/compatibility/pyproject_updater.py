from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping

import tomlkit
from tomlkit.items import Array, String
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from depcheck.compatibility.safe_updater import (
    RequirementUpdatePlan,
    RequirementsUpdater,
)
from depcheck.model import Diagnostic, SourceLocation
from depcheck.path_policy import require_within_project


@dataclass(frozen=True)
class PyprojectPreview:
    plan: RequirementUpdatePlan | None
    matched: tuple[str, ...]
    groups: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]


class PyprojectUpdater:
    """Preview static PEP 621 dependencies without writing the manifest."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root).resolve()

    def plan(
        self, file_path: Path, updates: dict[str, str], *, group: str | None = None
    ) -> PyprojectPreview:
        path = require_within_project(
            self.project_root, Path(file_path), operation="read pyproject update target"
        )

        def failure(code: str, message: str) -> PyprojectPreview:
            return PyprojectPreview(
                None,
                (),
                (),
                (Diagnostic(code, "error", message, SourceLocation(path)),),
            )

        try:
            original_bytes = path.read_bytes()
            original = original_bytes.decode("utf-8")
            document = tomlkit.parse(original)
            normalized = {
                str(
                    canonicalize_name(name, validate=True)
                ): RequirementsUpdater._normalize_spec(spec)
                for name, spec in updates.items()
            }
            if not normalized:
                return failure("update.invalid-target", "updates must not be empty")
        except (ValueError, UnicodeError, tomlkit.exceptions.TOMLKitError) as exc:
            return failure(
                "update.invalid-target", f"Invalid pyproject update target: {exc}"
            )
        project = document.get("project", {})
        if not isinstance(project, Mapping):
            return failure("update.unsupported-target", "project must be a table")
        dynamic = project.get("dynamic", [])
        if isinstance(dynamic, list) and (
            ("dependencies" in dynamic and (group is None or group == "project"))
            or (
                "optional-dependencies" in dynamic
                and (group is None or group.startswith("optional:"))
            )
        ):
            return failure(
                "update.unsupported-target", "Dynamic dependencies cannot be previewed"
            )
        groups: dict[str, object] = {}
        if "dependencies" in project:
            groups["project"] = project["dependencies"]
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, Mapping):
            groups.update(
                {f"optional:{name}": value for name, value in optional.items()}
            )
        elif group is None or group.startswith("optional:"):
            return failure(
                "update.unsupported-target", "optional-dependencies must be a table"
            )
        if group is not None:
            if group not in groups:
                return failure(
                    "update.unsupported-target",
                    f"Unsupported or absent group {group!r}",
                )
            groups = {group: groups[group]}
        entries: dict[str, list[tuple[str, Array, int, String, Requirement]]] = {}
        group_errors: dict[str, list[Diagnostic]] = {}
        for name, values in groups.items():
            if not isinstance(values, Array):
                group_errors[name] = [
                    Diagnostic(
                        "update.unsupported-target",
                        "error",
                        f"{name} must be a static string array",
                        SourceLocation(path),
                    )
                ]
                continue
            for index, item in enumerate(values):
                if not isinstance(item, String):
                    group_errors.setdefault(name, []).append(
                        Diagnostic(
                            "update.unsupported-target",
                            "error",
                            f"{name} contains a non-string dependency",
                            SourceLocation(path),
                        )
                    )
                    continue
                try:
                    requirement = Requirement(str(item))
                except InvalidRequirement as exc:
                    group_errors.setdefault(name, []).append(
                        Diagnostic(
                            "update.invalid-target",
                            "error",
                            f"Invalid requirement in {name}: {exc}",
                            SourceLocation(path),
                        )
                    )
                    continue
                package = str(canonicalize_name(requirement.name))
                if package in normalized:
                    entries.setdefault(package, []).append(
                        (name, values, index, item, requirement)
                    )
        errors: list[Diagnostic] = []
        selected_groups: set[str] = set()
        changed: dict[str, str] = {}
        for package, spec in normalized.items():
            matches = entries.get(package, [])
            candidates = sorted({entry[0] for entry in matches})
            if not matches:
                invalid_groups = [group] if group is not None else list(groups)
                invalid_entries = [
                    item
                    for name in invalid_groups
                    for item in group_errors.get(name, ())
                ]
                if invalid_entries:
                    errors.extend(invalid_entries)
                    continue
                errors.append(
                    Diagnostic(
                        "update.unsupported-target",
                        "error",
                        f"No supported dependency entry for {package!r}",
                        SourceLocation(path),
                    )
                )
                continue
            if len(candidates) > 1:
                errors.append(
                    Diagnostic(
                        "update.ambiguous-target",
                        "error",
                        f"{package!r} occurs in groups: {', '.join(candidates)}",
                        SourceLocation(path),
                    )
                )
                continue
            participating_errors = [
                item for name in candidates for item in group_errors.get(name, ())
            ]
            if participating_errors:
                errors.extend(participating_errors)
                continue
            selected_groups.update(candidates)
            for name, values, index, item, requirement in matches:
                if requirement.url is not None or item.type.is_multiline():
                    errors.append(
                        Diagnostic(
                            "update.unsupported-target",
                            "error",
                            f"{package!r} in {name} uses a URL or multiline string",
                            SourceLocation(path),
                        )
                    )
                    continue
                if requirement.specifier == SpecifierSet(spec):
                    continue
                try:
                    replacement_item = _replace_specifier(item, requirement, spec)
                except ValueError as exc:
                    errors.append(
                        Diagnostic(
                            "update.unsupported-target",
                            "error",
                            str(exc),
                            SourceLocation(path),
                        )
                    )
                    continue
                values[index] = replacement_item
                changed[package] = spec
        if errors:
            return PyprojectPreview(None, (), (), tuple(errors))
        updated = tomlkit.dumps(document)
        plan = None
        if updated != original:
            plan = RequirementUpdatePlan(
                path,
                hashlib.sha256(original_bytes).hexdigest(),
                original,
                updated,
                changed,
                {},
                self.project_root,
            )
        return PyprojectPreview(
            plan, tuple(sorted(entries)), tuple(sorted(selected_groups)), ()
        )


def _replace_specifier(item: String, requirement: Requirement, spec: str) -> String:
    """Keep TOML quoting and verify that only the requirement version changes."""
    package = str(canonicalize_name(requirement.name))
    raw = item.as_string()
    parts = re.fullmatch(
        r"([A-Za-z0-9_.-]+\s*(?:\[[^\]]*\]\s*)?)([^;]*?)(\s*;.*)?",
        raw[1:-1],
    )
    if parts is None:
        raise ValueError(f"{package!r} uses an unsupported escaped dependency name")
    replacement = raw[0] + parts[1] + spec + (parts[3] or "") + raw[-1]
    try:
        replacement_item = tomlkit.parse("value=" + replacement)["value"]
        if not isinstance(replacement_item, String):
            raise ValueError("replacement must remain a TOML string")
        replacement_requirement = Requirement(str(replacement_item))
        if (
            replacement_requirement.name != requirement.name
            or replacement_requirement.extras != requirement.extras
            or replacement_requirement.marker != requirement.marker
            or replacement_requirement.url != requirement.url
            or replacement_requirement.specifier != SpecifierSet(spec)
        ):
            raise ValueError(
                "replacement would alter dependency identity, extras or marker"
            )
    except (tomlkit.exceptions.TOMLKitError, ValueError) as exc:
        raise ValueError(f"Cannot preserve string syntax for {package!r}") from exc
    return replacement_item
