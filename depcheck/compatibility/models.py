"""Compatibility results and shared diagnostic accumulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from packaging.specifiers import SpecifierSet

from depcheck.model import Diagnostic


@dataclass(frozen=True)
class CompatibilityConflict:
    package: str
    declared: str | None
    required: str
    required_by: str


@dataclass(frozen=True)
class CompatibilityGap:
    package: str
    required: str
    required_by: str


@dataclass(frozen=True)
class PythonCompatibilityConflict:
    package: str
    version: str
    requires_python: str
    current_python: str


@dataclass(frozen=True)
class CompatibilityReport:
    conflicts: list[CompatibilityConflict]
    missing: list[CompatibilityGap]
    unconstrained: list[CompatibilityGap]
    suggestions: dict[str, str]
    python_conflicts: list[PythonCompatibilityConflict] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    selected_versions: dict[str, str] = field(default_factory=dict)
    resolution_status: str = "not-evaluated"
    resolution: dict[str, Any] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


@dataclass(frozen=True)
class RequirementConstraint:
    source: str
    specifier: SpecifierSet


def append_diagnostic(
    diagnostics: list[Diagnostic],
    diagnostic: Diagnostic,
) -> None:
    key = (diagnostic.code, diagnostic.severity, diagnostic.message)
    if not any((item.code, item.severity, item.message) == key for item in diagnostics):
        diagnostics.append(diagnostic)
