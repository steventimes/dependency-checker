"""Shared static evidence preparation and analysis for scans and indexes."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.config import ToolUsageDefinition
from depcheck.ecosystems.configuration.commands import apply_command_usage
from depcheck.ecosystems.configuration.tools import apply_tool_config_usage
from depcheck.model import (
    AnalysisReport,
    Diagnostic,
    EvidenceBundle,
    MappingConfidence,
    ProjectUnit,
    SourceLocation,
    UsageEvidence,
)

from .analysis import EvidenceAnalyzer


def analyze_bundle(
    bundle: EvidenceBundle,
    root: Path,
    projects: tuple[ProjectUnit, ...],
    settings: dict[str, Any],
    *,
    ignored_packages: tuple[str, ...],
    tool_usage: tuple[ToolUsageDefinition, ...],
) -> tuple[EvidenceBundle, AnalysisReport]:
    """Keep configured uses distinct from source evidence, in a fixed order."""
    bundle = prepare_bundle(
        bundle,
        root,
        projects,
        settings,
        ignored_packages=ignored_packages,
        tool_usage=tool_usage,
    )
    report = EvidenceAnalyzer().analyze(bundle)
    return replace(bundle, diagnostics=report.diagnostics), report


def without_ignored(
    bundle: EvidenceBundle,
    ignored_packages: tuple[str, ...],
) -> EvidenceBundle:
    normalize = (
        canonicalize_name if bundle.project.ecosystem.lower() == "pypi" else str.lower
    )
    ignored = {normalize(item) for item in ignored_packages}
    if not ignored:
        return bundle
    return replace(
        bundle,
        declarations=tuple(
            item
            for item in bundle.declarations
            if normalize(item.package.name) not in ignored
        ),
        resolved=tuple(
            item
            for item in bundle.resolved
            if normalize(item.package.name) not in ignored
        ),
        usages=tuple(
            item
            for item in bundle.usages
            if item.mapped_package is None
            or normalize(item.mapped_package.name) not in ignored
        ),
    )


def prepare_bundle(
    bundle: EvidenceBundle,
    root: Path,
    projects: tuple[ProjectUnit, ...],
    settings: dict[str, Any],
    *,
    ignored_packages: tuple[str, ...],
    tool_usage: tuple[ToolUsageDefinition, ...],
) -> EvidenceBundle:
    bundle = without_ignored(bundle, ignored_packages)
    if bundle.project.manager != "yarn-lock":
        bundle = apply_tool_usage(bundle, tool_usage, root)
        bundle = apply_command_usage(bundle, root, projects, settings)
        bundle = apply_tool_config_usage(bundle, root, projects, settings)
    return bundle


def apply_tool_usage(
    bundle: EvidenceBundle,
    definitions: tuple[ToolUsageDefinition, ...],
    repository_root: Path,
) -> EvidenceBundle:
    usages = list(bundle.usages)
    diagnostics = list(bundle.diagnostics)
    source = SourceLocation(repository_root / ".depcheck.toml")
    for definition in definitions:
        if (
            definition.project_id != bundle.project.project_id
            or definition.ecosystem.lower() != bundle.project.ecosystem.lower()
        ):
            continue
        declared = [
            item
            for item in bundle.declarations
            if item.kind == "direct" and item.package.name == definition.package
        ]
        if not declared:
            diagnostic = Diagnostic(
                code="config.tool-usage-unmatched",
                severity="warning",
                message=(
                    f"Configured tool '{definition.package}' has no direct declaration "
                    f"in {definition.project_id}."
                ),
                source=source,
            )
            if diagnostic not in diagnostics:
                diagnostics.append(diagnostic)
            continue
        non_build = [item for item in declared if item.scope != "build"]
        if not non_build:
            continue
        usage = UsageEvidence(
            project_id=bundle.project.project_id,
            language=bundle.project.language,
            reference=definition.package,
            source=source,
            scope=definition.scope,
            kind="tool",
            mapped_package=non_build[0].package,
            mapping_confidence=MappingConfidence.CONFIGURED,
            mapping_reason=definition.reason,
        )
        if usage not in usages:
            usages.append(usage)
    return replace(bundle, usages=tuple(usages), diagnostics=tuple(diagnostics))
