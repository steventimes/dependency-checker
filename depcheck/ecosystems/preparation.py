"""Shared static evidence preparation and analysis for scans and indexes."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.config import ToolUsageDefinition
from depcheck.model import AnalysisReport, EvidenceBundle, ProjectUnit

from .analysis import EvidenceAnalyzer
from .commands import apply_command_usage
from .tool_configs import apply_tool_config_usage
from .tool_usage import apply_tool_usage


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
