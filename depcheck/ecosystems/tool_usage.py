from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from depcheck.config import ToolUsageDefinition
from depcheck.model import (
    Diagnostic,
    EvidenceBundle,
    MappingConfidence,
    SourceLocation,
    UsageEvidence,
)


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
