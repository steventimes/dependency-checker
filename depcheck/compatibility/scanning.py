"""Convert Python evidence to compatibility requests and qualified findings."""

from __future__ import annotations

from typing import Any

from depcheck.compatibility.checker import CompatibilityChecker, CompatibilityReport
from depcheck.model import (
    AnalysisReport,
    Capability,
    CapabilityState,
    Diagnostic,
    EvidenceBundle,
    Finding,
    ManifestParseResult,
    PackageIdentity,
    PythonRequirement,
)


def analyze_compatibility(
    checker: CompatibilityChecker,
    bundles: tuple[EvidenceBundle, ...],
    reports: list[AnalysisReport],
    python_version: str | None,
    dependency_groups: tuple[str, ...] = (),
) -> tuple[list[AnalysisReport], dict[str, Any], Capability]:
    metadata: dict[str, Any] = {}
    matched = False
    complete = True
    for index, bundle in enumerate(bundles):
        if bundle.project.ecosystem.lower() != "pypi":
            continue
        matched = True
        declarations: list[PythonRequirement] = []
        conversion_diagnostics: list[Diagnostic] = []
        for item in bundle.declarations:
            if item.metadata.get("origin", {}).get("public") is not True:
                conversion_diagnostics.append(
                    Diagnostic(
                        code="compatibility.source-unverified",
                        severity="error",
                        message=f"{item.package.name}: public PyPI compatibility cannot be inferred for this source.",
                        source=item.source,
                    )
                )
            raw = str(
                item.metadata.get("raw_requirement")
                or f"{item.package.display_name}{item.constraint.raw}"
            )
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        raw,
                        source=item.source,
                        group=str(item.metadata.get("group") or item.scope),
                        kind=item.kind,
                        origin=item.metadata.get("origin"),
                    )
                )
            except ValueError as exc:
                conversion_diagnostics.append(
                    Diagnostic(
                        code="compatibility.invalid-evidence",
                        severity="error",
                        message=(
                            f"Cannot reconstruct {item.package.name} "
                            f"for compatibility analysis: {exc}"
                        ),
                        source=item.source,
                    )
                )
        manifest = ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(conversion_diagnostics),
            files=bundle.evidence_files,
        )
        compatibility = checker.check_detailed(
            manifest,
            python_version=python_version,
            **({"dependency_groups": dependency_groups} if dependency_groups else {}),
        )
        metadata[bundle.project.project_id] = _compatibility_payload(compatibility)
        findings = [
            *reports[index].findings,
            *_compatibility_findings(bundle, compatibility),
        ]
        diagnostics = [
            *reports[index].diagnostics,
            *conversion_diagnostics,
            *compatibility.diagnostics,
        ]
        reports[index] = AnalysisReport(
            findings=tuple(
                sorted(
                    findings,
                    key=lambda item: (
                        item.code,
                        item.package.sort_key,
                        item.message,
                    ),
                )
            ),
            diagnostics=tuple(diagnostics),
            import_mapping=reports[index].import_mapping,
        )
        complete = complete and not conversion_diagnostics and compatibility.complete

    if not matched:
        return (
            reports,
            metadata,
            Capability(
                "compatibility",
                CapabilityState.UNSUPPORTED,
                "compatibility analysis requires a PyPI project",
            ),
        )
    return (
        reports,
        metadata,
        Capability(
            "compatibility",
            (CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE),
            None if complete else "compatibility analysis is incomplete",
        ),
    )


def _compatibility_findings(
    bundle: EvidenceBundle,
    compatibility: CompatibilityReport,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []

    def identity(package: str) -> PackageIdentity:
        declaration = next(
            (item for item in bundle.declarations if item.package.name == package),
            None,
        )
        return PackageIdentity(
            bundle.project.project_id,
            bundle.project.ecosystem,
            package,
            purl=declaration.package.purl if declaration else None,
        )

    def locations(package: str) -> tuple:
        return tuple(
            item.source for item in bundle.declarations if item.package.name == package
        )

    for item in compatibility.conflicts:
        findings.append(
            Finding(
                code="compatibility.conflict",
                package=identity(item.package),
                severity="error",
                message=(
                    f"{item.package} {item.declared or '(unresolved)'} "
                    f"does not satisfy {item.required} required by "
                    f"{item.required_by}."
                ),
                locations=locations(item.package),
                details={
                    "declared": item.declared,
                    "required": item.required,
                    "required_by": item.required_by,
                },
            )
        )
    for code, gaps in (
        ("compatibility.missing", compatibility.missing),
        ("compatibility.unconstrained", compatibility.unconstrained),
    ):
        for gap in gaps:
            findings.append(
                Finding(
                    code=code,
                    package=identity(gap.package),
                    severity="error",
                    message=(
                        f"{gap.package} requires {gap.required} for {gap.required_by}."
                    ),
                    locations=locations(gap.package),
                    details={
                        "required": gap.required,
                        "required_by": gap.required_by,
                    },
                )
            )
    for python_conflict in compatibility.python_conflicts:
        findings.append(
            Finding(
                code="compatibility.python",
                package=identity(python_conflict.package),
                severity="error",
                message=(
                    f"{python_conflict.package}=={python_conflict.version} requires Python "
                    f"{python_conflict.requires_python}; target is "
                    f"{python_conflict.current_python}."
                ),
                locations=locations(python_conflict.package),
                details={
                    "version": python_conflict.version,
                    "requires_python": python_conflict.requires_python,
                    "current_python": python_conflict.current_python,
                },
            )
        )
    return tuple(findings)


def _compatibility_payload(
    report: CompatibilityReport,
) -> dict[str, Any]:
    return {
        "complete": report.complete,
        "resolution_status": report.resolution_status,
        "resolution": report.resolution,
        "conflicts": [
            {
                "package": item.package,
                "declared": item.declared,
                "required": item.required,
                "required_by": item.required_by,
            }
            for item in report.conflicts
        ],
        "missing": [
            {
                "package": item.package,
                "required": item.required,
                "required_by": item.required_by,
            }
            for item in report.missing
        ],
        "unconstrained": [
            {
                "package": item.package,
                "required": item.required,
                "required_by": item.required_by,
            }
            for item in report.unconstrained
        ],
        "python_conflicts": [
            {
                "package": item.package,
                "version": item.version,
                "requires_python": item.requires_python,
                "current_python": item.current_python,
            }
            for item in report.python_conflicts
        ],
        "suggestions": dict(sorted(report.suggestions.items())),
        "selected_versions": dict(sorted(report.selected_versions.items())),
    }
