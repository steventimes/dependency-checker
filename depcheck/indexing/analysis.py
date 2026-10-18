"""Analyze cached Python evidence alongside selected non-Python projects."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from depcheck.config import DepcheckConfig
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.coverage import repository_coverage
from depcheck.ecosystems.preparation import prepare_bundle
from depcheck.ecosystems.python import (
    adapt_python_bundle,
    create_python_pack,
    filter_python_manifest,
)
from depcheck.ecosystems.python_manifest import is_requirements_file
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import AnalysisReport, EvidenceBundle, ProjectUnit, ScanResult

from .store import IndexStore


@dataclass(frozen=True, slots=True)
class IndexAnalysis:
    bundles: list[EvidenceBundle]
    report: AnalysisReport
    coverage: dict[str, Any]
    complete: bool


def analyze_cached_evidence(
    root: Path,
    config: DepcheckConfig,
    store: IndexStore,
    manifest_digests: dict[str, str],
) -> IndexAnalysis:
    cached_imports = store.load_imports()
    manifests = store.load_manifests()
    project_id = ProjectUnit.stable_id(Path("."), "PyPI", "python")
    relative_manifests = tuple(Path(path) for path in sorted(manifest_digests))
    project = ProjectUnit(
        project_id=project_id,
        root=Path("."),
        language="python",
        ecosystem="PyPI",
        manager="python",
        manifests=relative_manifests,
        locks=tuple(
            path
            for path in relative_manifests
            if path.name in {"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"}
            or (path.suffix.lower() == ".lock" and is_requirements_file(path))
        ),
    )
    pack = create_python_pack(config.mapping_for("PyPI", project.project_id))
    bundle = adapt_python_bundle(
        root,
        project,
        pack,
        filter_python_manifest(manifests, config.python_version),
        cached_imports,
    )
    bundle = prepare_bundle(
        bundle,
        root,
        (project,),
        {"excluded_directories": config.excluded_directories},
        ignored_packages=config.ignored_packages,
        tool_usage=config.tool_usage,
    )
    python_enabled = any(item.lower() == "pypi" for item in config.enabled_ecosystems)
    has_python_evidence = bool(cached_imports.files) or any(
        path.name
        not in {
            "Dockerfile",
            "dockerfile",
            "Makefile",
            "makefile",
            "CMakeLists.txt",
        }
        for path in manifests.files
    )
    repository_reports = []
    if python_enabled and has_python_evidence:
        python_report = EvidenceAnalyzer().analyze(bundle)
        bundle = replace(bundle, diagnostics=python_report.diagnostics)
        repository_reports.append(python_report)
    repository_bundles = [bundle] if python_enabled and has_python_evidence else []
    non_python_ecosystems = tuple(
        item for item in config.enabled_ecosystems if item.lower() != "pypi"
    )
    if non_python_ecosystems:
        non_python = RepositoryScanner().scan(
            root,
            RepositoryScanOptions(
                security=False,
                compatibility=False,
                enabled_ecosystems=non_python_ecosystems,
                ignored_packages=config.ignored_packages,
            ),
        )
        repository_reports.append(_report_from_scan(non_python))
        repository_bundles.extend(non_python.bundles)
    coverage, coverage_diagnostics = repository_coverage(
        root,
        tuple(repository_bundles),
        excluded_directories=config.excluded_directories,
    )
    if coverage_diagnostics:
        repository_reports.append(AnalysisReport(diagnostics=coverage_diagnostics))
    repository_report = _combine_reports(repository_reports)
    evidence_complete = all(item.complete for item in repository_reports) and all(
        status.complete for item in repository_bundles for status in item.capabilities
    )
    return IndexAnalysis(
        repository_bundles, repository_report, coverage, evidence_complete
    )


def _report_from_scan(result: ScanResult) -> AnalysisReport:
    return AnalysisReport(
        findings=result.findings,
        diagnostics=result.diagnostics,
        import_mapping={
            usage.reference: usage.mapped_package.name
            for bundle in result.bundles
            for usage in bundle.usages
            if usage.mapped_package is not None
        },
    )


def _combine_reports(reports: list[AnalysisReport]) -> AnalysisReport:
    return AnalysisReport(
        findings=tuple(
            sorted(
                (finding for report in reports for finding in report.findings),
                key=lambda item: (item.code, item.package.sort_key, item.message),
            )
        ),
        diagnostics=tuple(
            diagnostic for report in reports for diagnostic in report.diagnostics
        ),
        import_mapping={
            reference: package
            for report in reports
            for reference, package in report.import_mapping.items()
        },
    )
