from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depcheck.compatibility.checker import CompatibilityChecker, CompatibilityReport
from depcheck.config import DepcheckConfig, load_project_config
from depcheck.model import (
    AnalysisReport,
    Capability,
    CapabilityState,
    PythonRequirement,
    Diagnostic,
    EvidenceBundle,
    Finding,
    ManifestParseResult,
    PackageIdentity,
    ProjectUnit,
    ScanResult,
)
from depcheck.security.osv_client import OSVClient
from depcheck.ecosystems import (
    EcosystemRegistry,
    ProviderContext,
    create_default_registry,
)
from depcheck.ecosystems.analysis import EvidenceAnalyzer


_OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
}


@dataclass(frozen=True, slots=True)
class RepositoryScanOptions:
    security: bool | None = None
    compatibility: bool | None = None
    enabled_ecosystems: tuple[str, ...] | None = None
    project_ids: tuple[str, ...] = field(default_factory=tuple)
    ignored_packages: tuple[str, ...] = field(default_factory=tuple)
    import_mapping: Mapping[str, str] = field(default_factory=dict)
    python_version: str | None = None


class RepositoryScanner:
    def __init__(
        self,
        *,
        registry: EcosystemRegistry | None = None,
        osv_client: Any | None = None,
        compatibility_checker: CompatibilityChecker | None = None,
    ) -> None:
        self.registry = registry
        self.osv_client = osv_client or OSVClient()
        self.compatibility_checker = compatibility_checker or CompatibilityChecker()

    def scan(
        self,
        repository_root: Path,
        options: RepositoryScanOptions | None = None,
    ) -> ScanResult:
        root = Path(repository_root).resolve()
        active = options or RepositoryScanOptions()
        config = load_project_config(root)
        enabled = active.enabled_ecosystems or config.enabled_ecosystems
        registry = self.registry or create_default_registry()
        for ecosystem in enabled:
            try:
                registry.get(ecosystem)
            except KeyError as exc:
                raise ValueError(f"unknown ecosystem: {ecosystem}") from exc
        provider_settings = {
            "excluded_directories": config.excluded_directories,
            "python_version": active.python_version or config.python_version,
        }
        projects = registry.discover(
            root,
            enabled,
            settings=provider_settings,
        )
        if active.project_ids:
            requested = set(active.project_ids)
            available = {project.project_id for project in projects}
            unmatched = sorted(requested - available)
            if unmatched:
                label = "project ID" if len(unmatched) == 1 else "project IDs"
                raise ValueError(f"unknown {label}: {', '.join(unmatched)}")
            projects = tuple(
                project for project in projects if project.project_id in requested
            )

        bundles: list[EvidenceBundle] = []
        reports: list[AnalysisReport] = []
        for project in projects:
            pack = self._pack_for_project(registry, project, config, active)
            bundle = self._collect(root, project, pack, provider_settings)
            bundle = self._without_ignored(bundle, active.ignored_packages)
            report = EvidenceAnalyzer().analyze(bundle)
            bundles.append(bundle)
            reports.append(report)

        security_enabled = (
            config.security if active.security is None else active.security
        )
        vulnerabilities: dict[
            tuple[str, str, str, str],
            list[dict[str, Any]],
        ] = {}
        if security_enabled:
            vulnerabilities, reports = self._security(
                tuple(bundles),
                reports,
            )
        compatibility_metadata: dict[str, Any] = {}
        compatibility_capability: Capability | None = None
        if active.compatibility:
            (
                reports,
                compatibility_metadata,
                compatibility_capability,
            ) = self._compatibility(
                tuple(bundles),
                reports,
                active.python_version or config.python_version,
            )
        findings = tuple(
            sorted(
                (finding for report in reports for finding in report.findings),
                key=lambda item: (
                    item.code,
                    item.package.sort_key,
                    item.message,
                ),
            )
        )
        diagnostics = tuple(
            diagnostic for report in reports for diagnostic in report.diagnostics
        )
        hygiene_errors = [
            item
            for item in diagnostics
            if item.severity == "error"
            and not item.code.startswith(("security.", "osv."))
        ]
        hygiene_complete = not hygiene_errors and all(
            capability.complete
            for bundle in bundles
            for capability in bundle.capabilities
        )
        security_errors = [
            item
            for item in diagnostics
            if item.severity == "error" and item.code.startswith(("security.", "osv."))
        ]
        capabilities: tuple[Capability, ...] = (
            Capability(
                "dependency_hygiene",
                (
                    CapabilityState.COMPLETE
                    if hygiene_complete
                    else CapabilityState.INCOMPLETE
                ),
                None if hygiene_complete else "dependency evidence is incomplete",
            ),
            Capability(
                "security",
                (
                    CapabilityState.COMPLETE
                    if security_enabled and not security_errors
                    else (
                        CapabilityState.INCOMPLETE
                        if security_enabled
                        else CapabilityState.SKIPPED
                    )
                ),
                (
                    None
                    if security_enabled and not security_errors
                    else (
                        "security analysis is incomplete"
                        if security_enabled
                        else "disabled by configuration"
                    )
                ),
            ),
        )
        if compatibility_capability is not None:
            capabilities = (*capabilities, compatibility_capability)
        vulnerability_map: dict[PackageIdentity, tuple[Mapping[str, Any], ...]] = {}
        for key, issues in vulnerabilities.items():
            project_id, ecosystem, package, version = key
            resolved = next(
                (
                    item
                    for bundle in bundles
                    for item in bundle.resolved
                    if item.project_id == project_id
                    and item.package.ecosystem.lower() == ecosystem
                    and item.package.name == package
                    and item.version == version
                ),
                None,
            )
            identity = PackageIdentity(
                project_id,
                resolved.package.ecosystem if resolved else ecosystem,
                package,
                version,
                resolved.instance_id if resolved else None,
                resolved.package.purl if resolved else None,
            )
            vulnerability_map[identity] = tuple(issues)
        return ScanResult(
            root=root,
            capabilities=capabilities,
            findings=findings,
            diagnostics=diagnostics,
            bundles=tuple(bundles),
            vulnerabilities=vulnerability_map,
            metadata={"compatibility": compatibility_metadata},
        )

    def _pack_for_project(
        self,
        registry: EcosystemRegistry,
        project: ProjectUnit,
        config: DepcheckConfig,
        options: RepositoryScanOptions,
    ):
        pack = registry.get(project.ecosystem)
        if project.ecosystem.lower() == "pypi":
            from depcheck.ecosystems.python import create_python_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(
                {key.lower(): value for key, value in options.import_mapping.items()}
            )
            return create_python_pack(mapping)
        if project.ecosystem.lower() == "npm":
            from depcheck.ecosystems.javascript import create_npm_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(
                {key.lower(): value for key, value in options.import_mapping.items()}
            )
            return create_npm_pack(mapping)
        if project.ecosystem.lower() == "go":
            from depcheck.ecosystems.go import create_go_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(options.import_mapping)
            return create_go_pack(mapping)
        if project.ecosystem.lower() == "maven":
            from depcheck.ecosystems.java import create_maven_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(options.import_mapping)
            return create_maven_pack(mapping)
        if project.ecosystem.lower() in {"conan", "vcpkg"}:
            from depcheck.ecosystems.cpp import create_conan_pack, create_vcpkg_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(options.import_mapping)
            factory = (
                create_conan_pack
                if project.ecosystem.lower() == "conan"
                else create_vcpkg_pack
            )
            return factory(mapping)
        return pack

    @staticmethod
    def _without_ignored(
        bundle: EvidenceBundle,
        ignored_packages: tuple[str, ...],
    ) -> EvidenceBundle:
        ignored = {item.lower() for item in ignored_packages}
        if not ignored:
            return bundle
        return EvidenceBundle(
            project=bundle.project,
            declarations=tuple(
                item
                for item in bundle.declarations
                if item.package.name.lower() not in ignored
            ),
            resolved=tuple(
                item
                for item in bundle.resolved
                if item.package.name.lower() not in ignored
            ),
            usages=tuple(
                item
                for item in bundle.usages
                if item.mapped_package is None
                or item.mapped_package.name.lower() not in ignored
            ),
            diagnostics=bundle.diagnostics,
            capabilities=bundle.capabilities,
            source_files=bundle.source_files,
            evidence_files=bundle.evidence_files,
        )

    @staticmethod
    def _collect(
        root: Path,
        project: ProjectUnit,
        pack,
        settings: Mapping[str, Any] | None = None,
    ) -> EvidenceBundle:
        if pack.collector is None:
            raise ValueError(f"no collector registered for {project.ecosystem}")
        return pack.collector.collect(
            ProviderContext(root, settings or {}),
            project,
            pack,
        )

    def _compatibility(
        self,
        bundles: tuple[EvidenceBundle, ...],
        reports: list[AnalysisReport],
        python_version: str | None,
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
            compatibility = self.compatibility_checker.check_detailed(
                manifest,
                python_version=python_version,
            )
            metadata[bundle.project.project_id] = self._compatibility_payload(
                compatibility
            )
            findings = [
                *reports[index].findings,
                *self._compatibility_findings(bundle, compatibility),
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
            complete = (
                complete and not conversion_diagnostics and compatibility.complete
            )

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

    @staticmethod
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
                item.source
                for item in bundle.declarations
                if item.package.name == package
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
                            f"{gap.package} requires {gap.required} "
                            f"for {gap.required_by}."
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

    @staticmethod
    def _compatibility_payload(
        report: CompatibilityReport,
    ) -> dict[str, Any]:
        return {
            "complete": report.complete,
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

    def _security(
        self,
        bundles: tuple[EvidenceBundle, ...],
        reports: list[AnalysisReport],
    ) -> tuple[
        dict[tuple[str, str, str, str], list[dict[str, Any]]],
        list[AnalysisReport],
    ]:
        result: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        for index, bundle in enumerate(bundles):
            osv_ecosystem = _OSV_ECOSYSTEMS.get(bundle.project.ecosystem.lower())
            coordinates = sorted(
                {
                    (item.package.name, item.version)
                    for item in bundle.resolved
                    if item.version
                    and item.project_id == bundle.project.project_id
                    and item.package.ecosystem.lower()
                    == bundle.project.ecosystem.lower()
                }
            )
            resolved_packages = {package for package, _version in coordinates}
            query_batches: list[dict[str, str]] = []
            for package, version in coordinates:
                batch = next(
                    (
                        candidate
                        for candidate in query_batches
                        if package not in candidate
                    ),
                    None,
                )
                if batch is None:
                    batch = {}
                    query_batches.append(batch)
                batch[package] = version
            diagnostics = list(reports[index].diagnostics)
            findings = list(reports[index].findings)
            if osv_ecosystem is None:
                diagnostics.append(
                    Diagnostic(
                        code="security.ecosystem-unsupported",
                        severity="error",
                        message=(
                            "OSV security scanning is not supported for "
                            f"{bundle.project.ecosystem}; no safe result was inferred."
                        ),
                    )
                )
                reports[index] = AnalysisReport(
                    findings=tuple(findings),
                    diagnostics=tuple(diagnostics),
                    import_mapping=reports[index].import_mapping,
                )
                continue
            direct = [
                item
                for item in bundle.declarations
                if item.kind == "direct" and item.scope != "build"
            ]
            unresolved = [
                item for item in direct if item.package.name not in resolved_packages
            ]
            diagnostics.extend(
                Diagnostic(
                    code="security.version-unresolved",
                    severity="error",
                    message=(
                        f"Cannot determine an exact {item.package.name} version; "
                        "the OSV query was skipped."
                    ),
                    source=item.source,
                )
                for item in unresolved
            )
            for exact in query_batches:
                scan = (
                    self.osv_client.scan(exact)
                    if osv_ecosystem == "PyPI"
                    else self.osv_client.scan_ecosystem(exact, osv_ecosystem)
                )
                diagnostics.extend(scan.diagnostics)
                for package, issues in scan.vulnerabilities.items():
                    queried_version = scan.queried.get(package, exact.get(package))
                    if queried_version is None:
                        continue
                    key = (
                        bundle.project.project_id,
                        bundle.project.ecosystem.lower(),
                        package,
                        queried_version,
                    )
                    versioned_issues = [
                        {**dict(issue), "version": queried_version} for issue in issues
                    ]
                    result.setdefault(key, []).extend(versioned_issues)
                    resolved_identity = next(
                        (
                            item.identity
                            for item in bundle.resolved
                            if item.project_id == bundle.project.project_id
                            and item.package.name == package
                            and item.version == queried_version
                        ),
                        PackageIdentity(
                            bundle.project.project_id,
                            bundle.project.ecosystem,
                            package,
                            queried_version,
                        ),
                    )
                    locations = tuple(
                        item.source for item in direct if item.package.name == package
                    )
                    findings.extend(
                        Finding(
                            code="security.vulnerability",
                            package=resolved_identity,
                            severity="error",
                            message=(
                                f"{package}@{queried_version} is affected by "
                                f"{issue.get('id', 'unknown')}: "
                                f"{issue.get('summary', '')}"
                            ),
                            locations=locations,
                            details={
                                **dict(issue),
                                "project_id": bundle.project.project_id,
                                "ecosystem": bundle.project.ecosystem,
                                "version": queried_version,
                            },
                        )
                        for issue in versioned_issues
                    )
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
        return result, reports
