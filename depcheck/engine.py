from __future__ import annotations

from depcheck.profiling import measured

from depcheck.bounded_io import repository_operation

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

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
    ANALYSIS_REVISION,
)
from depcheck.security.osv_client import OSVClient
from depcheck.ecosystems import (
    EcosystemRegistry,
    ProviderContext,
    create_default_registry,
)
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.tool_usage import apply_tool_usage
from depcheck.ecosystems.coverage import repository_coverage
from depcheck.ecosystems.commands import apply_command_usage
from depcheck.ecosystems.tool_configs import apply_tool_config_usage


_OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
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
    dependency_groups: tuple[str, ...] = field(default_factory=tuple)


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

    @repository_operation("repository_root")
    def scan(
        self,
        repository_root: Path,
        options: RepositoryScanOptions | None = None,
    ) -> ScanResult:
        root = Path(repository_root).resolve()
        if not root.is_dir():
            raise ValueError(f"repository root is not a directory: {root}")
        active = options or RepositoryScanOptions()
        config = load_project_config(root)
        enabled = (
            config.enabled_ecosystems
            if active.enabled_ecosystems is None
            else active.enabled_ecosystems
        )
        registry = self.registry or create_default_registry()
        for ecosystem in enabled:
            try:
                registry.get(ecosystem)
            except KeyError as exc:
                raise ValueError(f"unknown ecosystem: {ecosystem}") from exc
        provider_settings = {
            "excluded_directories": config.excluded_directories,
            "python_version": active.python_version or config.python_version,
            "python_roots": config.python_roots,
        }
        projects = registry.discover(
            root,
            enabled,
            settings=provider_settings,
        )
        config.validate_legacy_python_scope(projects)
        usage_projects = tuple(p for p in projects if p.manager != "yarn-lock")
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
            bundle = self._without_ignored(
                bundle, (*config.ignored_packages, *active.ignored_packages)
            )
            if project.manager != "yarn-lock":
                bundle = apply_tool_usage(bundle, config.tool_usage, root)
                bundle = apply_command_usage(
                    bundle, root, usage_projects, provider_settings
                )
                bundle = apply_tool_config_usage(
                    bundle, root, usage_projects, provider_settings
                )
            report = EvidenceAnalyzer().analyze(bundle)
            bundle = replace(bundle, diagnostics=report.diagnostics)
            bundles.append(bundle)
            reports.append(report)

        coverage, coverage_diagnostics = repository_coverage(
            root,
            tuple(bundles),
            selected=bool(active.project_ids or active.enabled_ecosystems),
            excluded_directories=config.excluded_directories,
        )

        security_enabled = (
            config.security if active.security is None else active.security
        )
        vulnerabilities: dict[PackageIdentity, list[dict[str, Any]]] = {}
        if security_enabled:
            vulnerabilities, reports = self._security(
                tuple(bundles),
                reports,
            )
        compatibility_metadata: dict[str, Any] = {}
        compatibility_capability: Capability | None = None
        compatibility_enabled = (
            config.compatibility
            if active.compatibility is None
            else active.compatibility
        )
        if compatibility_enabled:
            (
                reports,
                compatibility_metadata,
                compatibility_capability,
            ) = self._compatibility(
                tuple(bundles),
                reports,
                active.python_version or config.python_version,
                active.dependency_groups,
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
        diagnostics = (
            tuple(diagnostic for report in reports for diagnostic in report.diagnostics)
            + coverage_diagnostics
        )
        if coverage_diagnostics and security_enabled:
            diagnostics += (
                Diagnostic(
                    code="security.collection-incomplete",
                    severity="error",
                    message="Uncovered manifests prevent a complete repository security conclusion.",
                ),
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
        return ScanResult(
            root=root,
            capabilities=capabilities,
            findings=findings,
            diagnostics=diagnostics,
            bundles=tuple(bundles),
            vulnerabilities={
                identity: tuple(issues) for identity, issues in vulnerabilities.items()
            },
            metadata={
                "compatibility": compatibility_metadata,
                "coverage": coverage,
                "snapshot": {
                    "analysis_revision": ANALYSIS_REVISION,
                    "identity_source": "configured"
                    if config.repository_id
                    else "local-path",
                    "repository_key": hashlib.sha256(
                        (
                            "configured:" + config.repository_id
                            if config.repository_id
                            else "local-path:" + str(root)
                        ).encode()
                    ).hexdigest(),
                    "selection_key": hashlib.sha256(
                        json.dumps(
                            {
                                "config": asdict(config),
                                "ecosystems": sorted(e.lower() for e in enabled),
                                "projects": sorted(active.project_ids),
                                "ignored": sorted(active.ignored_packages),
                                "mappings": dict(active.import_mapping),
                                "python_version": active.python_version,
                            },
                            sort_keys=True,
                        ).encode()
                    ).hexdigest(),
                },
            },
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
        normalize = (
            canonicalize_name
            if bundle.project.ecosystem.lower() == "pypi"
            else str.lower
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

    @staticmethod
    @measured("collection.ecosystems")
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
            compatibility = self.compatibility_checker.check_detailed(
                manifest,
                python_version=python_version,
                **(
                    {"dependency_groups": dependency_groups}
                    if dependency_groups
                    else {}
                ),
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

    def _security(
        self,
        bundles: tuple[EvidenceBundle, ...],
        reports: list[AnalysisReport],
    ) -> tuple[
        dict[PackageIdentity, list[dict[str, Any]]],
        list[AnalysisReport],
    ]:
        result: dict[PackageIdentity, list[dict[str, Any]]] = {}
        for index, bundle in enumerate(bundles):
            osv_ecosystem = _OSV_ECOSYSTEMS.get(bundle.project.ecosystem.lower())
            eligible = [
                item
                for item in bundle.resolved
                if item.version
                and item.project_id == bundle.project.project_id
                and item.package.ecosystem.lower() == bundle.project.ecosystem.lower()
                and (
                    bundle.project.ecosystem.lower() != "pypi"
                    or (item.package.purl or "").startswith("pkg:pypi/")
                )
                and (
                    bundle.project.ecosystem.lower() != "cargo"
                    or (item.package.purl or "").startswith("pkg:cargo/")
                )
                and (
                    bundle.project.ecosystem.lower() != "npm"
                    or (
                        (item.package.purl or "").startswith("pkg:npm/")
                        and item.origin.get("public") is not False
                    )
                )
            ]
            coordinates = sorted(
                {(item.package.name, item.version) for item in eligible if item.version}
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
            blocked_npm_names = set()
            if bundle.project.ecosystem.lower() == "npm":
                for item in bundle.resolved:
                    if (
                        item.project_id != bundle.project.project_id
                        or item.package.ecosystem.lower() != "npm"
                    ):
                        continue
                    if (
                        not item.version
                        or not (item.package.purl or "").startswith("pkg:npm/")
                        or item.origin.get("public") is False
                    ):
                        blocked_npm_names.add(item.package.name)
                        diagnostics.append(
                            Diagnostic(
                                code="security.identity-unverified"
                                if item.version
                                else "security.version-unresolved",
                                severity="error",
                                message=f"No public OSV coordinates were established for npm instance {item.package.name} ({item.instance_id or 'unspecified'}); the query was skipped.",
                                source=item.source,
                            )
                        )
            findings = list(reports[index].findings)
            incomplete_collection = [
                item.name
                for item in bundle.capabilities
                if item.name in {"manifest", "resolution"} and not item.complete
            ]
            if incomplete_collection:
                diagnostics.append(
                    Diagnostic(
                        code="security.collection-incomplete",
                        severity="error",
                        message=(
                            f"Cannot establish complete security coverage for {bundle.project.project_id}: "
                            f"{', '.join(incomplete_collection)} evidence is incomplete. "
                            "Any known resolved versions are still checked."
                        ),
                    )
                )
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
                item
                for item in direct
                if (
                    item.package.name not in resolved_packages
                    or (
                        bundle.project.ecosystem.lower() == "npm"
                        and not item.package.purl
                    )
                )
                and item.package.name not in blocked_npm_names
            ]
            known_versions = {item.package.name for item in bundle.resolved}
            diagnostics.extend(
                Diagnostic(
                    code="security.identity-unverified"
                    if item.package.name in known_versions
                    else "security.version-unresolved",
                    severity="error",
                    message=(
                        f"Cannot establish a public registry identity for {item.package.name}; the OSV query was skipped."
                        if item.package.name in known_versions
                        else (
                            f"Cannot determine an exact {item.package.name} version; "
                            "the OSV query was skipped."
                        )
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
                    versioned_issues = [
                        {**dict(issue), "version": queried_version} for issue in issues
                    ]
                    identities = {
                        item.identity
                        for item in eligible
                        if item.project_id == bundle.project.project_id
                        and item.package.name == package
                        and item.version == queried_version
                    } or {
                        PackageIdentity(
                            bundle.project.project_id,
                            bundle.project.ecosystem,
                            package,
                            queried_version,
                        )
                    }
                    locations = tuple(
                        item.source for item in direct if item.package.name == package
                    )
                    for identity in sorted(identities, key=lambda item: item.sort_key):
                        lock_context = next(
                            (
                                item.origin["lock"]
                                for item in bundle.resolved
                                if item.identity == identity
                                and item.origin.get("lock", {}).get("conditional")
                            ),
                            None,
                        )
                        result.setdefault(identity, []).extend(versioned_issues)
                        findings.extend(
                            Finding(
                                code="security.vulnerability",
                                package=identity,
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
                                    **(
                                        {
                                            "lock_context": lock_context,
                                            "activation": "unknown",
                                        }
                                        if lock_context
                                        else {}
                                    ),
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
