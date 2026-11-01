from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from depcheck.compatibility.checker import CompatibilityChecker
from depcheck.compatibility.scanning import analyze_compatibility
from depcheck.config import DepcheckConfig, load_project_config
from depcheck.ecosystems import (
    EcosystemRegistry,
    ProviderContext,
    create_default_registry,
)
from depcheck.ecosystems.coverage import repository_coverage
from depcheck.ecosystems.preparation import analyze_bundle, without_ignored
from depcheck.filesystem import repository_operation
from depcheck.filesystem.positions import toml_position_scope
from depcheck.model import (
    ANALYSIS_REVISION,
    AnalysisReport,
    Capability,
    CapabilityState,
    Diagnostic,
    EvidenceBundle,
    PackageIdentity,
    ProjectUnit,
    ScanResult,
)
from depcheck.profiling import measured
from depcheck.security.osv_client import OSVClient
from depcheck.security.scanning import scan_security


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
    public_maven_packages: tuple[str, ...] = field(default_factory=tuple)


class RepositoryScanner:
    _without_ignored = staticmethod(without_ignored)

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
    @toml_position_scope()
    def scan(
        self,
        repository_root: Path,
        options: RepositoryScanOptions | None = None,
    ) -> ScanResult:
        root = Path(repository_root).resolve()
        if not root.is_dir():
            raise ValueError(f"repository root is not a directory: {root}")
        active = options or RepositoryScanOptions()
        from depcheck.ecosystems.java.coordinates import package_ref as maven_package

        public_maven = {
            name: maven_package(name, public=True)
            for name in active.public_maven_packages
        }
        if any(package.purl is None for package in public_maven.values()):
            raise ValueError(
                "public Maven assertions require exact group:artifact coordinates"
            )
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
            bundle, report = analyze_bundle(
                bundle,
                root,
                usage_projects,
                provider_settings,
                ignored_packages=(*config.ignored_packages, *active.ignored_packages),
                tool_usage=config.tool_usage,
            )
            bundles.append(bundle)
            reports.append(report)

        if public_maven:
            bundles = [
                replace(
                    bundle,
                    resolved=tuple(
                        replace(
                            item,
                            package=public_maven[item.package.name],
                            origin={
                                **item.origin,
                                "public": True,
                                "public_assertion": "caller-supplied-coordinate",
                            },
                        )
                        if item.package.ecosystem.lower() == "maven"
                        and item.package.name in public_maven
                        else item
                        for item in bundle.resolved
                    ),
                )
                for bundle in bundles
            ]

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
            vulnerabilities, reports = scan_security(
                self.osv_client,
                tuple(bundles),
                reports,
            )
        from depcheck.contracts import backend_info

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
            ) = analyze_compatibility(
                self.compatibility_checker,
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
                "backend": backend_info(),
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
                                "dependency_groups": sorted(active.dependency_groups),
                                "public_maven_packages": sorted(
                                    active.public_maven_packages
                                ),
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
            from depcheck.ecosystems.python.collector import create_python_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(
                {key.lower(): value for key, value in options.import_mapping.items()}
            )
            return create_python_pack(mapping)
        if project.ecosystem.lower() == "npm":
            from depcheck.ecosystems.javascript.collector import create_npm_pack

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
            from depcheck.ecosystems.java.collector import create_maven_pack

            mapping = config.mapping_for(project.ecosystem, project.project_id)
            mapping.update(options.import_mapping)
            return create_maven_pack(mapping)
        if project.ecosystem.lower() in {"conan", "vcpkg"}:
            from depcheck.ecosystems.cpp.collector import (
                create_conan_pack,
                create_vcpkg_pack,
            )

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
