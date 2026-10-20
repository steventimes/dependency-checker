"""Project supported resolved identities through OSV without losing source context."""

from __future__ import annotations

from typing import Any

from depcheck.model import (
    AnalysisReport,
    Diagnostic,
    EvidenceBundle,
    Finding,
    PackageIdentity,
)

_OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
}


def scan_security(
    client: Any,
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
                (candidate for candidate in query_batches if package not in candidate),
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
                or (bundle.project.ecosystem.lower() == "npm" and not item.package.purl)
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
                client.scan(exact)
                if osv_ecosystem == "PyPI"
                else client.scan_ecosystem(exact, osv_ecosystem)
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
