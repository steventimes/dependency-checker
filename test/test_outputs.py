import pytest
from datetime import date
from dataclasses import replace
from pathlib import Path

from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    Finding,
    PackageIdentity,
    PackageRef,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    ScanResult,
    SourceLocation,
    VersionConstraint,
)
from depcheck.output import (
    build_cyclonedx,
    build_sarif,
    evaluate_policy,
    render_json,
    render_text,
)


def sample_result() -> ScanResult:
    project = ProjectUnit(
        "npm:npm:.",
        Path("."),
        "javascript",
        "npm",
        "npm",
        manifests=(Path("package.json"),),
        locks=(Path("package-lock.json"),),
    )
    app = PackageRef("npm", "app-lib", "app-lib", "pkg:npm/app-lib")
    child = PackageRef("npm", "child-lib", "child-lib", "pkg:npm/child-lib")
    declaration = DependencyDeclaration(
        project.project_id,
        app,
        VersionConstraint("1.0.0", "semver", "1.0.0"),
        SourceLocation(Path("/repo/package.json"), 4, 5),
    )
    root_resolution = ResolvedDependency(
        project.project_id,
        app,
        "1.0.0",
        SourceLocation(Path("/repo/package-lock.json"), 8),
        direct=True,
        instance_id="node_modules/app-lib",
        dependency_links=(
            ResolvedDependencyLink(
                child,
                "2.0.0",
                "node_modules/app-lib/node_modules/child-lib",
            ),
        ),
    )
    child_resolution = ResolvedDependency(
        project.project_id,
        child,
        "2.0.0",
        SourceLocation(Path("/repo/package-lock.json"), 12),
        instance_id="node_modules/app-lib/node_modules/child-lib",
    )
    finding = Finding(
        "dependency.unused",
        PackageIdentity(
            project.project_id,
            "npm",
            "app-lib",
            purl="pkg:npm/app-lib",
        ),
        "warning",
        "app-lib has no qualified usage evidence",
        (SourceLocation(Path("/repo/package.json"), 4, 5),),
    )
    bundle = EvidenceBundle(
        project,
        declarations=(declaration,),
        resolved=(root_resolution, child_resolution),
        capabilities=(
            Capability("manifest", CapabilityState.COMPLETE),
            Capability("resolution", CapabilityState.COMPLETE),
            Capability("usage", CapabilityState.COMPLETE),
            Capability("mapping", CapabilityState.COMPLETE),
        ),
        evidence_files=(
            Path("/repo/package.json"),
            Path("/repo/package-lock.json"),
        ),
    )
    return ScanResult(
        Path("/repo"),
        (
            Capability("dependency_hygiene", CapabilityState.COMPLETE),
            Capability("security", CapabilityState.COMPLETE),
        ),
        findings=(finding,),
        bundles=(bundle,),
    )


def test_json_and_text_share_the_canonical_result() -> None:
    result = sample_result()

    payload = result.to_dict()

    assert payload["schema"] == "depcheck.scan.v1"
    assert payload["projects"][0]["project_id"] == "npm:npm:."
    assert len(payload["inventory"]["resolved_dependencies"]) == 2
    assert '"status": "fail"' in render_json(result)
    assert "npm:npm:./npm/app-lib" in render_text(result)


def test_sarif_and_cyclonedx_preserve_locations_and_dependency_edges() -> None:
    result = sample_result()

    sarif = build_sarif(result)
    cyclonedx = build_cyclonedx(
        result,
        timestamp="2026-08-17T00:00:00+00:00",
        serial_number="urn:uuid:00000000-0000-0000-0000-000000000000",
    )

    sarif_result = sarif["runs"][0]["results"][0]
    assert sarif_result["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 4,
        "startColumn": 5,
    }
    assert sarif_result["properties"]["project_id"] == "npm:npm:."

    components = {item["version"]: item["bom-ref"] for item in cyclonedx["components"]}
    app_edge = next(
        item for item in cyclonedx["dependencies"] if item["ref"] == components["1.0.0"]
    )
    assert app_edge["dependsOn"] == [components["2.0.0"]]


def test_policy_exemptions_apply_to_qualified_findings() -> None:
    result = sample_result()
    policy = {
        "fail_on": ["unused"],
        "exemptions": [
            {
                "risk": "unused",
                "package": "app-lib",
                "project_id": "npm:npm:.",
                "ecosystem": "npm",
                "reason": "temporary migration",
                "owner": "platform",
                "expires_at": "2026-09-01",
            }
        ],
    }

    evaluation = evaluate_policy(result, policy, today=date(2026, 8, 17))

    assert evaluation.effective_findings == ()
    assert evaluation.should_fail() is False


@pytest.mark.parametrize(
    "override,remaining",
    [
        ({}, 1),
        ({"expires_at": "2026-08-16"}, 2),
        ({"project_id": "npm:npm:other"}, 2),
        ({"ecosystem": "PyPI"}, 2),
        ({"risk": "missing"}, 2),
    ],
)
def test_unused_exemption_keeps_raw_finding_and_security_evidence(
    override: dict, remaining: int
) -> None:
    result = sample_result()
    vulnerability = replace(
        result.findings[0], code="security.vulnerability", severity="error"
    )
    result = replace(result, findings=(*result.findings, vulnerability))
    sbom_before = build_cyclonedx(result)
    exemption = {
        "risk": "unused",
        "package": "app-lib",
        "ecosystem": "npm",
        "project_id": "npm:npm:.",
        "reason": "Entry point migration",
        "owner": "platform",
        "expires_at": "2026-09-01",
        **override,
    }
    evaluated = evaluate_policy(
        result,
        {"fail_on": ["vuln"], "exemptions": [exemption]},
        today=date(2026, 8, 17),
    )
    assert len(evaluated.effective_findings) == remaining
    assert vulnerability in evaluated.effective_findings
    assert evaluated.should_fail()
    assert [f.code for f in result.findings] == [
        "dependency.unused",
        "security.vulnerability",
    ]
    sbom_after = build_cyclonedx(evaluated.result)
    assert sbom_before["components"] == sbom_after["components"]
    assert sbom_before["dependencies"] == sbom_after["dependencies"]
    assert evaluated.result.capability("security").complete


def test_tool_usage_preserves_security_coordinates_and_sbom(tmp_path: Path) -> None:
    from depcheck.engine import RepositoryScanner, RepositoryScanOptions
    from depcheck.security.osv_client import OSVScanResult

    class OfflineOSV:
        def scan(self, packages):
            return self.scan_ecosystem(packages, "PyPI")

        def scan_ecosystem(self, packages, ecosystem):
            assert (ecosystem, packages) == ("PyPI", {"ruff": "0.11.0"})
            return OSVScanResult({}, (), dict(packages))

    (tmp_path / "requirements.txt").write_text("ruff==0.11.0\n")
    scanner = RepositoryScanner(osv_client=OfflineOSV())
    before = scanner.scan(tmp_path, RepositoryScanOptions(security=True))
    (tmp_path / ".depcheck.toml").write_text(
        '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
        'package="ruff"\nscope="test"\nreason="Lint"\n'
    )
    after = scanner.scan(tmp_path, RepositoryScanOptions(security=True))
    assert any(f.code == "dependency.unused" for f in before.findings)
    assert not any(f.code == "dependency.unused" for f in after.findings)
    first, second = build_cyclonedx(before), build_cyclonedx(after)
    assert first["components"] == second["components"]
    assert first["dependencies"] == second["dependencies"]
    assert after.capability("security").state == "complete"


def test_sbom_references_are_unique_across_projects() -> None:
    first = sample_result()
    bundle = first.bundles[0]
    second_id = "npm:npm:apps/second"
    second = replace(
        bundle,
        project=replace(bundle.project, project_id=second_id),
        declarations=tuple(
            replace(item, project_id=second_id) for item in bundle.declarations
        ),
        resolved=tuple(replace(item, project_id=second_id) for item in bundle.resolved),
    )
    sbom = build_cyclonedx(replace(first, bundles=(bundle, second)))
    refs = [item["bom-ref"] for item in sbom["components"]]
    assert len(refs) == len(set(refs)) == 4
    owners = {
        item["bom-ref"]: item["properties"][0]["value"] for item in sbom["components"]
    }
    for edge in sbom["dependencies"][1:]:
        assert all(owners[child] == owners[edge["ref"]] for child in edge["dependsOn"])


def test_sarif_encodes_paths_and_preserves_failure_diagnostics() -> None:
    from depcheck.model import Diagnostic

    result = sample_result()
    result = replace(
        result,
        diagnostics=(Diagnostic("source.invalid", "error", "cannot parse source"),),
        findings=(
            replace(
                result.findings[0],
                locations=(SourceLocation(Path("/repo/a #b.js"), 1),),
            ),
        ),
    )
    run = build_sarif(result)["runs"][0]
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "a%20%23b.js"
    )
    assert (
        run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
        == "cannot parse source"
    )


def test_policy_preserves_go_coordinates_and_rejects_unknown_risks() -> None:
    result = sample_result()
    result = replace(
        result,
        findings=(
            replace(
                result.findings[0],
                package=PackageIdentity("go:go:.", "Go", "example.com/Some_Module"),
            ),
        ),
    )
    exemption = {
        "risk": "unused",
        "package": "example.com/Some_Module",
        "ecosystem": "Go",
        "project_id": "go:go:.",
        "reason": "migration",
        "owner": "platform",
        "expires_at": "2026-12-01",
    }
    evaluation = evaluate_policy(
        result,
        {"fail_on": ["unused"], "exemptions": [exemption]},
        today=date(2026, 9, 5),
    )
    assert not evaluation.should_fail()
    invalid = evaluate_policy(
        result, {"exemptions": [{**exemption, "risk": "typo"}]}, today=date(2026, 9, 5)
    )
    assert invalid.governance_risk_count == 1


def test_cyclonedx_transitive_is_not_optional() -> None:
    components = build_cyclonedx(sample_result())["components"]
    for component in components:
        assert "scope" not in component
        properties = {item["name"]: item["value"] for item in component["properties"]}
        assert properties["depcheck:dependency:direct"] == (
            "true" if component["name"] == "app-lib" else "false"
        )


def test_offline_hygiene_policy_preserves_strict_incomplete_policy() -> None:
    result = replace(
        sample_result(),
        capabilities=(
            Capability("dependency_hygiene", CapabilityState.COMPLETE),
            Capability("security", CapabilityState.SKIPPED),
        ),
    )
    assert evaluate_policy(result, {"fail_on": ["incomplete"]}).should_fail()
    assert not evaluate_policy(
        result, {"fail_on": ["hygiene-incomplete"]}
    ).should_fail()
    incomplete = replace(
        result,
        capabilities=(Capability("dependency_hygiene", CapabilityState.INCOMPLETE),),
    )
    assert evaluate_policy(
        incomplete, {"fail_on": ["hygiene-incomplete"]}
    ).should_fail()


@pytest.mark.parametrize("invalid", [False, 17, None, {"missing": True}])
def test_invalid_policy_fail_on_is_rejected(invalid) -> None:
    with pytest.raises(ValueError, match="fail_on"):
        evaluate_policy(sample_result(), {"fail_on": invalid})
