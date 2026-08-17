from datetime import date
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
