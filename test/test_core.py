from pathlib import Path
from types import SimpleNamespace

from depcheck.compatibility.checker import (
    CompatibilityConflict,
    CompatibilityReport,
)
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.engine import RepositoryScanner, RepositoryScanOptions

from depcheck.model import (
    AnalysisReport,
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    Finding,
    MappingConfidence,
    PackageRef,
    PackageIdentity,
    ProjectUnit,
    PythonRequirement,
    ScanResult,
    SourceLocation,
    UsageEvidence,
    VersionConstraint,
)


def test_package_identity_preserves_resolved_instances() -> None:
    first = PackageIdentity("npm:app:.", "npm", "react", "18.3.1", "node_modules/react")
    second = PackageIdentity(
        "npm:app:.", "npm", "react", "19.1.1", "packages/ui/node_modules/react"
    )

    assert first != second
    assert len({first, second}) == 2
    assert first.coordinates == (
        "npm:app:.",
        "npm",
        "react",
        "18.3.1",
        "node_modules/react",
    )


def test_scan_result_never_reports_pass_when_a_capability_was_skipped() -> None:
    result = ScanResult(
        root=Path("/workspace"),
        capabilities=(
            Capability("dependency_hygiene", CapabilityState.COMPLETE),
            Capability("security", CapabilityState.SKIPPED, "offline"),
        ),
    )

    assert result.complete is False
    assert result.status == "incomplete"
    assert result.to_dict()["capabilities"]["security"] == {
        "state": "skipped",
        "reason": "offline",
    }


def test_findings_fail_a_complete_scan_without_making_it_incomplete() -> None:
    result = ScanResult(
        root=Path("/workspace"),
        capabilities=(Capability("dependency_hygiene", CapabilityState.COMPLETE),),
        findings=(
            Finding(
                code="dependency.missing",
                package=PackageIdentity("pypi:python:.", "PyPI", "requests"),
                severity="error",
                message="requests is imported but not declared",
            ),
        ),
    )

    assert result.complete is True
    assert result.status == "fail"
    assert result.risk_count == 1


def test_evidence_bundle_uses_the_same_qualified_package_model() -> None:
    project = ProjectUnit("pypi:python:.", Path("."), "python", "PyPI", "python")
    package = PackageRef("PyPI", "requests", "requests", "pkg:pypi/requests")
    declaration = DependencyDeclaration(
        project.project_id,
        package,
        VersionConstraint(">=2", "pep440", ">=2"),
        SourceLocation(Path("pyproject.toml"), 8),
    )
    usage = UsageEvidence(
        project.project_id,
        "python",
        "requests",
        SourceLocation(Path("app.py"), 1),
        mapped_package=package,
        mapping_confidence=MappingConfidence.EXACT,
    )
    bundle = EvidenceBundle(
        project,
        declarations=(declaration,),
        usages=(usage,),
        capabilities=(Capability("usage", CapabilityState.COMPLETE),),
    )

    payload = bundle.to_dict(Path("."))
    assert payload["declarations"][0]["project_id"] == "pypi:python:."
    assert payload["usages"][0]["mapping_confidence"] == "exact"


def test_python_requirement_keeps_markers_and_exact_pins() -> None:
    requirement = PythonRequirement.from_requirement(
        'requests[security]==2.32.4; python_version >= "3.11"',
        source=SourceLocation(Path("requirements.txt"), 3),
    )

    assert requirement.name == "requests"
    assert requirement.extras == ("security",)
    assert requirement.pinned_version == "2.32.4"
    assert requirement.is_active({"python_version": "3.12"}) is True
    assert requirement.is_active({"python_version": "3.10"}) is False


def test_evidence_analyzer_returns_qualified_findings() -> None:
    project = ProjectUnit("npm:npm:.", Path("."), "javascript", "npm", "npm")
    package = PackageRef("npm", "left-pad", "left-pad", "pkg:npm/left-pad")
    bundle = EvidenceBundle(
        project,
        usages=(
            UsageEvidence(
                project.project_id,
                "javascript",
                "left-pad",
                SourceLocation(Path("index.js"), 1),
                mapped_package=package,
                mapping_confidence=MappingConfidence.EXACT,
            ),
        ),
        capabilities=(Capability("usage", CapabilityState.COMPLETE),),
    )

    report = EvidenceAnalyzer().analyze(bundle)

    assert isinstance(report, AnalysisReport)
    assert report.findings[0].package == PackageIdentity(
        "npm:npm:.", "npm", "left-pad", purl="pkg:npm/left-pad"
    )


def test_repository_scanner_returns_the_canonical_result(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"app","dependencies":{"left-pad":"1.3.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text(
        'import leftPad from "left-pad";\n',
        encoding="utf-8",
    )

    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            enabled_ecosystems=("npm",),
        ),
    )

    assert type(result) is ScanResult
    assert result.status == "incomplete"
    assert result.capability("security").state is CapabilityState.SKIPPED
    assert result.bundles[0].project.project_id == "npm:npm:."


def test_security_findings_keep_the_queried_version(tmp_path: Path) -> None:
    class FakeOSV:
        def scan(self, packages):
            return SimpleNamespace(
                vulnerabilities={
                    "requests": [{"id": "OSV-1", "summary": "affected", "severity": []}]
                },
                diagnostics=(),
                queried=dict(packages),
            )

    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    result = RepositoryScanner(osv_client=FakeOSV()).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            enabled_ecosystems=("PyPI",),
        ),
    )

    finding = next(
        item for item in result.findings if item.code == "security.vulnerability"
    )
    assert finding.package == PackageIdentity(
        "pypi:python:.", "PyPI", "requests", "2.31.0", purl="pkg:pypi/requests"
    )
    assert result.capability("security").state is CapabilityState.COMPLETE


def test_compatibility_is_a_stage_of_the_repository_scan(tmp_path: Path) -> None:
    class FakeCompatibility:
        def check_detailed(self, manifest, *, python_version=None):
            assert [item.name for item in manifest.declarations] == ["requests"]
            return CompatibilityReport(
                conflicts=[
                    CompatibilityConflict(
                        "requests",
                        "2.31.0",
                        ">=2.32",
                        "demo",
                    )
                ],
                missing=[],
                unconstrained=[],
                suggestions={"requests": "==2.32.4"},
            )

    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    result = RepositoryScanner(compatibility_checker=FakeCompatibility()).scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            compatibility=True,
            enabled_ecosystems=("PyPI",),
        ),
    )

    finding = next(
        item for item in result.findings if item.code == "compatibility.conflict"
    )
    assert finding.package == PackageIdentity(
        "pypi:python:.", "PyPI", "requests", purl="pkg:pypi/requests"
    )
    assert result.capability("compatibility").state is CapabilityState.COMPLETE
    assert result.metadata["compatibility"]["pypi:python:."]["suggestions"] == {
        "requests": "==2.32.4"
    }
