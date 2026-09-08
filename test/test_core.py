from pathlib import Path
from types import SimpleNamespace

import pytest

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


def test_configured_ignores_match_scan_and_index(tmp_path: Path) -> None:
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    (tmp_path / ".depcheck.toml").write_text(
        'security = false\nignore-packages = ["demo_pkg"]\n'
    )
    (tmp_path / "requirements.txt").write_text("demo-pkg>=1\n")
    (tmp_path / "app.py").write_text("import demo_pkg\n")
    result = RepositoryScanner().scan(tmp_path)
    RepositoryIndexer().refresh(tmp_path)
    assert result.findings == ()
    assert result.bundles[0].declarations == ()
    assert RepositoryIndex(tmp_path).dependencies() == []


def test_configured_compatibility_can_be_overridden(tmp_path: Path) -> None:
    class Compatibility:
        calls = 0

        def check_detailed(self, manifest, *, python_version=None):
            self.calls += 1
            return CompatibilityReport([], [], [], {})

    (tmp_path / ".depcheck.toml").write_text("security = false\ncompatibility = true\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    checker = Compatibility()
    scanner = RepositoryScanner(compatibility_checker=checker)
    scanner.scan(tmp_path)
    assert checker.calls == 1
    scanner.scan(tmp_path, RepositoryScanOptions(compatibility=False))
    assert checker.calls == 1


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_incomplete_usage_does_not_claim_dependencies_are_unused(
    tmp_path: Path, ecosystem: str
) -> None:
    if ecosystem == "PyPI":
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        (tmp_path / "app.py").write_text("import requests\nthis is invalid !!!\n")
    else:
        (tmp_path / "package.json").write_text('{"dependencies":{"react":"18.0.0"}}')
        (tmp_path / "app.js").write_text("const lib = import(resolveName());\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=(ecosystem,))
    )
    assert not result.capability("dependency_hygiene").complete
    assert not any(item.code == "dependency.unused" for item in result.findings)


@pytest.mark.parametrize(
    "vulns", [{"id": "OSV-1"}, ["OSV-1"], [{"summary": "no id"}], 7]
)
def test_osv_malformed_results_never_become_clean(vulns) -> None:
    from depcheck.security.osv_client import OSVClient

    class Session:
        def post(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"vulns": vulns}]},
            )

    result = OSVClient(session=Session()).scan({"requests": "2.31.0"})
    assert result.complete is False
    assert result.diagnostics[0].code == "osv.invalid-response"


def test_osv_stops_repeated_pagination_tokens() -> None:
    from depcheck.security.osv_client import OSVClient

    class Session:
        calls = 0

        def post(self, *args, **kwargs):
            self.calls += 1
            assert self.calls <= 2, "pagination must stop when the token repeats"
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"next_page_token": "same"}]},
            )

    result = OSVClient(session=Session()).scan({"requests": "2.31.0"})
    assert not result.complete


def test_osv_keeps_confirmed_vulnerabilities_when_later_batch_fails() -> None:
    import requests
    from depcheck.security.osv_client import OSVClient

    class Session:
        calls = 0

        def post(self, *args, **kwargs):
            self.calls += 1
            if self.calls > 1:
                raise requests.ConnectionError("connection interrupted")
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"vulns": [{"id": "OSV-1"}]}]},
            )

        def get(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"id": "OSV-1", "summary": "affected"},
            )

    result = OSVClient(session=Session(), batch_size=1, max_attempts=1).scan(
        {"requests": "2.31.0", "httpx": "0.27.0"}
    )
    assert not result.complete
    assert result.vulnerabilities["requests"][0]["id"] == "OSV-1"


def test_compatibility_honors_requirement_constraints(tmp_path: Path) -> None:
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.compatibility.pypi_client import PyPIFetchResult

    class PyPI:
        def fetch_metadata(self, package, version=None):
            if version is None:
                return PyPIFetchResult({"releases": {"1.0": [{}], "2.0": [{}]}})
            return PyPIFetchResult({"info": {"requires_dist": []}})

    (tmp_path / "requirements.txt").write_text("demo>=1\n-c constraints.txt\n")
    (tmp_path / "constraints.txt").write_text("demo<2\n")
    result = RepositoryScanner(compatibility_checker=CompatibilityChecker(PyPI())).scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=True)
    )
    assert result.metadata["compatibility"]["pypi:python:."]["selected_versions"] == {
        "demo": "1.0"
    }


@pytest.mark.parametrize("requires_dist", [["invalid requirement !!!"], 7, "requests"])
def test_invalid_compatibility_metadata_is_incomplete(
    tmp_path: Path, requires_dist
) -> None:
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.compatibility.pypi_client import PyPIFetchResult

    class PyPI:
        def fetch_metadata(self, package, version=None):
            return PyPIFetchResult({"info": {"requires_dist": requires_dist}})

    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    result = RepositoryScanner(compatibility_checker=CompatibilityChecker(PyPI())).scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=True)
    )
    assert not result.capability("compatibility").complete


def test_python_full_version_marker_uses_requested_target() -> None:
    from depcheck.ecosystems.python import filter_python_manifest
    from depcheck.model import ManifestParseResult

    requirement = PythonRequirement.from_requirement(
        'demo==1; python_full_version == "3.10.7"',
        source=SourceLocation(Path("requirements.txt")),
    )
    filtered = filter_python_manifest(
        ManifestParseResult(declarations=(requirement,)), "3.10.7"
    )
    assert filtered.declarations == (requirement,)
