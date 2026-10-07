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


@pytest.mark.parametrize(
    "command,expected",
    [
        (
            "RUN pip install requests==2.31.0 && groupadd --gid 10001 worker",
            {"requests"},
        ),
        (
            "RUN pip install --require-hashes -r requirements.lock && rm -rf /build && useradd --uid 10001 worker",
            set(),
        ),
        ("RUN pip install requests==2.31.0; rm -rf /wheels", {"requests"}),
        (
            "RUN pip install --target staging requests==2.31.0 | tee install.log",
            {"requests"},
        ),
    ],
)
def test_pip_install_hints_stop_before_shell_commands(tmp_path, command, expected):
    from depcheck.analyzer.pip_install_parser import PipInstallParser

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(command + "\n")
    parser = PipInstallParser(dockerfile)
    assert set(parser.parse()) == expected
    assert {d.name for d in parser.parse_detailed().declarations} == expected


@pytest.mark.parametrize(
    "filename",
    [
        "requirements.lock",
        "requirements-dev.lock",
        "runtime-requirements.lock",
        "build-requirements.lock",
    ],
)
def test_compiled_requirements_locks_keep_pins_hashes_and_markers(tmp_path, filename):
    from depcheck.ecosystems.python_manifest import PythonManifestCollector

    path = tmp_path / filename
    path.write_text(
        'urllib3==2.8.0; python_version >= "3.11" \\\n'
        "    --hash=sha256:" + "a" * 64 + " \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
    )
    parsed = PythonManifestCollector(tmp_path).collect()
    assert not parsed.diagnostics
    assert len(parsed.declarations) == 1
    declaration = parsed.declarations[0]
    assert declaration.kind == "locked"
    assert declaration.pinned_version == "2.8.0"
    assert declaration.marker is not None
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles[0].resolved[0].version == "2.8.0"
    assert result.bundles[0].project.locks == (Path(filename),)


def test_compiled_requirements_lock_ranges_remain_incomplete(tmp_path):
    (tmp_path / "requirements.lock").write_text("urllib3>=2\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.invalid-lock-entry" for d in result.diagnostics)


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


@pytest.mark.parametrize("options", [("-c", "-r"), ("-r", "-c")])
def test_requirements_include_keeps_direct_and_constraint_contexts(
    tmp_path: Path, options
) -> None:
    from depcheck.analyzer.requirement_parser import RequirementParser

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("".join(f"{option} shared.txt\n" for option in options))
    (tmp_path / "shared.txt").write_text("requests==2.31.0\n")

    parsed = RequirementParser(manifest, project_root=tmp_path).parse_detailed()
    assert not parsed.diagnostics
    assert {item.kind for item in parsed.declarations} == {"direct", "constraint"}
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {item.kind for item in result.bundles[0].declarations} == {
        "direct",
        "constraint",
    }
    assert result.bundles[0].resolved[0].direct


def test_security_preserves_every_affected_installation_instance(
    tmp_path: Path,
) -> None:
    import json

    class FakeOSV:
        def __init__(self):
            self.calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(
                vulnerabilities={"dep": [{"id": "OSV-1", "summary": "affected"}]},
                diagnostics=(),
                queried=dict(packages),
            )

    (tmp_path / "package.json").write_text('{"dependencies":{"dep":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/dep": {"version": "1.0.0"},
                    "node_modules/a/node_modules/dep": {"version": "1.0.0"},
                    "node_modules/b/node_modules/dep": {"version": "1.1.0"},
                }
            }
        )
    )
    osv = FakeOSV()
    result = RepositoryScanner(osv_client=osv).scan(tmp_path)
    identities = {item.identity for item in result.bundles[0].resolved}

    assert set(result.vulnerabilities) == identities
    assert {
        finding.package
        for finding in result.findings
        if finding.code == "security.vulnerability"
    } == identities
    assert osv.calls == [("npm", {"dep": "1.0.0"}), ("npm", {"dep": "1.1.0"})]
    assert len(result.to_dict()["vulnerabilities"]) == 3


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


@pytest.mark.parametrize("requires_python", ["broken", ">=>3.12", True])
def test_invalid_requires_python_cannot_establish_compatibility(
    tmp_path: Path, requires_python
) -> None:
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.compatibility.pypi_client import PyPIFetchResult

    class Client:
        def fetch_metadata(self, package, version=None):
            return PyPIFetchResult(
                {"info": {"requires_dist": [], "requires_python": requires_python}}
            )

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    result = RepositoryScanner(
        compatibility_checker=CompatibilityChecker(client=Client())
    ).scan(tmp_path, RepositoryScanOptions(security=False, compatibility=True))
    assert not result.capability("compatibility").complete
    assert any(d.code == "pypi.invalid-requires-python" for d in result.diagnostics)
    assert result.metadata["compatibility"]["pypi:python:."]["complete"] is False


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


def test_greedy_compatibility_conflict_is_not_a_complete_resolution() -> None:
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.compatibility.pypi_client import PyPIFetchResult

    class PyPI:
        def fetch_metadata(self, package, version=None):
            releases = {
                "alpha": {"1.0": [], "2.0": ["beta>=2"]},
                "beta": {"1.0": []},
            }
            if version is None:
                return PyPIFetchResult(
                    {"releases": {v: [{}] for v in releases[package]}}
                )
            return PyPIFetchResult(
                {"info": {"requires_dist": releases[package][version]}}
            )

    checker = CompatibilityChecker(PyPI())
    report = checker.check({"alpha": ">=1", "beta": "==1.0"})
    assert not report.complete
    assert report.conflicts
    assert any(
        d.code == "compatibility.backtracking-required" for d in report.diagnostics
    )
    compatible = checker.check({"alpha": "==1.0", "beta": "==1.0"})
    assert compatible.complete
    assert not compatible.conflicts
    pinned_conflict = checker.check({"alpha": "==2.0", "beta": "==1.0"})
    assert pinned_conflict.complete
    assert pinned_conflict.conflicts


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_pyproject_preview_preserves_comments_markers_and_newlines(
    tmp_path, newline, quote
):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    marker = "python_version >= '3.11'" if quote == '"' else 'python_version >= "3.11"'
    original = (
        (
            f'[project]\nname="app-2.31.0"\nversion="2.31.0"\ndependencies = [\n  {quote}requests[socks]==2.31.0; {marker}{quote}, # retain\n]\n'
        )
        .replace("\n", newline)
        .encode()
    )
    path = tmp_path / "pyproject.toml"
    path.write_bytes(original)
    result = PyprojectUpdater(tmp_path).plan(
        path, {"requests": "==2.32.4"}, group="project"
    )
    assert result.diagnostics == ()
    assert result.matched == ("requests",)
    assert result.groups == ("project",)
    assert result.plan.updated_content.encode() == original.replace(
        b"==2.31.0", b"==2.32.4"
    )
    assert path.read_bytes() == original


def test_pyproject_preview_requires_unambiguous_group(tmp_path):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests==1"]\n[project.optional-dependencies]\ntest=["requests==1; python_version < \'3.12\'", "requests==2; python_version >= \'3.12\'"]\ndocs=["requests==1"]\n'
    path.write_text(original)
    updater = PyprojectUpdater(tmp_path)
    result = updater.plan(path, {"requests": "3"})
    assert result.plan is None and result.matched == ()
    assert result.diagnostics[0].code == "update.ambiguous-target"
    result = updater.plan(path, {"requests": "3"}, group="optional:test")
    assert result.groups == ("optional:test",)
    assert result.plan.updated_content == original.replace(
        "requests==1;", "requests==3;"
    ).replace("requests==2;", "requests==3;")
    assert path.read_text() == original


@pytest.mark.parametrize(
    ("content", "updates", "group", "code"),
    [
        (
            '[project]\ndependencies=["requests @ https://example.org/a.whl"]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndynamic=["dependencies"]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["""requests==1"""]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            "[project]\ndependencies=[42]",
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["bad !!!"]',
            {"requests": "2"},
            None,
            "update.invalid-target",
        ),
        ("[project", {"requests": "2"}, None, "update.invalid-target"),
        (
            '[project]\ndependencies=["requests==1"]',
            {"requests": "not-a-version"},
            None,
            "update.invalid-target",
        ),
        (
            '[project]\ndependencies=["requests==1"]',
            {"urllib3": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["requests==1"]',
            {"requests": "2"},
            "optional:missing",
            "update.unsupported-target",
        ),
        (
            '[tool.poetry.dependencies]\nrequests="1"',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
    ],
)
def test_pyproject_preview_refuses_unsupported_targets(
    tmp_path, content, updates, group, code
):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    path.write_text(content)
    result = PyprojectUpdater(tmp_path).plan(path, updates, group=group)
    assert result.plan is None and result.matched == ()
    assert result.diagnostics[0].code == code
    assert result.diagnostics[0].severity == "error"
    assert path.read_text() == content


def test_pyproject_preview_noop_and_file_atomicity(tmp_path):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests>=1,<3", "urllib3 @ https://example.org/u.whl"]\n'
    path.write_text(original)
    updater = PyprojectUpdater(tmp_path)
    result = updater.plan(path, {"requests": "<3,>=1"})
    assert (
        result.plan is None
        and result.matched == ("requests",)
        and not result.diagnostics
    )
    result = updater.plan(path, {"requests": "2", "urllib3": "2"})
    assert result.plan is None and not result.matched and result.diagnostics
    assert path.read_text() == original


def test_pyproject_preview_rejects_external_symlink_before_read(tmp_path, monkeypatch):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater
    from depcheck.path_policy import ProjectPathError

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_text("[project]")
    link = root / "pyproject.toml"
    link.symlink_to(outside)

    def forbidden(*args, **kwargs):
        raise AssertionError("read before path validation")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    with pytest.raises(ProjectPathError):
        PyprojectUpdater(root).plan(link, {"requests": "2"})
    with pytest.raises(ProjectPathError):
        PyprojectUpdater(root).plan(root / "../outside.toml", {"requests": "2"})


@pytest.mark.parametrize(
    "entry",
    [r"requ\u0065sts==2.31.0", r"requests==2.31.0\u003b python_version < '3.12'"],
)
def test_pyproject_preview_refuses_escaped_tokens_without_corrupting_them(
    tmp_path, entry
):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    original = f'[project]\ndependencies=["{entry}"]\n'
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(path, {"requests": "2.32.4"})
    assert result.plan is None
    assert result.diagnostics[0].code == "update.unsupported-target"
    assert path.read_text() == original


def test_pyproject_preview_preserves_spaced_extras(tmp_path):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    original = "[project]\ndependencies=[\"requests [socks] ==2.31.0; python_version < '3.12'\"]\n"
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(path, {"requests": "2.32.4"})
    assert result.plan.updated_content == original.replace("2.31.0", "2.32.4")


@pytest.mark.parametrize(
    "suffix",
    [
        'dynamic=["optional-dependencies"]\n',
        "[project.optional-dependencies]\ntest=[42]\n",
        '[project.optional-dependencies]\ntest=["bad !!!"]\n',
    ],
)
def test_pyproject_preview_ignores_unaffected_groups(tmp_path, suffix):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests==1"]\n' + suffix
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(
        path,
        {"requests": "2"},
        group="project" if suffix.startswith("dynamic") else None,
    )
    assert not result.diagnostics
    assert result.plan.updated_content == original.replace("requests==1", "requests==2")
