"""Report formats, policy decisions, qualified identities, and export projections."""

import json
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
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
from depcheck.security.osv_client import OSVClient, OSVScanResult


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


@pytest.mark.parametrize(
    "source,public",
    [
        ({"editable": "vendor/requests"}, False),
        ({"path": "vendor/requests"}, False),
        ({"git": "https://example.invalid/requests"}, False),
        ({"registry": "https://pypi.org/simple"}, True),
        ({"registry": "https://private.invalid/simple"}, False),
        ({}, False),
    ],
)
def test_python_lock_sources_control_security_and_survive_index_reuse(
    tmp_path, source, public
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
    )
    literal = ",".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in source.items())
    (tmp_path / "uv.lock").write_text(
        f'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={{{literal}}}\n'
    )

    class OSV:
        def __init__(self):
            self.queries = []

        def scan(self, packages):
            self.queries.append(dict(packages))
            return OSVScanResult({}, (), dict(packages))

    osv = OSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path, RepositoryScanOptions(security=True)
    )
    assert bool(osv.queries) is public
    assert result.capability("security").complete is public
    locked = next(
        r for b in result.bundles for r in b.resolved if r.package.name == "requests"
    )
    assert bool(locked.package.purl) is public
    assert locked.origin["public"] is public
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    (tmp_path / "app.py").write_text("import requests\n")
    service.index_repository()
    indexed = service.explain_dependency("requests")
    origins = [
        d["metadata"].get("origin")
        for d in indexed["declarations"]
        if d["kind"] == "locked"
    ]
    assert origins and origins[0]["public"] is public


@pytest.mark.parametrize("layout", ["packages", "legacy", "shrinkwrap"])
def test_npm_origins_isolate_public_findings_and_survive_exports_and_index(
    tmp_path, layout
):
    dependencies = {
        "dual": "1.0.0",
        "wrapper": "2.0.0",
        "@corp/tool": "1.0.0",
        "git-tool": "git+https://git.example/project#abc",
        "local-tool": "file:../local",
        "remote-tool": "https://downloads.example/tool.tgz",
        "mystery": "catalog:tools",
        "mismatch": "1.0.0",
    }
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": dependencies}))
    (tmp_path / "app.js").write_text("import 'dual'; import '@corp/tool';\n")
    (tmp_path / ".npmrc").write_text(
        "@corp:registry=https://alice:fixture-secret@packages.example/npm/?token=fixture-query\n"
        "//packages.example/:_authToken=fixture-auth-token\n"
    )
    private = {
        "version": "1.0.0",
        "resolved": "https://alice:fixture-secret@packages.example/dual.tgz?token=fixture-query",
    }
    nodes = {
        name: {"version": "2.0.0" if name == "wrapper" else "1.0.0"}
        for name in dependencies
    }
    nodes["dual"]["resolved"] = "https://registry.npmjs.org/dual/-/dual-1.0.0.tgz"
    nodes["git-tool"]["resolved"] = (
        "https://registry.npmjs.org/git-tool/-/git-tool-1.0.0.tgz"
    )
    nodes["@corp/tool"]["resolved"] = (
        "https://registry.npmjs.org/@corp/tool/-/tool-1.0.0.tgz"
    )
    nodes["local-tool"]["link"] = True
    nodes["remote-tool"]["resolved"] = "https://downloads.example/tool.tgz"
    nodes["mismatch"]["resolved"] = (
        "https://registry.npmjs.org/different/-/different-1.0.0.tgz"
    )
    if layout == "legacy":
        nodes["wrapper"]["resolved"] = "wrapper/-/wrapper-2.0.0.tgz"
        nodes["git-tool"] = {"version": "git+https://git.example/project#abc"}
        nodes["wrapper"]["dependencies"] = {"dual": private}
        document = {"lockfileVersion": 1, "dependencies": nodes}
    else:
        nodes["wrapper"]["dependencies"] = {"dual": "1.0.0"}
        document = {
            "lockfileVersion": 3,
            "packages": {f"node_modules/{name}": raw for name, raw in nodes.items()},
        }
        document["packages"]["node_modules/wrapper/node_modules/dual"] = private
    (
        tmp_path
        / ("npm-shrinkwrap.json" if layout == "shrinkwrap" else "package-lock.json")
    ).write_text(json.dumps(document))

    class OSV:
        def __init__(self):
            self.queries = []

        def scan_ecosystem(self, packages, ecosystem):
            self.queries.append(dict(packages))
            return OSVScanResult(
                {"dual": [{"id": "TEST-dual", "summary": "public fixture"}]},
                (),
                dict(packages),
            )

    osv = OSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path, RepositoryScanOptions(security=True)
    )
    assert osv.queries == [{"dual": "1.0.0", "wrapper": "2.0.0"}]
    findings = [f for f in result.findings if f.code == "security.vulnerability"]
    assert [f.package.instance for f in findings] == ["node_modules/dual"]
    assert not result.capability("security").complete
    assert any(d.code == "security.identity-unverified" for d in result.diagnostics)
    bundle = result.bundles[0]
    resolutions = {r.instance_id: r for r in bundle.resolved}
    assert {instance for instance, r in resolutions.items() if r.origin["public"]} == {
        "node_modules/dual",
        "node_modules/wrapper",
    }
    assert len(resolutions) == len(dependencies) + 1
    wrapper = resolutions["node_modules/wrapper"]
    assert wrapper.origin["lock_source"] == (
        "relative-registry-tarball" if layout == "legacy" else "not-provided"
    )
    if layout == "legacy":
        assert resolutions["node_modules/git-tool"].origin["kind"] == "git"
    assert wrapper.dependency_links[0].package.purl is None
    assert (
        next(
            u for u in bundle.usages if u.reference == "@corp/tool"
        ).mapped_package.purl
        is None
    )
    sbom = build_cyclonedx(result)
    assert (
        len([c for c in sbom["components"] if c.get("purl") == "pkg:npm/dual@1.0.0"])
        == 1
    )
    assert len([c for c in sbom["components"] if c["name"] == "dual"]) == 2
    json_resolutions = json.loads(render_json(result))["inventory"][
        "resolved_dependencies"
    ]
    assert {
        r["identity"]["instance"]: r["origin"]["public"]
        for r in json_resolutions
        if r["identity"]["package"] == "dual"
    } == {"node_modules/dual": True, "node_modules/wrapper/node_modules/dual": False}
    for serialized in (
        render_json(result),
        json.dumps(build_sarif(result)),
        json.dumps(sbom),
    ):
        assert all(
            secret not in serialized
            for secret in ("fixture-secret", "fixture-query", "fixture-auth-token")
        )
    service = DependencyAgentService(tmp_path)
    service.index_repository(project_ids=(bundle.project.project_id,))
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    explanation = service.explain_dependency("dual")
    assert {r["origin"]["public"] for r in explanation["resolutions"]} == {True, False}
    assert service.repository_context()["stale"] is False
    assert before == (cache.read_bytes(), cache.stat().st_mtime_ns)


@pytest.mark.parametrize("manager", ["npm", "pnpm"])
def test_npm_registry_configuration_updates_selected_evidence_and_security(
    tmp_path, manager
):
    import yaml

    dependencies = {"@corp/tool": "1.0.0", "other": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": dependencies}))
    if manager == "npm":
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        f"node_modules/{name}": {"version": version}
                        for name, version in dependencies.items()
                    }
                }
            )
        )
    else:
        (tmp_path / "pnpm-lock.yaml").write_text(
            yaml.safe_dump(
                {
                    "lockfileVersion": "9.0",
                    "importers": {
                        ".": {
                            "dependencies": {
                                n: {"specifier": v, "version": v}
                                for n, v in dependencies.items()
                            }
                        }
                    },
                    "packages": {
                        f"{n}@{v}": {"resolution": {"integrity": "sha512-fixture"}}
                        for n, v in dependencies.items()
                    },
                    "snapshots": {f"{n}@{v}": {} for n, v in dependencies.items()},
                }
            )
        )

    class OSV:
        def __init__(self):
            self.queries = []

        def scan_ecosystem(self, packages, ecosystem):
            self.queries.append(dict(packages))
            return OSVScanResult({}, (), dict(packages))

    service = DependencyAgentService(tmp_path)
    service.index_repository(project_ids=("npm:npm:.",))
    path = tmp_path / ".npmrc"
    for text, public in (
        (
            "registry=https://private.example/npm/\n@corp:registry=https://registry.npmjs.org/\n",
            {"@corp/tool"},
        ),
        ("registry=${REGISTRY}\n", set()),
        (
            'registry="https://registry.npmjs.org/" # public assertion\n//registry.npmjs.org/:_authToken=first-secret\n',
            set(dependencies),
        ),
        (
            'registry="https://registry.npmjs.org/" # public assertion\n//registry.npmjs.org/:_authToken=changed-secret\n',
            set(dependencies),
        ),
        (
            "@corp:registry=https://private.example/npm/\n@corp:registry=https://registry.npmjs.org/\n",
            {"other"},
        ),
        (None, set(dependencies)),
    ):
        if text is None:
            path.unlink()
        else:
            path.write_text(text)
        assert service.repository_context()["stale"] is True
        osv = OSV()
        result = RepositoryScanner(osv_client=osv).scan(
            tmp_path, RepositoryScanOptions(security=True)
        )
        assert {name for query in osv.queries for name in query} == public
        assert result.capability("security").complete is (public == set(dependencies))
        service.index_repository(project_ids=("npm:npm:.",))
        assert service.repository_context()["stale"] is False
        indexed = service.explain_dependency("@corp/tool")
        assert next(r["origin"]["public"] for r in indexed["resolutions"]) is (
            "@corp/tool" in public
        )
        assert "first-secret" not in json.dumps(
            indexed
        ) and "changed-secret" not in json.dumps(indexed)


def test_uv_declared_local_source_blocks_stale_public_lock_query(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.uv.sources]\nrequests={path="vendor/requests",editable=true}\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://pypi.org/simple"}\n'
    )

    class OSV:
        def scan(self, packages):
            raise AssertionError("Local override must not reach public OSV")

    result = RepositoryScanner(osv_client=OSV()).scan(
        tmp_path, RepositoryScanOptions(security=True)
    )
    assert not result.capability("security").complete
    locked = next(r for b in result.bundles for r in b.resolved)
    assert locked.origin["lock"]["format"] == "uv"


def test_uv_fork_security_checks_candidates_and_qualifies_activation(tmp_path):
    from types import SimpleNamespace

    from depcheck.compatibility.checker import CompatibilityChecker

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["foo>=1"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        "version=1\nresolution-markers=[\"sys_platform == 'win32'\", \"sys_platform != 'win32'\"]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform == 'win32'\"]\n"
        '[[package]]\nname="foo"\nversion="2.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform != 'win32'\"]\n"
    )

    class Session:
        def __init__(self):
            self.calls = []
            self.detail_calls = 0

        def post(self, url, *, json, **kwargs):
            self.calls.append(
                {q["package"]["name"]: q["version"] for q in json["queries"]}
            )
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "TEST-1",
                                    "modified": "2020-01-01T00:00:00.123456789Z",
                                }
                            ]
                        }
                    ]
                },
            )

        def get(self, *args, **kwargs):
            self.detail_calls += 1
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "id": "TEST-1",
                    "modified": "2020-01-01T00:00:00.123456789Z",
                    "summary": "candidate issue",
                    "aliases": ["CVE-TEST"],
                    "affected": [
                        {
                            "package": {"name": "foo", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                                },
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "2.0.0"},
                                        {"fixed": "2.0.1"},
                                    ],
                                },
                            ],
                        }
                    ],
                },
            )

    class NoMetadata:
        def __getattr__(self, name):
            raise AssertionError("conditional lock cannot seed flat compatibility")

    session = Session()
    result = RepositoryScanner(
        osv_client=OSVClient(session=session),
        compatibility_checker=CompatibilityChecker(client=NoMetadata()),
    ).scan(
        tmp_path,
        RepositoryScanOptions(security=True, compatibility=True, python_version="3.12"),
    )
    assert session.calls == [{"foo": "1.0.0"}, {"foo": "2.0.0"}]
    assert session.detail_calls == 1
    findings = [f for f in result.findings if f.code == "security.vulnerability"]
    assert len(findings) == 2
    assert len({f.package.instance for f in findings}) == 2
    assert all(f.details["activation"] == "unknown" for f in findings)
    assert all(f.details["lock_context"]["conditional"] for f in findings)
    assert {f.details["version"]: f.details["fix_version"] for f in findings} == {
        "1.0.0": "1.0.1",
        "2.0.0": "2.0.1",
    }
    assert all(f.details["fix_versions"] == ["1.0.1", "2.0.1"] for f in findings)
    exported = json.loads(render_json(result))
    assert all(
        f["details"]["fix_version_status"] == "candidate"
        for f in exported["findings"]
        if f["code"] == "security.vulnerability"
    )
    sarif_findings = [
        f
        for f in build_sarif(result)["runs"][0]["results"]
        if f["properties"]["finding_code"] == "security.vulnerability"
    ]
    assert len(sarif_findings) == 2
    assert {
        f["properties"]["version"]: f["properties"]["fix_version"]
        for f in sarif_findings
    } == {
        "1.0.0": "1.0.1",
        "2.0.0": "2.0.1",
    }
    assert all(f["properties"]["activation"] == "unknown" for f in sarif_findings)
    assert not result.capability("security").complete
    assert not result.capability("compatibility").complete
    assert not any(f.code == "compatibility.conflict" for f in result.findings)
    assert result.metadata["compatibility"]["pypi:python:."]["selected_versions"] == {}
    components = build_cyclonedx(result)["components"]
    assert len(components) == 2
    assert len({c["bom-ref"] for c in components}) == 2
    for component in components:
        source = next(
            p["value"]
            for p in component["properties"]
            if p["name"] == "depcheck:source:origin"
        )
        assert json.loads(source)["lock"]["conditional"] is True


def test_osv_withdrawal_is_record_scoped_and_refreshes_repository_outputs(
    tmp_path, monkeypatch
):
    from datetime import datetime, timezone
    from decimal import localcontext
    from types import SimpleNamespace

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 17, microsecond=123456, tzinfo=timezone.utc)

    monkeypatch.setattr("depcheck.security.osv_client.datetime", Clock)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["foo==1"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="foo"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n'
    )
    (tmp_path / "app.py").write_text("import foo\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    before = {
        str(f.relative_to(tmp_path)): (f.read_bytes(), f.stat().st_mtime_ns)
        for f in tmp_path.rglob("*")
        if f.is_file()
    }

    class Session:
        phase = 0
        gets = 0

        def revision(self, identifier):
            digit = self.phase if identifier == "TEST-active" else 0
            return f"2020-01-01T00:00:00.12345678{digit}Z"

        def post(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": identifier,
                                    "modified": self.revision(identifier),
                                }
                                for identifier in (
                                    "TEST-withdrawn",
                                    "TEST-active",
                                    "TEST-future",
                                )
                            ]
                        }
                    ]
                },
            )

        def get(self, url, **kwargs):
            self.gets += 1
            identifier = url.rsplit("/", 1)[-1]
            detail = {
                "id": identifier,
                "modified": self.revision(identifier),
                "aliases": ["CVE-2026-12345"],
                "database_specific": {
                    "cwe_ids": {
                        "TEST-withdrawn": ["CWE-79"],
                        "TEST-active": ["CWE-77", "CWE-77"]
                        + (["NVD-CWE-noinfo"] if self.phase else []),
                        "TEST-future": ["CWE-94"],
                    }[identifier]
                },
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": str(2 + self.phase)},
                                ],
                            }
                        ],
                    }
                ],
            }
            if identifier == "TEST-withdrawn":
                detail["withdrawn"] = "2020-01-01T00:00:00Z"
            elif identifier == "TEST-future":
                detail["withdrawn"] = "2026-10-17T00:00:00.123456001Z"
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: detail)

    session = Session()
    scanner = RepositoryScanner(osv_client=OSVClient(session=session))
    for phase in (0, 1):
        session.phase = phase
        with localcontext() as context:
            context.prec = 5
            result = scanner.scan(tmp_path, RepositoryScanOptions(security=True))
        assert result.capability("security").complete
        findings = [f for f in result.findings if f.code == "security.vulnerability"]
        assert {f.details["id"] for f in findings} == {"TEST-active"}
        assert findings[0].details["advisory_ids"] == ["TEST-active", "TEST-future"]
        source_records = {a["id"]: a for a in findings[0].details["advisories"]}
        assert set(source_records) == {"TEST-active", "TEST-future"}
        details = findings[0].details
        assert details["cve_ids"] == ["CVE-2026-12345"]
        assert details["cwe_ids"] == ["CWE-77", "CWE-94"]
        assert details["weaknesses_status"] == ("incomplete" if phase else "reported")
        assert {
            (r["id"], r["advisory_id"], r["field"])
            for r in details["identifier_references"]
        } == {
            ("CVE-2026-12345", "TEST-active", "aliases"),
            ("CVE-2026-12345", "TEST-future", "aliases"),
            ("CWE-77", "TEST-active", "database_specific.cwe_ids"),
            ("CWE-94", "TEST-future", "database_specific.cwe_ids"),
        }
        assert "https://www.cve.org/CVERecord?id=CVE-2026-12345" in render_text(result)
        assert "https://cwe.mitre.org/data/definitions/77.html" in render_text(result)
        assert "CWE-79" not in render_text(result)
        assert any(
            d.code == "osv.invalid-weakness-metadata" for d in result.diagnostics
        ) is bool(phase)
        assert (
            source_records["TEST-future"]["withdrawn"]
            == "2026-10-17T00:00:00.123456001Z"
        )
        assert "withdrawn" not in findings[0].details
        assert next(
            f.details["fix_version"]
            for f in findings
            if f.details["id"] == "TEST-active"
        ) == str(2 + phase)
        assert {d.code for d in result.diagnostics} >= {
            "osv.withdrawn-advisory",
            "osv.withdrawal-pending",
        }
        exported = json.loads(render_json(result))
        exported_details = next(
            f["details"]
            for f in exported["findings"]
            if f["code"] == "security.vulnerability"
        )
        assert (
            exported_details["identifier_references"]
            == details["identifier_references"]
        )
        assert (
            len(
                [
                    f
                    for f in exported["findings"]
                    if f["code"] == "security.vulnerability"
                ]
            )
            == 1
        )
        sarif = build_sarif(result)["runs"][0]["results"]
        assert next(
            f["properties"]["cwe_ids"]
            for f in sarif
            if f["properties"]["finding_code"] == "security.vulnerability"
        ) == ["CWE-77", "CWE-94"]
        assert {
            f["properties"]["id"]
            for f in sarif
            if f["properties"]["finding_code"] == "security.vulnerability"
        } == {"TEST-active"}
        assert next(
            f["properties"]["advisory_ids"]
            for f in sarif
            if f["properties"]["finding_code"] == "security.vulnerability"
        ) == ["TEST-active", "TEST-future"]
        exemption = {
            "risk": "vuln",
            "package": "foo",
            "ecosystem": "PyPI",
            "project_id": "pypi:python:.",
            "reason": "temporary mitigation",
            "owner": "platform",
            "expires_at": "2026-11-01",
            "advisory_ids": ["TEST-withdrawn"],
            "versions": ["1"],
        }
        policy = {"fail_on": ["vuln"], "exemptions": [exemption]}
        assert evaluate_policy(result, policy, today=date(2026, 10, 17)).should_fail()
        exemption["advisory_ids"] = ["CVE-2026-12345"]
        assert not evaluate_policy(
            result, policy, today=date(2026, 10, 17)
        ).should_fail()
    assert session.gets == 4
    after = {
        str(f.relative_to(tmp_path)): (f.read_bytes(), f.stat().st_mtime_ns)
        for f in tmp_path.rglob("*")
        if f.is_file()
    }
    assert after == before


@pytest.mark.parametrize(
    "selection,public",
    [
        ("public", True),
        ("private", False),
        ("default", True),
        ("missing", False),
        ("duplicate", False),
    ],
)
@pytest.mark.parametrize("filename", ["Pipfile", "Pipfile.lock"])
def test_pipenv_source_selection_controls_public_queries_and_persists(
    tmp_path, selection, public, filename
):
    import tomllib

    source = (
        '[[source]]\nname="pypi"\nurl="https://pypi.org/simple"\nverify_ssl=true\n'
        '[[source]]\nname="private"\nurl="https://private.example/simple"\nverify_ssl=true\n'
    )
    if selection == "duplicate":
        source = source.replace('name="private"', 'name="pypi"')
    entry = (
        '"==2.31.0"'
        if selection == "default"
        else '{version="==2.31.0",index="'
        + {
            "public": "pypi",
            "private": "private",
            "missing": "absent",
            "duplicate": "pypi",
        }[selection]
        + '"}'
    )
    (tmp_path / "Pipfile").write_text(source + "[packages]\nrequests=" + entry + "\n")
    expected_line = 10
    if filename == "Pipfile.lock":
        (tmp_path / "Pipfile").write_text('[packages]\nrequests="==2.31.0"\n')
        lock_text = json.dumps(
            {
                "_meta": {"sources": tomllib.loads(source)["source"]},
                "default": {"requests": tomllib.loads("item=" + entry)["item"]},
            },
            indent=2,
        )
        (tmp_path / filename).write_text(lock_text)
        expected_line = next(
            i
            for i, line in enumerate(lock_text.splitlines(), 1)
            if line.lstrip().startswith('"requests":')
        )
    (tmp_path / "app.py").write_text("import requests\n")

    class OSV:
        def __init__(self):
            self.queries = []

        def scan(self, packages):
            self.queries.append(dict(packages))
            return OSVScanResult({}, (), dict(packages))

    osv = OSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert bool(osv.queries) is public
    assert result.capability("security").complete is public
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    (tmp_path / "app.py").write_text("import requests\n# source edit\n")
    service.index_repository()
    record = service.explain_dependency("requests")
    declaration = next(
        d for d in record["declarations"] if d["location"]["path"] == filename
    )
    assert declaration["metadata"]["origin"]["public"] is public
    assert declaration["location"]["line"] == expected_line
    assert bool(record["purl"]) is public


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


@pytest.mark.parametrize("advisory", ["OSV-A", "CVE-2026-12345"])
def test_policy_exemption_selects_advisory_alias_and_exact_version(
    advisory: str,
) -> None:
    result = sample_result()
    findings = tuple(
        Finding(
            "security.vulnerability",
            PackageIdentity("npm:npm:.", "npm", "app-lib", version),
            "error",
            "vulnerability",
            details={"id": identifier, "aliases": aliases},
        )
        for identifier, aliases, version in (
            ("OSV-A", ["CVE-2026-12345"], "1.0.0"),
            ("OSV-B", [], "1.0.0"),
            ("OSV-A", ["CVE-2026-12345"], "2.0.0"),
            ("OSV-A", [], None),
        )
    )
    result = replace(result, findings=findings)
    exemption = {
        "risk": "vuln",
        "package": "app-lib",
        "ecosystem": "npm",
        "project_id": "npm:npm:.",
        "reason": "temporary mitigation",
        "owner": "platform",
        "expires_at": "2026-11-01",
        "advisory_ids": [advisory],
        "versions": ["1.0.0"],
    }
    evaluation = evaluate_policy(
        result,
        {"fail_on": ["vuln"], "exemptions": [exemption]},
        today=date(2026, 10, 15),
    )
    assert evaluation.effective_findings == findings[1:]
    assert evaluation.should_fail()
    assert evaluation.result.findings == findings


@pytest.mark.parametrize(
    "selectors",
    [
        {"advisory_ids": []},
        {"advisory_ids": "OSV-A"},
        {"advisory_ids": [42]},
        {"versions": []},
        {"versions": [None]},
        {"risk": "unused", "advisory_ids": ["OSV-A"]},
    ],
)
def test_invalid_policy_selectors_fail_closed(selectors: dict) -> None:
    result = sample_result()
    evaluation = evaluate_policy(
        result,
        {
            "exemptions": [
                {
                    "risk": "unused",
                    "package": "app-lib",
                    "reason": "migration",
                    "owner": "platform",
                    "expires_at": "2026-11-01",
                    **selectors,
                }
            ]
        },
        today=date(2026, 10, 15),
    )
    assert evaluation.effective_findings == result.findings
    assert evaluation.invalid_exemptions
    assert evaluation.should_fail()


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


def test_cyclonedx_omits_constraints_and_install_hints(tmp_path: Path) -> None:

    (tmp_path / "requirements.txt").write_text("app-lib>=1\n-c constraints.txt\n")
    (tmp_path / "constraints.txt").write_text("requests==2.31.0\n")
    (tmp_path / "Dockerfile").write_text("RUN pip install hinted==1.0\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bom = build_cyclonedx(result)

    assert [component["name"] for component in bom["components"]] == ["app-lib"]
    assert bom["dependencies"][0]["dependsOn"] == [bom["components"][0]["bom-ref"]]


@pytest.mark.parametrize("resolved", [True, False], ids=["locked", "unresolved"])
def test_cyclonedx_transitive_is_neither_direct_nor_optional(resolved) -> None:
    result = sample_result()
    bundle = result.bundles[0]
    if not resolved:
        transitive = replace(
            bundle.declarations[0],
            package=bundle.resolved[1].package,
            kind="transitive",
        )
        result = replace(
            result,
            bundles=(
                replace(
                    bundle, resolved=(), declarations=(*bundle.declarations, transitive)
                ),
            ),
        )
    bom = build_cyclonedx(result)
    components = {component["name"]: component for component in bom["components"]}
    assert bom["dependencies"][0]["dependsOn"] == [components["app-lib"]["bom-ref"]]
    for name, component in components.items():
        assert "scope" not in component
        properties = {item["name"]: item["value"] for item in component["properties"]}
        assert properties["depcheck:dependency:direct"] == (
            "true" if name == "app-lib" else "false"
        )


def test_cargo_security_uses_registry_coordinates_and_sbom_keeps_instances(tmp_path):

    class RecordingOSV:
        def __init__(self):
            self.calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((dict(packages), ecosystem))
            return OSVScanResult({}, (), dict(packages))

    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nfoo="=1.2.3"\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.2.3"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname="foo"\nversion="2.0.0"\nsource="git+https://example.com/foo#abcd"\n'
    )
    osv = RecordingOSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert osv.calls == [({"foo": "1.2.3"}, "crates.io")]
    assert not result.capability("security").complete
    assert not any(
        f.code in {"dependency.missing", "dependency.unused"} for f in result.findings
    )
    components = build_cyclonedx(result)["components"]
    assert len(components) == 2
    assert len({c["bom-ref"] for c in components}) == 2
    registry = next(c for c in components if c["version"] == "1.2.3")
    git = next(c for c in components if c["version"] == "2.0.0")
    assert registry["purl"] == "pkg:cargo/foo@1.2.3"
    assert "purl" not in git
    assert {p["name"]: p["value"] for p in registry["properties"]}[
        "depcheck:dependency:direct"
    ] == "true"


def test_cargo_conditional_pins_do_not_establish_a_declaration_conflict(tmp_path):

    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\n'
        '[target."cfg(unix)".dependencies]\nfoo="=1.0.0"\n'
        '[target."cfg(windows)".dependencies]\nfoo="=2.0.0"\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)


def test_cyclonedx_import_preserves_qualified_instances_and_graph(tmp_path):

    (tmp_path / "package.json").write_text('{"dependencies":{"one":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/one": {
                        "version": "1.0.0",
                        "dependencies": {"two": "2.0.0"},
                    },
                    "node_modules/two": {"version": "2.0.0"},
                }
            }
        )
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    (tmp_path / "bom.json").write_text(json.dumps(build_cyclonedx(scan)))
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    actual = {
        tuple(
            i["identity"].get(k)
            for k in ("project_id", "ecosystem", "package", "version", "instance")
        )
        for i in result["components"]
    }
    assert actual == {r.identity.coordinates for b in scan.bundles for r in b.resolved}
    one = next(c for c in result["components"] if c["identity"]["package"] == "one")
    assert len(one["dependencies"]) == 1
    assert result["capabilities"]["usage"]["state"] == "unsupported"
    assert result["capabilities"]["security"]["state"] == "skipped"
    assert result["provenance"]["sha256"]
    assert not (tmp_path / ".depcheck").exists()


def test_external_sbom_keeps_unknown_identity_and_dangling_edges(tmp_path):

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [{"type": "library", "bom-ref": "opaque", "name": "closed-sdk"}],
        "dependencies": [{"ref": "opaque", "dependsOn": ["missing"]}],
    }
    (tmp_path / "bom.json").write_text(json.dumps(bom))
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert result["components"][0]["identity"]["ecosystem"] == "unknown"
    assert "version" not in result["components"][0]["identity"]
    assert result["capabilities"]["inventory"]["state"] == "incomplete"
    assert {d["code"] for d in result["diagnostics"]} >= {
        "sbom.identity-unknown",
        "sbom.edge-unresolved",
    }


@pytest.mark.parametrize(
    "manager,manifest,one,two",
    [
        ("npm", "package-lock.json", "pkg:npm/one@1.0.0", "pkg:npm/two@2.0.0"),
        (
            "pom",
            "pom.xml",
            "pkg:maven/org.example/one@1.0.0",
            "pkg:maven/org.example/two@2.0.0",
        ),
    ],
)
def test_sbom_separates_trivy_groups_from_package_directness(
    tmp_path, manager, manifest, one, two
):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {"component": {"bom-ref": "app", "name": "app"}},
                "components": [
                    {
                        "bom-ref": "group",
                        "name": manifest,
                        "type": "application",
                        "properties": [
                            {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                            {"name": "aquasecurity:trivy:Type", "value": manager},
                            {"name": "depcheck:dependency:direct", "value": "true"},
                        ],
                    },
                    {
                        "bom-ref": "one",
                        "name": "one",
                        "type": "library",
                        "purl": one,
                        "scope": "optional",
                        "licenses": [{"license": {"id": "MIT"}}],
                    },
                    {"bom-ref": "two", "name": "two", "purl": two},
                ],
                "dependencies": [
                    {"ref": "app", "dependsOn": ["group"]},
                    {"ref": "group", "dependsOn": ["one", "two"]},
                    {"ref": "one", "dependsOn": ["two"]},
                ],
            }
        )
    )
    original = path.read_bytes()
    service = DependencyAgentService(tmp_path)
    first = service.inspect_dependency_sbom("bom.json", limit=1)
    group = first["components"][0]
    assert group["kind"] == "dependency-group"
    assert group["component_type"] == "application"
    assert group["direct"] is None
    assert group["dependencies"] == ["one", "two"]
    assert first["application"]["dependencies"] == ["group"]
    assert first["total"] == 3 and first["next_offset"] == 1
    assert first["capabilities"]["inventory"]["state"] == "complete"
    assert first["capabilities"]["resolution"]["state"] == "complete"
    assert first["diagnostics"] == []
    packages = service.inspect_dependency_sbom("bom.json", limit=2, offset=1)[
        "components"
    ]
    assert [p["kind"] for p in packages] == ["package", "package"]
    assert [p["dependency_groups"] for p in packages] == [["group"], ["group"]]
    assert [p["direct"] for p in packages] == [None, None]
    assert packages[0]["scope"] == "optional"
    assert packages[0]["licenses"] == [{"license": {"id": "MIT"}}]
    assert first["capabilities"]["usage"]["state"] == "unsupported"
    assert first["capabilities"]["security"]["state"] == "skipped"
    assert path.read_bytes() == original and not (tmp_path / ".depcheck").exists()


@pytest.mark.parametrize(
    "license_entry,field,value",
    [
        ({"license": {"id": "MIT"}}, "id", "MIT"),
        ({"license": {"name": "Vendor terms"}}, "name", "Vendor terms"),
        ({"expression": "MIT OR Apache-2.0"}, "expression", "MIT OR Apache-2.0"),
    ],
)
def test_sbom_preserves_license_assertions_and_repeated_source_properties(
    tmp_path, license_entry, field, value
):
    component = {
        "name": "library",
        "purl": "pkg:npm/library@1.0.0",
        "licenses": [license_entry],
        "properties": [
            {"name": "source:path", "value": "first/package-lock.json"},
            {"name": "source:path", "value": "second/package-lock.json"},
        ],
    }
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {"component": component},
                "components": [component],
            }
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    for record in (result["components"][0], result["application"]):
        entry = record["licenses"][0]
        assert (entry if field == "expression" else entry["license"])[field] == value
        assert record["properties"] == [
            {"name": "source:path", "value": "first/package-lock.json"},
            {"name": "source:path", "value": "second/package-lock.json"},
        ]
    assert result["components"][0]["identity_provenance"] == "sbom-asserted"


@pytest.mark.parametrize("kind", ["library", "missing-type", "duplicate-class", "purl"])
def test_sbom_group_properties_do_not_hide_package_identity_gaps(tmp_path, kind):
    component = {
        "name": "opaque",
        "type": "application" if kind != "library" else "library",
        "properties": [
            {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
            {"name": "aquasecurity:trivy:Type", "value": "npm"},
        ],
    }
    if kind == "missing-type":
        component.pop("type")
    elif kind == "duplicate-class":
        component["properties"].append(
            {"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"}
        )
    elif kind == "purl":
        component["purl"] = "pkg:npm/opaque"
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [component]}
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert result["components"][0]["kind"] != "dependency-group"
    assert result["capabilities"]["inventory"]["state"] == "incomplete"
    assert any(d["code"] == "sbom.version-unknown" for d in result["diagnostics"])


def test_sbom_retains_application_edges(tmp_path):

    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {
                    "component": {
                        "bom-ref": "application",
                        "name": "app",
                        "type": "application",
                    }
                },
                "components": [
                    {
                        "bom-ref": "library",
                        "name": "requests",
                        "purl": "pkg:pypi/requests@2.32.0",
                    }
                ],
                "dependencies": [{"ref": "application", "dependsOn": ["library"]}],
            }
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert result["application"]["dependencies"] == ["library"]
    assert result["components"][0]["direct"] is True


def test_sbom_retains_service_generator_and_unknown_version_diagnostic(tmp_path):

    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {
                    "tools": {
                        "services": [{"name": "hosted-generator", "version": "2.4"}]
                    }
                },
                "components": [{"name": "requests", "purl": "pkg:pypi/requests"}],
            }
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert result["provenance"]["tools"][0]["version"] == "2.4"
    assert any(d["code"] == "sbom.version-unknown" for d in result["diagnostics"])


def test_sbom_unversioned_scoped_package_does_not_resolve_synthetic_refs(tmp_path):

    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"name": "@scope/tool", "purl": "pkg:npm/@scope/tool"}],
                "dependencies": [{"ref": "unreferenced:0", "dependsOn": []}],
            }
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert result["components"][0]["identity"]["package"] == "@scope/tool"
    assert result["components"][0]["bom_ref"] is None
    assert {d["code"] for d in result["diagnostics"]} >= {
        "sbom.version-unknown",
        "sbom.edge-unresolved",
    }


@pytest.mark.parametrize(
    "suffix,field,expected",
    [
        (
            "?repository_url=https%3A%2F%2Fprivate.example",
            "qualifiers",
            {"repository_url": "https://private.example"},
        ),
        (
            "?classifier=sources&type=jar",
            "qualifiers",
            {"classifier": "sources", "type": "jar"},
        ),
        ("#src/main", "subpath", "src/main"),
    ],
)
def test_sbom_keeps_purl_identity_dimensions_without_claiming_full_resolution(
    tmp_path, suffix, field, expected
):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {
                        "bom-ref": "plain",
                        "name": "tool",
                        "purl": "pkg:maven/org.example/tool@1",
                    },
                    {
                        "bom-ref": "qualified",
                        "name": "tool",
                        "purl": "pkg:maven/org.example/tool@1" + suffix,
                    },
                ],
            }
        )
    )
    original = path.read_bytes()
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    plain, qualified = result["components"]
    assert plain["identity"] != qualified["identity"]
    assert qualified["identity"][field] == expected
    assert qualified["package_url"][field] == expected
    assert qualified["purl"] == "pkg:maven/org.example/tool@1" + suffix
    assert result["capabilities"]["inventory"]["state"] == "incomplete"
    assert result["capabilities"]["resolution"]["state"] == "incomplete"
    assert result["capabilities"]["usage"]["state"] == "unsupported"
    assert result["capabilities"]["security"]["state"] == "skipped"
    assert any(d["code"] == "sbom.identity-qualified" for d in result["diagnostics"])
    assert path.read_bytes() == original and not (tmp_path / ".depcheck").exists()


@pytest.mark.parametrize(
    "purl,ecosystem,package,version",
    [
        (
            "pkg://NPM/%40Scope/LegacyName@1%2Bbuild",
            "npm",
            "@Scope/LegacyName",
            "1+build",
        ),
        ("pkg:pypi/My_Package.Name@2.0", "PyPI", "my-package-name", "2.0"),
        (
            "pkg:golang/github.com/Owner/Module@v1.0.0",
            "Go",
            "github.com/Owner/Module",
            "v1.0.0",
        ),
        ("pkg:cargo/foo@1.2.3", "Cargo", "foo", "1.2.3"),
        ("pkg:npm/%40scope/tool", "npm", "@scope/tool", None),
    ],
)
def test_sbom_parses_supported_purl_components_without_losing_case(
    tmp_path, purl, ecosystem, package, version
):
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"name": "reported", "purl": purl}],
            }
        )
    )
    component = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")[
        "components"
    ][0]
    assert component["identity"]["ecosystem"] == ecosystem
    assert component["identity"]["package"] == package
    assert component["identity"].get("version") == version
    assert component["package_url"]["type"] in {"npm", "pypi", "golang", "cargo"}
    assert component["purl"] == purl


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:pypi/vendor/requests@2",
        "pkg:cargo/vendor/foo@1",
        "pkg:maven/artifact@1",
        "pkg:npm/not-a-scope/tool@1",
        "pkg:npm/%40scope/nested/tool@1",
        "pkg:npm/tool@1?arch=x86&ARCH=arm",
        "pkg:npm/tool@1?arch=x86&arch=arm",
        "pkg:npm/tool@1?=x86",
        "pkg:npm/tool@1?bad%20key=x86",
        "pkg:npm/tool@1#../src",
        "pkg:npm/tool@1#src/%2e%2e",
        "pkg:npm/tool@1#src%2Fmain",
        "pkg:npm/tool@1?repository_url=%FF",
        "pkg:npm/tool@1?repository_url=%00",
        "pkg:npm/tool\n@1",
        "pkg:npm/%40scope%2Fother/tool@1",
        "pkg:npm/%40scope//tool@1",
        "pkg:golang/example.com//module@v1",
        "pkg:npm/tool @1",
    ],
)
def test_sbom_rejects_malformed_purl_dimensions(tmp_path, purl):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [{"name": "tool", "purl": purl}],
            }
        )
    )
    original = path.read_bytes()
    with pytest.raises(ValueError, match="SBOM package"):
        DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    assert path.read_bytes() == original and not (tmp_path / ".depcheck").exists()


def test_sbom_preserves_unknown_purl_type_dimensions_as_external_assertions(tmp_path):
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {"name": "sdk", "purl": "pkg:generic/vendor/sdk@2?arch=arm64#lib"}
                ],
            }
        )
    )
    result = DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")
    record = result["components"][0]
    assert record["identity"]["ecosystem"] == "unknown"
    assert record["package_url"] == {
        "type": "generic",
        "namespace": "vendor",
        "name": "sdk",
        "version": "2",
        "qualifiers": {"arch": "arm64"},
        "subpath": "lib",
    }
    assert "version" not in record["identity"]
    assert result["capabilities"]["inventory"]["state"] == "incomplete"


def test_configured_python_indexes_do_not_implicitly_use_public_registry(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n[[tool.uv.index]]\nname="private"\nurl="https://private.invalid/simple"\ndefault=true\n'
    )

    class OSV:
        def scan(self, packages):
            raise AssertionError("Unverified index reached public OSV")

    result = RepositoryScanner(osv_client=OSV()).scan(
        tmp_path, RepositoryScanOptions(security=True)
    )
    assert not result.capability("security").complete
    assert any(d.code == "security.identity-unverified" for d in result.diagnostics)


def test_sarif_positions_use_portable_bases_and_preserve_notification_locations(
    monkeypatch,
):
    from depcheck.model import Diagnostic

    result = sample_result()
    result = replace(
        result,
        root=Path("/repo/../repo"),
        findings=(
            replace(
                result.findings[0],
                locations=(SourceLocation(Path("src/a #雪%.js"), 7, 9),),
            ),
        ),
        diagnostics=(
            Diagnostic(
                "source.invalid",
                "error",
                "cannot parse source",
                SourceLocation(Path("src/a #雪%.js"), 8, 4),
            ),
            Diagnostic(
                "source.skipped",
                "warning",
                "file-only evidence",
                SourceLocation(Path("package.json")),
            ),
            Diagnostic("coverage.unknown", "warning", "no source location"),
        ),
    )
    expected_summary = result.to_dict()["summary"]

    def unexpected(*_args, **_kwargs):
        pytest.fail(
            "SARIF projection must not resolve source paths or serialize inventory"
        )

    monkeypatch.setattr(Path, "resolve", unexpected)
    monkeypatch.setattr(ScanResult, "to_dict", unexpected)
    run = build_sarif(result)["runs"][0]
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert run["columnKind"] == "unicodeCodePoints"
    assert run["newlineSequences"] == ["\r\n", "\r", "\n"]
    assert location["artifactLocation"] == {
        "uri": "src/a%20%23%E9%9B%AA%25.js",
        "uriBaseId": "%SRCROOT%",
    }
    assert location["region"] == {"startLine": 7, "startColumn": 9}
    assert "%SRCROOT%" in run["originalUriBaseIds"]
    assert "uri" not in run["originalUriBaseIds"]["%SRCROOT%"]
    assert run["invocations"][0]["properties"] == expected_summary
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert notifications[0]["message"]["text"] == "cannot parse source"
    assert notifications[0]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 8,
        "startColumn": 4,
    }
    assert (
        notifications[0]["locations"][0]["physicalLocation"]["artifactLocation"]
        == location["artifactLocation"]
    )
    assert "region" not in notifications[1]["locations"][0]["physicalLocation"]
    assert "locations" not in notifications[2]
    assert not run["invocations"][0]["executionSuccessful"]


def test_sarif_external_paths_do_not_become_same_named_repository_files():
    from depcheck.model import Diagnostic

    result = sample_result()
    first = Path("/external-one/requirements.txt")
    second = Path("/external-two/requirements.txt")
    third = Path("../external-three/requirements.txt")
    result = replace(
        result,
        findings=(
            replace(
                result.findings[0],
                locations=(
                    SourceLocation(first),
                    SourceLocation(second),
                    SourceLocation(third),
                ),
            ),
        ),
        diagnostics=(
            Diagnostic(
                "source.invalid", "error", "outside assertion", SourceLocation(first)
            ),
        ),
    )
    run = build_sarif(result)["runs"][0]
    artifacts = [
        location["physicalLocation"]["artifactLocation"]
        for location in run["results"][0]["locations"]
    ]
    assert len({a["uri"] for a in artifacts}) == 3
    assert all(
        a["uri"].startswith("file:///") and "uriBaseId" not in a for a in artifacts
    )
    assert all(a["uri"].endswith("requirements.txt") for a in artifacts)
    assert (
        run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]
        == artifacts[0]
    )


@pytest.mark.parametrize("known_project", [True, False])
def test_sarif_fallback_requires_a_manifest_from_the_affected_project(known_project):
    result = sample_result()
    finding = replace(
        result.findings[0],
        package=replace(
            result.findings[0].package,
            project_id="npm:npm:." if known_project else "npm:npm:absent",
        ),
        locations=(),
    )
    report = build_sarif(replace(result, findings=(finding,)))["runs"][0]["results"][0]
    assert report["message"]["text"] == finding.message
    if known_project:
        assert report["locations"][0]["physicalLocation"] == {
            "artifactLocation": {"uri": "package.json", "uriBaseId": "%SRCROOT%"}
        }
        assert "depcheck:location-status" not in report["properties"]
    else:
        assert report["locations"] == []
        assert report["properties"]["depcheck:location-status"] == "unavailable"
