"""Python pylock collection, ownership, and qualified static evidence."""

import json
from pathlib import Path

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions


@pytest.fixture
def pylock_inventory_data():
    return {
        "lock-version": "1.0",
        "created-by": "controlled-fixture",
        "packages": [
            {
                "name": "requests",
                "version": "2.31.0",
                "index": "https://pypi.org/simple",
                "wheels": [
                    {
                        "url": "https://files.pythonhosted.org/requests-2.31.0-py3-none-any.whl",
                        "hashes": {"sha256": "a" * 64},
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    "filename,known,unknown",
    [
        ("pylock.toml", {("simple", "2.0"), ("simplewheel", "2.0")}, {"simple2"}),
        ("pylock.mixed.toml", {("simplewheel", "2.0")}, {"singlemodule"}),
        ("pylock.directory.toml", set(), {"simplewheel", "singlemodule"}),
        ("pylock.certifi-with-upload_time.toml", {("certifi", "2026.6.17")}, set()),
        ("pylock.prerelease-wheel.toml", {("pkg-prerelease", "1.0a1")}, set()),
    ],
)
def test_pylock_inventory_native_pip_files_keep_sources_positions_and_unknown_versions(
    tmp_path, monkeypatch, filename, known, unknown
):
    import packaging.pylock as native
    from depcheck.ecosystems.python.parsers.pylock import PylockParser
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.filesystem import capture_reads

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "Static pylock interpretation must not select the host or fetch artifacts"
        )

    monkeypatch.setattr(native.Pylock, "select", forbidden)
    monkeypatch.setattr(native, "sys_tags", forbidden)
    monkeypatch.setattr(native, "default_environment", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    original = Path(__file__).parent / "fixtures/projects/pylock-pip" / filename
    path = tmp_path / filename
    path.write_bytes(original.read_bytes())
    before = path.read_bytes(), path.stat().st_mtime_ns
    with capture_reads() as reads:
        parsed = PylockParser(path).parse_detailed()
    assert set(reads) == {path.resolve()}
    assert {
        (r.name, r.pinned_version)
        for r in parsed.declarations
        if r.pinned_version is not None
    } == known
    assert {r.name for r in parsed.declarations if r.pinned_version is None} == unknown
    assert all(
        r.source.line is not None and r.metadata["activation"] == "unknown"
        for r in parsed.declarations
    )
    assert [r.metadata["package_index"] for r in parsed.declarations] == list(
        range(len(parsed.declarations))
    )
    assert all(r.origin["public"] is False for r in parsed.declarations)
    assert any(
        d.code == "resolution.pylock-activation-unknown" for d in parsed.diagnostics
    )
    assert not any(d.severity == "error" for d in parsed.diagnostics)
    report = CompatibilityChecker().check_detailed(parsed, python_version="3.15")
    assert report.resolution_status == "incomplete" and not report.suggestions
    if "upload_time" in filename:
        record = parsed.declarations[0]
        assert (
            record.metadata["context"]["package"]["sdist"]["upload-time"]
            == "2026-06-17T10:31:07+00:00"
        )
        json.dumps(record.metadata)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_pylock_inventory_public_private_instances_survive_cache_sbom_and_advisories(
    tmp_path, pylock_inventory_data
):
    import copy
    import tomlkit
    from depcheck.reporting.cyclonedx import build_cyclonedx
    from depcheck.security.osv_client import OSVScanResult

    data = pylock_inventory_data
    data["environments"] = ["sys_platform == 'win32'"]
    data["dependency-groups"] = ["ci"]
    first = data["packages"][0]
    first["marker"] = "'ci' in dependency_groups"
    for version, index, host in [
        ("2.31.0", "https://private.invalid/simple", "private.invalid"),
        ("2.32.0", "https://pypi.org/simple", "files.pythonhosted.org"),
        ("2.29.0", "https://pypi.org/simple", "private.invalid"),
    ]:
        row = copy.deepcopy(first)
        row["version"], row["index"] = version, index
        row["wheels"][0]["url"] = f"https://{host}/requests-{version}-py3-none-any.whl"
        data["packages"].append(row)
    path = tmp_path / "pylock.toml"
    path.write_text(tomlkit.dumps(data))
    before = path.read_bytes(), path.stat().st_mtime_ns
    queries = []

    class Client:
        def scan(self, packages):
            queries.append(dict(packages))
            return OSVScanResult({}, (), packages)

    scan = RepositoryScanner(osv_client=Client()).scan(
        tmp_path,
        RepositoryScanOptions(security=True, compatibility=True, python_version="3.15"),
    )
    (bundle,) = scan.bundles
    assert len(bundle.resolved) == len({r.instance_id for r in bundle.resolved}) == 4
    assert all(r.instance_id.startswith("lock:pylock:") for r in bundle.resolved)
    assert len([r for r in bundle.resolved if r.version == "2.31.0"]) == 2
    assert {tuple(p.items())[0] for p in queries} == {
        ("requests", "2.31.0"),
        ("requests", "2.32.0"),
    }
    assert all(not r.dependencies and not r.dependency_links for r in bundle.resolved)
    assert all(
        r.metadata["conditional"] and r.metadata["activation"] == "unknown"
        for r in bundle.resolved
    )
    bom = build_cyclonedx(scan)
    assert len([c for c in bom["components"] if c["name"] == "requests"]) == 4
    assert (
        len([c for c in bom["components"] if c["name"] == "requests" and "purl" in c])
        == 2
    )
    (tmp_path / "inventory.json").write_text(json.dumps(scan.to_dict()))
    advisory = (
        Path(__file__).parent
        / "fixtures/projects/multilingual/advisories/GHSA-9wx4-h78v-vm56.json"
    )
    (tmp_path / "advisory.json").write_bytes(advisory.read_bytes())
    service = DependencyAgentService(tmp_path)
    observations = service.reevaluate_vulnerabilities(
        "inventory.json", "advisory.json"
    )["observations"]
    assert sorted(o["status"] for o in observations) == [
        "matched",
        "not-matched-in-supplied-records",
        "unknown",
        "unknown",
    ]
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    cached = cache.read_bytes(), cache.stat().st_mtime_ns
    query = service.explain_dependency("requests")
    assert len(query["resolutions"]) == 4 and not query["evidence_complete"]
    assert all(r["metadata"]["lock_format"] == "pylock" for r in query["resolutions"])
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == cached
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_pylock_inventory_informational_selectors_bind_raw_records_without_required_edges(
    tmp_path,
):
    import tomlkit
    from depcheck.ecosystems.python.parsers.pylock import PylockParser

    selectors = [
        {"name": "child", "vcs": {"url": "https://user:one@example.invalid/repo"}},
        {"name": "child", "vcs": {"url": "https://user:two@example.invalid/repo"}},
        {"name": "child"},
        {"name": "missing"},
    ]
    packages = [
        {
            "name": "parent",
            "version": "1.0",
            "archive": {
                "url": "https://example.invalid/parent.tar.gz",
                "hashes": {"sha256": "00"},
            },
            "dependencies": selectors,
        }
    ]
    for revision, password in [("aaa", "one"), ("bbb", "two")]:
        packages.append(
            {
                "name": "child",
                "vcs": {
                    "type": "git",
                    "url": f"https://user:{password}@example.invalid/repo",
                    "commit-id": revision,
                },
            }
        )
    path = tmp_path / "pylock.toml"
    path.write_text(
        tomlkit.dumps(
            {"lock-version": "1.0", "created-by": "controlled", "packages": packages}
        )
    )
    result = PylockParser(path).parse_detailed()
    assert len(result.declarations) == 3
    parent, a, b = result.declarations
    assert a.pinned_version is None and b.pinned_version is None
    info = parent.metadata["informational_dependencies"]
    assert [i["status"] for i in info] == [
        "matched-record",
        "matched-record",
        "ambiguous",
        "unresolved",
    ]
    assert info[0]["target_package_indices"] == [1] and info[1][
        "target_package_indices"
    ] == [2]
    assert info[0]["selector"] == info[1]["selector"]
    assert [i["source_pointer"] for i in info] == [
        f"/packages/0/dependencies/{i}" for i in range(4)
    ]
    assert a.origin["source_assertion_sha256"] != b.origin["source_assertion_sha256"]
    assert "user:one" not in json.dumps(
        parent.metadata
    ) and "user:two" not in json.dumps(parent.metadata)
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    (record,) = scan.bundles[0].resolved
    assert record.metadata["dependency_status"] == "informational-only"
    assert not record.dependencies and not record.dependency_links


@pytest.mark.parametrize(
    "fault",
    [
        "major",
        "missing-creator",
        "bad-array",
        "bad-source",
        "bad-marker",
        "bad-version",
        "tree-version",
    ],
)
def test_pylock_inventory_invalid_context_cannot_select_a_compatibility_graph(
    tmp_path, pylock_inventory_data, fault
):
    import tomlkit
    from depcheck.ecosystems.python.parsers.pylock import PylockParser
    from depcheck.compatibility.checker import CompatibilityChecker

    data = pylock_inventory_data
    package = data["packages"][0]
    if fault == "major":
        data["lock-version"] = "2.0"
    elif fault == "missing-creator":
        data.pop("created-by")
    elif fault == "bad-array":
        data["packages"] = {}
    elif fault == "bad-source":
        package["directory"] = {"path": "../../not-opened"}
    elif fault == "bad-marker":
        package["marker"] = "not a marker"
    elif fault == "bad-version":
        package["version"] = "https://user:pylock-secret@example.invalid"
    else:
        package.pop("wheels")
        package["directory"] = {"path": "../../not-opened"}
    path = tmp_path / "pylock.ci.toml"
    path.write_text(tomlkit.dumps(data))
    before = path.read_bytes(), path.stat().st_mtime_ns
    result = PylockParser(path).parse_detailed()
    assert any(d.severity == "error" for d in result.diagnostics)
    assert all(r.origin["public"] is False for r in result.declarations)
    assert "pylock-secret" not in json.dumps([d.message for d in result.diagnostics])
    if fault in {"bad-version", "tree-version"}:
        assert result.declarations and result.declarations[0].pinned_version is None
    report = CompatibilityChecker().check_detailed(result, python_version="3.15")
    assert report.resolution_status == "incomplete" and not report.suggestions
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize(
    "limit",
    ["packages", "record", "details", "work", "compressed-tags", "encoded-separator"],
)
def test_pylock_inventory_limits_preserve_uncertainty_before_native_expansion(
    tmp_path, monkeypatch, pylock_inventory_data, limit
):
    import tomlkit
    from depcheck.ecosystems.python.parsers import pylock as parser

    data = pylock_inventory_data
    if limit == "packages":
        monkeypatch.setattr(parser, "_MAX_PACKAGES", 0)
    elif limit == "record":
        monkeypatch.setattr(parser, "_MAX_RECORD", 1)
    elif limit == "details":
        monkeypatch.setattr(parser, "_MAX_DETAILS", 1)
    elif limit == "work":
        monkeypatch.setattr(parser, "_MAX_WORK", 0)
    else:
        tags = [
            ".".join([prefix + str(i) for i in range(100)])
            for prefix in ["py", "abi", "platform"]
        ]
        if limit == "encoded-separator":
            tags[-1] = "prefix%2F" + tags[-1]
        data["packages"][0]["wheels"][0]["url"] = (
            "https://files.pythonhosted.org/requests-2.31.0-" + "-".join(tags) + ".whl"
        )
        original = parser.Pylock.from_dict

        def guarded(cls, value):
            assert not value["packages"], "Compressed tags reached native expansion"
            return original(value)

        monkeypatch.setattr(parser.Pylock, "from_dict", classmethod(guarded))
    path = tmp_path / "pylock.toml"
    path.write_text(tomlkit.dumps(data))
    result = parser.PylockParser(path).parse_detailed()
    assert any(d.severity == "error" for d in result.diagnostics)
    assert all(r.origin["public"] is False for r in result.declarations)
    assert all(r.metadata["activation"] == "unknown" for r in result.declarations)
    if limit == "packages":
        assert not result.declarations
    else:
        assert result.declarations[0].pinned_version == "2.31.0"


@pytest.mark.parametrize(
    "extension", ["source-key", "attestation-key", "header-key", "bad-attestation"]
)
def test_pylock_inventory_optional_extensions_do_not_leak_keys_or_erase_known_versions(
    tmp_path, pylock_inventory_data, extension
):
    import tomlkit
    from depcheck.ecosystems.python.parsers.pylock import PylockParser

    data = pylock_inventory_data
    package = data["packages"][0]
    canary = "pylock-extension-key-canary"
    key = "https://user:" + canary + "@example.invalid"
    if extension == "source-key":
        package["wheels"][0]["hashes"][key] = "opaque"
    elif extension == "attestation-key":
        package["attestation-identities"] = [{"kind": "GitHub", key: "opaque"}]
    elif extension == "header-key":
        data[key] = "opaque"
    else:
        package["attestation-identities"] = [{"repository": "unverified"}]
    path = tmp_path / "pylock.toml"
    path.write_text(tomlkit.dumps(data))
    result = PylockParser(path).parse_detailed()
    (row,) = result.declarations
    assert row.pinned_version == "2.31.0" and canary not in json.dumps(
        dict(row.metadata)
    ) + json.dumps(dict(row.origin))
    assert canary not in json.dumps([d.message for d in result.diagnostics])
    assert len(row.origin["source_assertion_sha256"]) == 64
    if extension in {"source-key", "header-key"}:
        assert row.origin["public"] is False
    else:
        assert row.origin["public"] is True
    if extension == "bad-attestation":
        assert row.metadata["attestation_identities_status"] == "unverified"
        assert any(
            d.code == "manifest.pylock-attestation-unverified"
            for d in result.diagnostics
        )


def test_pylock_inventory_multiple_named_files_remain_distinct_unselected_instances(
    tmp_path, pylock_inventory_data
):
    import copy
    import tomlkit

    data = pylock_inventory_data
    (tmp_path / "pylock.toml").write_text(tomlkit.dumps(data))
    other = copy.deepcopy(data)
    other["packages"][0]["index"] = "https://private.invalid/simple"
    (tmp_path / "pylock.ci.toml").write_text(tomlkit.dumps(other))
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=True)
    )
    rows = scan.bundles[0].resolved
    assert len(rows) == len({r.instance_id for r in rows}) == 2
    assert {r.source.path.name for r in rows} == {"pylock.toml", "pylock.ci.toml"}
    assert [r.version for r in rows] == ["2.31.0", "2.31.0"]
    assert sum(r.origin["public"] is True for r in rows) == 1
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    query = service.explain_dependency("requests")
    assert len(query["resolutions"]) == 2 and not query["evidence_complete"]
    assert all(r["metadata"]["activation"] == "unknown" for r in query["resolutions"])


@pytest.mark.parametrize(
    "filename,recognized",
    [
        ("pylock.toml", True),
        ("pylock.ci.toml", True),
        ("pylock.linux-x86_64.toml", True),
        ("pylock.ci.backup.toml", False),
        ("library.pylock.toml", False),
    ],
)
def test_pylock_coverage_names_keep_declared_and_native_versions_separate(
    tmp_path, filename, recognized
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
    )
    (tmp_path / "app.py").write_text("import requests\n")
    lock = tmp_path / filename
    lock.write_text(
        'lock-version="1.0"\ncreated-by="example"\n[[packages]]\nname="requests"\nversion="2.32.4"\n'
        'index="https://pypi.org/simple"\nwheels=[{url="https://files.pythonhosted.org/requests-2.32.4-py3-none-any.whl",hashes={sha256="00"}}]\n'
    )
    before = lock.read_bytes(), lock.stat().st_mtime_ns
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    (bundle,) = result.bundles
    assert [r.version for r in bundle.resolved] == (
        ["2.32.4"] if recognized else ["2.31.0"]
    )
    diagnostics = [d for d in result.diagnostics if d.source and d.source.path == lock]
    gaps = [
        g for g in result.metadata["coverage"]["uncovered"] if g["path"] == filename
    ]
    if recognized:
        assert any(
            d.code == "resolution.pylock-activation-unknown" for d in diagnostics
        )
        assert not any(d.code == "coverage.unsupported-manifest" for d in diagnostics)
        assert len({(g["path"], g["reason"], g["project_id"]) for g in gaps}) == len(
            gaps
        )
        (record,) = bundle.resolved
        assert record.source.path == lock and record.source.line == 4
        declared = next(d for d in bundle.declarations if d.kind == "direct")
        assert declared.constraint.raw == "==2.31.0"
        assert bundle.project.locks == (Path(filename),)
        assert not result.capability("dependency_hygiene").complete
        assert next(c for c in bundle.capabilities if c.name == "manifest").complete
        assert all(g["project_id"] == "pypi:python:." for g in gaps)
        selected = RepositoryScanner().scan(
            tmp_path,
            RepositoryScanOptions(
                security=False, compatibility=False, project_ids=("pypi:python:.",)
            ),
        )
        assert any(
            d.code == "resolution.pylock-activation-unknown"
            for d in selected.diagnostics
        )
    else:
        assert not diagnostics and not gaps and not bundle.project.locks
    assert (lock.read_bytes(), lock.stat().st_mtime_ns) == before


@pytest.mark.parametrize("filename", ["pylock.toml", "pylock.ci.toml"])
def test_pylock_coverage_invalid_data_and_disabled_python_keep_scope(
    tmp_path, filename
):
    path = tmp_path / filename
    path.write_text("Not TOML: content parsing is unsupported\n")
    for configured in [False, True]:
        if configured:
            (tmp_path / ".depcheck.toml").write_text('enabled-ecosystems=["Cargo"]\n')
        result = RepositoryScanner().scan(
            tmp_path,
            RepositoryScanOptions(security=False, compatibility=False),
        )
        assert not result.capability("dependency_hygiene").complete
        assert len(result.metadata["coverage"]["uncovered"]) == 1
        assert not any(b.resolved or b.declarations for b in result.bundles)
        if not configured:
            assert len(result.bundles) == 1
            assert result.bundles[0].project.locks == (Path(filename),)
            assert [
                d.code for d in result.diagnostics if d.source and d.source.path == path
            ] == ["manifest.invalid-lockfile"]
        else:
            assert any(
                d.code == "coverage.unsupported-manifest" for d in result.diagnostics
            )
    selected = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, enabled_ecosystems=("Cargo",)
        ),
    )
    assert selected.metadata["coverage"]["scope"] == "selection"
    assert not selected.metadata["coverage"]["uncovered"]


@pytest.mark.parametrize("filtered", [False, True])
def test_pylock_coverage_tracks_new_changed_deleted_inputs_with_readonly_queries(
    tmp_path, filtered
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
    )
    (tmp_path / "app.py").write_text("import requests\n")
    service = DependencyAgentService(tmp_path)
    kwargs = {"project_ids": ("pypi:python:.",)} if filtered else {}
    service.index_repository(**kwargs)
    lock = tmp_path / "pylock.ci.toml"
    cache = tmp_path / ".depcheck/index.sqlite3"
    for operation in ["create", "change", "delete", "recreate"]:
        if operation == "delete":
            lock.unlink()
        else:
            lock.write_text(
                'lock-version="1.0"\ncreated-by="' + operation + '"\npackages=[]\n'
            )
        before = cache.read_bytes(), cache.stat().st_mtime_ns
        context = service.repository_context()
        assert context["stale"]
        with pytest.raises(RuntimeError, match="stale"):
            service.explain_dependency("requests", project_id="pypi:python:.")
        assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
        service.index_repository(**kwargs)
        context = service.repository_context()
        assert not context["stale"]
        gaps = [g for g in context["coverage"]["uncovered"] if g["path"] == lock.name]
        assert bool(gaps) == (operation != "delete")
        query = service.explain_dependency("requests", project_id="pypi:python:.")
        assert query["resolved_versions"] == ["2.31.0"]
        if operation != "delete":
            assert not query["evidence_complete"]


def test_pylock_coverage_stays_with_its_python_component_and_honors_exclusions(
    tmp_path,
):
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["vendor"]\n')
    for name in ["left", "right"]:
        child = tmp_path / name
        child.mkdir()
        (child / "pyproject.toml").write_text(
            '[project]\nname="' + name + '"\nversion="1"\n'
        )
    (tmp_path / "right/pylock.ci.toml").write_text("unsupported\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor/pylock.toml").write_text("excluded\n")
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, project_ids=("pypi:python:left",)
        ),
    )
    assert not any(d.code == "manifest.pylock-unsupported" for d in result.diagnostics)
    assert not result.metadata["coverage"]["uncovered"]
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    gaps = [
        g for g in result.metadata["coverage"]["uncovered"] if "pylock" in g["path"]
    ]
    assert len(gaps) == 1 and gaps[0]["path"] == "right/pylock.ci.toml"
    assert gaps[0]["project_id"] == "pypi:python:right"
