"""Python uv collection, ownership, and qualified static evidence."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.registry import ProviderContext
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


@pytest.mark.parametrize("named_project", [False, True])
def test_uv_legacy_dev_is_development_evidence_in_scan_and_readonly_query(
    tmp_path, named_project
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n[tool.uv]\ndev-dependencies=["pyyaml==6.0.2"]\n'
    )
    if not named_project:
        (tmp_path / "pyproject.toml").write_text(
            '[tool.uv]\ndev-dependencies=["pyyaml==6.0.2"]\n'
        )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert len(result.bundles[0].declarations) == 1
    declaration = result.bundles[0].declarations[0]
    assert declaration.package.name == "pyyaml" and declaration.scope == "development"
    assert declaration.metadata["group"] == "dev:dev" and declaration.source.line == (
        5 if named_project else 2
    )
    assert not any(
        f.code in {"dependency.missing", "dependency.scope-mismatch"}
        for f in result.findings
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency(
        "pyyaml", ecosystem="PyPI", project_id="pypi:python:."
    )
    assert len(record["declarations"]) == 1 and record["declarations"][0]["location"][
        "line"
    ] == (5 if named_project else 2)
    assert record["declarations"][0]["scope"] == "development"
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]


def test_uv_legacy_and_standard_dev_constraints_share_one_group(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n'
        '[dependency-groups]\nDEV=["pyyaml==6.0.1"]\n'
        'ci=[{include-group="dev"}]\n'
        '[tool.uv]\ndev-dependencies=["pyyaml==6.0.2"]\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    conflicts = [f for f in result.findings if f.code == "declaration.conflict"]
    assert len(conflicts) == 1 and conflicts[0].details["group"] == "dev:DEV"
    assert [
        d.constraint.raw
        for d in result.bundles[0].declarations
        if d.metadata["group"] == "dev:ci"
    ] == ["==6.0.1"]


def test_workspace_matcher_bounded_globs_and_shared_uv_membership(tmp_path):
    from depcheck.ecosystems.configuration.workspaces import _workspace_pattern
    from depcheck.ecosystems.python.collector import _uv_workspace_root

    pattern = _workspace_pattern("**/packages/**/a?*")
    assert pattern.fullmatch("packages/app")
    assert pattern.fullmatch("one/packages/two/app")
    assert not _workspace_pattern("*a" * 28 + "b").fullmatch("a" * 28 + "c")
    with pytest.raises(ValueError, match="budget"):
        _workspace_pattern("*a" * 2000).fullmatch("a" * 4096)
    (tmp_path / "pyproject.toml").write_text(
        '[tool.uv.workspace]\nmembers = ["**/apps/*"]\nexclude = ["**/skip"]\n'
    )
    member = tmp_path / "apps/demo"
    member.mkdir(parents=True)
    assert _uv_workspace_root(tmp_path, member) == tmp_path


def _uv_source_workspace(
    root, policy, *, membership='members=["packages/*"]', local=""
):
    manifest = root / "pyproject.toml"
    manifest.write_text(
        '[project]\nname="workspace"\nversion="1"\n[tool.uv.workspace]\n'
        + membership
        + "\n"
        + policy
    )
    member = root / "packages/member"
    member.mkdir(parents=True)
    (member / "pyproject.toml").write_text(
        '[project]\nname="member"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
        '[tool.hatch.envs.test]\ndependencies=["requests==2.31.0"]\n' + local
    )
    return manifest, member


@pytest.mark.parametrize("source", ["git", "path", "workspace", "index", "root-index"])
def test_uv_workspace_inherits_root_source_assertions_without_public_queries(
    tmp_path, source
):
    from depcheck.security.osv_client import OSVScanResult

    canary = "workspace-source-credential-canary"
    values = {
        "git": '{git="https://user:'
        + canary
        + "@example.invalid/requests?token="
        + canary
        + '"}',
        "path": '{path="vendor/requests"}',
        "workspace": "{workspace=true}",
        "index": '{index="private"}',
    }
    policy = (
        '[[tool.uv.index]]\nname="private"\nurl="https://private.example/simple"\ndefault=true\n'
        if source == "root-index"
        else "[tool.uv.sources]\nrequests=" + values[source] + "\n"
    )
    manifest, member = _uv_source_workspace(tmp_path, policy)
    originals = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in [manifest, member / "pyproject.toml"]
    }
    queries = []

    def query(packages):
        queries.append(dict(packages))
        return OSVScanResult({}, (), packages)

    scan = RepositoryScanner(osv_client=SimpleNamespace(scan=query)).scan(
        tmp_path,
        RepositoryScanOptions(
            project_ids=("pypi:python:packages/member",), compatibility=False
        ),
    )
    (bundle,) = scan.bundles
    (row,) = bundle.resolved
    assert not queries and row.package.purl is None and row.origin["public"] is False
    assert row.origin["kind"] == ("unknown" if source == "root-index" else source)
    if source == "root-index":
        metadata = row.metadata["uv_index_policy"]
        assert metadata["configuration"]["path"] == "pyproject.toml"
        assert (
            metadata["selection"] == "pyproject" and metadata["activation"] == "unknown"
        )
    else:
        metadata = row.metadata["inherited_uv_source"]
        assert (
            metadata["configuration_file"] == "pyproject.toml"
            and metadata["origin_base"] == "."
        )
        assert (
            metadata["membership"] == "confirmed"
            and metadata["activation"] == "unknown"
        )
        assert metadata["selection"] == "inherited"
        assert metadata["line"] is not None
    environment = next(d for d in bundle.declarations if d.kind == "environment")
    assert "inherited_uv_source" not in environment.metadata
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value
        for p, value in originals.items()
    )
    assert canary not in json.dumps(scan.to_dict())


@pytest.mark.parametrize(
    "boundary",
    [
        "excluded",
        "not-member",
        "managed-false",
        "invalid-glob",
        "bad-source-table",
        "normalized-collision",
        "source-budget",
        "projection-budget",
        "member-override",
    ],
)
def test_uv_workspace_source_policy_preserves_membership_and_override_boundaries(
    tmp_path, monkeypatch, boundary
):
    from depcheck.ecosystems.python import collector

    policy = '[tool.uv.sources]\nrequests={git="https://example.invalid/root"}\n'
    membership = 'members=["packages/*"]'
    local = ""
    if boundary == "excluded":
        membership += '\nexclude=["packages/member"]'
    elif boundary == "not-member":
        membership = 'members=["elsewhere/*"]'
    elif boundary == "managed-false":
        local = "[tool.uv]\nmanaged=false\n"
    elif boundary == "invalid-glob":
        membership = 'members=["packages/[abc]"]'
    elif boundary == "bad-source-table":
        policy = '[tool.uv]\nsources="invalid"\n'
    elif boundary == "normalized-collision":
        policy += 'Requests={path="elsewhere"}\n'
    elif boundary == "source-budget":
        from depcheck.ecosystems.python import source_policy

        monkeypatch.setattr(source_policy, "_UV_SOURCE_BYTES", 1)
    elif boundary == "projection-budget":
        monkeypatch.setattr(collector, "_UV_INHERITED_BYTES", 1)
    elif boundary == "member-override":
        local = '[tool.uv.sources]\nRequests={path="../own",marker="sys_platform == \'unselected-platform\'"}\n'
    _uv_source_workspace(tmp_path, policy, membership=membership, local=local)
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = next(b for b in scan.bundles if b.project.root == Path("packages/member"))
    (row,) = bundle.resolved
    if boundary in {"excluded", "not-member", "managed-false"}:
        assert (
            row.origin["public"] is True and "inherited_uv_source" not in row.metadata
        )
    elif boundary == "member-override":
        assert (
            row.origin["kind"] == "path" and row.origin["assertion"]["path"] == "../own"
        )
        assert (
            row.origin["assertion"]["marker"] == "sys_platform == 'unselected-platform'"
        )
        assert "inherited_uv_source" not in row.metadata
    else:
        assert row.origin["public"] is False and row.origin["kind"] == "unknown"
        assert row.metadata["inherited_uv_source"]["selection"] == "unverified"
        assert any(
            d.code == "manifest.uv-workspace-source-policy-unknown"
            for d in scan.diagnostics
        )
        if boundary == "projection-budget":
            assert (
                row.metadata["inherited_uv_source"]["original_origin_status"]
                == "omitted-by-budget"
            )


def test_uv_workspace_real_member_redundant_override_and_selected_cache(tmp_path):
    import shutil
    from depcheck.ecosystems.python.collector import create_python_pack

    fixtures = (
        Path(__file__).parent / "fixtures/projects/multilingual/pydantic-ai-0.0.14"
    )
    work = tmp_path / "work"
    shutil.copytree(fixtures, work)
    member_id = "pypi:python:pydantic_ai_examples"
    options = RepositoryScanOptions(security=False, project_ids=(member_id,))
    original_scan = RepositoryScanner().scan(work, options)
    original_row = next(
        r
        for r in original_scan.bundles[0].resolved
        if r.package.name == "pydantic-ai-slim"
    )
    path = work / "pydantic_ai_examples/pyproject.toml"
    text = path.read_text()
    redundant = "[tool.uv.sources]\npydantic-ai-slim = { workspace = true }\n"
    assert text.count(redundant) == 1
    path.write_text(text.replace(redundant, ""))
    originals = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in work.rglob("*")
        if p.is_file()
    }
    scan = RepositoryScanner().scan(work, options)
    (bundle,) = scan.bundles
    row = next(r for r in bundle.resolved if r.package.name == "pydantic-ai-slim")
    assert (
        row.origin
        == original_row.origin
        == {"kind": "workspace", "public": False, "assertion": {"workspace": True}}
    )
    assert row.version == original_row.version == "0.0.14" and row.package.purl is None
    assert row.instance_id == original_row.instance_id
    root_manifest = work / "pyproject.toml"
    expected_line = (
        root_manifest.read_text()
        .splitlines()
        .index("pydantic-ai-slim = { workspace = true }")
        + 1
    )
    metadata = row.metadata["inherited_uv_source"]
    assert (
        metadata["line"] == expected_line
        and metadata["configuration_file"] == "pyproject.toml"
    )
    assert row.source.path == path
    assert not bundle.project.locks
    assert not any(
        r.metadata.get("python_kind") == "lock-record" for r in bundle.resolved
    )
    pack = create_python_pack()
    declarations = pack.manifest_provider.collect(ProviderContext(work), bundle.project)
    assert (
        next(d for d in declarations if d.package.name == "pydantic-ai-slim").metadata[
            "inherited_uv_source"
        ]
        == metadata
    )
    bom = build_cyclonedx(scan)
    component = next(c for c in bom["components"] if c["name"] == "pydantic-ai-slim")
    assert "purl" not in component
    projection = next(
        p["value"]
        for p in component["properties"]
        if p["name"] == "depcheck:resolution:metadata"
    )
    assert json.loads(projection)["inherited_uv_source"] == metadata
    service = DependencyAgentService(work)
    service.index_repository(project_ids=(member_id,))
    cache = work / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    query = service.explain_dependency("pydantic-ai-slim", project_id=member_id)
    assert query["resolutions"][0]["metadata"]["inherited_uv_source"] == metadata
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value
        for p, value in originals.items()
    )
    root_manifest.write_text(
        root_manifest.read_text().replace(
            "pydantic-ai-slim = { workspace = true }",
            'pydantic-ai-slim = { git = "https://example.invalid/slim" }',
        )
    )
    assert service.repository_context()["stale"] is True
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("pydantic-ai-slim", project_id=member_id)
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    service.index_repository(project_ids=(member_id,))
    updated = service.explain_dependency("pydantic-ai-slim", project_id=member_id)
    assert updated["resolutions"][0]["origin"]["kind"] == "git"


def test_uv_workspace_inherited_policy_does_not_rewrite_independent_requirements_or_scripts(
    tmp_path,
):
    _, member = _uv_source_workspace(
        tmp_path, '[tool.uv.sources]\nrequests={git="https://example.invalid/root"}\n'
    )
    requirements = member / "requirements.txt"
    requirements.write_text("requests==2.31.0\n")
    script = member / "tool.py"
    script.write_text(
        '# /// script\n# dependencies = ["requests==2.31.0"]\n# ///\nimport requests\n'
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    component = next(
        b
        for b in scan.bundles
        if b.project.root == Path("packages/member") and b.project.manager == "python"
    )
    by_path = {row.source.path: row for row in component.resolved}
    assert by_path[member / "pyproject.toml"].origin["kind"] == "git"
    assert by_path[requirements].origin["public"] is True
    assert "inherited_uv_source" not in by_path[requirements].metadata
    independent = next(b for b in scan.bundles if b.project.manager == "pep723")
    assert independent.resolved[0].origin["public"] is True
    assert "inherited_uv_source" not in independent.resolved[0].metadata


def test_uv_workspace_lock_only_registry_field_cannot_authorize_public_sources(
    tmp_path,
):
    policy = '[tool.uv.sources]\nrequests={registry="https://pypi.org/simple"}\n'
    manifest, _ = _uv_source_workspace(tmp_path, policy)
    text = manifest.read_text().replace(
        'name="workspace"\nversion="1"',
        'name="workspace"\nversion="1"\ndependencies=["requests==2.31.0"]',
    )
    manifest.write_text(text)
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert len(scan.bundles) == 2
    for bundle in scan.bundles:
        (row,) = bundle.resolved
        assert row.origin["kind"] == "unknown" and row.origin["public"] is False
        assert row.package.purl is None
        assert row.origin["assertion"]["registry"] == "https://pypi.org/simple"
        assert any(
            d.code == "resolution.python-source-unverified" for d in bundle.diagnostics
        )


@pytest.mark.parametrize(
    "form", ["legacy", "extra", "uv-toml", "modern-toml", "find-links", "no-index"]
)
def test_uv_index_policy_private_assertions_reach_members_and_block_public_queries(
    tmp_path, form
):
    from depcheck.security.osv_client import OSVScanResult

    canary = "uv-index-credential-canary"
    url = "https://user:" + canary + "@private.invalid/simple?token=" + canary
    config = {
        "legacy": "index-url=" + json.dumps(url),
        "extra": "extra-index-url=[" + json.dumps(url) + "]",
        "uv-toml": "index-url=" + json.dumps(url),
        "modern-toml": "[[index]]\nurl=" + json.dumps(url) + "\ndefault=true",
        "find-links": 'find-links=["vendor/wheels"]',
        "no-index": "no-index=true",
    }[form]
    policy = (
        "[tool.uv]\n" + config + "\n" if form not in {"uv-toml", "modern-toml"} else ""
    )
    root, member = _uv_source_workspace(tmp_path, policy)
    if form in {"uv-toml", "modern-toml"}:
        (tmp_path / "uv.toml").write_text(config + "\n")
    # A member-level config is ignored in the workspace project namespace.
    (member / "uv.toml").write_text('index-url="https://pypi.org/simple"\n')
    before = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    queries = []

    def query(packages):
        queries.append(packages)
        return OSVScanResult({}, (), packages)

    scan = RepositoryScanner(osv_client=SimpleNamespace(scan=query)).scan(
        tmp_path,
        RepositoryScanOptions(
            compatibility=False, project_ids=("pypi:python:packages/member",)
        ),
    )
    (bundle,) = scan.bundles
    (row,) = bundle.resolved
    assert row.origin["public"] is False and row.package.purl is None and not queries
    metadata = row.metadata["uv_index_policy"]
    assert metadata["namespace"] == "uv-project" and metadata["activation"] == "unknown"
    assert metadata["configuration"]["path"] == (
        "uv.toml" if form.endswith("toml") else "pyproject.toml"
    )
    assert any(
        p == tmp_path / metadata["configuration"]["path"] for p in bundle.evidence_files
    )
    assert canary not in json.dumps(scan.to_dict())
    assert all((p.read_bytes(), p.stat().st_mtime_ns) == v for p, v in before.items())


@pytest.mark.parametrize(
    "mode",
    [
        "empty-toml-shadow",
        "pip-only",
        "nearest-parent",
        "local-stop",
        "invalid-toml",
        "invalid-index",
        "symlink-outside",
        "budget",
    ],
)
def test_uv_index_policy_precedence_bounds_and_unknown_sources(
    tmp_path, monkeypatch, mode
):
    from depcheck.ecosystems.python.parsers import pyproject

    root, member = _uv_source_workspace(
        tmp_path, '[tool.uv]\nindex-url="https://private.invalid/simple"\n'
    )
    if mode == "empty-toml-shadow":
        (tmp_path / "uv.toml").write_text("")
    elif mode == "pip-only":
        (tmp_path / "uv.toml").write_text(
            '[pip]\nindex-url="https://private.invalid/pip-only"\n'
        )
    elif mode in {"nearest-parent", "local-stop"}:
        root.write_text('[project]\nname="root"\nversion="1"\n')
        (tmp_path / "uv.toml").write_text(
            'index-url="https://private.invalid/parent"\n'
        )
        if mode == "local-stop":
            p = member / "pyproject.toml"
            p.write_text(p.read_text() + "[tool.uv]\n")
    elif mode == "invalid-toml":
        (tmp_path / "uv.toml").write_text("index-url= [")
    elif mode == "invalid-index":
        (tmp_path / "uv.toml").write_text("index-url=false\n")
    elif mode == "symlink-outside":
        external = tmp_path.parent / "uv-index-outside.toml"
        external.write_text('index-url="https://secret.invalid"\n')
        (tmp_path / "uv.toml").symlink_to(external)
    elif mode == "budget":
        monkeypatch.setattr(pyproject, "_UV_CONFIG_DEPTH", 0)
    scan = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, project_ids=("pypi:python:packages/member",)
        ),
    )
    (row,) = scan.bundles[0].resolved
    metadata = row.metadata["uv_index_policy"]
    if mode in {"empty-toml-shadow", "pip-only", "local-stop"}:
        assert row.origin["public"] is True and row.package.purl is not None
        if mode == "pip-only":
            assert any(
                d.code == "manifest.uv-pip-index-not-project-policy"
                for d in scan.diagnostics
            )
    else:
        assert row.origin["public"] is False and row.package.purl is None
    if mode == "nearest-parent":
        assert metadata["configuration"]["path"] == "uv.toml"
    if mode in {"invalid-toml", "invalid-index", "symlink-outside", "budget"}:
        assert metadata["selection"] == "unverified"
        assert any(
            d.code == "manifest.uv-index-configuration-unverified"
            for d in scan.diagnostics
        )
        assert "secret.invalid" not in json.dumps(scan.to_dict())


def test_uv_index_policy_real_poetry_variant_keeps_physical_lock_source_and_readonly_cache(
    tmp_path,
):
    import shutil

    fixtures = Path(__file__).parent / "fixtures/projects/multilingual/poetry-1.8.3"
    work = tmp_path / "work"
    shutil.copytree(fixtures, work)
    manifest = work / "pyproject.toml"
    before_manifest = manifest.read_bytes()
    lock = work / "poetry.lock"
    before_lock = lock.read_bytes(), lock.stat().st_mtime_ns
    config = work / "uv.toml"
    config.write_text('index-url="https://private.invalid/simple"\n')
    scan = RepositoryScanner().scan(work, RepositoryScanOptions(security=False))
    requests = next(r for r in scan.bundles[0].resolved if r.package.name == "requests")
    assert (
        requests.version == "2.31.0"
        and requests.origin["public"] is True
        and requests.package.purl is not None
    )
    assert requests.metadata["lock_origin"]["public"] is True
    assert "uv_index_policy" not in requests.metadata
    assert "inherited_source_policy" not in requests.metadata
    bom = build_cyclonedx(scan)
    component = next(c for c in bom["components"] if c["name"] == "requests")
    assert component["purl"].startswith("pkg:pypi/requests@")
    service = DependencyAgentService(work)
    service.index_repository()
    cache = work / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    query = service.explain_dependency("requests")
    assert query["resolutions"][0]["metadata"] == dict(requests.metadata)
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    assert (
        manifest.read_bytes() == before_manifest
        and (lock.read_bytes(), lock.stat().st_mtime_ns) == before_lock
    )
    config.unlink()
    assert service.repository_context()["stale"] is True
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("requests")
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    service.index_repository()
    assert (
        service.explain_dependency("requests")["resolutions"][0]["origin"]["public"]
        is True
    )
    config.write_text('extra-index-url=["https://private.invalid/simple"]\n')
    assert service.repository_context()["stale"] is True


def test_uv_index_policy_preserves_explicit_lock_origins_and_independent_requirements(
    tmp_path,
):
    root, member = _uv_source_workspace(
        tmp_path, '[tool.uv]\nindex-url="https://private.invalid/simple"\n'
    )
    requirements = member / "requirements.txt"
    requirements.write_text("requests==2.31.0\n")
    # An explicit lock-source assertion does not become a selected installation.
    lock = member / "uv.lock"
    lock.write_text(
        'version=1\n[[package]]\nname="urllib3"\nversion="2.2.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    scan = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, project_ids=("pypi:python:packages/member",)
        ),
    )
    rows = scan.bundles[0].resolved
    by_path = {r.source.path: r for r in rows}
    assert by_path[member / "pyproject.toml"].origin["public"] is False
    assert by_path[requirements].origin["public"] is True
    assert by_path[lock].origin["public"] is True
    assert by_path[lock].metadata["lock_origin"]["public"] is True
    assert not next(
        c for c in scan.bundles[0].capabilities if c.name == "resolution"
    ).complete


@pytest.mark.parametrize(
    "boundary", ["changed-input", "outer-authority", "opaque-index-fields"]
)
def test_uv_index_policy_keeps_io_authority_and_opaque_fields_bounded(
    tmp_path, monkeypatch, boundary
):
    from depcheck.ecosystems.python.parsers import pyproject
    from depcheck.ecosystems.python.manifest import PythonManifestCollector
    from depcheck.filesystem import (
        ContentChangedError,
        ProjectPathError,
        repository_reads,
    )

    root, member = _uv_source_workspace(tmp_path, "")
    config = tmp_path / "uv.toml"
    config.write_text('index-url="https://private.invalid/simple"\n')
    if boundary == "outer-authority":
        with (
            repository_reads(member),
            pytest.raises(ProjectPathError, match="cannot expand"),
        ):
            PythonManifestCollector(member, configuration_root=tmp_path).collect()
        return
    if boundary == "changed-input":
        original = pyproject.read_text

        def changed(path, **kwargs):
            if path == config:
                raise ContentChangedError("controlled input changed")
            return original(path, **kwargs)

        monkeypatch.setattr(pyproject, "read_text", changed)
        with pytest.raises(ContentChangedError, match="controlled input changed"):
            RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
        return
    canary = "uv-index-opaque-credential-canary"
    config.write_text(
        '[[index]]\nname="private"\nurl="https://user:'
        + canary
        + "@private.invalid/simple?token="
        + canary
        + '"\npassword="'
        + canary
        + '"\n"https://user:'
        + canary
        + '@private.invalid"="opaque"\n'
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert canary not in json.dumps(scan.to_dict())
    assert any(d.code == "manifest.uv-index-fields-omitted" for d in scan.diagnostics)
    assert all(
        row.origin["public"] is False for b in scan.bundles for row in b.resolved
    )


@pytest.mark.parametrize("profile", ["index", "malformed-sources"])
def test_uv_source_profile_real_project_variant_preserves_lock_and_advisory_identity(
    tmp_path,
    profile,
):
    import shutil

    fixtures = Path(__file__).parent / "fixtures/projects/multilingual"
    work = tmp_path / "work"
    shutil.copytree(fixtures / "pydantic-ai-0.0.14", work)
    member = work / "pydantic_ai_slim/pyproject.toml"
    text = member.read_text()
    assert text.count("requests>=2.32.3") == 1
    # Deliberate synthetic exact-pin variant of the fixed upstream manifest.
    member.write_text(text.replace("requests>=2.32.3", "requests==2.32.3"))
    lock = work / "uv.lock"
    before_lock = lock.read_bytes(), lock.stat().st_mtime_ns
    options = RepositoryScanOptions(
        security=False, project_ids=("pypi:python:pydantic_ai_slim",)
    )
    baseline = RepositoryScanner().scan(work, options)
    control = next(
        r for r in baseline.bundles[0].resolved if r.package.name == "requests"
    )
    assert control.origin["public"] is True and control.version == "2.32.3"
    if profile == "index":
        config = work / "uv.toml"
        config.write_text('index-url="https://private.invalid/simple"\n')
    else:
        member.write_text(member.read_text() + "[tool.uv]\nsources=[]\n")
    scan = RepositoryScanner().scan(work, options)
    (bundle,) = scan.bundles
    row = next(r for r in bundle.resolved if r.package.name == "requests")
    assert (
        row.origin["public"] is False
        and row.package.purl is None
        and row.version == control.version
    )
    if profile == "index":
        assert row.metadata["uv_index_policy"]["configuration"]["path"] == "uv.toml"
    else:
        assert row.metadata["uv_source_status"] == "unverified"
    assert (
        not bundle.project.locks
        and (lock.read_bytes(), lock.stat().st_mtime_ns) == before_lock
    )
    advisory = work / "advisory.json"
    shutil.copyfile(fixtures / "advisories/GHSA-9hjg-9r4m-mvj7.json", advisory)
    inventory = work / "inventory.json"
    service = DependencyAgentService(work)
    statuses = []
    for result in [baseline, scan]:
        inventory.write_text(json.dumps(result.to_dict()))
        reevaluated = service.reevaluate_vulnerabilities(
            "inventory.json", "advisory.json"
        )
        statuses.append(
            next(
                r["status"]
                for r in reevaluated["observations"]
                if r["identity"]["package"] == "requests"
            )
        )
    assert statuses == ["matched", "unknown"]
    bom = build_cyclonedx(scan)
    assert all("purl" not in c for c in bom["components"] if c["name"] == "requests")
    service.index_repository(project_ids=("pypi:python:pydantic_ai_slim",))
    cache = work / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    result = service.explain_dependency(
        "requests", project_id="pypi:python:pydantic_ai_slim"
    )
    assert result["resolutions"][0]["metadata"] == dict(row.metadata)
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before


def test_uv_index_policy_wrong_uv_toml_namespace_is_not_a_public_default(tmp_path):
    _uv_source_workspace(tmp_path, "")
    (tmp_path / "uv.toml").write_text(
        '[tool.uv]\nindex-url="https://private.invalid/simple"\n'
    )
    scan = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, project_ids=("pypi:python:packages/member",)
        ),
    )
    (row,) = scan.bundles[0].resolved
    assert (
        row.origin["public"] is False
        and row.metadata["uv_index_policy"]["selection"] == "unverified"
    )
    assert any(
        d.code == "manifest.uv-index-configuration-unverified" for d in scan.diagnostics
    )


@pytest.mark.parametrize(
    "fault",
    [
        "list-table",
        "scalar-table",
        "normalized-collision",
        "invalid-name",
        "table-budget",
        "entry-budget",
        "projection-budget",
    ],
)
def test_uv_source_profile_root_invalid_and_bounded_tables_never_become_public(
    tmp_path, monkeypatch, fault
):
    from depcheck.ecosystems.python import source_policy
    from depcheck.ecosystems.python.parsers import pyproject
    from depcheck.security.osv_client import OSVScanResult

    config = '[tool.uv.sources]\nRequests={git="https://example.invalid/source"}\n'
    if fault == "list-table":
        config = "[tool.uv]\nsources=[]\n"
    elif fault == "scalar-table":
        config = '[tool.uv]\nsources="opaque"\n'
    elif fault == "normalized-collision":
        config += 'requests={path="vendor/request"}\n'
    elif fault == "invalid-name":
        config += '"not a package"={git="https://example.invalid/other"}\n'
    elif fault == "table-budget":
        monkeypatch.setattr(source_policy, "_UV_SOURCE_BYTES", 1)
    elif fault == "entry-budget":
        monkeypatch.setattr(source_policy, "_UV_SOURCE_VALUE_BYTES", 1)
    elif fault == "projection-budget":
        monkeypatch.setattr(pyproject, "_UV_SOURCE_PROJECT_BYTES", 1)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
        + config
    )
    queries = []

    def query(packages):
        queries.append(packages)
        return OSVScanResult({}, (), packages)

    scan = RepositoryScanner(osv_client=SimpleNamespace(scan=query)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    (row,) = scan.bundles[0].resolved
    assert row.origin["public"] is False and row.package.purl is None
    assert not queries
    assert row.metadata["uv_source_status"] in {"unverified", "incomplete"}
    assert not next(
        c for c in scan.bundles[0].capabilities if c.name == "resolution"
    ).complete
    assert any(
        d.code
        in {
            "manifest.uv-source-table-unverified",
            "manifest.uv-source-context-incomplete",
        }
        for d in scan.diagnostics
    )


@pytest.mark.parametrize(
    "variant",
    ["conditional", "opaque", "malformed-fields", "mixed-kinds", "alternatives-budget"],
)
def test_uv_source_profile_conditions_and_omissions_survive_cache_and_exports(
    tmp_path, monkeypatch, variant
):
    from depcheck.ecosystems.python import source_policy

    canary = "uv-source-opaque-key-canary"
    value = [
        {
            "git": "https://example.invalid/one",
            "marker": "sys_platform == 'darwin'",
            "tag": "0.1.0-beta.1",
        },
        {
            "path": "vendor/requests",
            "marker": "sys_platform != 'darwin'",
            "editable": True,
            "package": False,
        },
    ]
    if variant == "opaque":
        value = {
            "git": "https://example.invalid/repo",
            "password": canary,
            "https://user:" + canary + "@example.invalid": "opaque",
        }
    elif variant == "malformed-fields":
        value = {"git": "https://example.invalid/repo", "marker": {"opaque": canary}}
    elif variant == "mixed-kinds":
        value = {"git": "https://example.invalid/repo", "path": "vendor/requests"}
    elif variant == "alternatives-budget":
        monkeypatch.setattr(source_policy, "_UV_SOURCE_ALTERNATIVES", 1)

    def toml(v):
        if isinstance(v, dict):
            return (
                "{"
                + ",".join(json.dumps(k) + "=" + toml(x) for k, x in v.items())
                + "}"
            )
        if isinstance(v, list):
            return "[" + ",".join(toml(x) for x in v) + "]"
        return json.dumps(v)

    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.uv.sources]\nrequests='
        + toml(value)
        + "\n"
    )
    before = path.read_bytes(), path.stat().st_mtime_ns
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    (row,) = scan.bundles[0].resolved
    assert row.origin["public"] is False and row.package.purl is None
    assert canary not in json.dumps(scan.to_dict())
    if variant == "conditional":
        assert row.origin["assertion"] == value
        assert row.metadata["uv_index_policy"]["activation"] == "unknown"
    else:
        assert (
            row.origin.get("details_omitted")
            or row.origin.get("source_validation") == "unverified"
        )
        assert row.origin[
            "source_assertion_sha256"
        ] == source_policy.source_assertion_digest(value)
    bom = build_cyclonedx(scan)
    component = next(c for c in bom["components"] if c["name"] == "requests")
    assert "purl" not in component
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    old_cache = cache.read_bytes(), cache.stat().st_mtime_ns
    query = service.explain_dependency("requests")
    assert query["resolutions"][0]["origin"] == dict(row.origin)
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == old_cache and (
        path.read_bytes(),
        path.stat().st_mtime_ns,
    ) == before


def test_uv_source_profile_redacted_assertions_keep_content_identity_without_binding():
    from depcheck.ecosystems.python.source_policy import uv_source_origin

    a = {"git": "https://user:one@example.invalid/repo", "extra": "one"}
    b = {"git": "https://user:two@example.invalid/repo", "extra": "one"}
    first, second = uv_source_origin(a), uv_source_origin(b)
    assert first["assertion"] == second["assertion"]
    assert first["source_assertion_sha256"] != second["source_assertion_sha256"]
    assert "one@" not in json.dumps(first) and "two@" not in json.dumps(second)


def test_uv_source_profile_raw_direct_url_and_poetry_scope_remain_separate(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests @ https://example.invalid/requests.whl"]\n[tool.uv]\nsources=[]\n[tool.poetry.dependencies]\nurllib3="==2.2.0"\n'
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declarations = scan.bundles[0].declarations
    direct = next(d for d in declarations if d.package.name == "requests")
    assert direct.metadata["origin"]["kind"] == "unknown"
    assert direct.metadata["uv_declared_origin"]["kind"] == "url"
    other = next(d for d in declarations if d.package.name == "urllib3")
    assert (
        other.metadata["origin"]["public"] is True
        and "uv_source_status" not in other.metadata
    )
