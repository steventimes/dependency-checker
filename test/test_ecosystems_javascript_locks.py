"""Javascript locks collection, ownership, and qualified static evidence."""

import json
from pathlib import Path

import pytest
import yaml

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


@pytest.mark.parametrize(
    "workspace", [None, 'packages: ["packages/*", "!independent"]\n']
)
def test_independent_npm_child_does_not_inherit_unrelated_pnpm_lock(
    tmp_path, workspace
):
    (tmp_path / "package.json").write_text('{"private":true}')
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n"
    )
    if workspace is not None:
        (tmp_path / "pnpm-workspace.yaml").write_text(workspace)
    child = tmp_path / "independent"
    child.mkdir()
    (child / "package.json").write_text('{"dependencies":{"tool":"1.0.0"}}')
    (child / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, project_ids=("npm:npm:independent",)),
    )
    bundle = result.bundles[0]
    assert [p.name for p in bundle.project.locks] == ["package-lock.json"]
    assert [(r.package.name, r.version) for r in bundle.resolved] == [("tool", "1.0.0")]
    assert not any(
        d.code == "resolution.package-manager-ambiguous" for d in result.diagnostics
    )


def test_pnpm_unknown_workspace_membership_does_not_establish_resolution(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true}')
    (tmp_path / "pnpm-workspace.yaml").write_text("packages: 42\n")
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  app: {}\n"
    )
    child = tmp_path / "app"
    child.mkdir()
    (child / "package.json").write_text('{"dependencies":{}}')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, project_ids=("npm:npm:app",))
    )
    assert any(d.code == "resolution.workspace-ambiguous" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize(
    "patterns,child_name,ambiguous",
    [
        ("{}", "app", True),
        ('packages: ["packages/**", "!**/test/**"]', "packages/test", False),
    ],
)
def test_pnpm_workspace_omitted_patterns_and_zero_segment_globstar(
    tmp_path, patterns, child_name, ambiguous
):
    (tmp_path / "package.json").write_text('{"private":true}')
    (tmp_path / "pnpm-workspace.yaml").write_text(patterns)
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  " + child_name + ": {}\n"
    )
    child = tmp_path / child_name
    child.mkdir(parents=True)
    (child / "package.json").write_text('{"dependencies":{"tool":"1.0.0"}}')
    (child / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, project_ids=("npm:npm:" + child_name,)),
    )
    assert (
        any(
            d.code == "resolution.package-manager-ambiguous" for d in result.diagnostics
        )
        is ambiguous
    )
    assert bool(result.bundles[0].resolved) is not ambiguous


def test_pnpm_lock_does_not_cross_a_closer_workspace_without_lock(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true}')
    (tmp_path / "pnpm-workspace.yaml").write_text('packages: ["nested/**"]')
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  nested/app: {}\n"
    )
    child = tmp_path / "nested/app"
    child.mkdir(parents=True)
    (tmp_path / "nested/pnpm-workspace.yaml").write_text('packages: ["packages/*"]')
    (child / "package.json").write_text('{"dependencies":{}}')
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, project_ids=("npm:npm:nested/app",)),
    )
    assert not result.bundles[0].project.locks


def test_pnpm_extended_glob_membership_stays_unknown(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true}')
    (tmp_path / "pnpm-workspace.yaml").write_text('packages: ["packages/@(app|lib)"]')
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  packages/app: {}\n"
    )
    child = tmp_path / "packages/app"
    child.mkdir(parents=True)
    (child / "package.json").write_text("{}")
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, project_ids=("npm:npm:packages/app",)),
    )
    assert any(d.code == "resolution.workspace-ambiguous" for d in result.diagnostics)


@pytest.mark.parametrize("fixture", [1, 2, 3])
def test_pnpm_real_locks_preserve_project_versions_and_edges(tmp_path, fixture):

    text = (
        Path(__file__).parent / "fixtures/pnpm" / f"pnpm-real-{fixture}.yaml"
    ).read_text()
    document = yaml.safe_load(text)
    (tmp_path / "pnpm-lock.yaml").write_text(text)
    (tmp_path / "pnpm-workspace.yaml").write_text('packages: ["**"]\n')
    for importer, entry in document["importers"].items():
        project = tmp_path / importer
        project.mkdir(parents=True, exist_ok=True)
        manifest = {
            section: {name: value["specifier"] for name, value in entries.items()}
            for section, entries in entry.items()
        }
        (project / "package.json").write_text(json.dumps(manifest))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundles = {b.project.root.as_posix(): b for b in result.bundles}
    if fixture == 1:
        assert {r.package.name for r in bundles["app-a"].resolved} == {"is-positive"}
        assert any(
            d.code == "lock.unsupported" and "link:" in d.message
            for d in result.diagnostics
        )
    elif fixture == 2:
        assert len(bundles["."].resolved) == 7
        peer = next(
            r for r in bundles["."].resolved if r.package.name == "ajv-keywords"
        )
        assert peer.instance_id.endswith("(ajv@6.10.2)")
        assert [(e.package.name, e.version) for e in peer.dependency_links] == [
            ("ajv", "6.10.2")
        ]
    else:
        for importer, version in [
            ("packages/bar", "6.10.2"),
            ("packages/foo", "6.12.6"),
        ]:
            assert {
                r.version for r in bundles[importer].resolved if r.package.name == "ajv"
            } == {version}
    sbom = build_cyclonedx(result)
    refs = {component["bom-ref"] for component in sbom["components"]}
    assert all(
        target in refs for edge in sbom["dependencies"] for target in edge["dependsOn"]
    )
    service = DependencyAgentService(tmp_path)
    selected = next(b.project.project_id for b in result.bundles if b.resolved)
    service.index_repository(project_ids=(selected,))
    assert service.repository_context()["stale"] is False
    (tmp_path / "pnpm-lock.yaml").write_text(text + "\n# changed\n")
    assert service.repository_context()["stale"] is True


@pytest.mark.parametrize(
    "text",
    [
        "lockfileVersion: '6.0'\n",
        "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n",
        "x: &loop [*loop]\n",
        "x: !!python/object/apply:os.system ['echo unexpected']\n",
        "x: " + "[" * 70 + "0" + "]" * 70,
    ],
)
def test_unsafe_or_unsupported_pnpm_is_incomplete(tmp_path, text):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "pnpm-lock.yaml").write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        d.code in {"lock.invalid", "lock.unsupported"} for d in result.diagnostics
    )
    assert not next(
        c for c in result.bundles[0].capabilities if c.name == "resolution"
    ).complete


@pytest.mark.parametrize("lock_version", [8, 10])
def test_yarn_inventory_keeps_physical_assertions_separate_from_application(
    tmp_path, lock_version
):
    text = f"""# Yarn Modern inventory
__metadata:
  version: {lock_version}
  cacheKey: 10
"alias@npm:real@^1, real@npm:^1":
  version: 1.0.0
  resolution: "real@npm:1.0.0"
  checksum: 10/unverified
  dependencies:
    child: "npm:^2"
  peerDependencies:
    host: "^3"
  dependenciesMeta:
    child:
      optional: true
  linkType: hard
"real@npm:~1.0":
  version: 1.0.0
  resolution: "real@npm:1.0.0"
  conditions: "os=linux & cpu=x64"
"local@workspace:*":
  version: 0.0.0-use.local
  resolution: "local@workspace:packages/local"
  linkType: soft
"patched@patch:patched@npm%3A1.0.0#./fix.patch":
  version: 1.0.0
  resolution: "patched@patch:patched@npm%3A1.0.0#./fix.patch"
"git-tool@https://github.com/example/tool.git#commit=fixture":
  version: 1.0.0
  resolution: "git-tool@https://github.com/example/tool.git#commit=fixture"
"@example/tool@npm:^2.0.0":
  version: 2.1.0-beta.0+build.001
  resolution: "@example/tool@npm:2.1.0-beta.0+build.001"
"""
    (tmp_path / "yarn.lock").write_text(text)
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"eslint":"^9"},"scripts":{"lint":"eslint ."}}'
    )
    (tmp_path / "app.js").write_text('import "real";\n')
    nested = tmp_path / "tools"
    nested.mkdir()
    (nested / "yarn.lock").write_text(text)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules/yarn.lock").write_text(text)

    class OSV:
        def scan_ecosystem(self, *_):
            pytest.fail("Yarn configuration assertions must not make public queries")

    result = RepositoryScanner(osv_client=OSV()).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    bundles = {b.project.project_id: b for b in result.bundles}
    assert set(bundles) == {"npm:npm:.", "npm:yarn-lock:.", "npm:yarn-lock:tools"}
    bundle = bundles["npm:yarn-lock:."]
    assert any(
        u.mapped_package and u.mapped_package.name == "eslint" and u.kind == "command"
        for u in bundles["npm:npm:."].usages
    )
    assert not any(d.code == "command.invalid" for d in result.diagnostics)
    assert len(bundle.declarations) == 7
    assert bundle.project.manifests == bundle.project.locks == (Path("yarn.lock"),)
    assert all(
        d.kind == "conditional" and d.scope == "unknown" for d in bundle.declarations
    )
    assert all(not d.package.purl for d in bundle.declarations)
    assert not bundle.resolved and not bundle.usages
    assert next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    real = [d for d in bundle.declarations if d.package.name == "real"]
    assert len(real) == 3
    assert [d.constraint.raw for d in real] == ["npm:real@^1", "npm:^1", "npm:~1.0"]
    assert real[0].metadata["installation_name"] == "alias"
    assert real[0].source.line == real[1].source.line == 5
    assert real[2].source.line == 17
    assert (
        real[0].metadata["context"]["dependenciesMeta"]["child"]["optional"] == "true"
    )
    assert real[0].metadata["context"]["checksum"] == "10/unverified"
    assert real[2].metadata["context"]["conditions"] == "os=linux & cpu=x64"
    assert real[0].metadata["version_status"] == "canonical-npm-assertion"
    assert all(d.metadata["activation"] == "unknown" for d in bundle.declarations)
    assert any(
        f.code == "dependency.missing"
        and f.package.name == "real"
        and f.package.project_id == "npm:npm:."
        for f in result.findings
    )
    assert not any(
        f.package.project_id.startswith("npm:yarn-lock:") for f in result.findings
    )
    sbom = build_cyclonedx(result)
    assertions = [
        json.loads(p["value"])
        for c in sbom["components"]
        for p in c.get("properties", [])
        if p["name"] == "depcheck:conditional-declaration"
    ]
    assert len(assertions) == 14
    assert all(a["metadata"]["application_ownership"] == "unknown" for a in assertions)
    assert len(sbom["dependencies"][0]["dependsOn"]) == 1
    nested_bundle = (
        RepositoryScanner()
        .scan(nested, RepositoryScanOptions(security=False))
        .bundles[0]
    )
    assert nested_bundle.project.project_id == "npm:yarn-lock:."


def test_yarn_malformed_records_preserve_neighbors_and_explicit_uncertainty(tmp_path):
    (tmp_path / "yarn.lock").write_text("""__metadata: {version: 10}
"good@npm:^1": {version: 1.0.0, resolution: "good@npm:1.0.0"}
"missing@npm:^1": {version: 1.0.0}
"mismatch@npm:^1": {version: 1.0.0, resolution: "mismatch@npm:2.0.0"}
"shape@npm:^1":
  version: 1.0.0
  resolution: "shape@npm:1.0.0"
  dependencies: [unknown]
  checksum: !!binary YQ==
  bin: {unsafe: !!float .nan}
  conditions: os=linux
  npmAuthToken: fixture-secret
"bad/name@npm:*, tail@npm:^1": {version: 1.0.0, resolution: "tail@npm:1.0.0"}
"odd@npm:\\uD800": {version: 1.0.0, resolution: "odd@npm:1.0.0"}
""")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert [d.package.name for d in bundle.declarations] == [
        "good",
        "mismatch",
        "shape",
        "tail",
        "odd",
    ]
    assert (
        bundle.declarations[1].metadata["version_status"] == "conflicting-npm-assertion"
    )
    assert bundle.declarations[2].metadata["context"]["dependencies"] == ["unknown"]
    assert bundle.declarations[2].metadata["context"]["conditions"] == "os=linux"
    assert "checksum" not in bundle.declarations[2].metadata["context"]
    assert "bin" not in bundle.declarations[2].metadata["context"]
    assert "fixture-secret" not in json.dumps(result.to_dict())
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert not result.findings


@pytest.mark.parametrize(
    "contents",
    [
        '# yarn lockfile v1\nfoo@^1:\n  version "1.0.0"\n',
        '__metadata: {version: 6}\n"foo@^1": {version: 1.0.0, resolution: "foo@npm:1.0.0"}\n',
        '__metadata: {version: 10}\n"foo@npm:^1": &record {version: 1.0.0, resolution: "foo@npm:1.0.0"}\n"foo@npm:~1": *record\n',
    ],
)
def test_yarn_unsupported_formats_and_yaml_aliases_remain_gaps(tmp_path, contents):
    (tmp_path / "yarn.lock").write_text(contents)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert len(result.bundles) == 1
    assert not result.bundles[0].declarations
    assert any(d.code == "manifest.yarn-lock-invalid" for d in result.diagnostics)
    assert not next(
        c for c in result.bundles[0].capabilities if c.name == "manifest"
    ).complete


@pytest.mark.parametrize("budget", ["entries", "context"])
def test_yarn_inventory_budget_retains_prefix_and_coverage_gap(
    tmp_path, monkeypatch, budget
):
    import depcheck.ecosystems.javascript.yarn as javascript_yarn

    if budget == "entries":
        monkeypatch.setattr(javascript_yarn, "_MAX_ENTRIES", 1)
    else:
        monkeypatch.setattr(javascript_yarn, "DEFAULT_MAX_BYTES", 1600)
    (tmp_path / "yarn.lock").write_text(
        '__metadata: {version: 10}\n"first@npm:^1": {version: 1.0.0, resolution: "first@npm:1.0.0"}\n"second@npm:^1": {version: 1.0.0, resolution: "second@npm:1.0.0", conditions: "'
        + "x" * 2000
        + '"}\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [d.package.name for d in result.bundles[0].declarations] == ["first"]
    assert any(
        d.code == "manifest.yarn-lock-invalid" and "budget" in d.message
        for d in result.diagnostics
    )
    assert any(
        g["reason"] == "manifest.yarn-lock-invalid"
        for g in result.metadata["coverage"]["uncovered"]
    )


def test_yarn_selected_index_preserves_assertions_and_rejects_stale_queries(tmp_path):
    lock = tmp_path / "yarn.lock"
    text = '__metadata: {version: 10}\n"alias@npm:foo@^1, foo@npm:~1": {version: 1.0.0, resolution: "foo@npm:1.0.0", conditions: os=linux}\n'
    lock.write_text(text)
    service = DependencyAgentService(tmp_path)
    project_id = "npm:yarn-lock:."
    service.index_repository(project_ids=(project_id,))
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    assert service.query_dependencies("alias", project_id=project_id)["count"] == 1
    explanation = service.explain_dependency(
        "foo", ecosystem="npm", project_id=project_id
    )
    assert len(explanation["declarations"]) == 2
    assert explanation["declarations"][0]["location"]["line"] == 2
    assert (
        explanation["declarations"][0]["metadata"]["context"]["conditions"]
        == "os=linux"
    )
    assert explanation["resolved_versions"] == [] and not explanation["usages"]
    assert not explanation["evidence_complete"] and not explanation["findings"]
    lock.write_text(text.replace("os=linux", "os=darwin"))
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies(project_id=project_id)
    assert before == (cache.read_bytes(), cache.stat().st_mtime_ns)
    service.index_repository(project_ids=(project_id,))
    updated = service.explain_dependency("foo", ecosystem="npm", project_id=project_id)
    assert (
        updated["declarations"][0]["metadata"]["context"]["conditions"] == "os=darwin"
    )
    lock.unlink()
    assert service.repository_context()["stale"]
