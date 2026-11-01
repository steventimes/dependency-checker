"""Rust collection, ownership, and qualified static evidence."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.registry import ProviderContext
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import MappingConfidence
from depcheck.output import build_cyclonedx


def test_toml_locations_reuse_keeps_real_shared_locks_fresh_and_each_read(
    tmp_path, monkeypatch
):
    import shutil
    from depcheck.ecosystems.rust import common
    from depcheck.filesystem import capture_reads
    from depcheck.filesystem.positions import _PositionedTomlParser
    from depcheck.profiling import capture_profile

    original = Path(__file__).parent / "fixtures/projects/multilingual/wezterm-20220624"
    shutil.copytree(original, tmp_path, dirs_exist_ok=True)
    lock = tmp_path / "Cargo.lock"
    text = lock.read_text()
    originals = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    parses = 0
    reads = 0
    native_parse = _PositionedTomlParser.parse
    native_read = common.read_text

    def parse(parser):
        nonlocal parses
        if parser.text in {text, "# controlled later scan\n" + text}:
            parses += 1
        return native_parse(parser)

    def read(path):
        nonlocal reads
        if path == lock:
            reads += 1
        return native_read(path)

    monkeypatch.setattr(_PositionedTomlParser, "parse", parse)
    monkeypatch.setattr(common, "read_text", read)
    options = RepositoryScanOptions(
        security=False,
        compatibility=False,
        enabled_ecosystems=("Cargo",),
        project_ids=("cargo:cargo:wezterm", "cargo:cargo:wezterm-gui"),
    )
    with capture_profile() as profile, capture_reads():
        first = RepositoryScanner().scan(tmp_path, options)
    assert reads == 2 and parses == 1
    cache = profile["parsing.toml-position-cache"]
    assert cache["requests"] > cache["misses"]
    assert [len(b.resolved) for b in first.bundles] == [511, 511]
    second = RepositoryScanner().scan(tmp_path, options)
    assert reads == 4 and parses == 2
    assert first.to_dict() == second.to_dict()
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value
        for p, value in originals.items()
    )
    lock.write_text("# controlled later scan\n" + text)
    third = RepositoryScanner().scan(tmp_path, options)
    assert reads == 6 and parses == 3
    for before, after in zip(second.bundles, third.bundles, strict=True):
        assert before.declarations == after.declarations
        for old, new in zip(before.resolved, after.resolved, strict=True):
            assert old.identity == new.identity and old.metadata == new.metadata
            assert new.source.line == old.source.line + 1


def test_toml_locations_real_ambient_workspace_declarations_survive_index(tmp_path):
    import shutil
    from dataclasses import replace

    from depcheck.model import Finding, PackageIdentity
    from depcheck.output import build_sarif

    original = Path(__file__).parent / "fixtures/projects/multilingual/ambient-ef44a742"
    shutil.copytree(original, tmp_path, dirs_exist_ok=True)
    before = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    selected = ("cargo:cargo:crates/git_rev", "cargo:cargo:crates/pipeline_types")
    scan = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            compatibility=False,
            enabled_ecosystems=("Cargo",),
            project_ids=selected,
        ),
    )
    expected = {
        (selected[0], "once_cell"): 13,
        (selected[1], "serde"): 13,
        (selected[1], "glam"): 14,
        (selected[1], "toml"): 16,
    }
    actual = {}
    for bundle in scan.bundles:
        assert len(bundle.resolved) == 937
        for item in bundle.declarations:
            key = (bundle.project.project_id, item.package.name)
            if key in expected:
                actual[key] = item
                assert item.metadata["workspace"] is True
                assert item.metadata["workspace_origin"]["path"] == "Cargo.toml"
                assert item.metadata["workspace_origin"]["line"] is not None
                assert (item.source.line, item.source.column) == (expected[key], 1)
    assert set(actual) == set(expected)
    service = DependencyAgentService(tmp_path)
    service.index_repository(ecosystems=("Cargo",), project_ids=selected)
    cache = tmp_path / ".depcheck/index.sqlite3"
    cache_before = cache.read_bytes(), cache.stat().st_mtime_ns
    for (project_id, package), item in actual.items():
        explanation = service.explain_dependency(
            package, ecosystem="Cargo", project_id=project_id
        )
        (declaration,) = [
            d for d in explanation["declarations"] if d["kind"] == "direct"
        ]
        assert declaration["location"] == item.source.to_dict(tmp_path)
        assert (
            declaration["metadata"]["workspace_origin"]
            == item.metadata["workspace_origin"]
        )
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before
    # A controlled finding checks the shared report projection, not a newly
    # inferred issue or observed exploit in the upstream project.
    item = actual[(selected[0], "once_cell")]
    finding = Finding(
        code="test.location-projection",
        severity="warning",
        package=PackageIdentity(
            project_id=selected[0], ecosystem="Cargo", name="once_cell"
        ),
        message="Controlled position projection",
        locations=(item.source,),
    )
    report = build_sarif(replace(scan, findings=(finding,)))
    physical = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "crates/git_rev/Cargo.toml"
    assert physical["region"] == {"startLine": 13, "startColumn": 1}
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value for p, value in before.items()
    )


def _cargo_bundles(root):
    from depcheck.ecosystems.rust.collector import create_cargo_pack

    context = ProviderContext(root)
    pack = create_cargo_pack()
    return tuple(
        pack.collector.collect(context, project, pack)
        for project in pack.detector.detect(context)
    )


@pytest.mark.parametrize("edition", [None, "2015", "2018", "2021"])
def test_cargo_legacy_dependency_sections_keep_scope_and_positions(tmp_path, edition):
    text = '[package]\nname="app"\nversion="0.1.0"\n'
    if edition:
        text += f'edition="{edition}"\n'
    text += (
        '[dev_dependencies]\nserde="1"\n'
        '[build_dependencies]\ncc="1"\n'
        '[target."cfg(windows)".dev_dependencies]\nwinapi="0.3"\n'
        '[target."cfg(unix)".build_dependencies]\nlibc="0.2"\n'
    )
    (tmp_path / "Cargo.toml").write_text(text)
    bundle = _cargo_bundles(tmp_path)[0]
    assert [
        (d.package.name, d.scope, d.kind, d.marker) for d in bundle.declarations
    ] == [
        ("serde", "development", "direct", None),
        ("cc", "build", "direct", None),
        ("winapi", "development", "direct", "cfg(windows)"),
        ("libc", "build", "direct", "cfg(unix)"),
    ]
    for declaration in bundle.declarations:
        assert text.splitlines()[declaration.source.line - 1].startswith(
            declaration.package.name
        )
        assert declaration.source.column == 1
        assert declaration.metadata["legacy_section"]["status"] == "accepted"
        assert declaration.metadata["legacy_section"]["edition"] == (edition or "2015")
    assert next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_cargo_legacy_sections_shadowed_by_canonical_remain_inventory(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n'
        '[dev-dependencies]\nfoo="=1.0.0"\n'
        '[dev_dependencies]\nfoo="=2.0.0"\n'
        "[build-dependencies]\n"
        '[build_dependencies]\ncc="=1.0.0"\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname="foo"\nversion="2.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname="cc"\nversion="1.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert len(bundle.declarations) == 3
    legacy = [d for d in bundle.declarations if "legacy_section" in d.metadata]
    assert len(legacy) == 2
    assert all(d.kind == "configuration" for d in legacy)
    assert all(d.metadata["legacy_section"]["status"] == "ignored" for d in legacy)
    assert {(r.package.name, r.version) for r in bundle.resolved if r.direct} == {
        ("foo", "1.0.0")
    }
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)


@pytest.mark.parametrize(
    "edition",
    [
        '"2024"',
        '"future"',
        "{workspace=true}",
        pytest.param('"' + "x" * 500 + '"', id="oversized-edition"),
        pytest.param("{workspace=1}", id="invalid-inheritance"),
    ],
)
def test_cargo_legacy_sections_unknown_or_rejected_editions_stay_qualified(
    tmp_path, edition
):
    (tmp_path / "Cargo.toml").write_text(
        f'[package]\nname="app"\nversion="0.1.0"\nedition={edition}\n'
        '[dependencies]\nserde="1"\n[dev_dependencies]\nfoo="=1.0.0"\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    legacy = next(d for d in bundle.declarations if d.package.name == "foo")
    assert legacy.kind == "configuration"
    assert legacy.source.line == 8
    assert len(legacy.metadata["legacy_section"]["edition"]) <= 7
    assert not any(r.direct for r in bundle.resolved)
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert any(
        d.code == "manifest.cargo-legacy-section" and d.source.line == 7
        for d in bundle.diagnostics
    )


@pytest.mark.parametrize("package_table", ["package", "project"])
def test_cargo_legacy_sections_follow_inherited_edition_and_origin(
    tmp_path, package_table
):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers=["child"]\n[workspace.package]\nedition="2021"\n'
        '[workspace.dependencies]\nfoo="1"\n'
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "Cargo.toml").write_text(
        f'[{package_table}]\nname="child"\nversion="0.1.0"\nedition.workspace=true\n'
        "[dev_dependencies]\nfoo={workspace=true}\n"
    )
    bundle = next(
        b for b in _cargo_bundles(tmp_path) if b.project.root == Path("child")
    )
    declaration = bundle.declarations[0]
    assert declaration.constraint.raw == "1"
    assert (
        declaration.source.path == child / "Cargo.toml" and declaration.source.line == 6
    )
    assert declaration.metadata["workspace_origin"] == {
        "path": "Cargo.toml",
        "line": 6,
        "column": 1,
    }
    assert declaration.metadata["legacy_section"]["edition"] == "2021"
    assert declaration.kind == "direct"


@pytest.mark.parametrize("shadowed", [False, True])
def test_cargo_legacy_path_members_respect_canonical_precedence(tmp_path, shadowed):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="root"\nversion="0.1.0"\n[workspace]\nmembers=[]\n'
        + ("[build-dependencies]\n" if shadowed else "")
        + '[build_dependencies]\nchild={path="child"}\n'
    )
    (tmp_path / "Cargo.lock").write_text("version=4\n")
    child = tmp_path / "child"
    child.mkdir()
    (child / "Cargo.toml").write_text('[package]\nname="child"\nversion="0.1.0"\n')
    bundle = next(
        b for b in _cargo_bundles(tmp_path) if b.project.root == Path("child")
    )
    assert bool(bundle.project.locks) is (not shadowed)


@pytest.mark.parametrize("edition", ["2021", "2024"])
def test_cargo_legacy_package_alias_qualifies_even_canonical_dependencies(
    tmp_path, edition
):
    (tmp_path / "Cargo.toml").write_text(
        f'[project]\nname="legacy"\nversion="0.1.0"\nedition="{edition}"\n'
        '[dependencies]\nfoo="1"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert bundle.declarations[0].package.name == "foo"
    manifest = next(c for c in bundle.capabilities if c.name == "manifest")
    assert manifest.complete is (edition == "2021")
    assert any(
        d.code.endswith("cargo-legacy-package") and d.source.line == 1
        for d in bundle.diagnostics
    )


@pytest.mark.parametrize("virtual", [True, False])
def test_cargo_legacy_aliases_do_not_invent_a_valid_package_edition(tmp_path, virtual):
    if virtual:
        text = '[workspace]\n[dev_dependencies]\nfoo="1"\n'
    else:
        text = 'project=[]\n[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n'
    (tmp_path / "Cargo.toml").write_text(text)
    bundle = _cargo_bundles(tmp_path)[0]
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete
    if virtual:
        assert bundle.declarations[0].kind == "configuration"
        assert bundle.declarations[0].metadata["legacy_section"]["edition"] == "unknown"


def test_cargo_keeps_ranges_aliases_scopes_and_conditions(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n'
        '[dependencies]\nserde = "1.2.3"\n'
        'renamed = { package = "serde", version = "=2.0.0", optional = true, '
        'features = ["derive"], default-features = false }\n'
        '[dev-dependencies]\nproptest = "1"\n'
        '[build-dependencies]\ncc = "1"\n'
        "[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src/lib.rs").write_text("use serde::Serialize;\n")
    bundle = _cargo_bundles(tmp_path)[0]
    assert bundle.project.project_id == "cargo:cargo:."
    assert bundle.project.language == "rust"
    assert [(d.package.name, d.scope, d.marker) for d in bundle.declarations] == [
        ("serde", "runtime", None),
        ("serde", "runtime", None),
        ("proptest", "development", None),
        ("cc", "build", None),
        ("winapi", "runtime", "cfg(windows)"),
    ]
    first, aliased = bundle.declarations[:2]
    assert first.constraint.scheme == "cargo"
    assert first.constraint.normalized is None
    assert aliased.constraint.raw == "=2.0.0"
    assert aliased.constraint.normalized == "=2.0.0"
    assert (first.source.line, first.source.column) == (5, 1)
    assert aliased.metadata["installation_name"] == "renamed"
    assert aliased.metadata["optional"] is True
    assert aliased.metadata["features"] == ["derive"]
    assert aliased.metadata["default-features"] is False
    assert {c.name: c.state.value for c in bundle.capabilities}["usage"] == "incomplete"
    assert {c.name: c.state.value for c in bundle.capabilities}[
        "mapping"
    ] == "incomplete"
    assert [
        (u.reference, u.mapped_package.name, u.mapping_confidence)
        for u in bundle.usages
    ] == [("serde", "serde", MappingConfidence.INFERRED)]
    assert bundle.source_files == (tmp_path / "src/lib.rs",)


def test_cargo_rust_references_preserve_aliases_and_ignore_literal_examples(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n'
        '[dependencies]\nrenamed={package="serde",version="1"}\n'
        'raw-name="1"\nprivate={package="internal",path="../private"}\n'
        'shadow="1"\ncollision="1"\n'
        '[target."cfg(windows)".dependencies]\ncollision={package="other",version="1"}\n'
    )
    source = tmp_path / "lib.rs"
    source.write_text(
        "// renamed::comment\n/* outer /* raw_name::nested */ renamed::doc */\n"
        'const A: &str = "renamed::string";\n'
        'const B: &str = r###"renamed::raw"###;\n'
        'const C: &[u8] = br##"raw_name::bytes"##;\n'
        'const D: &CStr = c"renamed::c_string";\n'
        "let ch = '\\''; let byte = b'X'; fn lifetime<'renamed>() {}\n"
        "use renamed::Serialize;\nuse raw_name as local;\n"
        "extern crate private;\nextern crate undeclared;\n"
        '#[cfg(feature="optional")] #[derive(renamed::Serialize)]\nstruct Data;\n'
        "fn f() { let 名 = 1; renamed::call(); ::r#raw_name::call(); }\n"
        "crate::renamed::local(); self::raw_name::local(); outer::private::local();\n"
        "shadow::call(); collision::call();\n",
        encoding="utf-8",
    )
    # A local module in another owned source file makes the alias ambiguous.
    (tmp_path / "module.rs").write_text("mod shadow;\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert [u.reference for u in bundle.usages] == [
        "renamed",
        "raw_name",
        "private",
        "undeclared",
        "renamed",
        "renamed",
        "raw_name",
        "shadow",
        "collision",
    ]
    assert [
        u.mapped_package.name if u.mapped_package else None for u in bundle.usages
    ] == [
        "serde",
        "raw-name",
        "internal",
        None,
        "serde",
        "serde",
        "raw-name",
        None,
        None,
    ]
    assert bundle.usages[2].mapped_package.purl is None
    assert all(u.scope == "unknown" and u.kind == "conditional" for u in bundle.usages)
    assert all(not u.mapping_confidence.qualifies_for_hygiene for u in bundle.usages)
    unicode_usage = bundle.usages[5]
    line = source.read_text(encoding="utf-8").splitlines()[13]
    assert (unicode_usage.source.line, unicode_usage.source.column) == (
        14,
        line.index("renamed::") + 1,
    )
    assert not any(f.code.startswith("dependency.") for f in result.findings)
    assert any(
        g["reason"] == "usage.rust-uncollected"
        for g in result.metadata["coverage"]["uncovered"]
    )


def test_cargo_rust_ownership_keeps_virtual_and_nested_projects_separate(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers=["member"]\n[workspace.dependencies]\nserde="1"\n'
    )
    (tmp_path / "orphan.rs").write_text("use serde::Serialize;\n")
    child = tmp_path / "member"
    child.mkdir()
    (child / "Cargo.toml").write_text(
        '[package]\nname="child"\nversion="0.1.0"\n[dependencies]\nserde.workspace=true\n'
    )
    (child / "lib.rs").write_text("use serde::Serialize;\n")
    root, member = _cargo_bundles(tmp_path)
    assert root.usages == ()
    assert root.source_files == (tmp_path / "orphan.rs",)
    assert any(d.code == "usage.rust-owner-unresolved" for d in root.diagnostics)
    assert [(u.reference, u.mapped_package.name) for u in member.usages] == [
        ("serde", "serde")
    ]
    assert member.usages[0].source.path == child / "lib.rs"


@pytest.mark.parametrize(
    "boundary", ["lexical", "tokens", "references", "files", "context", "read"]
)
def test_cargo_rust_source_boundaries_keep_prefix_and_qualify_gaps(
    tmp_path, monkeypatch, boundary
):
    import depcheck.ecosystems.rust.source as rust_source
    from depcheck.ecosystems.static import StaticReadError

    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nserde="1"\n'
    )
    (tmp_path / "a.rs").write_text(
        "serde::a();\n" + ("/* unclosed" if boundary == "lexical" else "serde::b();\n")
    )
    (tmp_path / "b.rs").write_text("serde::c();\n")
    if boundary == "tokens":
        monkeypatch.setattr(rust_source, "_MAX_TOKENS", 7)
    elif boundary == "references":
        monkeypatch.setattr(rust_source, "_MAX_REFERENCES", 1)
    elif boundary == "files":
        monkeypatch.setattr(rust_source, "_MAX_FILES", 1)
    elif boundary == "context":
        monkeypatch.setattr(
            rust_source, "_MAX_CHARACTERS", len((tmp_path / "a.rs").read_text())
        )
    elif boundary == "read":
        original = rust_source.read_text

        def read(path):
            if path.name == "b.rs":
                raise StaticReadError("Unreadable Rust source")
            return original(path)

        monkeypatch.setattr(rust_source, "read_text", read)
    bundle = _cargo_bundles(tmp_path)[0]
    assert bundle.usages and bundle.usages[0].reference == "serde"
    assert any(
        d.code.startswith("usage.rust-") and d.code != "usage.rust-uncollected"
        for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "usage").complete


def test_cargo_exact_versions_preserve_prereleases_and_reject_invalid_public_queries(
    tmp_path,
):
    accepted = [
        "0.164.0-alpha.3",
        "0.163.0-alpha.10.2",
        "1.0.0-beta.1",
        "1.0.0-rc.2+build.001",
        "1.0.0+001",
        "9007199254740992.0.0",
        "18446744073709551615.0.0",
        "1.0.0-" + "9" * 260,
    ]
    rejected = [
        "1.0.0-alpha.01",
        "1.0.0-01",
        "1١.0.0",
        "18446744073709551616.0.0",
        "v1.0.0",
        "1.0.0 ",
        "1.0.0-alpha..1",
    ]
    versions = {f"crate-{i}": value for i, value in enumerate(accepted + rejected)}
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\n'
        + "".join(f'{name}="={value}"\n' for name, value in versions.items())
    )
    (tmp_path / "Cargo.lock").write_text(
        "version=4\n"
        + "".join(
            f'[[package]]\nname="{name}"\nversion="{value}"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
            for name, value in versions.items()
        )
    )

    class PublicQueries:
        def __init__(self):
            self.packages = {}

        def scan_ecosystem(self, packages, ecosystem):
            assert ecosystem == "crates.io"
            self.packages.update(packages)
            return SimpleNamespace(
                vulnerabilities={}, diagnostics=(), queried=dict(packages)
            )

    client = PublicQueries()
    result = RepositoryScanner(osv_client=client).scan(tmp_path)
    bundle = result.bundles[0]
    assert sorted(client.packages.values()) == sorted(accepted)
    assert [r.version for r in bundle.resolved] == accepted
    expected_constraints = [f"={v}" for v in accepted] + [None] * len(rejected)
    # Cargo request grammar permits surrounding whitespace; exact lock values do not.
    expected_constraints[len(accepted) + rejected.index("1.0.0 ")] = "=1.0.0"
    assert [
        d.constraint.normalized for d in bundle.declarations
    ] == expected_constraints
    assert sum(d.code == "lock.invalid" for d in bundle.diagnostics) == len(rejected)
    assert not result.capability("security").complete


def test_cargo_workspace_inherits_origin_and_shares_only_member_lock(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/standalone"]\n'
        "[workspace.dependencies]\n"
        'serde = { version = "1", features = ["std"] }\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version = 4\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    for name in ["member", "standalone"]:
        child = tmp_path / "crates" / name
        child.mkdir(parents=True)
        (child / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion = "0.1.0"\n'
            '[dependencies]\nserde = { workspace = true, features = ["derive"] }\n'
        )
    bundles = {b.project.project_id: b for b in _cargo_bundles(tmp_path)}
    root = bundles["cargo:cargo:."]
    member = bundles["cargo:cargo:crates/member"]
    standalone = bundles["cargo:cargo:crates/standalone"]
    assert root.declarations[0].kind == "constraint"
    inherited = member.declarations[0]
    assert inherited.constraint.raw == "1"
    assert inherited.metadata["features"] == ["std", "derive"]
    assert inherited.metadata["workspace_origin"] == {
        "path": "Cargo.toml",
        "line": 5,
        "column": 1,
    }
    assert inherited.source.path == tmp_path / "crates/member/Cargo.toml"
    assert member.project.locks == (Path("Cargo.lock"),)
    assert Path("Cargo.toml") in member.project.manifests
    assert len(member.resolved) == 1
    assert not standalone.project.locks
    assert any(
        d.code == "manifest.workspace-unresolved" for d in standalone.diagnostics
    )


def test_multilingual_cargo_git_edges_and_credentials_survive_all_projections(tmp_path):
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    secret = "fixture-lock-secret"
    source = (
        "git+https://user:fixture-password@example.invalid/foo?rev=left&token=" + secret
    )
    other = (
        "git+https://user:fixture-password@example.invalid/foo?rev=right&token="
        + secret
    )
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n'
        '[dependencies]\nfoo={git="https://user:fixture-password@example.invalid/foo",rev="left"}\n'
    )
    rows = [
        {
            "name": "app",
            "version": "0.1.0",
            "dependencies": [f"foo 1.0.0 ({source})", "foo"],
        },
        {"name": "foo", "version": "1.0.0", "source": source + "#" + "a" * 40},
        {"name": "foo", "version": "1.0.0", "source": other + "#" + "b" * 40},
        {
            "name": "foo",
            "version": "1.0.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
        },
    ]
    (tmp_path / "Cargo.lock").write_text(
        "version=3\n"
        + "".join(
            "[[package]]\n"
            + "".join(
                key + "=" + json.dumps(value) + "\n" for key, value in row.items()
            )
            for row in rows
        )
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Cargo",))
    )
    (bundle,) = scan.bundles
    app = next(item for item in bundle.resolved if item.package.name == "app")
    first = next(
        item for item in bundle.resolved if item.metadata.get("package_index") == 1
    )
    assert app.dependency_links[0].instance_id == first.instance_id
    assert app.dependency_links[1].instance_id is None
    assert len({item.instance_id for item in bundle.resolved}) == 4
    assert first.origin["public"] is False and first.package.purl is None
    assert (
        first.metadata["source_sha256"]
        == hashlib.sha256(rows[1]["source"].encode()).hexdigest()
    )
    RepositoryIndexer().refresh(tmp_path, ecosystems=("Cargo",))
    projections = [
        scan.to_dict(),
        build_cyclonedx(scan),
        RepositoryIndex(tmp_path).dependencies(),
    ]
    serialized = json.dumps(projections)
    assert secret not in serialized and "fixture-password" not in serialized
    assert "source-sha256:" in first.instance_id


@pytest.mark.parametrize(
    "precision", ["omitted", "exact", "ambiguous", "different-query"]
)
def test_multilingual_cargo_source_qualification_keeps_ambiguity(tmp_path, precision):
    base = "git+https://example.invalid/foo?rev=one"
    target = base + "#" + "a" * 40
    reference = target if precision == "exact" else base
    if precision == "different-query":
        reference = "git+https://example.invalid/foo?rev=other"
    (tmp_path / "Cargo.toml").write_text('[package]\nname="app"\nversion="0.1.0"\n')
    packages = (
        '[[package]]\nname="app"\nversion="0.1.0"\n'
        "dependencies=[" + json.dumps("foo 1.0.0 (" + reference + ")") + "]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource=' + json.dumps(target) + "\n"
    )
    if precision == "ambiguous":
        packages += (
            '[[package]]\nname="foo"\nversion="1.0.0"\nsource='
            + json.dumps(base + "#" + "b" * 40)
            + "\n"
        )
    (tmp_path / "Cargo.lock").write_text("version=3\n" + packages)
    (bundle,) = _cargo_bundles(tmp_path)
    parent = next(item for item in bundle.resolved if item.package.name == "app")
    linked = parent.dependency_links[0].instance_id
    assert bool(linked) is (precision in {"omitted", "exact"})
    assert all(item.origin.get("public") is False for item in bundle.resolved)


def test_cargo_lock_preserves_source_instances_and_qualified_edges(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nfoo = "1"\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        "version = 3\n"
        '[[package]]\nname = "app"\nversion = "0.1.0"\n'
        'dependencies = ["foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "foo"]\n'
        '[[package]]\nname = "foo"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "abc123"\n'
        '[[package]]\nname = "foo"\nversion = "1.0.0"\n'
        'source = "git+https://example.org/foo#abcdef"\n'
        '[[package]]\nname = "foo"\nversion = "2.0.0"\n'
        'source = "registry+https://example.org/index"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert len(bundle.resolved) == 4
    registry = next(r for r in bundle.resolved if r.integrity == "abc123")
    assert registry.package.purl == "pkg:cargo/foo"
    assert (
        "registry+https://github.com/rust-lang/crates.io-index" in registry.instance_id
    )
    assert len({r.instance_id for r in bundle.resolved}) == 4
    assert all(r.package.purl is None for r in bundle.resolved if r is not registry)
    app = next(r for r in bundle.resolved if r.package.name == "app")
    assert app.dependency_links[0].instance_id == registry.instance_id
    assert app.dependency_links[1].instance_id is None
    assert app.dependency_links[1].version is None
    assert any(d.code == "resolution.cargo-link-ambiguous" for d in bundle.diagnostics)
    assert any(
        d.code == "resolution.cargo-activation-unknown" for d in bundle.diagnostics
    )
    assert {c.name: c.state.value for c in bundle.capabilities}[
        "resolution"
    ] == "incomplete"


@pytest.mark.parametrize(
    "lock_text",
    [
        "version = [",
        'version = 2\n[[package]]\nname = "foo"\nversion = "1.0.0"\n',
        'version = 4\npackage = "wrong"\n',
        'version = 4\n[[package]]\nname = "foo"\nversion = 1\n',
    ],
)
def test_cargo_malformed_or_unsupported_lock_is_incomplete(tmp_path, lock_text):
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nfoo = "1"\n')
    (tmp_path / "Cargo.lock").write_text(lock_text)
    bundle = _cargo_bundles(tmp_path)[0]
    assert not bundle.resolved
    assert any(d.code == "lock.invalid" for d in bundle.diagnostics)
    assert {c.name: c.state.value for c in bundle.capabilities}[
        "resolution"
    ] == "incomplete"


def test_cargo_does_not_infer_resolved_crates_from_manifest_pins(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nfoo = "=1.0.0"\n'
        'local = { path = "../outside", version = "=9.0.0" }\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert not bundle.resolved
    assert bundle.declarations[1].package.purl is None
    assert bundle.declarations[1].metadata["path"] == "../outside"
    assert any(d.code == "resolution.lock-missing" for d in bundle.diagnostics)
    assert any(d.code == "manifest.path-outside-root" for d in bundle.diagnostics)


def test_cargo_rejects_external_workspace_and_lock_symlinks(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\nworkspace = ".."\n'
        "[dependencies]\nfoo.workspace = true\n"
    )
    (tmp_path / "Cargo.toml").write_text('[workspace.dependencies]\nfoo = "=9.0.0"\n')
    external = tmp_path / "Cargo.lock"
    external.write_text('version = 4\n[[package]]\nname = "foo"\nversion = "9.0.0"\n')
    (root / "Cargo.lock").symlink_to(external)
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    bundle = _cargo_bundles(root)[0]
    assert bundle.project.manifests == (Path("Cargo.toml"),)
    assert not bundle.resolved
    assert any(d.code == "manifest.workspace-outside-root" for d in bundle.diagnostics)
    assert any("symlink" in d.message for d in bundle.diagnostics)


@pytest.mark.parametrize(
    "root_table,member_table",
    [
        ("workspace = 3\n", "foo.workspace = true\n"),
        (
            '[workspace]\nmembers = ["child"]\ndependencies = "bad"\n',
            "foo.workspace = true\n",
        ),
        (
            '[workspace]\nmembers = ["child"]\n[workspace.dependencies]\nfoo = { version = "1", features = [1] }\n',
            'foo = { workspace = true, features = ["ok"] }\n',
        ),
    ],
)
def test_cargo_invalid_workspace_data_remains_diagnostic(
    tmp_path, root_table, member_table
):
    (tmp_path / "Cargo.toml").write_text(root_table)
    child = tmp_path / "child"
    child.mkdir()
    (child / "Cargo.toml").write_text("[dependencies]\n" + member_table)
    bundles = _cargo_bundles(tmp_path)
    assert any(d.code.startswith("manifest.") for b in bundles for d in b.diagnostics)
    assert all(
        not c.complete for b in bundles for c in b.capabilities if c.name == "manifest"
    )
    assert not any(
        c.complete for b in bundles for c in b.capabilities if c.name == "resolution"
    )


def test_cargo_workspace_path_members_are_static_and_exclusions_hold(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "root"\nversion = "0.1.0"\n'
        '[workspace]\nexclude = ["excluded"]\n'
        '[workspace.dependencies]\nfoo = "1"\n'
        '[dependencies]\nlocal = { path = "local" }\n'
        'excluded = { path = "excluded" }\n'
    )
    (tmp_path / "Cargo.lock").write_text("version = 4\n")
    for name in ["local", "excluded"]:
        child = tmp_path / name
        child.mkdir()
        (child / "Cargo.toml").write_text("[dependencies]\nfoo.workspace = true\n")
    bundles = {b.project.project_id: b for b in _cargo_bundles(tmp_path)}
    assert bundles["cargo:cargo:local"].project.locks == (Path("Cargo.lock"),)
    assert bundles["cargo:cargo:local"].declarations[0].constraint.raw == "1"
    assert not bundles["cargo:cargo:excluded"].project.locks


def test_cargo_symlinked_dependency_path_retains_unverified_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text('[dependencies]\nfoo = { path = "link" }\n')
    (repo / "link").symlink_to(tmp_path, target_is_directory=True)
    bundle = _cargo_bundles(repo)[0]
    assert bundle.declarations[0].metadata["path"] == "link"
    assert bundle.declarations[0].package.purl is None
    assert any(d.code == "manifest.path-outside-root" for d in bundle.diagnostics)


def test_cargo_workspace_recursive_glob_and_explicit_missing_owner(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["./crates/**"]\n[workspace.dependencies]\nfoo = "1"\n'
    )
    child = tmp_path / "crates/nested/member"
    child.mkdir(parents=True)
    (child / "Cargo.toml").write_text("[dependencies]\nfoo.workspace = true\n")
    bundles = {b.project.project_id: b for b in _cargo_bundles(tmp_path)}
    assert (
        bundles["cargo:cargo:crates/nested/member"].declarations[0].constraint.raw
        == "1"
    )
    (child / "Cargo.toml").write_text(
        '[package]\nname = "member"\nversion = "0.1.0"\nworkspace = "missing"\n'
        '[dependencies]\nfoo = "1"\n'
    )
    member = next(
        b
        for b in _cargo_bundles(tmp_path)
        if b.project.root == Path("crates/nested/member")
    )
    assert any(d.code == "manifest.workspace-unresolved" for d in member.diagnostics)


def test_cargo_preserves_feature_inheritance_policy_without_assuming_toolchain(
    tmp_path,
):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["child"]\n[workspace.dependencies]\n'
        'foo = { version = "1", default-features = true }\n'
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "Cargo.toml").write_text(
        "[dependencies]\nfoo = { workspace = true, default-features = false }\n"
    )
    bundle = next(
        b for b in _cargo_bundles(tmp_path) if b.project.root == Path("child")
    )
    assert bundle.declarations[0].metadata["workspace-default-features"] is True
    assert bundle.declarations[0].metadata["default-features"] is False
    assert any(
        d.code == "manifest.cargo-feature-policy-unknown" for d in bundle.diagnostics
    )


def test_cargo_unknown_and_invalid_metadata_survives_json_serialization(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[dependencies]\nfoo = { version = "1", artifact = "bin", git = 2026-10-11 }\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    serialized = json.loads(json.dumps(bundle.to_dict(tmp_path)))
    metadata = serialized["declarations"][0]["metadata"]
    assert metadata["artifact"] == "bin"
    assert metadata["git"] == "2026-10-11"
    assert any(d.code == "manifest.invalid" for d in bundle.diagnostics)
    assert any(d.code == "manifest.unsupported-expression" for d in bundle.diagnostics)


def test_cargo_directness_requires_unique_matching_declared_source(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nfoo = "=1.0.0"\n')
    (tmp_path / "Cargo.lock").write_text(
        'version = 4\n[[package]]\nname = "foo"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'dependencies = ["child"]\n'
        '[[package]]\nname = "child"\nversion = "0.5.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname = "foo"\nversion = "2.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '[[package]]\nname = "foo"\nversion = "1.0.0"\n'
        'source = "git+https://example.org/foo#abc123"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert [(r.package.name, r.version, r.direct) for r in bundle.resolved] == [
        ("foo", "1.0.0", True),
        ("child", "0.5.0", False),
        ("foo", "2.0.0", False),
        ("foo", "1.0.0", False),
    ]
    (tmp_path / "Cargo.lock").write_text(
        (tmp_path / "Cargo.lock").read_text()
        + '[[package]]\nname = "foo"\nversion = "1.5.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nfoo = "1"\n')
    bundle = _cargo_bundles(tmp_path)[0]
    assert not any(r.direct for r in bundle.resolved)
    assert any(
        d.code == "resolution.cargo-direct-ambiguous" for d in bundle.diagnostics
    )


@pytest.mark.parametrize(
    "constraint,locked_version,direct,diagnostic",
    [
        ("1", "2.0.0", False, "resolution.cargo-constraint-mismatch"),
        ("1.2.3", "1.9.0", True, None),
        ("1.2.3", "2.0.0", False, "resolution.cargo-constraint-mismatch"),
        ("0.2", "0.2.9", True, None),
        ("0.2", "0.3.0", False, "resolution.cargo-constraint-mismatch"),
        ("~1.2", "1.2.9", True, None),
        (">=1.0, <2.0", "1.5.0", True, None),
        ("1 || 2", "1.5.0", False, "resolution.cargo-constraint-unknown"),
        ("1.0.0-alpha", "1.0.0-alpha", False, "resolution.cargo-constraint-unknown"),
        ("1١.0.0", "11.0.0", False, "resolution.cargo-constraint-unknown"),
        ("18446744073709551616", "1.0.0", False, "resolution.cargo-constraint-unknown"),
        ("1.0.0+bad..metadata", "1.0.0", False, "resolution.cargo-constraint-unknown"),
    ],
)
def test_cargo_directness_checks_cargo_range_semantics(
    tmp_path, constraint, locked_version, direct, diagnostic
):
    (tmp_path / "Cargo.toml").write_text(f'[dependencies]\nfoo = "{constraint}"\n')
    (tmp_path / "Cargo.lock").write_text(
        'version = 4\n[[package]]\nname = "foo"\n'
        f'version = "{locked_version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert bundle.resolved[0].direct is direct
    assert bundle.declarations[0].constraint.raw == constraint
    if diagnostic:
        assert any(d.code == diagnostic for d in bundle.diagnostics)
    else:
        assert not any(
            d.code.startswith("resolution.cargo-constraint-")
            for d in bundle.diagnostics
        )


@pytest.mark.parametrize(
    "declaration,lock_source",
    [
        ('"1"', "git+https://example.org/foo#abc123"),
        (
            '{ git = "https://example.org/declared" }',
            "git+https://example.org/other#abc123",
        ),
        (
            '{ git = "https://example.org/foo", branch = "main" }',
            "git+https://example.org/foo?branch=other#abc123",
        ),
    ],
)
def test_cargo_directness_rejects_mismatched_declared_source(
    tmp_path, declaration, lock_source
):
    (tmp_path / "Cargo.toml").write_text(f"[dependencies]\nfoo = {declaration}\n")
    (tmp_path / "Cargo.lock").write_text(
        'version = 4\n[[package]]\nname = "foo"\nversion = "1.0.0"\n'
        f'source = "{lock_source}"\n'
    )
    bundle = _cargo_bundles(tmp_path)[0]
    assert not bundle.resolved[0].direct
    assert any(d.code == "resolution.cargo-source-mismatch" for d in bundle.diagnostics)


def test_multilingual_cargo_workspace_patch_reaches_selected_member_and_cache(tmp_path):
    import shutil
    import tomllib

    original = Path(__file__).parent / "fixtures/projects/multilingual/wezterm-20220624"
    shutil.copytree(original, tmp_path, dirs_exist_ok=True)
    inputs = {
        p: (p.read_bytes(), p.stat().st_mtime_ns)
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    selection = ("cargo:cargo:wezterm-gui",)
    scan = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            compatibility=False,
            enabled_ecosystems=("Cargo",),
            project_ids=selection,
        ),
    )
    (bundle,) = scan.bundles
    expected = tomllib.loads((original / "Cargo.lock").read_text())["package"]
    assert len(bundle.resolved) == len(expected) == 511
    for item in bundle.resolved:
        row = expected[item.metadata["package_index"]]
        assert (item.package.name, item.version) == (row["name"], row["version"])
        source = row.get("source")
        assert item.metadata.get("source_sha256") == (
            hashlib.sha256(source.encode()).hexdigest() if source is not None else None
        )
    mlua = next(item for item in bundle.resolved if item.package.name == "mlua")
    assert (
        not mlua.direct and mlua.origin["public"] is False and mlua.package.purl is None
    )
    assert mlua.metadata["directness_status"] == "unknown"
    assert mlua.metadata["cargo_override_status"] == "unsupported"
    overrides = [
        d
        for d in bundle.diagnostics
        if d.code == "manifest.cargo-overrides-unsupported"
    ]
    assert overrides and all(
        d.source.path == tmp_path / "Cargo.toml" and d.source.line in {25, 26, 27}
        for d in overrides
    )
    assert not any(
        d.code == "resolution.cargo-source-mismatch" and "mlua" in d.message
        for d in bundle.diagnostics
    )
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value for p, value in inputs.items()
    )

    bom = build_cyclonedx(scan)
    component = next(
        item
        for item in bom["components"]
        if item["name"] == "mlua" and item.get("version") == mlua.version
    )
    metadata = next(
        p["value"]
        for p in component["properties"]
        if p["name"] == "depcheck:resolution:metadata"
    )
    assert json.loads(metadata) == dict(mlua.metadata)
    service = DependencyAgentService(tmp_path)
    service.index_repository(ecosystems=("Cargo",), project_ids=selection)
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency(
        "mlua", ecosystem="Cargo", project_id=selection[0]
    )
    assert record["resolutions"][0]["metadata"] == dict(mlua.metadata)
    declaration = next(d for d in record["declarations"] if d["kind"] == "direct")
    assert declaration["metadata"]["directness_status"] == "unknown"
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(manifest.read_text().split("[patch.crates-io]", 1)[0])
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("mlua", ecosystem="Cargo", project_id=selection[0])
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    service.index_repository(ecosystems=("Cargo",), project_ids=selection)
    again = service.explain_dependency(
        "mlua", ecosystem="Cargo", project_id=selection[0]
    )
    assert "cargo_override_status" not in again["resolutions"][0]["metadata"]


@pytest.mark.parametrize(
    "override,dependency,guarded",
    [
        (
            '[patch.crates-io]\nalias={package="foo",git="https://example.invalid/patch"}',
            '"=1.0.0"',
            True,
        ),
        (
            '[replace]\n"foo:1.0.0"={git="https://example.invalid/patch"}',
            '"=1.0.0"',
            True,
        ),
        (
            '[replace]\n"foo@1.0.0"={git="https://example.invalid/patch"}',
            '"=1.0.0"',
            True,
        ),
        (
            '[replace]\n"foo:9.0.0"={git="https://example.invalid/patch"}',
            '"=1.0.0"',
            False,
        ),
        (
            '[patch.crates-io]\nfoo={git="https://example.invalid/patch"}',
            '{git="https://example.invalid/declared"}',
            False,
        ),
        (
            '[patch."https://example.invalid/declared"]\nfoo={git="https://example.invalid/patch"}',
            '{git="https://example.invalid/declared"}',
            True,
        ),
    ],
)
def test_multilingual_cargo_overrides_only_qualify_applicable_sources(
    tmp_path, override, dependency, guarded
):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nfoo='
        + dependency
        + '\nbar="=1.0.0"\n'
        + override
        + "\n"
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\nsource="git+https://example.invalid/patch#abcd"\n[[package]]\nname="bar"\nversion="2.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    (bundle,) = _cargo_bundles(tmp_path)
    foo = next(row for row in bundle.resolved if row.package.name == "foo")
    mismatches = [
        d
        for d in bundle.diagnostics
        if d.code == "resolution.cargo-source-mismatch" and "'foo'" in d.message
    ]
    assert bool(mismatches) is not guarded
    assert not foo.direct and foo.origin["public"] is False
    declaration = next(
        d for d in bundle.declarations if d.package.name == "foo" and d.kind == "direct"
    )
    assert (
        declaration.metadata.get("cargo_override_status") == "unsupported"
    ) is guarded
    if guarded:
        assert foo.metadata.get("cargo_override_status") == "unsupported"
    assert any(
        d.code == "resolution.cargo-constraint-mismatch" and "'bar'" in d.message
        for d in bundle.diagnostics
    )


def test_multilingual_cargo_member_override_is_ignored(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers=["member"]\n')
    member = tmp_path / "member"
    member.mkdir()
    (member / "Cargo.toml").write_text(
        '[package]\nname="member"\nversion="1.0.0"\n[dependencies]\nfoo="=1.0.0"\n[patch.crates-io]\nfoo={git="https://example.invalid/patch"}\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\nsource="git+https://example.invalid/patch#abcd"\n'
    )
    bundle = next(
        b for b in _cargo_bundles(tmp_path) if b.project.root == Path("member")
    )
    assert any(d.code == "resolution.cargo-source-mismatch" for d in bundle.diagnostics)
    assert "cargo_override_status" not in bundle.resolved[0].metadata
    assert any(
        "ignored" in d.message.lower() and d.source.path == member / "Cargo.toml"
        for d in bundle.diagnostics
    )


@pytest.mark.parametrize(
    "declared",
    [
        "https://github.com/org/repo.git",
        "https://github.com/org/repo/",
        "https://github.com/Org/Repo",
        "http://github.com/org/repo",
    ],
)
def test_multilingual_cargo_override_retains_equivalent_git_spellings(
    tmp_path, declared
):
    source = "git+https://example.invalid/replacement#abcd"
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\n'
        f'foo={{git="{declared}"}}\n'
        '[patch."https://github.com/org/repo"]\n'
        'foo={git="https://example.invalid/replacement"}\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        f'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\nsource="{source}"\n'
    )
    (bundle,) = _cargo_bundles(tmp_path)
    assert not any(
        d.code == "resolution.cargo-source-mismatch" for d in bundle.diagnostics
    )
    (row,) = bundle.resolved
    assert not row.direct and row.origin["public"] is False
    assert row.metadata["source_sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert row.metadata["cargo_override_status"] == "unsupported"


@pytest.mark.parametrize("versions", [("3.0.0",), ("3.0.0", "1.0.0")])
def test_multilingual_cargo_patch_does_not_relax_original_constraint(
    tmp_path, versions
):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n'
        '[dependencies]\nfoo="=1.0.0"\n'
        '[patch.crates-io]\nfoo={version="=2.0.0",path="replacement"}\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        "version=4\n"
        + "".join(
            f'[[package]]\nname="foo"\nversion="{version}"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            for version in versions
        )
    )
    (bundle,) = _cargo_bundles(tmp_path)
    mismatches = [
        d
        for d in bundle.diagnostics
        if d.code == "resolution.cargo-constraint-mismatch"
    ]
    assert bool(mismatches) is ("1.0.0" not in versions)
    assert len(bundle.resolved) == len(versions)
    assert all(not row.direct for row in bundle.resolved)
    assert all(
        row.metadata["directness_status"] == "unknown" for row in bundle.resolved
    )


@pytest.mark.parametrize("shape", ["empty", "invalid"])
def test_multilingual_cargo_empty_and_invalid_overrides_keep_distinct_states(
    tmp_path, shape
):
    prefix = "patch=1\n" if shape == "invalid" else ""
    suffix = "\n[patch.crates-io]\n[replace]\n" if shape == "empty" else ""
    (tmp_path / "Cargo.toml").write_text(
        prefix + '[package]\nname="app"\nversion="0.1.0"\n'
        '[dependencies]\nfoo="=1.0.0"\n' + suffix
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    (bundle,) = _cargo_bundles(tmp_path)
    (row,) = bundle.resolved
    assert row.direct is (shape == "empty")
    if shape == "invalid":
        assert row.metadata["directness_status"] == "unknown"
        assert any(d.code == "manifest.invalid" for d in bundle.diagnostics)
    else:
        assert not any("cargo-overrides" in d.code for d in bundle.diagnostics)


@pytest.mark.parametrize(
    "budget,code",
    [
        ("_OVERRIDE_ENTRY_LIMIT", "manifest.cargo-overrides-budget"),
        ("_OVERRIDE_WORK_LIMIT", "resolution.cargo-overrides-budget"),
        ("_OVERRIDE_VIEW_DETAIL_BYTES", "manifest.cargo-overrides-details-omitted"),
    ],
)
def test_multilingual_cargo_override_budget_retains_unknown_inventory(
    tmp_path, monkeypatch, budget, code
):
    from depcheck.ecosystems.rust import lock, overrides

    module = overrides if budget == "_OVERRIDE_ENTRY_LIMIT" else lock
    monkeypatch.setattr(module, budget, 0)
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\nfoo="=1.0.0"\n'
        '[patch.crates-io]\nfoo={path="replacement"}\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    (bundle,) = _cargo_bundles(tmp_path)
    (row,) = bundle.resolved
    assert row.version == "1.0.0" and not row.direct
    assert row.metadata["directness_status"] == "unknown"
    assert any(d.code == code for d in bundle.diagnostics)
    declaration = next(d for d in bundle.declarations if d.kind == "direct")
    assert declaration.metadata["directness_status"] == "unknown"


def test_multilingual_cargo_override_source_key_is_redacted(tmp_path):
    from dataclasses import asdict

    canary = "override-secret-canary"
    source = f"https://user:{canary}@example.invalid/original"
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="app"\nversion="0.1.0"\n[dependencies]\n'
        f'foo={{git="{source}"}}\n[patch."{source}"]\n'
        'foo={path="replacement"}\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source="git+https://example.invalid/replacement#abcd"\n'
    )
    (bundle,) = _cargo_bundles(tmp_path)
    assert canary not in json.dumps(asdict(bundle), default=str)
    declaration = next(d for d in bundle.declarations if d.kind == "direct")
    assert declaration.metadata["cargo_overrides"]["matching_entries"] == 1
    assert not bundle.resolved[0].direct
