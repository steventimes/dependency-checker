"""Gradle collection, ownership, and qualified static evidence."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


@pytest.mark.parametrize("name", ["build.gradle", "build.gradle.kts"])
def test_gradle_literals_ignore_documentation_and_preserve_lock_variants(
    tmp_path, name
):
    class CapturingOSV:
        def __init__(self):
            self.calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(vulnerabilities={}, diagnostics=(), queried=packages)

    keyword = "val" if name.endswith(".kts") else "def"
    (tmp_path / name).write_text(
        keyword + ' doc = """\nimplementation("ghost:doc:9.0")\n"""\n'
        '/*\nimplementation("ghost:comment:8.0")\n*/\ndependencies {\n'
        '  implementation(\n    "org.slf4j:slf4j-api:1.7.36"\n  )\n'
        '  testImplementation("org.slf4j:slf4j-api:2.0.16")\n'
        '  implementation("org.example:dynamic:$chosen")\n}\n'
    )
    (tmp_path / "gradle.lockfile").write_text(
        "org.slf4j:slf4j-api:1.7.36=compileClasspath\n"
        "org.slf4j:slf4j-api:2.0.16=testCompileClasspath\n"
    )
    osv = CapturingOSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            enabled_ecosystems=("Maven",),
            public_maven_packages=("org.slf4j:slf4j-api",),
        ),
    )
    bundle = result.bundles[0]
    assert len(bundle.declarations) == 3
    assert all(d.kind == "conditional" for d in bundle.declarations)
    assert {d.package.name for d in bundle.declarations} == {
        "org.slf4j:slf4j-api",
        "org.example:dynamic",
    }
    assert (
        bundle.declarations[0].source.line,
        bundle.declarations[0].source.column,
    ) == (9, 5)
    assert bundle.declarations[2].constraint.normalized is None
    assert {r.version for r in bundle.resolved} == {"1.7.36", "2.0.16"}
    assert len({r.instance_id for r in bundle.resolved}) == 2
    assert osv.calls == [
        ("Maven", {"org.slf4j:slf4j-api": "1.7.36"}),
        ("Maven", {"org.slf4j:slf4j-api": "2.0.16"}),
    ]
    assert not result.capability("security").complete
    assert not result.findings


def test_gradle_wrappers_constraints_custom_scopes_and_aliases_stay_distinct(tmp_path):
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies { implementation(platform("org.junit:junit-bom:5.11.0")); '
        'testImplementation(testFixtures("example:fixtures:2.0")); '
        'constraints { api("example:managed:3.0") }; '
        'customRuntime("example:custom:4.0"); implementation(libs.alias) }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declarations = result.bundles[0].declarations
    assert len(declarations) == 4
    assert declarations[0].metadata["gradle_kind"] == "platform"
    assert declarations[0].scope == "build"
    assert declarations[1].metadata["gradle_kind"] == "testFixtures"
    assert declarations[1].scope == "test"
    assert declarations[2].kind == "constraint"
    assert declarations[3].scope == "unknown"
    assert {d.code for d in result.diagnostics} >= {
        "manifest.unsupported-expression",
        "manifest.gradle-configuration-uncollected",
    }
    assert not result.bundles[0].resolved


def test_gradle_versionless_and_classifier_notations_preserve_assertions(tmp_path):
    (tmp_path / "build.gradle").write_text(
        'dependencies { compileOnly "example:no-version"; '
        'implementation "example:tests:1.0:tests@jar" }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    versionless, classified = result.bundles[0].declarations
    assert (
        versionless.constraint.raw == "" and versionless.constraint.normalized is None
    )
    assert classified.constraint.raw == "1.0"
    assert classified.metadata["classifier"] == "tests"
    assert classified.metadata["extension"] == "jar"
    assert classified.metadata["notation"] == "example:tests:1.0:tests@jar"
    assert not result.bundles[0].resolved
    sbom = build_cyclonedx(result)
    assert not sbom["dependencies"][0]["dependsOn"]
    assert all("version" not in c for c in sbom["components"])


def test_gradle_interpolation_is_opaque_and_does_not_hide_later_literals(tmp_path):
    (tmp_path / "build.gradle.kts").write_text(
        'val doc = "prefix ${"implementation(\\"ghost:nested:1.0\\")"} suffix"\n'
        'dependencies { implementation("example:real:1.0") }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [d.package.name for d in result.bundles[0].declarations] == ["example:real"]


@pytest.mark.parametrize(
    "tail",
    [
        '/* unfinished\nimplementation("ghost:comment:1")',
        'val value = "unterminated\nimplementation("ghost:string:1")',
        'def regex = /implementation("ghost:slashy:1")/',
        'val raw = """\nimplementation("ghost:triple:1")',
    ],
)
def test_gradle_lexical_uncertainty_retains_only_a_qualified_prefix(tmp_path, tail):
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies { implementation("example:prefix:1") }\n' + tail + "\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [d.package.name for d in result.bundles[0].declarations] == [
        "example:prefix"
    ]
    assert any(
        d.code == "manifest.gradle-lexical-uncollected" for d in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete


def test_gradle_lock_repeated_instances_and_buildscript_context_survive_queries(
    tmp_path,
):
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation "example:lib:1" }\n'
    )
    (tmp_path / "gradle.lockfile").write_text(
        "# ghost:comment:9=ignored\n"
        "example:lib:1=compileClasspath\nexample:lib:2=testCompileClasspath\n"
        "example:lib:1=compileClasspath\nexample:lib:1=runtimeClasspath\n"
        "malformed\nexample:bad:$chosen=runtimeClasspath\nempty=annotationProcessor\n"
    )
    (tmp_path / "buildscript-gradle.lockfile").write_text("example:lib:3=classpath\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    resolved = result.bundles[0].resolved
    assert len(resolved) == 5 and len({r.instance_id for r in resolved}) == 5
    assert all(not r.direct and r.origin["selection"] == "unknown" for r in resolved)
    assert any(r.origin["lock_kind"] == "buildscript" for r in resolved)
    assert any(d.code == "lock.gradle-invalid-entry" for d in result.diagnostics)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    original = (cache.read_bytes(), cache.stat().st_mtime_ns)
    explanation = service.explain_dependency(
        "example:lib", ecosystem="Maven", project_id="maven:gradle:."
    )
    assert explanation["resolved_versions"] == ["1", "2", "3"]
    assert (
        explanation["resolved_version"] is None and not explanation["evidence_complete"]
    )
    assert len(explanation["resolutions"]) == 5
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original
    sbom = build_cyclonedx(result)
    refs = [c["bom-ref"] for c in sbom["components"]]
    assert len(refs) == len(set(refs)) and not sbom["dependencies"][0]["dependsOn"]


def test_gradle_both_build_scripts_and_uncovered_configuration_affect_freshness(
    tmp_path,
):
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation "example:groovy:1" }\n'
    )
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies { implementation("example:kotlin:2") }\n'
    )
    (tmp_path / "settings.gradle.kts").write_text("import org.slf4j.Logger\n")
    (tmp_path / "conventions.gradle.kts").write_text("import org.slf4j.Logger\n")
    (tmp_path / "gradle").mkdir()
    catalog = tmp_path / "gradle/libs.versions.toml"
    catalog.write_text('[versions]\nexample="1"\n')
    child = tmp_path / "child"
    child.mkdir()
    (child / "build.gradle.kts").write_text(
        'dependencies { implementation("example:child:3") }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == {
        "example:groovy",
        "example:kotlin",
    }
    assert (
        len(bundle.project.manifests) == 2
        and not bundle.usages
        and not bundle.source_files
    )
    child_bundle = next(b for b in result.bundles if b.project.root == Path("child"))
    assert (
        child_bundle.declarations[0].metadata["call_source"]["path"]
        == "child/build.gradle.kts"
    )
    gaps = {g["path"] for g in result.metadata["coverage"]["uncovered"]}
    assert gaps >= {
        "settings.gradle.kts",
        "conventions.gradle.kts",
        "gradle/libs.versions.toml",
    }
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    catalog.write_text('[versions]\nexample="2"\n')
    assert service.repository_context()["stale"]


def test_gradle_catalog_library_definitions_keep_versions_bundles_and_locations(
    tmp_path,
):
    catalog = tmp_path / "gradle/libs.versions.toml"
    catalog.parent.mkdir()
    text = (
        '[versions]\ncommon = "1.4"\n'
        'rich = { strictly = "[1.0,2.0[", prefer = "1.2", reject = ["1.1"] }\n'
        '[libraries]\ncore-lib = { module = "example:core", version.ref = "common" }\n'
        'alternate = "example:core:2.0"\n'
        'rich-lib = { group = "example", name = "rich", version.ref = "rich" }\n'
        'without-version = { module = "example:plain" }\n'
        '[bundles]\nmain = ["core_lib", "rich-lib", "core-lib"]\n'
        '[plugins]\ncompile = { id = "example.compile", version = "1.0" }\n'
    )
    catalog.write_text(text)
    (tmp_path / "build.gradle.kts").write_text(
        "dependencies { implementation(libs.core.lib) }\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    catalogs = [b for b in result.bundles if b.project.manager == "gradle-catalog"]
    assert len(catalogs) == 1
    bundle = catalogs[0]
    assert bundle.project.project_id == "maven:gradle-catalog:gradle"
    assert bundle.project.manifests == (Path("gradle/libs.versions.toml"),)
    assert bundle.project.locks == () and bundle.resolved == () and bundle.usages == ()
    core, alternate, rich, plain = bundle.declarations
    assert core.package.name == alternate.package.name == "example:core"
    assert (
        core.constraint.scheme == "gradle-catalog"
        and core.constraint.normalized == "1.4"
    )
    assert core.source.line == 5 and core.metadata["version_source"]["line"] == 2
    assert core.metadata["version_reference_source"]["line"] == 5
    assert [m["member"] for m in core.metadata["bundles"]] == ["core_lib", "core-lib"]
    assert {m["member_source"]["line"] for m in core.metadata["bundles"]} == {10}
    assert rich.constraint.normalized is None
    assert rich.metadata["version_assertion"]["strictly"] == "[1.0,2.0["
    assert (
        plain.constraint.normalized is None
        and plain.metadata["version_status"] == "unspecified"
    )
    assert all(
        d.kind == "conditional" and d.scope == "unknown" for d in bundle.declarations
    )
    assert all(d.metadata["activation"] == "unknown" for d in bundle.declarations)
    assert any(
        d.code == "manifest.gradle-catalog-plugins-uncollected"
        for d in bundle.diagnostics
    )
    assert not any(
        d.code == "coverage.unsupported-manifest" and d.source.path == catalog
        for d in result.diagnostics
    )
    assert not any(
        b.declarations for b in result.bundles if b.project.manager == "gradle"
    )
    assert not result.findings


def test_gradle_catalog_files_do_not_share_version_definitions(tmp_path):
    (tmp_path / "first.versions.toml").write_text(
        '[versions]\nshared="1"\n[libraries]\naaa={module="example:first",version.ref="shared"}\n'
    )
    (tmp_path / "second.versions.toml").write_text(
        '[libraries]\nbbb={module="example:second",version.ref="shared"}\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert len(result.bundles) == 1
    bundle = result.bundles[0]
    assert (
        bundle.project.project_id == "maven:gradle-catalog:."
        and len(bundle.project.manifests) == 2
    )
    first, second = bundle.declarations
    assert first.constraint.normalized == "1" and second.constraint.normalized is None
    assert (
        second.metadata["version_reference"] == "shared"
        and second.metadata["version_assertion"] is None
    )
    assert any(
        d.code == "manifest.gradle-catalog-reference-unresolved"
        and d.source.path.name == "second.versions.toml"
        for d in bundle.diagnostics
    )


def test_gradle_catalog_alias_queries_search_all_declarations_before_paging(tmp_path):
    text = "[libraries]\n" + "".join(
        f'alias-{n:02d} = "example:lib:1"\n' for n in range(24)
    )
    (tmp_path / "libs.versions.toml").write_text(text)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    page = service.query_dependencies(
        "alias-23", ecosystem="Maven", project_id="maven:gradle-catalog:."
    )
    assert page["count"] == 1 and page["dependencies"][0]["package"] == "example:lib"
    assert page["dependencies"][0]["evidence_page"]["counts"]["declarations"] == 24
    record = service.explain_dependency(
        "example:lib",
        ecosystem="Maven",
        project_id="maven:gradle-catalog:.",
        evidence_offset=20,
    )
    assert len(record["declarations"]) == 4 and record["resolved_versions"] == []
    assert not record["usage_complete"] and not record["evidence_complete"]
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]


@pytest.mark.parametrize(
    "notation,retained",
    [
        ('"example:bad"', False),
        ("7", False),
        ("{ module = 7 }", False),
        ('{ module="example:bad", group="other", name="bad" }', False),
        ('{ group="example", name=7 }', False),
        ('{ module="example:bad", classifier="tests" }', True),
        ('{ module="${group}:bad" }', False),
    ],
)
def test_gradle_catalog_invalid_libraries_keep_valid_siblings(
    tmp_path, notation, retained
):
    (tmp_path / "libs.versions.toml").write_text(
        "[libraries]\nbad=" + notation + '\ngood="example:good:1"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == (
        {"example:bad", "example:good"} if retained else {"example:good"}
    )
    assert any(
        d.code.startswith("manifest.gradle-catalog-") for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


@pytest.mark.parametrize(
    "version",
    [
        "7",
        "true",
        '{ref="missing"}',
        '{ref="known",prefer="2"}',
        "{require=7}",
        '{reject="2"}',
        "{rejectAll=1}",
        '{unknown="2"}',
    ],
)
def test_gradle_catalog_unknown_version_is_not_selected(tmp_path, version):
    (tmp_path / "libs.versions.toml").write_text(
        '[versions]\nknown="1"\n[libraries]\nbad={module="example:bad",version='
        + version
        + '}\ngood="example:good:2"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bad, good = result.bundles[0].declarations
    assert bad.constraint.normalized is None and good.constraint.normalized == "2"
    assert bad.metadata["version_assertion"] is None and not result.bundles[0].resolved
    assert any(
        d.code.startswith("manifest.gradle-catalog-") for d in result.diagnostics
    )
    assert not result.findings


def test_gradle_catalog_normalized_alias_collisions_preserve_all_assertions(tmp_path):
    (tmp_path / "libs.versions.toml").write_text(
        '[versions]\nv-one="1"\nv_one="2"\ncommon-version="3"\n'
        '[libraries]\nfoo-bar={module="example:first",version.ref="v-one"}\n'
        'foo_bar={module="example:second",version.ref="common_version"}\n'
        'class="example:reserved:1"\nversions-first="example:prefix:1"\n'
        '[bundles]\nmain=["foo.bar","absent",7]\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    first, second, reserved, prefix = result.bundles[0].declarations
    assert (
        first.metadata["alias_status"] == second.metadata["alias_status"] == "ambiguous"
    )
    assert first.constraint.normalized is None and second.constraint.normalized == "3"
    assert (
        reserved.metadata["alias_status"]
        == prefix.metadata["alias_status"]
        == "unsupported"
    )
    assert all(d.metadata["bundles"] == [] for d in result.bundles[0].declarations)
    assert any(
        d.code == "manifest.gradle-catalog-alias-ambiguous" for d in result.diagnostics
    )


@pytest.mark.parametrize(
    "data",
    [
        '[libraries]\naa="example:first:1"\naa="example:second:2"\n',
        "libraries=[]\nversions=7\n",
        "[libraries]\ninvalid=" + "[" * 1500 + "0" + "]" * 1500,
    ],
)
def test_gradle_catalog_malformed_input_is_qualified(tmp_path, data):
    (tmp_path / "libs.versions.toml").write_text(data)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles and not result.bundles[0].declarations
    assert any(
        d.code.startswith("manifest.gradle-catalog-") for d in result.diagnostics
    )
    assert not next(
        c for c in result.bundles[0].capabilities if c.name == "manifest"
    ).complete


def test_gradle_catalog_missing_positions_keep_file_only_locations(
    tmp_path, monkeypatch
):
    from depcheck.filesystem.positions import SourcePositions

    monkeypatch.setattr(
        SourcePositions, "toml", lambda path, text: SourcePositions(path, text)
    )
    (tmp_path / "libs.versions.toml").write_text('[libraries]\ncore="example:core:1"\n')
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declaration = result.bundles[0].declarations[0]
    assert declaration.source.line is None and declaration.source.column is None
    assert declaration.metadata["version_source"] == {"path": "libs.versions.toml"}


def test_gradle_catalog_context_expansion_keeps_qualified_prefix(tmp_path, monkeypatch):
    import depcheck.ecosystems.java.catalog as gradle_catalog

    monkeypatch.setattr(gradle_catalog, "DEFAULT_MAX_BYTES", 2200)
    (tmp_path / "libs.versions.toml").write_text(
        "[versions]\ncommon={reject=["
        + ",".join('"' + str(n) + '"' for n in range(30))
        + "]}\n"
        "[libraries]\n"
        + "".join(
            f'alias-{n}={{module="example:lib{n}",version.ref="common"}}\n'
            for n in range(8)
        )
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert 0 < len(result.bundles[0].declarations) < 8
    assert any("budget" in d.message for d in result.diagnostics)
    assert not next(
        c for c in result.bundles[0].capabilities if c.name == "manifest"
    ).complete


def test_gradle_catalog_definitions_do_not_create_application_edges_or_osv_queries(
    tmp_path,
):
    (tmp_path / "libs.versions.toml").write_text(
        '[libraries]\ncore="example:core:1.2.3"\n'
    )

    def unexpected(*args, **kwargs):
        raise AssertionError(
            "Catalog definitions cannot supply selected security versions"
        )

    result = RepositoryScanner(
        osv_client=SimpleNamespace(scan_ecosystem=unexpected)
    ).scan(tmp_path)
    assert result.bundles[0].resolved == () and not result.findings
    bom = build_cyclonedx(result)
    package = next(c for c in bom["components"] if c["name"] == "example:core")
    assert "version" not in package
    app_edges = next(
        e
        for e in bom["dependencies"]
        if e["ref"] == bom["metadata"]["component"]["bom-ref"]
    )
    assert app_edges["dependsOn"] == []


def test_gradle_catalog_only_component_root_and_freshness_topology(tmp_path):
    folder = tmp_path / "gradle"
    folder.mkdir()
    catalog = folder / "libs.versions.toml"
    catalog.write_text('[libraries]\ncore="example:core:1"\n')
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert not service.repository_context()["stale"]
    catalog.write_text('[libraries]\ncore="example:core:2"\n')
    assert service.repository_context()["stale"]
    service.index_repository()
    (folder / "more.versions.toml").write_text('[libraries]\nother="example:other:1"\n')
    assert service.repository_context()["stale"]
    service.index_repository()
    root_bundle = (
        RepositoryScanner()
        .scan(folder, RepositoryScanOptions(security=False))
        .bundles[0]
    )
    assert root_bundle.project.project_id == "maven:gradle-catalog:."
    catalog.unlink()
    assert service.repository_context()["stale"]


def test_gradle_catalog_selected_queries_reject_stale_without_mutating_cache(tmp_path):
    catalog = tmp_path / "libs.versions.toml"
    catalog.write_text('[libraries]\nfirst-alias="example:lib:1"\n')
    service = DependencyAgentService(tmp_path)
    project_id = "maven:gradle-catalog:."
    service.index_repository(project_ids=(project_id,))
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    assert (
        service.query_dependencies("first-alias", project_id=project_id)["count"] == 1
    )
    catalog.write_text('[libraries]\nsecond-alias="example:lib:2"\n')
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies("second-alias", project_id=project_id)
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]
    service.index_repository(project_ids=(project_id,))
    record = service.query_dependencies("second-alias", project_id=project_id)[
        "dependencies"
    ][0]
    assert record["declarations"][0]["constraint"]["normalized"] == "2"
    assert (
        service.query_dependencies("first-alias", project_id=project_id)["count"] == 0
    )


def test_gradle_catalog_entry_budget_is_an_explicit_coverage_gap(tmp_path, monkeypatch):
    import depcheck.ecosystems.java.catalog as gradle_catalog

    monkeypatch.setattr(gradle_catalog, "_MAX_ENTRIES", 2)
    (tmp_path / "libs.versions.toml").write_text(
        '[libraries]\naaa="example:first:1"\nbbb="example:second:1"\nccc="example:third:1"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.bundles[0].declarations
    assert any(
        g["reason"] == "manifest.gradle-catalog-budget"
        for g in result.metadata["coverage"]["uncovered"]
    )


def test_gradle_literal_context_expansion_is_bounded(tmp_path, monkeypatch):
    import depcheck.ecosystems.java.gradle as gradle

    monkeypatch.setattr(gradle, "DEFAULT_MAX_BYTES", 2400)
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation "example:prefix:1"; implementation "example:other:2" }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert len(result.bundles[0].declarations) == 1
    assert any(d.code == "manifest.gradle-budget" for d in result.diagnostics)


@pytest.mark.parametrize("name", ["build.gradle", "build.gradle.kts"])
def test_gradle_triple_quote_escaping_follows_its_dsl(tmp_path, name):
    if name.endswith(".kts"):
        text = 'val doc = """ends with ' + "\\" + '"""\n'
    else:
        text = 'def doc = """\n' + "\\" + '"""\nimplementation("ghost:triple:9")\n"""\n'
    text += 'dependencies { implementation("example:real:1") }\n'
    (tmp_path / name).write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [d.package.name for d in result.bundles[0].declarations] == ["example:real"]
    assert not any(
        d.code == "manifest.gradle-lexical-uncollected" for d in result.diagnostics
    )


@pytest.mark.parametrize("budget", ["tokens", "calls", "interpolation"])
def test_gradle_lexer_budgets_do_not_scan_untrusted_suffixes(
    tmp_path, monkeypatch, budget
):
    import depcheck.ecosystems.java.gradle as gradle

    if budget == "tokens":
        monkeypatch.setattr(gradle, "_MAX_TOKENS", 15)
        tail = "noise " * 30
    elif budget == "calls":
        monkeypatch.setattr(gradle, "_MAX_DEPTH", 4)
        tail = "val value = " + "(" * 8 + "value" + ")" * 8
    else:
        monkeypatch.setattr(gradle, "_MAX_DEPTH", 4)
        expression = '"value"'
        for _ in range(8):
            expression = '"${' + expression + '}"'
        tail = "val value = " + expression
    (tmp_path / "build.gradle.kts").write_text(
        'dependencies { implementation("example:prefix:1") }\n'
        + tail
        + '\ndependencies { implementation("ghost:suffix:9") }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [d.package.name for d in result.bundles[0].declarations] == [
        "example:prefix"
    ]
    assert any("budget" in d.message for d in result.diagnostics)
