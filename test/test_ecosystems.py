"""Static ecosystem collectors, ownership, source evidence, and lock semantics."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from depcheck.agent import DependencyAgentService
from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.ecosystems.base import ProviderContext
from depcheck.ecosystems.cpp import create_conan_pack, create_vcpkg_pack
from depcheck.ecosystems.java import create_maven_pack
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import MappingConfidence
from depcheck.output import build_cyclonedx


def test_tsconfig_records_type_plugin_and_inherited_configuration_usage(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {
                    "@types/node": "22.0.0",
                    "typescript-plugin": "1.0.0",
                    "@tsconfig/node22": "22.0.0",
                }
            }
        )
    )
    (tmp_path / "main.ts").write_text("console.log(process.version);\n")
    (tmp_path / "tsconfig.json").write_text(
        '{ // compiler configuration\n "extends":"./base.json",\n'
        ' "compilerOptions":{"types":["node"],},\n}\n'
    )
    (tmp_path / "base.json").write_text(
        '{"extends":"@tsconfig/node22/tsconfig.json",\n'
        ' "compilerOptions":{"plugins":[{"name":"typescript-plugin"}]}}'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    configs = [u for u in result.bundles[0].usages if u.kind == "configuration"]
    assert {u.mapped_package.name for u in configs} == {
        "@types/node",
        "typescript-plugin",
        "@tsconfig/node22",
    }
    assert all(u.scope == "build" and u.source.line for u in configs)
    assert not any(f.code == "dependency.unused" for f in result.findings)
    assert {p.name for p in result.bundles[0].evidence_files} >= {
        "tsconfig.json",
        "base.json",
    }


@pytest.mark.parametrize(
    "config",
    [
        '{"extends":"../outside.json"}',
        '{"extends":"./tsconfig.json"}',
        '{"compilerOptions":{"types":"node"}}',
        '{"compilerOptions":{"plugins":[{"name":4}]}}',
        '{"compilerOptions":{"types":["node"],"types":[]}}',
    ],
)
def test_tsconfig_unsupported_configuration_prevents_unused_claims(tmp_path, config):
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"@types/node":"22.0.0"}}'
    )
    (tmp_path / "main.ts").write_text("console.log(process.version);\n")
    (tmp_path / "tsconfig.json").write_text(config)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(d.code.startswith("configuration.") for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    "configuration",
    ['addopts="-p pytest_mock"', 'required_plugins=["pytest-mock>=3.0"]'],
    ids=["addopts", "required-plugins"],
)
def test_pytest_plugin_configuration_is_usage_evidence(tmp_path, configuration):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="example"\nversion="0.1"\n'
        '[project.optional-dependencies]\ntest=["pytest-mock==3.14.0"]\n'
        f"[tool.pytest.ini_options]\n{configuration}\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not any(f.code == "dependency.unused" for f in result.findings)
    usage = next(u for u in result.bundles[0].usages if u.kind == "configuration")
    assert usage.mapped_package.name == "pytest-mock"
    assert usage.scope == "test" and usage.source.line == 7
    assert "execution" in usage.mapping_reason


def test_deep_python_component_metadata_remains_incomplete(tmp_path):
    child = tmp_path / "component"
    child.mkdir()
    (child / "pyproject.toml").write_text(
        '[project]\nname="test"\ndependencies=[]\n[tool.payload]\na='
        + "[" * 1500
        + "0"
        + "]" * 1500
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert result.diagnostics


def test_tsconfig_inherited_file_changes_invalidate_index(tmp_path):
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"@types/node":"22.0.0"}}'
    )
    (tmp_path / "tsconfig.json").write_text('{"extends":"./base.json"}')
    base = tmp_path / "base.json"
    base.write_text('{"compilerOptions":{"types":["node"]}}')
    RepositoryIndexer().refresh(tmp_path)
    assert not RepositoryIndex(tmp_path).context()["stale"]
    base.write_text('{"compilerOptions":{"types":[]}}')
    assert RepositoryIndex(tmp_path).context()["stale"]


@pytest.mark.parametrize("inherited", [False, True])
def test_tsconfig_custom_type_roots_do_not_map_local_types_to_npm(tmp_path, inherited):
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"@types/node":"22.0.0"}}'
    )
    (tmp_path / "tsconfig.json").write_text(
        '{"compilerOptions":{"typeRoots":["./local-types"],"types":["node"]}}'
    )
    if inherited:
        (tmp_path / "base.json").write_text(
            '{"compilerOptions":{"typeRoots":["./local-types"]}}'
        )
        (tmp_path / "tsconfig.json").write_text(
            '{"extends":"./base.json","compilerOptions":{"types":["node"]}}'
        )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not any(
        u.mapping_confidence is MappingConfidence.EXACT
        for u in result.bundles[0].usages
    )
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    ("options", "package"),
    [
        ({"jsx": "preserve", "jsxImportSource": "preact"}, "preact"),
        ({"importHelpers": True, "target": "ESNext"}, "tslib"),
    ],
)
def test_tsconfig_emit_options_do_not_assert_runtime_scope(tmp_path, options, package):
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {package: "1.0.0"}})
    )
    (tmp_path / "tsconfig.json").write_text(json.dumps({"compilerOptions": options}))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    usage = next(u for u in result.bundles[0].usages if u.kind == "configuration")
    assert usage.mapped_package.name == package and usage.scope == "unknown"
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.scope-mismatch" for f in result.findings)


def test_unreferenced_json_is_not_index_evidence(tmp_path):
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    (tmp_path / "package.json").write_text("{}")
    note = tmp_path / "notes.json"
    note.write_text('{"note":"before"}')
    RepositoryIndexer().refresh(tmp_path)
    note.write_text('{"note":"after"}')
    assert not RepositoryIndex(tmp_path).context()["stale"]


def test_npm_duplicate_json_key_location_follows_retained_value(tmp_path):
    (tmp_path / "package.json").write_text(
        '{\n "dependencies":{"tool":"1.0.0"},\n "dependencies":{\n  "tool":"2.0.0"\n }\n}\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declaration = result.bundles[0].declarations[0]
    assert declaration.constraint.raw == "2.0.0"
    assert (declaration.source.line, declaration.source.column) == (4, 3)


@pytest.mark.parametrize(
    "locks",
    [
        ("package-lock.json", "pnpm-lock.yaml"),
        ("package-lock.json", "yarn.lock"),
        ("pnpm-lock.yaml", "yarn.lock"),
    ],
)
def test_npm_conflicting_package_managers_do_not_choose_a_lock_graph(tmp_path, locks):
    from depcheck.security.osv_client import OSVScanResult

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"tool":"^1.0.0"},"packageManager":"pnpm@9.0.0"}'
    )
    (tmp_path / "app.js").write_text('import "tool";\n')
    contents = {
        "package-lock.json": json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/tool": {"version": "1.0.0"}},
            }
        ),
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      tool:\n        specifier: ^1.0.0\n        version: 1.1.0\npackages:\n  tool@1.1.0: {}\nsnapshots:\n  tool@1.1.0: {}\n",
        "yarn.lock": "# yarn lockfile\n",
    }
    for name in locks:
        (tmp_path / name).write_text(contents[name])
    before = {name: (tmp_path / name).read_bytes() for name in locks}
    queries = []

    def query(packages, ecosystem):
        queries.append((packages, ecosystem))
        return OSVScanResult({}, (), packages)

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=query)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    bundle = result.bundles[0]
    assert not bundle.resolved
    assert not queries
    assert any(
        d.code == "resolution.package-manager-ambiguous" for d in result.diagnostics
    )
    assert not result.capability("security").complete
    assert not result.capability("dependency_hygiene").complete
    assert any(
        item["reason"] == "resolution.package-manager-ambiguous"
        for item in result.metadata["coverage"]["uncovered"]
    )
    assert {name: (tmp_path / name).read_bytes() for name in locks} == before


def test_npm_shrinkwrap_precedes_package_lock(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"tool":"^1.0.0"}}')
    for name, version in (
        ("package-lock.json", "1.0.0"),
        ("npm-shrinkwrap.json", "1.1.0"),
    ):
        (tmp_path / name).write_text(
            json.dumps({"packages": {"node_modules/tool": {"version": version}}})
        )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert [(r.package.name, r.version) for r in result.bundles[0].resolved] == [
        ("tool", "1.1.0")
    ]
    assert result.bundles[0].resolved[0].source.path.name == "npm-shrinkwrap.json"
    assert not any(
        d.code == "resolution.package-manager-ambiguous" for d in result.diagnostics
    )


def test_npm_child_lock_and_inherited_pnpm_lock_remain_ambiguous(tmp_path):
    (tmp_path / "package.json").write_text('{"private":true,"workspaces":["app"]}')
    (tmp_path / "pnpm-workspace.yaml").write_text('packages: ["app"]\n')
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\nimporters: {}\n")
    child = tmp_path / "app"
    child.mkdir()
    (child / "package.json").write_text('{"dependencies":{"tool":"^1.0.0"}}')
    (child / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, project_ids=("npm:npm:app",)
        ),
    )
    assert not result.bundles[0].resolved
    assert any(
        d.code == "resolution.package-manager-ambiguous" for d in result.diagnostics
    )


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


@pytest.mark.parametrize("ecosystem", ["npm", "Maven"])
def test_manifest_columns_count_unicode_characters(tmp_path, ecosystem):
    if ecosystem == "npm":
        name, text, token = (
            "package.json",
            '{"description":"中文","dependencies":{"tool":"1.0.0"}}',
            '"tool"',
        )
    else:
        name, text, token = (
            "pom.xml",
            "<project><!-- 中文 --><dependencies><dependency><groupId>example</groupId><artifactId>tool</artifactId><version>1</version></dependency></dependencies></project>",
            "<dependency>",
        )
    (tmp_path / name).write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    source = result.bundles[0].declarations[0].source
    assert source.line == 1
    assert text[source.column - 1 :].startswith(token)


def test_malformed_json_has_parse_error_location(tmp_path):
    (tmp_path / "package.json").write_text('{\n "dependencies": {\n "tool":\n }\n}\n')
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    diagnostic = next(d for d in result.diagnostics if d.code == "manifest.invalid")
    assert (diagnostic.source.line, diagnostic.source.column) == (4, 2)
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize(
    "source,line,column,reason",
    [
        ("import tool from 'tool';\nconst view = <Widget />;\n", 2, 14, "JSX"),
        (
            "import tool from 'tool';\nconst value = `hello ${name}`;\n",
            2,
            22,
            "template",
        ),
        ("import tool from 'tool';\n/* unterminated comment", 2, 1, "comment"),
        (
            "import tool from 'tool';\nconst value = import(name);\n",
            2,
            15,
            "non-literal",
        ),
        (
            "import tool from 'tool';\nconst lazy = import(resolveName());\n",
            2,
            14,
            "non-literal",
        ),
    ],
)
def test_javascript_uncertain_usage_has_source_and_project_context(
    tmp_path, source, line, column, reason
):
    (tmp_path / "package.json").write_text('{"dependencies":{"tool":"1.0.0"}}')
    (tmp_path / "source.js").write_text(source)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    diagnostic = next(
        d for d in result.diagnostics if d.code in {"usage.ambiguous", "usage.dynamic"}
    )
    assert (diagnostic.source.line, diagnostic.source.column) == (line, column)
    assert "npm:npm:." in diagnostic.message
    assert reason.lower() in diagnostic.message.lower()
    assert diagnostic.code == (
        "usage.dynamic" if reason == "non-literal" else "usage.ambiguous"
    )
    assert result.bundles[0].usages[0].mapped_package.name == "tool"
    assert not result.capability("dependency_hygiene").complete


def test_unmapped_java_namespace_has_project_and_reference_location(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><artifactId>example</artifactId></project>"
    )
    source = tmp_path / "Main.java"
    source.write_text("package local;\n\nimport vendor.unknown.Client;\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    diagnostic = next(d for d in result.diagnostics if d.code == "mapping.unresolved")
    assert diagnostic.source is not None
    assert (
        diagnostic.source.path,
        diagnostic.source.line,
        diagnostic.source.column,
    ) == (source, 3, 8)
    assert "maven:maven:." in diagnostic.message
    assert "vendor.unknown.Client" in diagnostic.message
    assert not result.capability("dependency_hygiene").complete


def test_npm_declaration_positions_distinguish_sections_aliases_and_escaped_keys(
    tmp_path,
):
    (tmp_path / "package.json").write_text(
        "{\n"
        '  "description": "fake \\"shared\\": \\"9.0.0\\"",\n'
        '  "metadata": {"dependencies": {"shared": "9.0.0"}},\n'
        '  "dependencies": {\n'
        '    "first": "npm:requests@1.0.0",\n'
        '    "shared": "1.0.0"\n'
        "  },\n"
        '  "devDependencies": {\n'
        '    "shared": "2.0.0",\n'
        '    "\\u0074ool": "1.0.0"\n'
        "  }\n"
        "}\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [
        (d.package.name, d.scope, d.source.line, d.source.column)
        for d in result.bundles[0].declarations
    ] == [
        ("requests", "runtime", 5, 5),
        ("shared", "runtime", 6, 5),
        ("shared", "development", 9, 5),
        ("tool", "development", 10, 5),
    ]


@pytest.mark.parametrize("application_dependency", [False, True])
def test_maven_plugins_preserve_configuration_without_application_or_security_claims(
    tmp_path, application_dependency
):
    library = (
        "<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.0-jre</version></dependency></dependencies>"
        if application_dependency
        else ""
    )
    text = (
        "<project>\n<groupId>example</groupId><artifactId>app</artifactId><version>1</version>\n"
        "<properties><plugin.version>3.13.0</plugin.version></properties>\n"
        + library
        + "\n"
        "<build><pluginManagement><plugins>\n"
        "<plugin><artifactId>maven-compiler-plugin</artifactId><version>${plugin.version}</version></plugin>\n"
        "</plugins></pluginManagement><plugins>\n"
        "<plugin><artifactId>maven-compiler-plugin</artifactId>\n"
        "<executions><execution><id>compile-it</id><phase>compile</phase><goals><goal>compile</goal></goals></execution></executions>\n"
        "<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>29.0-jre</version></dependency></dependencies>\n"
        "<configuration><target>not executed</target></configuration></plugin>\n"
        "</plugins></build>\n"
        "<reporting><plugins><plugin><artifactId>maven-project-info-reports-plugin</artifactId><version>3.9.0</version><reportSets><reportSet><id>basic</id><reports><report>summary</report></reports></reportSet></reportSets></plugin></plugins></reporting>\n"
        "<profiles><profile><id>ci</id><activation><file><exists>../private-marker</exists></file></activation>\n"
        "<properties><profile.version>9</profile.version></properties><build><plugins>\n"
        "<plugin><groupId>org.codehaus.mojo</groupId><artifactId>versions-maven-plugin</artifactId><version>${profile.version}</version></plugin>\n"
        "</plugins></build></profile></profiles>\n</project>\n"
    )
    (tmp_path / "pom.xml").write_text(text, encoding="utf-8")
    (tmp_path / "Main.java").write_text(
        "import com.google.common.collect.ImmutableList;\n", encoding="utf-8"
    )
    queries = []

    def query(packages, ecosystem):
        queries.append((dict(packages), ecosystem))
        return SimpleNamespace(
            vulnerabilities={}, queried=dict(packages), diagnostics=(), complete=True
        )

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=query)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.manager == "maven")
    configuration = [d for d in bundle.declarations if d.kind == "conditional"]
    assert len(configuration) == 5
    assert all(
        d.scope == "build" and d.metadata["activation"] == "unknown"
        for d in configuration
    )
    assert {d.metadata["maven_kind"] for d in configuration} == {
        "build-plugin",
        "plugin-management",
        "plugin-dependency",
        "reporting-plugin",
    }
    compiler = [
        d
        for d in configuration
        if d.package.name == "org.apache.maven.plugins:maven-compiler-plugin"
    ]
    assert len(compiler) == 2
    management = next(
        d for d in compiler if d.metadata["maven_kind"] == "plugin-management"
    )
    actual = next(d for d in compiler if d.metadata["maven_kind"] == "build-plugin")
    assert (
        management.constraint.normalized == "3.13.0"
        and actual.constraint.normalized is None
    )
    assert actual.metadata["executions"][0]["id"] == "compile-it"
    assert actual.metadata["executions"][0]["phase"] == "compile"
    assert actual.metadata["executions"][0]["goals"] == ["compile"]
    assert actual.metadata["configuration_present"] is True
    reporting = next(
        d for d in configuration if d.metadata["maven_kind"] == "reporting-plugin"
    )
    assert reporting.metadata["report_sets"][0]["id"] == "basic"
    assert reporting.metadata["report_sets"][0]["reports"] == ["summary"]
    dependency = next(
        d for d in configuration if d.metadata["maven_kind"] == "plugin-dependency"
    )
    assert dependency.package.name == "com.google.guava:guava"
    assert dependency.metadata["classpath"] == "plugin"
    assert (
        dependency.metadata["owner_plugin"]
        == "org.apache.maven.plugins:maven-compiler-plugin"
    )
    profile = next(d for d in configuration if d.metadata.get("profile"))
    assert profile.metadata["profile"]["id"] == "ci"
    assert (
        profile.metadata["profile"]["activation"]["file"]["exists"]
        == "../private-marker"
    )
    assert (
        profile.constraint.raw == "${profile.version}"
        and profile.constraint.normalized is None
    )
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(
        d.code == "resolution.maven-plugin-activation-unknown"
        for d in bundle.diagnostics
    )
    if application_dependency:
        assert queries == [({"com.google.guava:guava": "31.0-jre"}, "Maven")]
        assert not any(f.code == "dependency.missing" for f in result.findings)
    else:
        assert queries == [] and not bundle.resolved
        assert any(
            f.code == "dependency.missing"
            and f.package.name == "com.google.guava:guava"
            for f in result.findings
        )
    assert not result.capability("security").complete
    assert not any(
        f.code == "dependency.unused" and f.package.name.endswith("-plugin")
        for f in result.findings
    )
    assert (actual.source.line, actual.source.column) == (8, 1)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    record = service.explain_dependency(
        "org.apache.maven.plugins:maven-compiler-plugin", ecosystem="Maven"
    )
    assert len(record["declarations"]) == 2 and record["resolved_versions"] == []
    assert not record["evidence_complete"]
    bom = build_cyclonedx(result)
    compiler_components = [
        c
        for c in bom["components"]
        if c["name"] == "org.apache.maven.plugins:maven-compiler-plugin"
    ]
    assert len(compiler_components) == 1
    assert (
        len(
            [
                p
                for p in compiler_components[0]["properties"]
                if p["name"] == "depcheck:conditional-declaration"
            ]
        )
        == 2
    )
    assert compiler_components[0]["bom-ref"] not in bom["dependencies"][0]["dependsOn"]


def test_maven_plugin_inheritance_keeps_declaring_context_and_false_boundaries(
    tmp_path,
):
    parent = tmp_path / "pom.xml"
    parent.write_text(
        "<project><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><properties><plugin.version>3.1</plugin.version></properties><build><plugins>"
        "<plugin><artifactId>maven-compiler-plugin</artifactId><version>${plugin.version}</version><executions><execution><id>private</id><inherited>false</inherited><goals><goal>compile</goal></goals></execution></executions></plugin>"
        "<plugin><artifactId>maven-antrun-plugin</artifactId><version>3.0</version><inherited>false</inherited></plugin>"
        "<plugin><artifactId>maven-resources-plugin</artifactId><version>3.3</version><inherited>false</inherited><executions><execution><id>keep</id><inherited>true</inherited><goals><goal>resources</goal></goals></execution><execution><id>implicit-drop</id><goals><goal>resources</goal></goals></execution></executions></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId><properties><plugin.version>9.0</plugin.version></properties></project>",
        encoding="utf-8",
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    record = service.explain_dependency(
        "org.apache.maven.plugins:maven-compiler-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    )
    assert record["declarations"][0]["constraint"]["normalized"] == "3.1"
    assert record["declarations"][0]["location"]["path"] == "pom.xml"
    assert record["declarations"][0]["metadata"]["property_context"] == "declaring-pom"
    assert record["declarations"][0]["metadata"]["executions"] == []
    assert not service.explain_dependency(
        "org.apache.maven.plugins:maven-antrun-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    ).get("declared", False)
    inherited_execution = service.explain_dependency(
        "org.apache.maven.plugins:maven-resources-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    )
    assert (
        inherited_execution["declarations"][0]["metadata"]["executions"][0]["id"]
        == "keep"
    )
    assert len(inherited_execution["declarations"][0]["metadata"]["executions"]) == 1
    parent.write_text(
        parent.read_text().replace(
            "<plugin.version>3.1</plugin.version>",
            "<plugin.version>3.2</plugin.version>",
        ),
        encoding="utf-8",
    )
    assert service.repository_context()["stale"]
    service.index_repository()
    assert (
        service.explain_dependency(
            "org.apache.maven.plugins:maven-compiler-plugin",
            ecosystem="Maven",
            project_id="maven:maven:child",
        )["declarations"][0]["constraint"]["normalized"]
        == "3.2"
    )


@pytest.mark.parametrize(
    "group",
    ["<groupId>${unknown}</groupId>", "<groupId/>", "<groupId>bad:group</groupId>"],
)
def test_maven_invalid_plugin_identity_does_not_invent_default_or_lose_libraries(
    tmp_path, group
):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies><build><plugins><plugin>"
        + group
        + "<artifactId>wrong-plugin</artifactId><version>1</version></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == {"example:library"}
    assert any(
        d.code == "manifest.maven-plugin-identity-unresolved"
        for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_maven_profile_activation_is_data_and_unknown_layers_are_qualified(
    tmp_path, monkeypatch
):
    outside = tmp_path.parent / "outside-activation-marker"
    original = Path.is_file

    def is_file(path):
        assert path != outside, "profile activation performed a filesystem probe"
        return original(path)

    monkeypatch.setattr(Path, "is_file", is_file)
    (tmp_path / "pom.xml").write_text(
        "<project><build><extensions><extension><groupId>example</groupId><artifactId>ext</artifactId><version>1</version></extension></extensions></build><profiles><profile><id>x</id><activation><file><exists>"
        + str(outside)
        + '</exists></file><custom><nested><value>unknown</value></nested></custom></activation><dependencies><dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>1</version></dependency></dependencies><build><plugins><plugin><artifactId>maven-antrun-plugin</artifactId><version>3</version><configuration><target><touch file="'
        + str(tmp_path / "executed")
        + '"/></target></configuration></plugin></plugins></build></profile></profiles></project>',
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    codes = {d.code for d in result.diagnostics}
    assert {
        "manifest.maven-build-extensions-uncollected",
        "manifest.maven-profile-dependencies-uncollected",
        "manifest.maven-profile-activation-uncollected",
    } <= codes
    assert not (tmp_path / "executed").exists()
    record = next(
        d
        for b in result.bundles
        for d in b.declarations
        if d.metadata.get("maven_kind") == "build-plugin"
    )
    assert record.metadata["profile"]["activation"]["file"]["exists"] == str(outside)
    assert record.metadata["profile"]["activation"]["uncollected_conditions"] is True


def test_maven_plugin_metadata_expansion_is_bounded(tmp_path):
    plugin = "<plugin><artifactId>maven-compiler-plugin</artifactId><version>1</version></plugin>"
    (tmp_path / "pom.xml").write_text(
        "<project><profiles><profile><id>large</id><activation><property><name>"
        + "x" * 2000
        + "</name></property></activation><build><plugins>"
        + plugin * 7000
        + "</plugins></build></profile></profiles></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declarations = [d for b in result.bundles for d in b.declarations]
    assert 0 < len(declarations) < 7000
    assert any(d.code == "manifest.maven-plugin-budget" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


def test_maven_without_declared_plugins_does_not_imply_complete_build_resolution(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert [r.version for r in bundle.resolved] == ["1"]
    assert next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(
        d.code == "resolution.maven-build-graph-unknown" for d in bundle.diagnostics
    )


@pytest.mark.parametrize(
    ("extension", "expected"), [("true", "build-extension"), ("${unknown}", "unknown")]
)
def test_maven_namespace_and_plugin_extension_assertions_keep_unicode_positions(
    tmp_path, extension, expected
):
    text = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><!--备注--><build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version><extensions>'
        + extension
        + "</extensions></plugin></plugins></build></project>"
    )
    (tmp_path / "pom.xml").write_text(text, encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.metadata["classpath"] == expected
    assert (declaration.source.line, declaration.source.column) == (
        1,
        text.index("<plugin>") + 1,
    )
    assert not result.bundles[0].resolved


def test_maven_declarations_and_version_diagnostics_keep_xml_positions(tmp_path):
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <!-- <dependency> is a comment, not evidence -->\n"
        "  <dependencies>\n"
        '    <dependency label="a > b">\n'
        "      <groupId>example</groupId><artifactId>library</artifactId>\n"
        "      <version>${unknown}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declaration = result.bundles[0].declarations[0]
    assert (declaration.source.line, declaration.source.column) == (4, 5)
    diagnostic = next(
        d for d in result.diagnostics if d.code == "manifest.unsupported-expression"
    )
    assert (diagnostic.source.line, diagnostic.source.column) == (4, 5)
    assert not result.capability("dependency_hygiene").complete


def test_maven_inherited_management_keeps_parent_location(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>example</groupId><artifactId>parent</artifactId><version>1</version>\n"
        "  <dependencyManagement><dependencies>\n"
        "    <dependency>\n"
        "      <groupId>example</groupId><artifactId>library</artifactId><version>2</version>\n"
        "    </dependency>\n"
        "  </dependencies></dependencyManagement>\n"
        "</project>\n"
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project>\n"
        "  <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>\n"
        "  <artifactId>child</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId></dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = next(b for b in result.bundles if b.project.root == Path("child"))
    constraint = next(d for d in bundle.declarations if d.kind == "constraint")
    direct = next(d for d in bundle.declarations if d.kind == "direct")
    assert (
        constraint.source.path,
        constraint.source.line,
        constraint.source.column,
    ) == (tmp_path / "pom.xml", 4, 5)
    assert (direct.source.path, direct.source.line, direct.source.column) == (
        child / "pom.xml",
        5,
        5,
    )
    assert direct.constraint.normalized == "2"


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


@pytest.mark.parametrize("lock_kind", ["npm", "legacy", "pnpm"])
def test_installation_alias_queries_real_package_and_maps_usage(tmp_path, lock_kind):

    class CapturingOSV:
        def __init__(self):
            self.calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(
                vulnerabilities={}, diagnostics=(), queried=dict(packages)
            )

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"safe-name": "npm:lodash@4.17.20"}})
    )
    (tmp_path / "app.js").write_text("import a from 'safe-name/fp';\n")
    if lock_kind == "npm":
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/safe-name": {
                            "name": "lodash",
                            "version": "4.17.20",
                        },
                    }
                }
            )
        )
    elif lock_kind == "legacy":
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "dependencies": {
                        "safe-name": {"version": "npm:lodash@4.17.20"},
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
                                "safe-name": {
                                    "specifier": "npm:lodash@4.17.20",
                                    "version": "lodash@4.17.20",
                                }
                            }
                        }
                    },
                    "packages": {
                        "lodash@4.17.20": {
                            "resolution": {"integrity": "sha512-fixture"}
                        },
                        "on@1.0.0": {"resolution": {"integrity": "sha512-optional"}},
                    },
                    "snapshots": {
                        "lodash@4.17.20": {"optionalDependencies": {"on": "1.0.0"}},
                        "on@1.0.0": {},
                    },
                },
                sort_keys=False,
            )
        )
    osv = CapturingOSV()
    result = RepositoryScanner(osv_client=osv).scan(tmp_path)
    assert any(packages.get("lodash") == "4.17.20" for _, packages in osv.calls)
    assert all("safe-name" not in packages for _, packages in osv.calls)
    assert result.bundles[0].usages[0].mapped_package.name == "lodash"
    assert result.capability("security").complete
    assert not result.findings
    assert any(c["name"] == "lodash" for c in build_cyclonedx(result)["components"])
    if lock_kind == "pnpm":
        parent = next(r for r in result.bundles[0].resolved if r.direct)
        assert parent.dependency_links[0].package.name == "on"


@pytest.mark.parametrize("directory", ["site-packages", "dist-packages"])
def test_installed_libraries_do_not_become_repository_evidence(tmp_path, directory):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "app.py").write_text("import requests\n")
    (tmp_path / "package.json").write_text("{}")
    installed = tmp_path / "artifacts/environment/lib/python3.12" / directory
    installed.mkdir(parents=True)
    (installed / "pyproject.toml").write_text('[project]\ndependencies=["bogus==1"]\n')
    (installed / "library.py").write_text("import yaml\n")
    (installed / "package.json").write_text('{"dependencies":{"bogus":"1.0.0"}}')
    (installed / "library.js").write_text("import bogus from 'bogus';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.findings
    assert {d.package.name for b in result.bundles for d in b.declarations} == {
        "requests"
    }
    assert {p for b in result.bundles for p in b.source_files} == {tmp_path / "app.py"}


@pytest.mark.parametrize(
    "filename,scope",
    [
        ("src/site.test.ts", "test"),
        ("src/site.spec.mjs", "test"),
        ("playwright.config.ts", "test"),
        ("vitest.config.ts", "test"),
        ("astro.config.mjs", "build"),
        ("vite.config.ts", "build"),
        ("webpack.config.cjs", "build"),
    ],
)
def test_javascript_tool_configs_and_test_files_accept_dev_dependencies(
    tmp_path, filename, scope
):
    (tmp_path / "package.json").write_text('{"devDependencies":{"tool-lib":"1.0.0"}}')
    source = tmp_path / filename
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("import tool from 'tool-lib';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.findings
    assert result.bundles[0].usages[0].scope == scope
    source.rename(tmp_path / "runtime.js")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(f.code == "dependency.scope-mismatch" for f in result.findings)


@pytest.mark.parametrize("suffix", [".vue", ".svelte"])
def test_frontend_component_regions_keep_usage_and_template_uncertainty(
    tmp_path, suffix
):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"component-lib":"1.0.0","theme":"1","unused":"1"}}'
    )
    source = tmp_path / ("Component" + suffix)
    source.write_text(
        '<script lang="ts">\nimport thing from "component-lib";\n</script>\n<style>@import "theme";</style>\n<div>{dynamic}</div>\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)
    assert any(
        d.code == "usage.unsupported-component-template" for d in result.diagnostics
    )
    assert {u.reference for u in result.bundles[0].usages} == {"component-lib", "theme"}
    assert (
        next(
            u for u in result.bundles[0].usages if u.reference == "component-lib"
        ).source.line
        == 2
    )
    assert source in result.bundles[0].source_files


@pytest.mark.parametrize("suffix", [".vue", ".svelte"])
@pytest.mark.parametrize(
    "template",
    [
        '<script setup lang="ts">import "known";</script><template>{{value}}</template>',
        '<template>{{ "</template><script>import fake from \'fake\'</script>" }}</template><script>import "known";</script>',
        '<style lang="scss">@use "fake";</style><script>import "known";</script>',
        '<style src="known/base.css"></style>',
    ],
)
def test_component_regions_reject_hidden_markup_and_preserve_css_scope(
    tmp_path, suffix, template
):
    (tmp_path / "package.json").write_text('{"devDependencies":{"known":"1.0.0"}}')
    (tmp_path / ("Page" + suffix)).write_text(template)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert all(u.reference != "fake" for u in result.bundles[0].usages)
    if "src=" in template:
        assert result.bundles[0].usages[0].scope == "unknown"
        assert not any(f.code == "dependency.scope-mismatch" for f in result.findings)
    assert not result.capability("dependency_hygiene").complete


def test_astro_frontmatter_scripts_styles_keep_locations_and_mappings(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "font-alias": "npm:@fontsource/font@1.0.0",
                    "client": "1.0.0",
                    "theme": "1.0.0",
                }
            }
        )
    )
    source = tmp_path / "Page.astro"
    source.write_text(
        '---\nimport "font-alias/style.css";\nimport { Image } from "astro:assets";\n---\n'
        '<!-- <script>import "fake";</script> -->\n'
        '<script>import client from "client";</script>\n'
        '<style>@import "theme/base.css";</style>\n<div>Hello</div>\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    usages = result.bundles[0].usages
    assert [u.mapped_package.name for u in usages] == [
        "@fontsource/font",
        "client",
        "theme",
    ]
    assert [(u.source.line, u.source.column) for u in usages] == [
        (2, 8),
        (6, 28),
        (7, 16),
    ]
    assert all(u.mapping_confidence == MappingConfidence.EXACT for u in usages)
    assert [u.scope for u in usages] == ["runtime", "runtime", "unknown"]
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "usage.unsupported-css-scope" for d in result.diagnostics)
    assert not result.findings


@pytest.mark.parametrize(
    "specifier", ['"theme/base.css"', 'url("theme/base.css")', "url(theme/base.css)"]
)
def test_css_package_import_variants_are_collected(tmp_path, specifier):
    (tmp_path / "package.json").write_text('{"dependencies":{"theme":"1"}}')
    (tmp_path / "global.css").write_text(
        '/* @import "fake"; */\n@import ' + specifier + " layer(base) screen;\n"
        'a { content: "@import fake"; background: url(other.png); }\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    usages = result.bundles[0].usages
    assert len(usages) == 1 and usages[0].mapped_package.name == "theme"
    assert usages[0].source.line == 2
    assert usages[0].scope == "unknown"
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "usage.unsupported-css-scope" for d in result.diagnostics)


@pytest.mark.parametrize("configuration", [None, "vite.config.ts", "vite.config.css"])
def test_css_build_dependencies_keep_scope_uncertainty_without_config(
    tmp_path, configuration
):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {
                    "tailwindcss": "4.0.0",
                    "@tailwindcss/vite": "4.0.0",
                    "vite": "6.0.0",
                },
                "scripts": {"build": "vite build"},
            }
        )
    )
    source = tmp_path / "src" / "global.css"
    source.parent.mkdir()
    source.write_text('@import "tailwindcss";\n')
    configured = configuration == "vite.config.ts"
    if configured:
        (tmp_path / configuration).write_text(
            'import tailwindcss from "@tailwindcss/vite";\n'
            'import { defineConfig } from "vite";\n'
            "export default defineConfig({plugins: [tailwindcss()]});\n"
        )
    elif configuration:
        (tmp_path / configuration).write_text("/* not a build configuration */")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    css_usage = next(
        u for u in result.bundles[0].usages if u.reference == "tailwindcss"
    )
    assert css_usage.scope == ("build" if configured else "unknown")
    assert css_usage.mapping_confidence == MappingConfidence.EXACT
    assert not any(f.code == "dependency.scope-mismatch" for f in result.findings)
    assert not any(f.code == "dependency.unused" for f in result.findings)
    assert result.capability("dependency_hygiene").complete == configured
    assert (
        any(d.code == "usage.unsupported-css-scope" for d in result.diagnostics)
        != configured
    )
    from depcheck.agent import DependencyAgentService
    from depcheck.indexing import RepositoryIndexer

    RepositoryIndexer().refresh(tmp_path)
    explanation = DependencyAgentService(tmp_path).explain_dependency("tailwindcss")
    assert explanation["usages"][0]["scope"] == css_usage.scope
    assert explanation["usage_complete"] == configured


def test_css_local_name_wins_over_declared_package_and_unknown_urls_stay_unknown(
    tmp_path,
):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"theme.css":"1", "keep":"1"}}'
    )
    (tmp_path / "theme.css").write_text("body {}")
    (tmp_path / "global.css").write_text(
        '@import "theme.css";\n@import "./local.css";\n@import "https://cdn.example/a.css";\n'
        '@import "unknown-package/base.css";\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not any(u.mapped_package for u in result.bundles[0].usages)
    assert not result.capability("dependency_hygiene").complete
    assert not any(
        f.code in {"dependency.unused", "dependency.missing"} for f in result.findings
    )
    assert any("unsupported" in d.code for d in result.diagnostics)


@pytest.mark.parametrize(
    "text",
    [
        '---\nimport "known";\n---\n<div>{import(name)}</div><script>import "fake";</script>',
        '---\nimport "known";\n---\n<script is:inline>import "browser";</script>',
        '---\nimport "known";\n---\n<script src="https://cdn.example/browser.js"></script>',
        '---\nimport "known";\n---\n<style lang="scss">@use "sass-tool";</style>',
    ],
)
def test_astro_uncovered_regions_preserve_known_imports_without_removal_claims(
    tmp_path, text
):
    (tmp_path / "package.json").write_text('{"dependencies":{"known":"1", "keep":"1"}}')
    (tmp_path / "Page.astro").write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [
        u.mapped_package.name for u in result.bundles[0].usages if u.mapped_package
    ] == ["known"]
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    "text",
    [
        '@import "theme',
        '@import "th\\65me";',
        "@import var(--theme);",
        '@plugin "plugin";',
        "/* unterminated",
    ],
)
def test_css_unsupported_syntax_is_qualified(tmp_path, text):
    (tmp_path / "package.json").write_text('{"dependencies":{"keep":"1"}}')
    (tmp_path / "global.css").write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.source and d.source.line == 1 for d in result.diagnostics)


def test_frontend_regions_ignore_text_elements_and_component_script_names(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"known":"1"}}')
    (tmp_path / "Page.astro").write_text(
        '---\nimport "known";\n---\n'
        '<textarea><script>import "fake-one";</script></textarea>\n'
        '<title><script>import "fake-two";</script></title>\n'
        '<Script>import "fake-three";</Script>\n'
        '<script type="application/ld+json">{"import":"fake-four"}</script>\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [u.reference for u in result.bundles[0].usages] == ["known"]


def test_frontend_sources_belong_to_nearest_npm_component(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"root-theme":"1"}}')
    child = tmp_path / "child"
    child.mkdir()
    (child / "package.json").write_text('{"dependencies":{"child-theme":"1"}}')
    (tmp_path / "root.css").write_text('@import "root-theme";')
    (child / "Page.astro").write_text('---\nimport "child-theme";\n---\n<div />')
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {
        b.project.project_id: [u.mapped_package.name for u in b.usages]
        for b in result.bundles
    } == {"npm:npm:.": ["root-theme"], "npm:npm:child": ["child-theme"]}


@pytest.mark.parametrize("version", ["", "${external.version}"])
def test_unresolved_maven_managed_versions_are_not_unpinned_findings(tmp_path, version):
    rendered = f"<version>{version}</version>" if version else ""
    (tmp_path / "pom.xml").write_text(
        "<project><dependencyManagement><dependencies><dependency>"
        "<groupId>org.example</groupId><artifactId>platform</artifactId><version>1.0.0</version>"
        "<type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>"
        "<dependencies><dependency><groupId>org.example</groupId><artifactId>managed</artifactId>"
        + rendered
        + "</dependency><dependency><groupId>org.example</groupId><artifactId>floating</artifactId>"
        "<version>[1.0,2.0)</version></dependency></dependencies></project>"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert {
        f.package.name for f in result.findings if f.code == "dependency.unpinned"
    } == {"org.example:floating"}


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


@pytest.mark.parametrize(
    "lock_name,content",
    [
        (
            name,
            '[[package]]\nname="known"\nversion="1.0.0"\n'
            '[[package]]\nname="hidden"\nversion="not-a-version"\n',
        )
        for name in ("uv.lock", "poetry.lock", "pdm.lock")
    ]
    + [
        (
            "Pipfile.lock",
            '{"default":{"known":{"version":"==1.0.0"},'
            '"hidden":{"version":"invalid"}}}',
        )
    ],
)
def test_invalid_python_lock_entries_keep_security_incomplete(
    tmp_path: Path, lock_name, content
) -> None:

    class FakeOSV:
        def scan(self, packages):
            return SimpleNamespace(
                vulnerabilities={}, diagnostics=(), queried=dict(packages)
            )

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / lock_name).write_text(content)
    result = RepositoryScanner(osv_client=FakeOSV()).scan(tmp_path)
    assert not result.capability("security").complete
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "security.collection-incomplete" for d in result.diagnostics)
    assert {r.package.name for r in result.bundles[0].resolved} == {"requests", "known"}
    assert not DependencyAgentService(tmp_path).index_repository()["complete"]


@pytest.mark.parametrize(
    "group_table",
    [
        '[dependency-groups]\ntest=["pyyaml==6.0.2"]\n',
        '[tool.poetry.group.test.dependencies]\npyyaml="==6.0.2"\n',
        '[tool.poetry.dev-dependencies]\npyyaml="==6.0.2"\n',
        '[tool.pdm.dev-dependencies]\ntest=["pyyaml==6.0.2"]\n',
    ],
)
def test_python_development_groups_accept_test_usage(
    tmp_path: Path, group_table
) -> None:

    (tmp_path / "pyproject.toml").write_text(group_table)
    source = tmp_path / "test_app.py"
    source.write_text("import yaml\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.findings
    declaration = result.bundles[0].declarations[0]
    assert declaration.scope == "development"
    assert declaration.metadata["group"].startswith("dev:")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert not service.explain_dependency("pyyaml")["findings"]

    source.rename(tmp_path / "app.py")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(f.code == "dependency.scope-mismatch" for f in result.findings)


def test_pep735_repeated_includes_survive_collection_indexing_and_query(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n[dependency-groups]\n'
        'Base_Test=["pyyaml==6.0.2"]\n'
        'ci=[{include-group="base.test"},{include-group="BASE-TEST"}]\n'
    )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert [
        (d.package.name, d.metadata["group"]) for d in result.bundles[0].declarations
    ] == [("pyyaml", "dev:Base_Test"), ("pyyaml", "dev:ci"), ("pyyaml", "dev:ci")]
    assert not any(f.code == "declaration.duplicate" for f in result.findings)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency(
        "pyyaml", ecosystem="PyPI", project_id="pypi:python:."
    )
    assert (
        len(record["declarations"]) == 3
        and record["evidence_page"]["counts"]["declarations"] == 3
    )
    assert [d["metadata"]["group"] for d in record["declarations"]].count("dev:ci") == 2
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]


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


@pytest.mark.parametrize(
    "tables",
    [
        '[dependency-groups]\nleft=["pyyaml==6.0.1"]\nright=["pyyaml==6.0.2"]\n',
        '[dependency-groups]\nleft=["pyyaml>=6,<6.1"]\nright=["pyyaml>=6.1,<7"]\n',
        '[tool.poetry.group.left.dependencies]\npyyaml="==6.0.1"\n[tool.poetry.group.right.dependencies]\npyyaml="==6.0.2"\n',
        '[tool.pdm.dev-dependencies]\nleft=["pyyaml==6.0.1"]\nright=["pyyaml==6.0.2"]\n',
    ],
)
def test_python_separate_development_groups_do_not_establish_active_conflict(
    tmp_path, tables
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n' + tables
    )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)
    assert any(
        d.code == "analysis.python-group-selection-unknown" for d in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete
    assert any(
        d.code == "analysis.python-group-selection-unknown"
        for d in result.bundles[0].diagnostics
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency(
        "pyyaml", ecosystem="PyPI", project_id="pypi:python:."
    )
    assert not record["evidence_complete"] and record["usage_complete"]
    assert not any(f["code"] == "declaration.conflict" for f in record["findings"])
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]


@pytest.mark.parametrize(
    "body,group",
    [
        (
            '[dependency-groups]\nbroken=["pyyaml==6.0.1","pyyaml==6.0.2"]\n',
            "dev:broken",
        ),
        (
            '[dependency-groups]\nleft=["pyyaml==6.0.1"]\nright=["pyyaml==6.0.2"]\ncombined=[{include-group="left"},{include-group="right"}]\n',
            "dev:combined",
        ),
    ],
)
def test_python_incompatible_constraints_within_one_declared_group_still_report(
    tmp_path, body, group
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n' + body
    )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    conflicts = [f for f in result.findings if f.code == "declaration.conflict"]
    assert len(conflicts) == 1 and conflicts[0].details["group"] == group
    assert len(conflicts[0].locations) == 2
    assert not any(
        d.code == "analysis.python-group-selection-unknown" for d in result.diagnostics
    )


@pytest.mark.parametrize("filtered", [False, True])
def test_python_group_selection_diagnostics_survive_both_index_paths(
    tmp_path, filtered
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["pyyaml==6.0.2"]\n'
        '[dependency-groups]\nolder=["pyyaml==6.0.1"]\n'
    )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    service = DependencyAgentService(tmp_path)
    kwargs = {"project_ids": ("pypi:python:.",)} if filtered else {}
    service.index_repository(**kwargs)
    for _ in range(2):
        record = service.explain_dependency(
            "pyyaml", ecosystem="PyPI", project_id="pypi:python:."
        )
        assert not record["evidence_complete"] and record["usage_complete"]
        assert len(record["declarations"]) == 2
        assert not any(f["code"] == "declaration.conflict" for f in record["findings"])
        assert any(
            g["reason"] == "analysis.python-group-selection-unknown"
            for g in service.repository_context()["coverage"]["uncovered"]
        )
        service.index_repository(**kwargs)


def test_python_analysis_uncertainty_does_not_taint_another_component(tmp_path):
    for name in ("uncertain", "known"):
        root = tmp_path / name
        root.mkdir()
        text = f'[project]\nname="{name}"\nversion="1"\n'
        text += (
            '[dependency-groups]\nleft=["pyyaml==6.0.1"]\nright=["pyyaml==6.0.2"]\n'
            if name == "uncertain"
            else 'dependencies=["pyyaml==6.0.2"]\n'
        )
        (root / "pyproject.toml").write_text(text)
        (root / "test_app.py").write_text("import yaml\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    for name, complete in (("uncertain", False), ("known", True)):
        record = service.explain_dependency(
            "pyyaml", ecosystem="PyPI", project_id=f"pypi:python:{name}"
        )
        assert record["evidence_complete"] is complete and record["usage_complete"]


@pytest.mark.parametrize("with_markers", [False, True])
def test_python_compatible_development_groups_have_no_selection_gap(
    tmp_path, with_markers
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n'
        '[dependency-groups]\nleft=["pyyaml>=6"]\nright=["pyyaml==6.0.2"]\n'
    )
    if with_markers:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname="demo"\nversion="1"\n[dependency-groups]\nleft='
            + json.dumps(["pyyaml>=6; sys_platform == 'linux'"])
            + "\nright="
            + json.dumps(["pyyaml==6.0.2; sys_platform == 'win32'"])
            + "\n"
        )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not any(
        d.code == "analysis.python-group-selection-unknown" for d in result.diagnostics
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)


@pytest.mark.parametrize(
    "markers,conflict",
    [
        (("sys_platform == 'linux'", "sys_platform == 'win32'"), False),
        (("", "sys_platform == 'linux'"), False),
        (("sys_platform == 'linux'", "sys_platform == 'linux'"), True),
    ],
)
def test_python_group_conflicts_preserve_marker_applicability(
    tmp_path, markers, conflict
):
    requirements = [
        "pyyaml==6.0.1" + ("; " + markers[0] if markers[0] else ""),
        "pyyaml==6.0.2" + ("; " + markers[1] if markers[1] else ""),
    ]
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n[dependency-groups]\nbroken='
        + json.dumps(requirements)
        + "\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    findings = [f for f in result.findings if f.code == "declaration.conflict"]
    assert bool(findings) is conflict
    if conflict:
        assert findings[0].details["marker"] == str(
            result.bundles[0].declarations[0].marker
        )
    else:
        assert any(
            d.code == "analysis.constraint-intersection-unknown"
            for d in result.diagnostics
        )
        assert not result.capability("dependency_hygiene").complete


def test_analysis_errors_qualify_cached_npm_evidence_without_changing_usage(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"x":"^1.0.0-beta.1"},"devDependencies":{"x":">=1.0.0"}}'
    )
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"x":"^1.0.0-beta.1"},"devDependencies":{"x":">=1.0.0"}},"node_modules/x":{"version":"1.0.0"}}}'
    )
    (tmp_path / "app.js").write_text('import "x";\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(
        d.code == "analysis.constraint-intersection-unknown"
        for d in result.bundles[0].diagnostics
    )
    assert all(c.complete for c in result.bundles[0].capabilities)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency("x", ecosystem="npm", project_id="npm:npm:.")
    assert not record["evidence_complete"] and record["usage_complete"]
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]


@pytest.mark.parametrize("field", ["dependencies", "optional-dependencies"])
def test_dynamic_pyproject_dependencies_do_not_establish_missing_packages(
    tmp_path: Path, field
) -> None:

    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname="sample"\ndynamic=["{field}"]\n'
    )
    (tmp_path / "app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.dynamic-pyproject" for d in result.diagnostics)
    assert not any(f.code == "dependency.missing" for f in result.findings)
    service = DependencyAgentService(tmp_path)
    assert not service.index_repository()["complete"]
    assert not service.explain_dependency("pyyaml")["findings"]


@pytest.mark.parametrize(
    "content",
    [
        "project=[]\n",
        "build-system=[]\n",
        "dependency-groups=[]\n",
        "[project]\noptional-dependencies=[]\n",
        '[project]\ndynamic="dependencies"\n',
    ],
)
def test_malformed_pyproject_dependency_tables_are_incomplete(tmp_path, content):
    (tmp_path / "pyproject.toml").write_text(content)
    (tmp_path / "app.py").write_text("import yaml\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.severity == "error" for d in result.diagnostics)
    assert not any(f.code == "dependency.missing" for f in result.findings)


@pytest.mark.parametrize(
    "manifest",
    [
        "module\texample.com/app\nrequire\texample.com/dep v1.0.0\n",
        "module example.com/app // app module\n"
        "require ( // required modules\n\texample.com/dep v1.0.0\n) // end\n",
    ],
)
def test_go_mod_accepts_whitespace_and_directive_comments(tmp_path, manifest):
    (tmp_path / "go.mod").write_text(manifest)
    (tmp_path / "main.go").write_text('package main\nimport "example.com/dep"\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert not result.capability("dependency_hygiene").complete
    assert not result.findings
    assert not result.bundles[0].resolved
    assert result.bundles[0].declarations[0].kind == "direct"


def test_go_mod_retains_indirect_flag_after_comment_parsing(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module\texample.com/app // app\n"
        "require ( // dependencies\n\texample.com/dep v1.0.0 // indirect\n)\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert not result.capability("dependency_hygiene").complete
    assert result.bundles[0].declarations[0].kind == "transitive"
    assert not result.bundles[0].resolved


def test_go_mod_unterminated_dependency_block_is_incomplete(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire (\nexample.com/dep v1.0.0\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)


def test_go_minimums_and_checksums_do_not_select_a_build_version(tmp_path):
    class CapturingOSV:
        def __init__(self):
            self.calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(vulnerabilities={}, diagnostics=(), queried=packages)

    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\nrequire (\n\texample.com/dep v1.0.0\n)\n"
    )
    checksum = "h1:" + "A" * 43 + "="
    (tmp_path / "go.sum").write_text(
        f"example.com/dep v1.0.0/go.mod {checksum}\n\n"
        f"example.com/dep v1.4.0 {checksum}\n"
        f"example.com/old v0.9.0 {checksum}\n"
        f"example.com/dep v1.4.0 {checksum}\n"
    )
    (tmp_path / "main.go").write_text('package main\nimport "example.com/dep"\n')
    osv = CapturingOSV()
    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path, RepositoryScanOptions(security=True, enabled_ecosystems=("Go",))
    )
    bundle = result.bundles[0]
    assert not bundle.resolved and not osv.calls
    assert not result.capability("security").complete
    assert any(d.code == "resolution.go-build-list-unknown" for d in result.diagnostics)
    assert any(
        gap["reason"] == "resolution.go-build-list-unknown"
        for gap in result.metadata["coverage"]["uncovered"]
    )
    requirement = next(d for d in bundle.declarations if d.kind == "direct")
    assert requirement.constraint.scheme == "go-minimum"
    assert (requirement.source.line, requirement.source.column) == (4, 2)
    checksums = [d for d in bundle.declarations if d.kind == "checksum"]
    assert [d.source.line for d in checksums] == [1, 3, 4, 5]
    assert checksums[0].metadata["checksum_kind"] == "go.mod"
    assert checksums[1].metadata["checksum_kind"] == "module-zip"
    assert all(d.metadata["integrity_verified"] is False for d in checksums)
    assert not any(f.package.name == "example.com/old" for f in result.findings)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    explanation = service.explain_dependency("example.com/dep", ecosystem="Go")
    assert explanation["resolved_versions"] == []
    assert not explanation["evidence_complete"]
    assert len(explanation["declarations"]) == 4
    sbom = build_cyclonedx(result)
    stale = next(c for c in sbom["components"] if c["name"] == "example.com/old")
    assert "version" not in stale and stale["scope"] == "optional"
    assert any(p["name"] == "depcheck:checksum-assertion" for p in stale["properties"])
    assert stale["bom-ref"] not in sbom["dependencies"][0]["dependsOn"]


@pytest.mark.parametrize("quote", ['"', "`", ""])
def test_go_literal_tokens_preserve_requirement_and_replacement_positions(
    tmp_path, quote
):
    (tmp_path / "go.mod").write_text(
        f"module {quote}example.com/app{quote}\n\n"
        f"require {quote}example.com/dep{quote} {quote}v1.0.0{quote}\n"
        f"replace {quote}example.com/dep{quote} => {quote}example.com/fork{quote} {quote}v1.2.3{quote}\n"
        f"exclude {quote}example.com/dep{quote} {quote}v0.9.0{quote}\n"
    )
    (tmp_path / "main.go").write_text('package main\nimport "example.com/dep"\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.package.name == "example.com/fork"
    assert (declaration.source.line, declaration.source.column) == (3, 9)
    assert declaration.metadata["replacement_source"] == {
        "path": "go.mod",
        "line": 4,
        "column": 9,
    }
    assert declaration.metadata["excluded_assertions"][0]["source"] == {
        "path": "go.mod",
        "line": 5,
        "column": 9,
    }
    assert not result.bundles[0].resolved


def test_go_quoted_local_replacement_keeps_comment_like_path(tmp_path):
    (tmp_path / "go.mod").write_text(
        'module "example.com/app"\nrequire example.com/dep v1.0.0\n'
        'replace example.com/dep => "../local//with spaces" // local assertion\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.metadata["replacement_path"] == "../local//with spaces"
    assert not result.bundles[0].resolved
    assert not any(d.code == "manifest.invalid" for d in result.diagnostics)


@pytest.mark.parametrize(
    "directive",
    [
        "ignore ./generated",
        "future (\n example.com/tool\n)",
    ],
)
def test_go_uncollected_directives_preserve_requirements_and_block_unused(
    tmp_path, directive
):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/tool v1.0.0\n" + directive + "\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert result.bundles[0].declarations[0].package.name == "example.com/tool"
    assert any(
        d.code == "manifest.go-directive-uncollected" for d in result.diagnostics
    )
    assert any(
        gap["reason"] == "manifest.go-directive-uncollected"
        for gap in result.metadata["coverage"]["uncovered"]
    )
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_go_invalid_and_conflicting_checksums_keep_valid_siblings(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    checksum = "h1:" + "A" * 43 + "="
    other = "h1:" + "B" * 42 + "A="
    (tmp_path / "go.sum").write_text(
        f"example.com/dep v1.0.0 {checksum}\n"
        "not a checksum\n"
        f"example.com/dep v1.0.0 {other}\n"
        f"example.com/dep branch {checksum}\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert not result.bundles[0].resolved
    assert [d.source.line for d in result.bundles[0].declarations] == [1, 3]
    assert {d.code for d in result.diagnostics} >= {
        "lock.go-sum-invalid",
        "lock.go-sum-conflict",
    }


@pytest.mark.parametrize("indirect", [False, True])
def test_go_tool_directives_are_positioned_configuration_not_imports(
    tmp_path, indirect
):
    marker = " // indirect" if indirect else ""
    (tmp_path / "go.mod").write_text(
        "module example.com/app\ngo 1.24.0\nrequire (\n"
        f"\texample.com/tool v1.0.0{marker}\n"
        "\texample.com/unrelated v2.0.0\n)\ntool (\n"
        '\texample.com/tool/cmd/lint\n\t"example.com/tool/cmd/lint"\n)\n'
        "tool example.com/app/cmd/local\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    bundle = result.bundles[0]
    tools = bundle.usages
    assert len(tools) == 2 and not bundle.source_files
    assert all(u.kind == "configuration" and u.scope == "build" for u in tools)
    assert [(u.source.line, u.source.column) for u in tools] == [(8, 2), (9, 2)]
    assert all(u.mapped_package.name == "example.com/tool" for u in tools)
    assert all(u.mapping_confidence is MappingConfidence.EXACT for u in tools)
    assert all(
        "execution" in u.mapping_reason and "tool" in u.mapping_reason for u in tools
    )
    assert {
        f.package.name for f in result.findings if f.code == "dependency.unused"
    } == {"example.com/unrelated"}
    assert not any(f.code == "dependency.missing" for f in result.findings)
    assert not any(
        d.code == "manifest.go-directive-uncollected" for d in result.diagnostics
    )
    assert not bundle.resolved and not result.capability("dependency_hygiene").complete
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    explanation = service.explain_dependency("example.com/tool", ecosystem="Go")
    assert len(explanation["usages"]) == 2 and explanation["imports"] == []
    assert (
        explanation["resolved_versions"] == [] and not explanation["evidence_complete"]
    )


def test_go_tool_owner_requires_a_declared_module_boundary(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/tools v1.0.0\n"
        "tool example.com/toolshed/cmd/lint\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    tool = result.bundles[0].usages[0]
    assert (
        tool.mapped_package is None
        and tool.mapping_confidence is MappingConfidence.UNKNOWN
    )
    assert any(
        d.code == "configuration.go-tool-owner-unresolved" for d in result.diagnostics
    )
    assert any(
        gap["reason"] == "configuration.go-tool-owner-unresolved"
        for gap in result.metadata["coverage"]["uncovered"]
    )
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_go_tools_choose_the_longest_declared_module_and_keep_component_owners(
    tmp_path,
):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire (\nexample.com/tools v1.0.0\n"
        "example.com/tools/nested v1.1.0\n)\n"
        "tool example.com/tools/nested/cmd/lint\n"
        "tool example.com/child-tools/cmd/lint\n"
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "go.mod").write_text(
        "module example.com/child\nrequire example.com/child-tools v1.0.0\n"
        "tool example.com/child-tools/cmd/lint\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    root_bundle, child_bundle = result.bundles
    assert root_bundle.usages[0].mapped_package.name == "example.com/tools/nested"
    assert root_bundle.usages[1].mapped_package is None
    assert child_bundle.usages[0].mapped_package.name == "example.com/child-tools"
    assert child_bundle.usages[0].project_id == "go:gomod:child"
    assert child_bundle.usages[0].source.path == child / "go.mod"


def test_go_nested_required_module_is_not_a_local_tool_or_import(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/app/toolkit v1.0.0\n"
        "tool example.com/app/toolkit/cmd/lint\n"
    )
    (tmp_path / "main.go").write_text(
        'package main\nimport "example.com/app/toolkit/api"\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert len(result.bundles[0].usages) == 2
    assert {u.kind for u in result.bundles[0].usages} == {"regular", "configuration"}
    assert all(
        u.mapped_package.name == "example.com/app/toolkit"
        for u in result.bundles[0].usages
    )
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize("version", ["", " v1.0.0"])
def test_go_tool_replacements_keep_configuration_applicability_unknown(
    tmp_path, version
):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/tool v1.0.0\n"
        f"replace example.com/tool{version} => example.com/fork v1.2.3\n"
        "tool example.com/tool/cmd/lint\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    bundle = result.bundles[0]
    assert bundle.usages[0].mapped_package.name == (
        "example.com/tool" if version else "example.com/fork"
    )
    assert not bundle.resolved
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    "invalid",
    [
        "tool",
        'tool ""',
        "tool example.com/tool@v1.0.0",
        "tool example.com/tool/...",
        'tool "example.com/tool with spaces"',
    ],
)
def test_go_invalid_tool_directives_are_incomplete(tmp_path, invalid):
    (tmp_path / "go.mod").write_text("module example.com/app\n" + invalid + "\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


def test_go_tool_configuration_budget_prevents_unused_conclusions(
    tmp_path, monkeypatch
):
    import depcheck.ecosystems.go as go

    monkeypatch.setattr(go, "DEFAULT_MAX_BYTES", 4000)
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/tool v1.0.0\n"
        + "tool example.com/tool/cmd/lint\n" * 8
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert 0 < len(result.bundles[0].usages) < 8
    assert any(d.code == "configuration.go-tool-budget" for d in result.diagnostics)
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_go_tool_and_import_honor_a_declared_local_module_without_domain(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire localtools v0.0.0\n"
        "replace localtools => ./local-tools\ntool localtools/cmd/lint\n"
    )
    (tmp_path / "main.go").write_text('package main\nimport "localtools/api"\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    bundle = result.bundles[0]
    assert len(bundle.usages) == 2
    assert all(u.mapped_package.name == "localtools" for u in bundle.usages)
    assert not bundle.resolved
    assert any(d.code == "security.local-replacement" for d in bundle.diagnostics)
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_go_versioned_replacement_does_not_choose_from_a_minimum(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/dep v1.0.0\n"
        "replace example.com/dep v1.0.0 => example.com/fork v1.2.3\n"
    )
    (tmp_path / "main.go").write_text('package main\nimport "example.com/dep"\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    bundle = result.bundles[0]
    assert bundle.declarations[0].package.name == "example.com/dep"
    assert bundle.declarations[0].constraint.scheme == "go-minimum"
    assert bundle.declarations[0].metadata["replacement_applicability"] == "unknown"
    assert bundle.usages[0].mapped_package.name == "example.com/dep"
    assert not bundle.resolved


def test_go_context_expansion_keeps_a_bounded_prefix(tmp_path, monkeypatch):
    import depcheck.ecosystems.go as go

    monkeypatch.setattr(go, "DEFAULT_MAX_BYTES", 4000)
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/dep v1.0.0\n"
        "require example.com/dep v1.1.0\nexclude example.com/dep v0.9.0\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert len(result.bundles[0].declarations) == 1
    assert any(d.code == "manifest.go-context-budget" for d in result.diagnostics)
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_go_workspace_only_repository_exposes_uncollected_manifest(tmp_path):
    (tmp_path / "go.work").write_text("go 1.24\nuse ../external-module\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        gap["path"] == "go.work" and gap["reason"] == "coverage.unsupported-manifest"
        for gap in result.metadata["coverage"]["uncovered"]
    )
    assert not result.capability("dependency_hygiene").complete


def test_go_checksum_does_not_satisfy_a_required_import(tmp_path):
    from depcheck.ecosystems.analysis import EvidenceAnalyzer
    from depcheck.ecosystems.go import create_go_pack

    (tmp_path / "go.mod").write_text("module example.com/app\n")
    (tmp_path / "go.sum").write_text("example.com/dep v1.0.0 h1:" + "A" * 43 + "=\n")
    (tmp_path / "main.go").write_text('package main\nimport "example.com/dep"\n')
    pack = create_go_pack({"example.com/dep": "example.com/dep"})
    context = ProviderContext(tmp_path)
    bundle = pack.collector.collect(context, pack.detector.detect(context)[0], pack)
    assert any(
        f.code == "dependency.missing"
        for f in EvidenceAnalyzer().analyze(bundle).findings
    )
    assert not bundle.resolved


@pytest.mark.parametrize(
    "invalid",
    [
        'require example.com/dep "v1.0.0',
        "module example.com/other",
        "require (\n require (\n)",
        "replace example.com/dep => ../one\nreplace example.com/dep => ../two",
    ],
)
def test_go_ambiguous_or_malformed_syntax_is_incomplete(tmp_path, invalid):
    (tmp_path / "go.mod").write_text("module example.com/app\n" + invalid + "\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


def test_small_manifest_expansion_is_bounded(tmp_path):
    from depcheck.analyzer.pyproject_parser import PyProjectParser

    (tmp_path / "pom.xml").write_text(
        "<project><properties><a>${a}${a}</a></properties></project>"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        d.code == "manifest.invalid" and "cycle" in d.message
        for d in result.diagnostics
    )

    groups = ["[dependency-groups]", 'g0 = ["requests==2"]']
    groups.extend(
        f'g{i} = [{{include-group="g{i - 1}"}}, {{include-group="g{i - 1}"}}]'
        for i in range(1, 40)
    )
    (tmp_path / "pyproject.toml").write_text("\n".join(groups))
    parsed = PyProjectParser(tmp_path / "pyproject.toml").parse_detailed()
    assert 0 < len(parsed.declarations) < 20_000
    assert [
        sum(d.group == f"dev:g{i}" for d in parsed.declarations) for i in range(4)
    ] == [1, 2, 4, 8]
    assert [d.code for d in parsed.diagnostics] == ["manifest.group-limit"]

    repeated = " || ".join(["*"] * 100)
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                section: {"example": repeated}
                for section in (
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                )
            }
        )
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)
    assert not any(
        d.code == "analysis.constraint-intersection-unknown" for d in result.diagnostics
    )


def test_python_manifest_usage_and_resolution_share_one_identity(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.4\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, enabled_ecosystems=("PyPI",)),
    )

    assert result.findings == ()
    bundle = result.bundles[0]
    assert bundle.project.project_id == "pypi:python:."
    assert bundle.resolved[0].identity.coordinates == (
        "pypi:python:.",
        "PyPI",
        "requests",
        "2.32.4",
        None,
    )
    assert bundle.usages[0].mapped_package == bundle.resolved[0].package


def test_tool_usage_preserves_inventory_and_unused_candidates(tmp_path: Path) -> None:
    from depcheck.config import load_project_config

    (tmp_path / "requirements.txt").write_text("ruff==0.11.0\nrequests==2.31.0\n")
    (tmp_path / ".depcheck.toml").write_text(
        '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
        'package="ruff"\nscope="test"\nreason="CI lint command"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {
        f.package.name for f in result.findings if f.code == "dependency.unused"
    } == {"requests"}
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == {"ruff", "requests"}
    assert {d.package.name for d in bundle.resolved} == {"ruff", "requests"}
    usage = bundle.usages[0]
    assert usage.kind == "tool"
    assert usage.mapping_confidence is MappingConfidence.CONFIGURED
    assert usage.mapping_reason == "CI lint command"
    assert usage.source.path == tmp_path / ".depcheck.toml"
    from depcheck.ecosystems.tool_usage import apply_tool_usage

    assert (
        apply_tool_usage(bundle, load_project_config(tmp_path).tool_usage, tmp_path)
        == bundle
    )


def test_tool_usage_does_not_cross_project_or_ecosystem(tmp_path: Path) -> None:
    for directory in ("one", "two"):
        project = tmp_path / directory
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"shared":"1.0.0"}}')
    (tmp_path / "requirements.txt").write_text("shared==1.0.0\n")
    (tmp_path / ".depcheck.toml").write_text(
        '[[tool-usage]]\necosystem="npm"\nproject-id="npm:npm:one"\n'
        'package="shared"\nscope="runtime"\nreason="Entry point"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    unused = {
        f.package.project_id for f in result.findings if f.code == "dependency.unused"
    }
    assert unused == {"npm:npm:two", "pypi:python:."}


@pytest.mark.parametrize("dynamic", [False, True])
def test_tool_usage_unmatched_build_and_incomplete_boundaries(
    tmp_path: Path, dynamic: bool
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
        '[build-system]\nrequires=["setuptools==80.9.0"]\n'
    )
    (tmp_path / ".depcheck.toml").write_text(
        "".join(
            '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
            f'package="{package}"\nscope="test"\nreason="CI tool"\n'
            for package in ("setuptools", "absent")
        )
    )
    if dynamic:
        (tmp_path / "app.py").write_text(
            "import importlib\nimportlib.import_module(name)\n"
        )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    unmatched = [
        d for d in result.diagnostics if d.code == "config.tool-usage-unmatched"
    ]
    assert len(unmatched) == 1 and "absent" in unmatched[0].message
    assert not any(f.code == "dependency.missing" for f in result.findings)
    assert not result.bundles[0].usages
    if dynamic:
        assert result.capability("dependency_hygiene").state == "incomplete"
        assert not any(f.code == "dependency.unused" for f in result.findings)


def test_same_dependency_in_different_python_extras_is_not_a_duplicate(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\n'
        '[project.optional-dependencies]\nagent=["mcp>=1.28,<2"]\ntest=["mcp>=1.28,<2"]\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not any(f.code.startswith("declaration.") for f in result.findings)
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nrequests==2.32.4\n")
    conflicts = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False)
    )
    assert {f.code for f in conflicts.findings if f.package.name == "requests"} >= {
        "declaration.duplicate",
        "declaration.conflict",
    }


def test_npm_lock_graph_and_lexer_are_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "1.3.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"left-pad": "1.3.0"}},
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "app.ts").write_text(
        "// require('comment-only')\n"
        "const prose = \"require('string-only')\";\n"
        "const actual = require('left-pad');\n",
        encoding="utf-8",
    )

    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, enabled_ecosystems=("npm",)),
    )

    bundle = result.bundles[0]
    assert [(item.reference, item.source.line) for item in bundle.usages] == [
        ("left-pad", 3)
    ]
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("left-pad", "1.3.0")
    ]
    assert result.findings == ()


def test_go_replace_retains_asserted_coordinate_without_security_selection(
    tmp_path: Path,
) -> None:
    class CapturingOSV:
        calls: list[tuple[str, dict[str, str]]] = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(
                vulnerabilities={},
                diagnostics=(),
                queried=dict(packages),
            )

    (tmp_path / "go.mod").write_text(
        "module example.com/app\n"
        "require old.example/module v1.0.0\n"
        "replace old.example/module => new.example/fork v1.2.3\n",
        encoding="utf-8",
    )
    (tmp_path / "go.sum").write_text(
        "new.example/fork v1.2.3 h1:" + "A" * 43 + "=\n",
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        'package main\nimport "old.example/module/subpackage"\n',
        encoding="utf-8",
    )
    osv = CapturingOSV()

    result = RepositoryScanner(osv_client=osv).scan(
        tmp_path,
        RepositoryScanOptions(security=True, enabled_ecosystems=("Go",)),
    )

    bundle = result.bundles[0]
    assert not osv.calls and not bundle.resolved
    assert bundle.declarations[0].package.name == "new.example/fork"
    assert bundle.declarations[0].metadata["replacement_version"] == "v1.2.3"
    assert bundle.declarations[1].kind == "checksum"
    assert bundle.declarations[1].metadata["integrity_verified"] is False
    assert not result.capability("security").complete
    assert bundle.usages[0].mapped_package.name == "new.example/fork"


@pytest.mark.parametrize("parent_version", ["1.0.0", "${revision}"])
def test_maven_parent_mismatch_preserves_child_declarations(tmp_path, parent_version):
    (tmp_path / "pom.xml").write_text(
        """<project>
  <groupId>unrelated</groupId><artifactId>reactor</artifactId><version>1.0.0</version>
  <properties><managed.version>9.9.9</managed.version></properties>
  <dependencyManagement><dependencies><dependency>
    <groupId>example</groupId><artifactId>managed</artifactId><version>9.9.9</version>
  </dependency></dependencies></dependencyManagement>
</project>"""
    )
    child = tmp_path / "component"
    child.mkdir()
    (child / "pom.xml").write_text(
        f"""<project>
  <parent>
    <groupId>external</groupId><artifactId>parent</artifactId><version>{parent_version}</version>
  </parent>
  <artifactId>component</artifactId>
  <dependencies>
    <dependency><groupId>example</groupId><artifactId>pinned</artifactId><version>2.0.0</version></dependency>
    <dependency><groupId>example</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>example</groupId><artifactId>expression</artifactId><version>${{managed.version}}</version></dependency>
  </dependencies>
</project>"""
    )

    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Maven",))
    )
    bundle = next(
        item for item in result.bundles if item.project.root == Path("component")
    )
    direct = {
        item.package.name: item for item in bundle.declarations if item.kind == "direct"
    }

    assert set(direct) == {"example:pinned", "example:managed", "example:expression"}
    assert direct["example:managed"].constraint.normalized is None
    assert direct["example:expression"].constraint.normalized == "${managed.version}"
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("example:pinned", "2.0.0")
    ]
    assert all(
        not item.complete
        for item in bundle.capabilities
        if item.name in {"manifest", "resolution"}
    )
    assert "manifest.parent-coordinate-mismatch" in {
        item.code for item in bundle.diagnostics
    }


def test_maven_management_supplies_version_and_maps_java_usage(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "main" / "java" / "example"
    source.mkdir(parents=True)
    (tmp_path / "pom.xml").write_text(
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement><dependencies><dependency>
    <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
    <version>33.2.1-jre</version>
  </dependency></dependencies></dependencyManagement>
  <dependencies><dependency>
    <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
  </dependency></dependencies>
</project>
""",
        encoding="utf-8",
    )
    (source / "App.java").write_text(
        "package example;\nimport com.google.common.collect.ImmutableList;\n",
        encoding="utf-8",
    )
    pack = create_maven_pack()
    context = ProviderContext(tmp_path)
    project = pack.detector.detect(context)[0]

    bundle = pack.collector.collect(context, project, pack)

    direct = [item for item in bundle.declarations if item.kind == "direct"]
    assert [item.constraint.normalized for item in direct] == ["33.2.1-jre"]
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("com.google.guava:guava", "33.2.1-jre")
    ]
    assert bundle.usages[0].mapped_package.name == "com.google.guava:guava"


def test_conan_and_vcpkg_preserve_lock_scope_and_header_mapping(
    tmp_path: Path,
) -> None:
    (tmp_path / "conanfile.txt").write_text(
        "[requires]\nfmt/10.2.1\n",
        encoding="utf-8",
    )
    (tmp_path / "conan.lock").write_text(
        json.dumps({"requires": ["fmt/10.2.1#revision"]}),
        encoding="utf-8",
    )
    (tmp_path / "vcpkg.json").write_text(
        json.dumps(
            {"dependencies": [{"name": "protobuf", "features": ["zlib"], "host": True}]}
        ),
        encoding="utf-8",
    )
    (tmp_path / "vcpkg-lock.json").write_text(
        json.dumps({"dependencies": {"protobuf": {"version-string": "25.1"}}}),
        encoding="utf-8",
    )
    (tmp_path / "main.cpp").write_text(
        "#include <fmt/core.h>\n#include <google/protobuf/message.h>\n",
        encoding="utf-8",
    )

    conan = create_conan_pack()
    conan_context = ProviderContext(tmp_path)
    conan_project = conan.detector.detect(conan_context)[0]
    conan_bundle = conan.collector.collect(
        conan_context,
        conan_project,
        conan,
    )
    vcpkg = create_vcpkg_pack({"google/protobuf": "protobuf"})
    vcpkg_context = ProviderContext(tmp_path)
    vcpkg_project = vcpkg.detector.detect(vcpkg_context)[0]
    vcpkg_bundle = vcpkg.collector.collect(
        vcpkg_context,
        vcpkg_project,
        vcpkg,
    )

    assert [(item.package.name, item.version) for item in conan_bundle.resolved] == [
        ("fmt", "10.2.1")
    ]
    protobuf = vcpkg_bundle.declarations[0]
    assert protobuf.scope == "host"
    assert protobuf.metadata["features"] == ["zlib"]
    assert vcpkg_bundle.resolved[0].version == "25.1"
    assert vcpkg_bundle.usages[1].mapping_confidence.value == "configured"


@pytest.mark.parametrize("manifest", ["conanfile.txt", "conanfile.py"])
def test_conan_ranges_remain_unresolved_and_revision_assertions_survive(
    tmp_path, manifest
):
    text = (
        "# fmt/decoy\n[requires]\n fmt/[>=1.0 <2.0]\n fmt/2.0#recipe123 # trailing note\n"
        if manifest.endswith("txt")
        else 'class Recipe:\n    requires = ("fmt/[>=1.0 <2.0]", "fmt/2.0#recipe123")\n'
    )
    (tmp_path / manifest).write_text(text, encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "Conan")
    assert len(bundle.declarations) == 2
    assert bundle.declarations[0].constraint.raw == "[>=1.0 <2.0]"
    assert bundle.declarations[0].constraint.normalized is None
    assert bundle.declarations[1].metadata["reference"] == "fmt/2.0#recipe123"
    assert [r.version for r in bundle.resolved] == ["2.0"]
    assert bundle.resolved[0].origin["reference"] == "fmt/2.0#recipe123"
    assert bundle.resolved[0].origin["activation"] == "unknown"


@pytest.mark.parametrize(
    "lock",
    [
        "{}",
        '{"version":"0.4","lockfile":{"nodes":{}}}',
        '{"requires":["fmt/[>=1.0 <2.0]"]}',
        '{"requires":false}',
    ],
)
def test_conan_unsupported_or_invalid_locks_are_qualified(tmp_path, lock):
    (tmp_path / "conanfile.txt").write_text(
        "[requires]\nfmt/[>=1.0 <2.0]\n", encoding="utf-8"
    )
    (tmp_path / "conan.lock").write_text(lock, encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "Conan")
    assert bundle.resolved == ()
    assert any(d.code == "lock.invalid" for d in bundle.diagnostics)
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete


@pytest.mark.parametrize("duplicate_override", [False, True])
def test_vcpkg_minimum_and_ambiguous_override_do_not_resolve(
    tmp_path, duplicate_override
):
    document = {"dependencies": [{"name": "fmt", "version>=": "10.0"}]}
    if duplicate_override:
        document["overrides"] = [
            {"name": "fmt", "version": "10.0"},
            {"name": "fmt", "version": "11.0"},
        ]
    (tmp_path / "vcpkg.json").write_text(json.dumps(document), encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    declaration = bundle.declarations[0]
    assert (
        declaration.constraint.raw == ">=10.0"
        and declaration.constraint.normalized is None
    )
    assert "override_source" not in declaration.metadata
    assert bundle.resolved == ()
    assert any(f.code == "dependency.unpinned" for f in result.findings)
    assert (
        any(d.code == "manifest.ambiguous-vcpkg-override" for d in bundle.diagnostics)
        is duplicate_override
    )


def test_vcpkg_date_port_revision_and_supplied_inventory_location(tmp_path):
    (tmp_path / "vcpkg.json").write_text(
        json.dumps(
            {
                "dependencies": ["fmt"],
                "overrides": [
                    {"name": "fmt", "version-date": "2026-01-01", "port-version": 2}
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "vcpkg-lock.json").write_text(
        json.dumps(
            {"dependencies": {"fmt": {"version-date": "2026-01-01#2"}}}, indent=2
        ),
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert bundle.declarations[0].constraint.normalized == "2026-01-01#2"
    resolution = bundle.resolved[0]
    assert resolution.version == "2026-01-01#2"
    assert (resolution.source.line, resolution.source.column) == (3, 5)
    assert resolution.origin == {
        "kind": "supplied-dependency-inventory",
        "activation": "unknown",
    }


@pytest.mark.parametrize(
    "fields", [{"host": "false"}, {"version>=": 10}, {"features": [{"name": False}]}]
)
def test_vcpkg_invalid_consumed_fields_do_not_become_static_evidence(tmp_path, fields):
    (tmp_path / "vcpkg.json").write_text(
        json.dumps({"dependencies": [{"name": "fmt", **fields}]}), encoding="utf-8"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert bundle.declarations == ()
    assert any(d.code == "manifest.invalid" for d in bundle.diagnostics)
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_vcpkg_feature_inventory_keeps_activation_unknown_without_false_hygiene(
    tmp_path,
):
    (tmp_path / "vcpkg.json").write_text(
        '{"dependencies":["fmt"],"features":{"unit-tests":{"description":"Tests","dependencies":["gtest"]}}}',
        encoding="utf-8",
    )
    (tmp_path / "unit_test.cc").write_text(
        "#include <gtest/gtest.h>\n", encoding="utf-8"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    feature = next(d for d in bundle.declarations if d.package.name == "gtest")
    assert feature.kind == "conditional"
    assert feature.metadata["feature"] == "unit-tests"
    assert feature.metadata["activation"] == "unknown"
    assert next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert any(
        d.code == "resolution.vcpkg-feature-activation-unknown"
        for d in result.diagnostics
    )
    assert not any(f.package.name == "gtest" for f in result.findings)
    assert any(
        f.code == "dependency.unused" and f.package.name == "fmt"
        for f in result.findings
    )
    assert not result.capability("dependency_hygiene").complete


def test_vcpkg_feature_conditions_defaults_and_cache_positions(tmp_path):
    document = {
        "name": "my-lib",
        "supports": "!uwp",
        "default-features": ["gui", {"name": "tests", "platform": "windows"}],
        "dependencies": ["fmt"],
        "overrides": [{"name": "gtest", "version": "1.18.0"}],
        "features": {
            "gui": {
                "description": "GUI",
                "supports": "windows",
                "dependencies": [
                    {"name": "fmt", "platform": "x64"},
                    "sdl2",
                    {
                        "name": "my-lib",
                        "default-features": False,
                        "features": ["core-ui"],
                    },
                ],
            },
            "tests": {
                "description": "Tests",
                "dependencies": [
                    {"name": "gtest", "host": True, "version>=": "1.17.0"}
                ],
            },
            "core-ui": {"description": "Base"},
        },
    }
    text = json.dumps(document, indent=2)
    manifest = tmp_path / "vcpkg.json"
    manifest.write_text(text, encoding="utf-8")
    (tmp_path / "main.cc").write_text(
        "#include <gtest/gtest.h>\n#include <spdlog/spdlog.h>\n", encoding="utf-8"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert len(bundle.declarations) == 5
    root, gui_fmt, sdl, self_ref, gtest = bundle.declarations
    assert root.kind == "direct" and all(
        d.kind == "conditional" for d in bundle.declarations[1:]
    )
    assert gui_fmt.marker == "x64" and gui_fmt.metadata["feature_supports"] == "windows"
    assert gui_fmt.metadata["project_supports"] == "!uwp"
    assert gui_fmt.metadata["default_feature_assertions"] == ["gui"]
    assert self_ref.metadata["self_reference"] is True
    assert (
        self_ref.metadata["features"] == ["core-ui"]
        and self_ref.metadata["default_features"] is False
    )
    assert gtest.scope == "host" and gtest.constraint.normalized == "1.18.0"
    assert gtest.metadata["default_feature_assertions"] == [
        {"name": "tests", "platform": "windows"}
    ]
    assert not bundle.resolved
    for declaration in bundle.declarations:
        source = declaration.source
        assert text.splitlines()[source.line - 1][source.column - 1 :].startswith(
            json.dumps(declaration.package.name)
        )
    assert not any(f.package.name == "gtest" for f in result.findings)
    assert any(
        f.code == "dependency.missing" and f.package.name == "spdlog"
        for f in result.findings
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency("gtest", ecosystem="vcpkg")
    assert record["declared"] and record["resolved_versions"] == []
    assert record["declarations"][0]["kind"] == "conditional"
    assert record["declarations"][0]["metadata"]["feature"] == "tests"
    assert record["declarations"][0]["location"]["line"] == gtest.source.line
    assert not record["evidence_complete"]
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    assert manifest.read_text() == text
    document["features"]["tests"]["dependencies"].append("spdlog")
    manifest.write_text(json.dumps(document, indent=2), encoding="utf-8")
    assert service.repository_context()["stale"]
    service.index_repository()
    refreshed = service.explain_dependency("spdlog", ecosystem="vcpkg")
    assert refreshed["declarations"][0]["kind"] == "conditional"
    assert refreshed["declarations"][0]["metadata"]["feature"] == "tests"


@pytest.mark.parametrize(
    ("root_dependency", "supplied_inventory"),
    [(False, False), (True, False), (False, True)],
)
def test_vcpkg_conditional_sbom_keeps_groups_without_promoting_edges(
    tmp_path, root_dependency, supplied_inventory
):
    document = {
        "dependencies": ["gtest"] if root_dependency else [],
        "overrides": [{"name": "gtest", "version": "1.18.0"}],
        "features": {
            "gui": {"description": "GUI", "dependencies": ["gtest"]},
            "tests": {"description": "Tests", "dependencies": ["gtest"]},
        },
    }
    if root_dependency:
        document.pop("overrides")
    (tmp_path / "vcpkg.json").write_text(json.dumps(document), encoding="utf-8")
    if supplied_inventory:
        (tmp_path / "vcpkg-lock.json").write_text(
            '{"dependencies":{"gtest":{"version":"1.17.0"}}}', encoding="utf-8"
        )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bom = build_cyclonedx(result)
    package_components = [c for c in bom["components"] if c["name"] == "gtest"]
    assertions = [
        (c, json.loads(p["value"]))
        for c in package_components
        for p in c["properties"]
        if p["name"] == "depcheck:conditional-declaration"
    ]
    assert len(assertions) == 2
    assert {a["metadata"]["feature"] for _, a in assertions} == {"gui", "tests"}
    assert all(a["metadata"]["activation"] == "unknown" for _, a in assertions)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cached = service.explain_dependency("gtest", ecosystem="vcpkg")
    assert {
        d["metadata"]["feature"]
        for d in cached["declarations"]
        if d["kind"] == "conditional"
    } == {"gui", "tests"}
    refs = bom["dependencies"][0]["dependsOn"]
    if root_dependency:
        assert refs
    else:
        assert refs == []
        assert all(c["scope"] == "optional" for c, _ in assertions)
        assert all(not r.direct for b in result.bundles for r in b.resolved)
    from dataclasses import replace

    reversed_result = replace(
        result,
        bundles=tuple(
            replace(b, declarations=tuple(reversed(b.declarations)))
            for b in result.bundles
        ),
    )
    reversed_bom = build_cyclonedx(reversed_result)
    assert sorted(reversed_bom["dependencies"][0]["dependsOn"]) == sorted(refs)
    assert (
        sum(
            p["name"] == "depcheck:conditional-declaration"
            for c in reversed_bom["components"]
            for p in c["properties"]
        )
        == 2
    )


def test_vcpkg_feature_context_expansion_is_bounded_and_explicit(tmp_path):
    document = {
        "features": {
            "huge": {
                "description": "Budget fixture",
                "supports": "x" * 1000,
                "dependencies": ["fmt"] * 20000,
            }
        }
    }
    (tmp_path / "vcpkg.json").write_text(json.dumps(document), encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert 0 < len(bundle.declarations) < 20000
    assert any(d.code == "manifest.vcpkg-feature-budget" for d in bundle.diagnostics)
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize("defaults", [False, [{"name": False}], ["missing"]])
def test_vcpkg_invalid_default_feature_assertions_stay_unknown(tmp_path, defaults):
    (tmp_path / "vcpkg.json").write_text(
        json.dumps(
            {
                "default-features": defaults,
                "features": {
                    "tests": {"description": "Tests", "dependencies": ["gtest"]}
                },
            }
        ),
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert (
        bundle.declarations[0].metadata["default_feature_assertions_complete"] is False
    )
    assert any(
        d.code == "manifest.invalid-vcpkg-default-feature" for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


@pytest.mark.parametrize(
    "invalid", [{"dependencies": False}, [], {"dependencies": [False]}]
)
def test_vcpkg_bad_feature_preserves_other_scopes_with_explicit_gap(tmp_path, invalid):
    (tmp_path / "vcpkg.json").write_text(
        json.dumps(
            {
                "dependencies": ["fmt"],
                "features": {
                    "broken": invalid,
                    "good": {"description": "Good", "dependencies": ["gtest"]},
                },
            }
        ),
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert {d.package.name for d in bundle.declarations} == {"fmt", "gtest"}
    assert any(d.code == "manifest.invalid-vcpkg-feature" for d in bundle.diagnostics)
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_conan_lock_positions_contexts_and_inactive_versions_survive_index(tmp_path):
    (tmp_path / "conanfile.txt").write_text(
        "[requires]\n  fmt/10.2.1\n[tool_requires]\n fmt/10.2.1\n",
        encoding="utf-8",
    )
    (tmp_path / "conan.lock").write_text(
        '{\n "version": "0.5",\n "requires": [\n'
        '  "fmt/10.2.1#one%123",\n  "fmt/10.2.1#two%234"\n ],\n'
        ' "build_requires": [\n  "fmt/10.2.1#one%123"\n ],\n'
        ' "python_requires": [\n  "pybase/1.0#rev%345"\n ],\n'
        ' "config_requires": [\n  "config/1.0#cfg%456"\n ]\n}\n',
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "Conan")
    assert [(d.source.line, d.source.column) for d in bundle.declarations] == [
        (2, 3),
        (4, 2),
    ]
    assert len(bundle.resolved) == 5
    assert [r.source.line for r in bundle.resolved] == [4, 5, 8, 11, 14]
    assert len({r.instance_id for r in bundle.resolved}) == 5
    assert [r.origin["context"] for r in bundle.resolved] == [
        "requires",
        "requires",
        "build_requires",
        "python_requires",
        "config_requires",
    ]
    assert [r.integrity for r in bundle.resolved] == ["one", "two", "one", "rev", "cfg"]
    assert all(r.origin["activation"] == "unknown" for r in bundle.resolved)
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    explanation = service.explain_dependency("fmt", ecosystem="Conan")
    assert explanation["resolved_versions"] == ["10.2.1"]
    assert len(explanation["resolutions"]) == 3
    assert len({r["instance"] for r in explanation["resolutions"]}) == 3
    assert all(
        r["origin"]["activation"] == "unknown" for r in explanation["resolutions"]
    )


@pytest.mark.parametrize("filename", ["vcpkg.json", "vcpkg-lock.json"])
def test_cpp_json_parse_errors_retain_authoritative_positions(tmp_path, filename):
    if filename.endswith("lock.json"):
        (tmp_path / "vcpkg.json").write_text('{"dependencies":[]}', encoding="utf-8")
    (tmp_path / filename).write_text('\n{"dependencies": [}\n', encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    diagnostic = next(
        d
        for d in result.diagnostics
        if d.code
        == ("lock.invalid" if filename.endswith("lock.json") else "manifest.invalid")
    )
    assert diagnostic.source.path.name == filename
    assert (diagnostic.source.line, diagnostic.source.column) == (2, 19)


def test_conan_recipe_positions_keep_literal_nodes_and_dynamic_call_gap(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "conanfile.py").write_text(
        f'open({str(marker)!r}, "w").write("bad")\n'
        'description = "fmt/10.2.1"\nclass Recipe:\n'
        '    requires = (\n        "fmt/10.2.1",\n        "gtest/1.17.0",\n    )\n'
        '    def requirements(self):\n        self.requires(\n            "spdlog/1.0"\n        )\n'
        '        self.requires(f"fmt/{self.version}")\n',
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "Conan")
    assert [
        (d.package.name, d.source.line, d.source.column) for d in bundle.declarations
    ] == [("fmt", 5, 9), ("gtest", 6, 9), ("spdlog", 10, 13)]
    assert not marker.exists()
    assert any(
        d.code == "manifest.unsupported-expression" and d.source.line == 12
        for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_vcpkg_positions_preserve_conditions_and_override_origin(tmp_path):
    (tmp_path / "vcpkg.json").write_text(
        '{\r\n "$note": "fmt",\r\n "dependencies": [\r\n  "fmt",\r\n'
        '  {"\\u006eame": "fmt", "platform": "windows", "version>=": "10.0",\r\n'
        '   "features": [{"name": "unicode", "platform": "linux"}], "default-features": false}\r\n ],\r\n'
        ' "overrides": [\r\n  {"name": "fmt", "version": "11.0#2"}\r\n ]\r\n}\r\n',
        encoding="utf-8",
        newline="",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    first, second = bundle.declarations
    assert (first.source.line, first.source.column) == (4, 3)
    assert (second.source.line, second.source.column) == (5, 17)
    assert second.marker == "windows"
    assert second.metadata["features"] == [{"name": "unicode", "platform": "linux"}]
    assert second.metadata["minimum_version"] == "10.0"
    assert second.metadata["default_features"] is False
    assert second.metadata["override_source"] == {
        "path": "vcpkg.json",
        "line": 9,
        "column": 30,
    }
    assert second.constraint.normalized == "11.0#2"
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete


@pytest.mark.parametrize(
    "lock", ["{}", '{"https://example.test/registry":{"HEAD":"abc"}}']
)
def test_vcpkg_registry_lock_is_not_complete_dependency_resolution(tmp_path, lock):
    (tmp_path / "vcpkg.json").write_text('{"dependencies":["fmt"]}', encoding="utf-8")
    (tmp_path / "vcpkg-lock.json").write_text(lock, encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "vcpkg")
    assert bundle.resolved == ()
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(d.code == "lock.invalid" for d in bundle.diagnostics)


@pytest.mark.parametrize("ecosystem", ["Conan", "vcpkg"])
def test_googletest_headers_share_package_and_preserve_source_scope(
    tmp_path: Path, ecosystem: str
) -> None:
    if ecosystem == "Conan":
        (tmp_path / "conanfile.txt").write_text(
            "[test_requires]\ngtest/1.17.0\n", encoding="utf-8"
        )
        pack = create_conan_pack()
    else:
        (tmp_path / "vcpkg.json").write_text(
            json.dumps({"dependencies": ["gtest"]}), encoding="utf-8"
        )
        pack = create_vcpkg_pack()
    (tmp_path / "hello_test.cc").write_text(
        "#include <gtest/gtest.h>\n#include <gmock/gmock.h>\n", encoding="utf-8"
    )
    (tmp_path / "runtime.cc").write_text(
        "#include <gtest/gtest.h>\n#include <gtest_extra/header.h>\n", encoding="utf-8"
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "# find_package(GTest)\n#[=[ find_package(GTest) ]=]\n"
        "find_package(\n  GTest CONFIG REQUIRED)\n",
        encoding="utf-8",
    )
    context = ProviderContext(tmp_path)
    project = pack.detector.detect(context)[0]
    bundle = pack.collector.collect(context, project, pack)
    includes = [usage for usage in bundle.usages if usage.language == "cpp"]
    assert [usage.reference for usage in includes] == [
        "gtest/gtest.h",
        "gmock/gmock.h",
        "gtest/gtest.h",
        "gtest_extra/header.h",
    ]
    assert [usage.scope for usage in includes] == ["test", "test", "runtime", "runtime"]
    for usage in includes[:3]:
        assert usage.mapped_package is not None
        assert usage.mapped_package.name == "gtest"
        assert usage.mapped_package.ecosystem == ecosystem
        assert usage.mapping_confidence.value == "exact"
    assert includes[3].mapped_package is None
    hints = [usage for usage in bundle.usages if usage.kind == "build-hint"]
    assert len(hints) == 1
    assert hints[0].reference == "find_package:GTest"
    assert hints[0].scope == "build"
    assert hints[0].source.line == 4
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    mismatches = [
        finding
        for finding in result.findings
        if finding.code == "dependency.scope-mismatch"
    ]
    assert [
        location.path.name for finding in mismatches for location in finding.locations
    ] == (["runtime.cc"] if ecosystem == "Conan" else [])


@pytest.mark.parametrize(
    ("filename", "scope"),
    [
        ("samples/sample1_unittest.cc", "test"),
        ("mock/Widget_UNITTEST.cpp", "test"),
        ("samples/sample1_unittest_helper.cc", "runtime"),
        ("samples/unittest.cc", "runtime"),
    ],
)
def test_cpp_googletest_sample_scope_avoids_runtime_mismatch(
    tmp_path: Path, filename: str, scope: str
) -> None:
    (tmp_path / "conanfile.txt").write_text(
        "[test_requires]\ngtest/1.17.0\n", encoding="utf-8"
    )
    source = tmp_path / filename
    source.parent.mkdir(parents=True)
    source.write_text('#include "gtest/gtest.h"\n', encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "Conan")
    assert len(bundle.usages) == 1
    usage = bundle.usages[0]
    assert usage.scope == scope
    assert usage.mapped_package is not None
    assert usage.mapped_package.name == "gtest"
    mismatches = [f for f in result.findings if f.code == "dependency.scope-mismatch"]
    assert len(mismatches) == (1 if scope == "runtime" else 0)
    if mismatches:
        assert mismatches[0].locations[0].path == source


@pytest.mark.parametrize("ecosystem", ["Conan", "vcpkg"])
def test_cpp_include_lexer_ignores_examples_and_keeps_physical_locations(
    tmp_path, ecosystem
):
    if ecosystem == "Conan":
        (tmp_path / "conanfile.txt").write_text("[test_requires]\ngtest/1.17.0\n")
    else:
        (tmp_path / "vcpkg.json").write_text('{"dependencies":["gtest"]}')
    text = (
        "/*\n#include <fmt/comment.h>\n*/\n"
        'const char* example = u8R"docs(\n#include <spdlog/example.h>\n)docs";\n'
        "// continued comment \\\n#include <boost/comment.h>\n"
        "/* prefix */ # /* split */ include /* operand */ <gtest/gtest.h>\n"
        '#inc\\\nlude "gmock/gmock.h" // real include\n'
        "auto number = 1'000;\n"
    )
    source = tmp_path / "hello_test.cc"
    source.write_text(text)
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == ecosystem)
    assert [u.reference for u in bundle.usages] == ["gtest/gtest.h", "gmock/gmock.h"]
    assert all(
        u.scope == "test" and u.mapped_package.name == "gtest" for u in bundle.usages
    )
    assert all(u.mapping_confidence is MappingConfidence.EXACT for u in bundle.usages)
    for usage in bundle.usages:
        line = text.splitlines()[usage.source.line - 1]
        assert line[usage.source.column - 1 :].startswith("#")
    assert bundle.usages[0].source.line == 9
    assert bundle.usages[1].source.line == 10
    assert not any(
        f.code in {"dependency.missing", "dependency.scope-mismatch"}
        for f in result.findings
    )


@pytest.mark.parametrize("ecosystem", ["Conan", "vcpkg"])
def test_cpp_conditional_and_macro_includes_preserve_unknown_activation(
    tmp_path, ecosystem
):
    if ecosystem == "Conan":
        (tmp_path / "conanfile.txt").write_text("[requires]\nfmt/11.0.2\n")
    else:
        (tmp_path / "vcpkg.json").write_text('{"dependencies":["fmt"]}')
    (tmp_path / "main.cc").write_text(
        "#if 0\n#include <gtest/gtest.h>\n#else\n#include <gmock/gmock.h>\n#endif\n"
        "#define HEADER <fmt/format.h>\n#include HEADER\n"
        "#include <boost/bad.h> trailing_tokens\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == ecosystem)
    assert [u.reference for u in bundle.usages] == ["gtest/gtest.h", "gmock/gmock.h"]
    assert all(u.kind == "conditional" for u in bundle.usages)
    assert all(
        u.mapping_confidence is MappingConfidence.INFERRED for u in bundle.usages
    )
    assert all("activation" in u.mapping_reason for u in bundle.usages)
    assert not next(c for c in bundle.capabilities if c.name == "usage").complete
    assert not any(
        f.code in {"dependency.missing", "dependency.unused"} for f in result.findings
    )
    assert {
        d.source.line for d in bundle.diagnostics if d.code == "source.cpp-uncollected"
    } >= {2, 7, 8}


@pytest.mark.parametrize(
    "prefix",
    [
        'auto doc = R"tag(\n)ta\\\ng"\n#include <ghost/header.h>\n)tag";\n',
        'auto doc = "continued \\\n#include <ghost/header.h>";\n',
        "/\\\n/ continued comment\n",
        "/* prefix */ ",
        "auto number = 0xF'00; auto character = L'x';\n",
    ],
)
def test_cpp_lexical_boundaries_do_not_create_imports(prefix):
    from depcheck.ecosystems.cpp_source import CppInclude, cpp_includes

    text = prefix + "#include <gtest/gtest.h>\n"
    events = list(cpp_includes(text))
    assert len(events) == 1 and isinstance(events[0], CppInclude)
    assert events[0].reference == "gtest/gtest.h"
    assert text[events[0].offset :].startswith("#include")


@pytest.mark.parametrize(
    "suffix",
    [
        "/* unclosed\n#include <ghost/header.h>\n",
        'auto doc = R"tag(\n#include <ghost/header.h>\n',
        'auto doc = "unclosed\n#include <ghost/header.h>\n',
        "#if X\n" * 65 + "#include <ghost/header.h>\n",
    ],
)
def test_cpp_malformed_source_retains_only_qualified_prefix(tmp_path, suffix):
    (tmp_path / "conanfile.txt").write_text("[requires]\ngtest/1.17.0\n")
    (tmp_path / "main.cc").write_text("#include <gtest/gtest.h>\n" + suffix)
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert [u.reference for u in bundle.usages] == ["gtest/gtest.h"]
    assert any(d.code == "source.invalid" for d in bundle.diagnostics)
    assert not next(c for c in bundle.capabilities if c.name == "usage").complete


@pytest.mark.parametrize("translation", ["??/\n", "\\ \n", "\r"])
def test_cpp_compiler_dependent_translation_leaves_gap(translation):
    from depcheck.ecosystems.cpp_source import CppInclude, CppSourceGap, cpp_includes

    text = "#include <gtest/gtest.h>\n// compiler-dependent " + translation
    text += "#include <ghost/header.h>\n"
    events = list(cpp_includes(text))
    assert any(isinstance(e, CppSourceGap) for e in events)
    assert [e.reference for e in events if isinstance(e, CppInclude)] == [
        "gtest/gtest.h"
    ]


def test_cpp_source_token_budget_qualifies_missing_usage(tmp_path, monkeypatch):
    import depcheck.ecosystems.cpp_source as source_module

    (tmp_path / "conanfile.txt").write_text("[requires]\ngtest/1.17.0\n")
    (tmp_path / "main.cc").write_text("int x;\n" * 10 + "#include <gtest/gtest.h>\n")
    monkeypatch.setattr(source_module, "_MAX_TOKENS", 8)
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not result.bundles[0].usages
    assert any("budget" in d.message for d in result.diagnostics)
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_cpp_conditional_evidence_survives_readonly_index_query(tmp_path):
    (tmp_path / "conanfile.txt").write_text("[test_requires]\ngtest/1.17.0\n")
    text = "#if ENABLE_TESTS\n  #include <gtest/gtest.h>\n#endif\n"
    (tmp_path / "main.cc").write_text(text)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency("gtest", ecosystem="Conan")
    usage = record["usages"][0]
    assert usage["kind"] == "conditional" and usage["mapping_confidence"] == "inferred"
    assert usage["location"]["line"] == 2 and usage["location"]["column"] == 3
    assert not record["evidence_complete"] and not record["findings"]
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]
    assert (tmp_path / "main.cc").read_text() == text


def test_python_fallback_mapping_does_not_assert_a_distribution(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("other-distribution==1.0\n")
    (tmp_path / "app.py").write_text("import unknown_import\n")
    options = RepositoryScanOptions(security=False, compatibility=False)
    result = RepositoryScanner().scan(tmp_path, options)
    usage = result.bundles[0].usages[0]
    assert usage.mapping_confidence.value == "inferred"
    assert usage.mapped_package.name == "unknown-import"
    assert not any(f.code == "dependency.missing" for f in result.findings)
    configured = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, import_mapping={"unknown_import": "real-package"}
        ),
    )
    assert configured.bundles[0].usages[0].mapping_confidence.value == "configured"
    assert any(f.code == "dependency.missing" for f in configured.findings)


@pytest.mark.parametrize("filename", ["CMakeLists.txt", "ExportConfig.cmake"])
def test_cmake_find_dependency_is_an_unevaluated_package_assertion(tmp_path, filename):
    (tmp_path / filename).write_text(
        '# find_dependency(Ghost)\nmessage("find_dependency(Example)")\n'
        "find_dependency(\n  GTest 1.18 EXACT CONFIG\n)\n"
        "if(ENABLE_EXTRA)\nfind_dependency(GTest)\nendif()\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert [d.package.name for d in bundle.declarations] == ["gtest", "gtest"]
    assert [d.source.line for d in bundle.declarations] == [4, 7]
    assert bundle.declarations[0].constraint.raw == "1.18"
    assert all(
        d.metadata["mechanism"] == "find_dependency" for d in bundle.declarations
    )
    assert all(
        d.metadata["activation"] == "unknown" and d.package.purl is None
        for d in bundle.declarations
    )
    assert not bundle.usages and not bundle.resolved and not result.findings


def test_bzlmod_preserves_requests_aliases_and_development_conditions(tmp_path):
    (tmp_path / "MODULE.bazel").write_text(
        'module(name="demo",version="head")\n'
        '# bazel_dep(name="ghost",version="9")\n'
        'bazel_dep(\n name="abseil-cpp",version="20260526.0",repo_name="absl"\n)\n'
        'bazel_dep(name="rules_python",version="2.2.0",dev_dependency=True)\n'
        'bazel_dep(name="abseil-cpp",version="20240116.0",repo_name=None)\n'
    )
    no_osv = SimpleNamespace(
        scan_ecosystem=lambda *a: pytest.fail("Bazel requests are not OSV coordinates")
    )
    result = RepositoryScanner(osv_client=no_osv).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    bundle = result.bundles[0]
    assert bundle.project.project_id == "bazel:bzlmod:."
    assert [d.package.name for d in bundle.declarations] == [
        "abseil-cpp",
        "rules_python",
        "abseil-cpp",
    ]
    first, dev, nodep = bundle.declarations
    assert first.constraint.raw == "20260526.0" and first.constraint.scheme == "bazel"
    assert first.metadata["arguments"]["repo_name"] == "absl"
    assert first.source.line == 4 and first.source.column == 7
    assert (
        dev.scope == "development"
        and dev.metadata["arguments"]["dev_dependency"] is True
    )
    assert nodep.metadata["arguments"]["repo_name"] is None
    assert all(
        d.kind == "conditional"
        and d.package.purl is None
        and d.metadata["activation"] == "unknown"
        for d in bundle.declarations
    )
    assert not bundle.resolved and not bundle.usages and not result.findings
    assert not result.capability("dependency_hygiene").complete
    bom = build_cyclonedx(result)
    root_edge = next(
        d
        for d in bom["dependencies"]
        if d["ref"] == bom["metadata"]["component"]["bom-ref"]
    )
    assert root_edge["dependsOn"] == []
    assert all(
        "version" not in component and "purl" not in component
        for component in bom["components"]
    )


@pytest.mark.parametrize(
    "value", ["VERSION", "'1' + '.0'", "'1' '2'", r"'\x31.0'", 'r"1.0"']
)
def test_bzlmod_dynamic_or_nonportable_literal_versions_stay_unknown(tmp_path, value):
    (tmp_path / "MODULE.bazel").write_text(f'bazel_dep(name="fmt",version={value})\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.package.name == "fmt" and declaration.constraint.raw == ""
    assert declaration.metadata["dynamic_arguments"] == ["version"]
    assert any(d.code == "manifest.bazel-uncollected" for d in result.diagnostics)


def test_bzlmod_extensions_overrides_and_nested_calls_leave_gaps(tmp_path):
    (tmp_path / "MODULE.bazel").write_text(
        'bazel_dep(name="fmt",version="11.0.0")\n'
        'local_path_override(module_name="fmt",path="../private")\n'
        'include("//:extra.MODULE.bazel")\n'
        'ext=use_extension("//:fake.bzl","fake")\n'
        "ext.do_something()\n"
        'wrapper(bazel_dep(name="hidden",version="9"))\n'
        '__import__("pathlib").Path("executed.txt").write_text("bad")\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert [d.package.name for d in result.bundles[0].declarations] == ["fmt"]
    assert (
        len([d for d in result.diagnostics if d.code == "manifest.bazel-uncollected"])
        == 6
    )
    assert not (tmp_path / "executed.txt").exists()
    assert any(
        g["reason"] == "manifest.bazel-uncollected"
        for g in result.metadata["coverage"]["uncovered"]
    )


@pytest.mark.parametrize(
    "limit",
    [
        "_MAX_TOKENS",
        "_MAX_NODES",
        "_MAX_CONTEXT_BYTES",
        "_MAX_RECORDS",
        "_MAX_DIAGNOSTICS",
    ],
)
def test_bzlmod_limits_do_not_turn_omitted_evidence_into_complete_inventory(
    tmp_path, monkeypatch, limit
):
    import depcheck.ecosystems.bazel as bazel_module

    monkeypatch.setattr(bazel_module, limit, 1)
    (tmp_path / "MODULE.bazel").write_text(
        'bazel_dep(name="fmt",version="11")\n'
        'include("//:extra.MODULE.bazel")\n'
        'bazel_dep(name="re2",version="2025")\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert len(result.bundles[0].declarations) <= 1
    assert any("budget" in d.message for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


def test_bzlmod_invalid_syntax_and_unknown_development_condition_are_qualified(
    tmp_path,
):
    manifest = tmp_path / "MODULE.bazel"
    manifest.write_text(
        'bazel_dep(name="fmt",version="11",dev_dependency=SELECTED,repo_name=ALIAS)\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.scope == "unknown"
    assert declaration.metadata["dynamic_arguments"] == ["dev_dependency", "repo_name"]
    assert "repo_name" not in declaration.metadata["arguments"]
    manifest.write_text('bazel_dep(name="fmt",\n')
    invalid = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.invalid-bzlmod" for d in invalid.diagnostics)
    assert not invalid.capability("dependency_hygiene").complete


def test_bzlmod_components_keep_relative_ids_and_respect_exclusions(tmp_path):
    (tmp_path / "MODULE.bazel").write_text('bazel_dep(name="fmt",version="11")\n')
    child = tmp_path / "child"
    child.mkdir()
    (child / "MODULE.bazel").write_text('bazel_dep(name="re2",version="2025")\n')
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["child"]\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert [b.project.project_id for b in result.bundles] == ["bazel:bzlmod:."]
    child_result = RepositoryScanner().scan(
        child, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert child_result.bundles[0].project.project_id == "bazel:bzlmod:."
    assert child_result.bundles[0].declarations[0].package.name == "re2"


def test_bzlmod_literal_positions_handle_utf8_columns(tmp_path):
    text = '"说明"; bazel_dep(name="fmt",version="11")\n'
    (tmp_path / "MODULE.bazel").write_text(text)
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.package.name == "fmt"
    assert declaration.source.column == text.index('"fmt"') + 1


@pytest.mark.parametrize(
    "bad",
    [
        'bazel_dep(name="bad",name="other")',
        'bazel_dep("positional")',
        "bazel_dep(**ARGS)",
    ],
)
def test_bzlmod_ambiguous_calls_keep_valid_sibling_declarations(tmp_path, bad):
    (tmp_path / "MODULE.bazel").write_text(
        bad + '\nbazel_dep(name="fmt",version="11")\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert [d.package.name for d in result.bundles[0].declarations] == ["fmt"]
    assert any(d.code == "manifest.bazel-uncollected" for d in result.diagnostics)


@pytest.mark.parametrize(
    "filename",
    [
        "WORKSPACE",
        "WORKSPACE.bazel",
        "BUILD",
        "BUILD.bazel",
        "MODULE.bazel.lock",
        "deps.bzl",
    ],
)
def test_uncollected_bazel_inputs_prevent_complete_repository_audit(tmp_path, filename):
    (tmp_path / filename).write_text("# selected Bazel input\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not result.capability("dependency_hygiene").complete
    assert any(
        d.code == "coverage.unsupported-manifest" and d.source.path.name == filename
        for d in result.diagnostics
    )


def test_cmake_template_collects_literals_without_expanding_placeholders(tmp_path):
    template = tmp_path / "GTestConfig.cmake.in"
    template.write_text(
        "@PACKAGE_INIT@\ninclude(CMakeFindDependencyMacro)\n"
        "if(@HAS_THREADS@)\n  find_dependency(Threads)\nendif()\n"
        "find_dependency(absl @ABSL_VERSION@ CONFIG)\n"
        "find_dependency(@DEPENDENCY@)\nfind_dependency([=[@BRACKET_DEP@]=])\n"
        'file(WRITE "executed.txt" "bad")\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert bundle.project.project_id == "cmake:cmake-script:."
    assert bundle.project.manifests == (Path(template.name),)
    assert [d.package.name for d in bundle.declarations] == ["threads", "absl"]
    assert [d.source.line for d in bundle.declarations] == [4, 6]
    assert all(
        d.metadata["template"] and d.metadata["activation"] == "unknown"
        for d in bundle.declarations
    )
    assert bundle.declarations[1].constraint.raw == ""
    assert bundle.declarations[1].metadata["dynamic_arguments"] == [0]
    assert any(
        d.code == "manifest.unsupported-cmake-template-expansion"
        for d in bundle.diagnostics
    )
    assert any(
        gap["path"] == template.name
        and gap["reason"] == "manifest.unsupported-cmake-template-expansion"
        for gap in result.metadata["coverage"]["uncovered"]
    )
    assert not result.capability("dependency_hygiene").complete
    assert not (tmp_path / "executed.txt").exists()


def test_cmake_templates_respect_tree_ownership_and_exclusions(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text("project(app)\n")
    (tmp_path / "App.Config.cmake.in").write_text("find_dependency(GTest)\n")
    (tmp_path / "unrelated.in").write_text("find_dependency(Ghost)\n")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "Bad.cmake.in").write_text("find_dependency(Excluded)\n")
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["ignored"]\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert bundle.project.project_id == "cmake:cmake:."
    assert set(bundle.project.manifests) == {
        Path("CMakeLists.txt"),
        Path("App.Config.cmake.in"),
    }
    assert [d.package.name for d in bundle.declarations] == ["gtest"]


def test_cmake_inventory_preserves_assertions_without_claiming_activation(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text(
        "project(example)\ninclude(FetchContent)\n"
        "#[=[ FetchContent_Declare(fake URL https://invalid.test/fake.zip) ]=]\n"
        'message("FetchContent_Declare(also_fake URL absent)")\n'
        "FetchContent_Declare(\n  GoogleTest\n"
        "  URL [=[https://github.com/google/googletest/archive/commit.zip]=]\n)\n"
        "if(USE_ALTERNATIVE)\n"
        "FetchContent_Declare(googletest GIT_REPOSITORY https://example.test/fork.git GIT_TAG main)\n"
        "endif()\nFetchContent_MakeAvailable(GOOGLETEST)\n"
    )
    helper = tmp_path / "cmake" / "testing.cmake"
    helper.parent.mkdir()
    helper.write_text(
        "FetchContent_Declare(Catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2.git GIT_TAG v3.8.1)\n"
        "find_package(GTest 1.17 EXACT CONFIG REQUIRED)\n"
    )
    no_osv = SimpleNamespace(
        scan_ecosystem=lambda *args: pytest.fail(
            "CMake has no verified OSV coordinates"
        )
    )
    result = RepositoryScanner(osv_client=no_osv).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert not result.capability("dependency_hygiene").complete
    bundle = next(b for b in result.bundles if b.project.ecosystem == "CMake")
    assert bundle.project.project_id == "cmake:cmake:."
    assert [d.package.name for d in bundle.declarations] == [
        "googletest",
        "googletest",
        "catch2",
        "gtest",
    ]
    first = bundle.declarations[0]
    assert first.source.line == 6 and first.source.column == 3
    assert first.metadata["options"]["URL"] == [
        "https://github.com/google/googletest/archive/commit.zip"
    ]
    assert all(d.metadata["activation"] == "unknown" for d in bundle.declarations)
    assert all(
        d.package.purl is None and d.scope == "build" for d in bundle.declarations
    )
    assert bundle.resolved == ()
    assert (
        next(c for c in bundle.capabilities if c.name == "usage").state.value
        == "unsupported"
    )
    assert bundle.usages[0].kind == "configuration"
    assert bundle.usages[0].mapping_confidence.value == "inferred"
    assert not result.findings
    assert any(
        d.code == "resolution.cmake-activation-unknown" for d in result.diagnostics
    )
    assert any(d.code == "security.ecosystem-unsupported" for d in result.diagnostics)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param('message("unclosed)', id="unclosed-quote"),
        pytest.param("message([=[unclosed)", id="unclosed-bracket"),
        pytest.param("if((unfinished)", id="unclosed-call"),
        pytest.param("if(" * 100, id="depth-budget"),
        pytest.param("message(" + "x " * 18000 + ")", id="argument-budget"),
        pytest.param("project(x)\n" * 30000, id="token-budget"),
    ],
)
def test_cmake_malformed_input_keeps_prior_declarations_and_reports_gap(tmp_path, bad):
    (tmp_path / "CMakeLists.txt").write_text(
        "FetchContent_Declare(known URL https://example.test/a.zip)\n" + bad
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not result.capability("dependency_hygiene").complete
    bundle = next(b for b in result.bundles if b.project.ecosystem == "CMake")
    assert [d.package.name for d in bundle.declarations] == ["known"]
    assert any(
        d.code == "manifest.invalid" and d.source.path.name == "CMakeLists.txt"
        for d in result.diagnostics
    )


def test_cmake_script_scopes_do_not_absorb_project_components(tmp_path):
    (tmp_path / "bootstrap.cmake").write_text("find_package(RootTool)\n")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "deps.cmake").write_text("find_package(SharedTool)\n")
    app = tmp_path / "app"
    app.mkdir()
    (app / "CMakeLists.txt").write_text("include(deps.cmake)\n")
    (app / "deps.cmake").write_text("find_package(AppTool)\nfind_package(SharedTool)\n")
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "CMakeLists.txt").write_text("find_package(ExcludedProject)\n")
    (archive / "deps.cmake").write_text("find_package(ExcludedScript)\n")
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["archive"]\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundles = {b.project.project_id: b for b in result.bundles}
    assert set(bundles) == {"cmake:cmake-script:.", "cmake:cmake:app"}
    assert [d.package.name for d in bundles["cmake:cmake-script:."].declarations] == [
        "roottool",
        "sharedtool",
    ]
    assert [d.package.name for d in bundles["cmake:cmake:app"].declarations] == [
        "apptool",
        "sharedtool",
    ]
    files = [path for bundle in bundles.values() for path in bundle.project.manifests]
    assert len(files) == len(set(files)) == 4
    assert not result.capability("dependency_hygiene").complete
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    ambiguous = service.explain_dependency("SharedTool", ecosystem="CMake")
    assert ambiguous["error"]["code"] == "dependency.ambiguous"
    assert {choice["project_id"] for choice in ambiguous["error"]["choices"]} == set(
        bundles
    )
    for project_id, expected in (
        ("cmake:cmake-script:.", "scripts/deps.cmake"),
        ("cmake:cmake:app", "app/deps.cmake"),
    ):
        record = service.explain_dependency(
            "SharedTool", ecosystem="CMake", project_id=project_id
        )
        assert record["declarations"][0]["location"]["path"] == expected
    component = RepositoryScanner().scan(
        scripts, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert component.bundles[0].project.project_id == "cmake:cmake-script:."
    assert [d.package.name for d in component.bundles[0].declarations] == ["sharedtool"]


def test_cmake_script_only_wrappers_report_the_uncollected_calls(tmp_path):
    (tmp_path / "packages.cmake").write_text(
        'CPMAddPackage("gh:fmtlib/fmt#11.0.0")\n'
        "CPMFindPackage(NAME Catch2 VERSION 3.8.1)\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert result.bundles[0].project.project_id == "cmake:cmake-script:."
    assert result.bundles[0].declarations == ()
    assert not result.capability("dependency_hygiene").complete
    assert [
        d.source.line
        for d in result.diagnostics
        if d.code == "manifest.unsupported-cmake-command"
    ] == [1, 2]
    assert any(
        gap["path"] == "packages.cmake"
        and gap["reason"] == "manifest.unsupported-cmake-command"
        for gap in result.metadata["coverage"]["uncovered"]
    )


def test_cmake_dynamic_and_unsupported_options_remain_qualified(tmp_path):
    marker = tmp_path / "executed.txt"
    (tmp_path / "CMakeLists.txt").write_text(
        f'file(WRITE "{marker.as_posix()}" "unexpected")\n'
        "FetchContent_Declare(${NAME} URL https://example.test/unknown.zip)\n"
        'FetchContent_Declare(known GIT_REPOSITORY "${REPO}" GIT_TAG "${TAG}" GIT_SHALLOW TRUE)\n'
        "FetchContent_Declare(patched URL https://example.test/a.zip PATCH_COMMAND arbitrary-code)\n"
        "ExternalProject_Add(other URL https://example.test/other.zip)\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.ecosystem == "CMake")
    assert [d.package.name for d in bundle.declarations] == ["known", "patched"]
    assert bundle.declarations[0].metadata["dynamic_arguments"]
    metadata = bundle.declarations[0].metadata
    assert [metadata["arguments"][i] for i in metadata["dynamic_arguments"]] == [
        "${REPO}",
        "${TAG}",
    ]
    assert bundle.declarations[0].metadata["options"]["GIT_SHALLOW"] == ["TRUE"]
    assert bundle.declarations[1].metadata["unparsed_options"] == [
        "PATCH_COMMAND",
        "arbitrary-code",
    ]
    assert {d.code for d in result.diagnostics} >= {
        "manifest.cmake-dynamic",
        "manifest.unsupported-cmake-options",
        "manifest.unsupported-cmake-command",
    }
    assert not result.capability("dependency_hygiene").complete
    assert not marker.exists()


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module(name)\n",
        "import importlib as loader\nloader.import_module(name)\n",
        "from importlib import import_module as load\nload(name)\n",
        "__import__(name)\n",
    ],
)
def test_unresolved_python_dynamic_import_blocks_unused_claims(
    tmp_path: Path, source: str
) -> None:

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "app.py").write_text(source)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)
    assert any(d.code == "usage.dynamic" and d.source.line for d in result.diagnostics)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert service.repository_context()["complete"] is False
    assert service.repository_context()["stale"] is False
    assert not service.explain_dependency("requests")["findings"]


def test_python_literal_dynamic_imports_and_relative_names(tmp_path: Path) -> None:

    (tmp_path / "app.py").write_text(
        "import importlib as loader\n"
        "from importlib import import_module as load\n"
        "loader.import_module('requests')\n"
        "load(name='yaml')\n"
        "load('.helper', package='app')\n"
    )
    result = ImportScanner().scan_detailed(tmp_path)
    assert [item.module for item in result.imports] == ["requests", "yaml"]
    assert all(item.kind == "dynamic" for item in result.imports)
    assert result.diagnostics == ()


def test_notebook_dynamic_import_aliases_cross_cell_boundaries(tmp_path: Path) -> None:

    (tmp_path / "analysis.ipynb").write_text(
        json.dumps(
            {
                "cells": [
                    {
                        "cell_type": "code",
                        "source": "from importlib import import_module as load\n",
                    },
                    {"cell_type": "code", "source": "load('requests')\nload(name)\n"},
                ]
            }
        )
    )
    result = ImportScanner().scan_detailed(tmp_path)
    assert [item.module for item in result.imports] == ["requests"]
    assert [item.code for item in result.diagnostics] == ["usage.dynamic"]
    assert result.diagnostics[0].source.line > result.imports[0].source.line


@pytest.mark.parametrize("suffix", [".py", ".pyi"])
def test_python_script_package_branch_keeps_sibling_import_local(tmp_path, suffix):

    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / ("evidence" + suffix)).write_text("VALUE = 1\n")
    script = scripts / "report.py"
    script.write_text(
        "if __package__:\n"
        "    from .evidence import VALUE\n"
        "else:\n"
        "    from evidence import VALUE\n"
        "    import requests\n"
        "import evidence\n"
    )
    scanner = ImportScanner()

    for result in (
        scanner.scan_detailed(tmp_path),
        scanner.scan_files(tmp_path, [script]),
    ):
        assert {(item.module, item.source.line) for item in result.imports} == {
            ("requests", 5),
            ("evidence", 6),
        }
        assert not result.diagnostics


@pytest.mark.parametrize("layout", ["pkg", "src/pkg"])
def test_nested_python_module_does_not_hide_external_import(
    tmp_path: Path, layout: str
) -> None:

    package = tmp_path / layout
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "requests.py").write_text("")
    (tmp_path / "local.py").write_text("")
    (tmp_path / "app.py").write_text(
        "import requests\nimport pkg.requests\nimport local\n"
    )
    result = ImportScanner().scan_detailed(tmp_path)
    assert [item.module for item in result.imports] == ["requests"]


@pytest.mark.parametrize(
    "section",
    ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"],
)
def test_malformed_npm_dependency_sections_are_incomplete(
    tmp_path: Path, section: str
) -> None:
    (tmp_path / "package.json").write_text(json.dumps({section: ["lodash"]}))
    (tmp_path / "app.js").write_text("import lodash from 'lodash';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=True))
    assert not result.capability("dependency_hygiene").complete
    assert not result.capability("security").complete
    assert {d.code for d in result.diagnostics} >= {
        "manifest.invalid",
        "security.collection-incomplete",
    }
    assert not any(f.code == "dependency.missing" for f in result.findings)


@pytest.mark.parametrize("specifier", [42, False, None, {"version": "1"}])
def test_npm_non_string_dependency_specifiers_are_incomplete(
    tmp_path: Path, specifier
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": specifier}})
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)


def test_npm_empty_version_range_is_valid_but_unpinned(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":""}}')
    (tmp_path / "app.js").write_text("import lodash from 'lodash';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.capability("dependency_hygiene").complete
    assert [f.code for f in result.findings] == ["dependency.unpinned"]


def test_npm_subpath_aliases_preserve_unknown_and_configured_usage(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":"4.17.21"}}')
    (tmp_path / "app.js").write_text("import lodash from '#lodash';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert not any(f.code == "dependency.unused" for f in result.findings)
    assert result.bundles[0].usages[0].mapping_confidence.value == "unknown"
    configured = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, import_mapping={"#lodash": "lodash"}),
    )
    assert configured.capability("dependency_hygiene").complete
    assert configured.bundles[0].usages[0].mapping_confidence.value == "configured"
    assert not configured.findings


def test_node_builtins_are_not_missing_npm_dependencies(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "app.js").write_text(
        "import a from 'async_hooks'; import b from 'diagnostics_channel';\n"
        "import c from 'http2'; import d from 'inspector/promises'; import e from 'node:test';\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles[0].usages == ()
    assert result.findings == ()


@pytest.mark.parametrize(
    "document",
    [{"packages": 42}, {"dependencies": []}, {"packages": {"node_modules/lodash": []}}],
)
def test_invalid_lock_structure_never_reports_complete_security(
    tmp_path: Path, document: dict
) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text(json.dumps(document))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=True))
    assert not result.capability("dependency_hygiene").complete
    assert not result.capability("security").complete
    assert {d.code for d in result.diagnostics} >= {
        "lock.invalid",
        "security.collection-incomplete",
    }


def test_incomplete_collection_still_checks_known_versions(tmp_path: Path) -> None:
    class CapturingOSV:
        calls = []

        def scan_ecosystem(self, packages, ecosystem):
            self.calls.append((ecosystem, dict(packages)))
            return SimpleNamespace(vulnerabilities={}, diagnostics=(), queried=packages)

    (tmp_path / "package.json").write_text('{"dependencies":false}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}'
    )
    osv = CapturingOSV()
    result = RepositoryScanner(osv_client=osv).scan(tmp_path)
    assert osv.calls == [("npm", {"lodash": "4.17.21"})]
    assert not result.capability("security").complete


@pytest.mark.parametrize(
    "ecosystem,manifest,lock,content",
    [
        (
            "npm",
            "package.json",
            "package-lock.json",
            '{"dependencies":{"secret":"1.0.0"}}',
        ),
        (
            "Go",
            "go.mod",
            "go.sum",
            "module example.com/app\nrequire example.com/secret v1.0.0\n",
        ),
        ("Maven", "build.gradle", "gradle.lockfile", "dependencies {}\n"),
        (
            "Maven",
            "build.gradle.kts",
            "buildscript-gradle.lockfile",
            "dependencies {}\n",
        ),
    ],
)
def test_external_lock_symlink_is_incomplete(
    tmp_path: Path, ecosystem: str, manifest: str, lock: str, content: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / manifest).write_text(content)
    external = tmp_path / lock
    external.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/secret":{"version":"1.0.0"}}}'
    )
    (root / lock).symlink_to(external)
    result = RepositoryScanner().scan(
        root, RepositoryScanOptions(security=False, enabled_ecosystems=(ecosystem,))
    )
    assert not result.capability("dependency_hygiene").complete
    assert any("symlink" in d.message for d in result.diagnostics)


def test_package_imports_map_external_and_local_targets(tmp_path):

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "1.0.0", "@scope/pkg": "1.0.0"},
                "imports": {
                    "#format": "lodash/fp",
                    "#scoped": "@scope/pkg/sub",
                    "#util": "./util.js",
                    "#fs": "fs",
                },
            }
        )
    )
    (tmp_path / "app.js").write_text(
        "import a from '#format';\nimport b from '#scoped';\nimport c from '#util';\nimport fs from '#fs';\n"
    )
    (tmp_path / "util.js").write_text("import a from 'lodash';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.capability("dependency_hygiene").complete
    usages = result.bundles[0].usages
    assert {(u.reference, u.mapped_package.name) for u in usages} == {
        ("#format", "lodash"),
        ("#scoped", "@scope/pkg"),
        ("lodash", "lodash"),
    }
    alias = next(u for u in usages if u.reference == "#format")
    assert alias.mapping_confidence is MappingConfidence.EXACT
    assert (
        "package.json" in alias.mapping_reason and "lodash/fp" in alias.mapping_reason
    )
    assert alias.source.line == 1
    assert not result.findings


@pytest.mark.parametrize(
    "target",
    [
        {"default": "lodash"},
        ["lodash"],
        None,
        "lodash/*",
        "#other",
        "./missing.js",
        "https://example.org/a",
        "../outside.js",
        "/absolute.js",
        "",
        "lodash?x",
        "./util.js?x",
    ],
)
def test_package_imports_unknown_targets_keep_incomplete_evidence(tmp_path, target):

    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "1"}, "imports": {"#alias": target}})
    )
    (tmp_path / "app.js").write_text("import a from '#alias';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert result.bundles[0].usages[0].mapping_confidence is MappingConfidence.UNKNOWN
    assert any(d.code == "mapping.alias-unsupported" for d in result.diagnostics)
    assert not any(f.code == "dependency.unused" for f in result.findings)


def test_package_imports_reject_symlink_and_child_project(tmp_path):

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("")
    (root / "linked.js").symlink_to(outside)
    (root / "loop.js").symlink_to("loop.js")
    (root / "child").mkdir()
    (root / "child/package.json").write_text("{}")
    (root / "child/util.js").write_text("")
    for target in ["./linked.js", "./child/util.js", "./loop.js"]:
        (root / "package.json").write_text(json.dumps({"imports": {"#alias": target}}))
        (root / "app.js").write_text("import a from '#alias';\n")
        result = RepositoryScanner().scan(root, RepositoryScanOptions(security=False))
        bundle = next(b for b in result.bundles if b.project.project_id == "npm:npm:.")
        assert bundle.usages[0].mapping_confidence is MappingConfidence.UNKNOWN


def test_scoped_mapping_overrides_package_imports(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"lodash":"1"},"imports":{"#alias":"other"}}'
    )
    (tmp_path / "app.js").write_text("import a from '#alias';\n")
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, import_mapping={"#alias": "lodash"}),
    )
    usage = result.bundles[0].usages[0]
    assert usage.mapped_package.name == "lodash"
    assert usage.mapping_confidence is MappingConfidence.CONFIGURED


@pytest.mark.parametrize(
    "target",
    [
        "./src/../util.js",
        "node:fs/../../lodash",
        "@scope/../other",
        "lodash/../other",
        "lodash/node_modules/other",
        "./node_modules/../util.js",
        "./src/%2e%2e/util.js",
    ],
)
def test_package_imports_invalid_path_segments_remain_unknown(tmp_path, target):

    (tmp_path / "src").mkdir()
    (tmp_path / "util.js").write_text("")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "1.0.0"}, "imports": {"#alias": target}})
    )
    (tmp_path / "app.js").write_text("import a from '#alias';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "mapping.alias-unsupported" for d in result.diagnostics)
    assert result.bundles[0].usages[0].mapping_confidence is MappingConfidence.UNKNOWN
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    ("reference", "target"),
    [
        ("#", "./util.js"),
        ("#util/", "./util.js"),
        ("#util", "node:fs"),
        ("#util", "./NODE_MODULES/util.js"),
        ("#util", "./bad\x00.js"),
    ],
)
def test_invalid_package_imports_never_report_complete(tmp_path, reference, target):
    (tmp_path / "NODE_MODULES").mkdir()
    for path in [tmp_path / "util.js", tmp_path / "NODE_MODULES/util.js"]:
        path.write_text("")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"imports": {reference: target}, "dependencies": {"lodash": "1.0.0"}}
        )
    )
    (tmp_path / "app.js").write_text(f"import {reference!r};\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "mapping.alias-unsupported" for d in result.diagnostics)
    assert result.bundles[0].usages[0].mapping_confidence is MappingConfidence.UNKNOWN
    assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize("aliased", [False, True])
def test_package_import_builtin_requires_an_exact_module_name(tmp_path, aliased):
    (tmp_path / "package.json").write_text(
        json.dumps({"imports": {"#builtin": "fs/promises", "#package": "fs/extra"}})
    )
    builtin, external = (
        ("#builtin", "#package") if aliased else ("fs/promises", "fs/extra")
    )
    (tmp_path / "app.js").write_text(f"import {builtin!r}; import {external!r};\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.capability("dependency_hygiene").complete
    assert [(u.reference, u.mapped_package.name) for u in result.bundles[0].usages] == [
        (external, "fs")
    ]
    assert [f.code for f in result.findings] == ["dependency.missing"]


def _cargo_bundles(root):
    from depcheck.ecosystems.cargo import create_cargo_pack

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
    from depcheck.ecosystems import rust_source
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


def test_npm_workspaces_without_pnpm_yaml_do_not_confirm_pnpm_resolution(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"packageManager":"pnpm@9.15.9","workspaces":["app"]}'
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\nimporters:\n  app: {}\n"
    )
    child = tmp_path / "app"
    child.mkdir()
    (child / "package.json").write_text("{}")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, project_ids=("npm:npm:app",))
    )
    assert any(d.code == "resolution.workspace-ambiguous" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


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
        tmp_path, RepositoryScanOptions(security=True, enabled_ecosystems=("Maven",))
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
    from depcheck.source_locations import SourcePositions

    monkeypatch.setattr(
        SourcePositions, "toml", lambda path, text: SourcePositions(path, text)
    )
    (tmp_path / "libs.versions.toml").write_text('[libraries]\ncore="example:core:1"\n')
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declaration = result.bundles[0].declarations[0]
    assert declaration.source.line is None and declaration.source.column is None
    assert declaration.metadata["version_source"] == {"path": "libs.versions.toml"}


def test_gradle_catalog_context_expansion_keeps_qualified_prefix(tmp_path, monkeypatch):
    from depcheck.ecosystems import gradle_catalog

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
    from depcheck.ecosystems import gradle_catalog

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
    from depcheck.ecosystems import gradle

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
    from depcheck.ecosystems import gradle

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


@pytest.mark.parametrize("mode", ["dynamic", "budget", "aliased"])
def test_npm_registry_inputs_are_bounded_and_do_not_follow_external_configuration(
    tmp_path, monkeypatch, mode
):
    from depcheck.ecosystems import javascript_packages

    (tmp_path / "package.json").write_text('{"dependencies":{"tool":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    path = tmp_path / ".npmrc"
    outside = tmp_path.parent / ("external-" + mode + ".npmrc")
    outside.write_text(
        "registry=https://registry.npmjs.org/\n_authToken=outside-secret\n"
    )
    monkeypatch.setenv("REGISTRY", "https://registry.npmjs.org/")
    if mode == "dynamic":
        path.write_text("registry=${REGISTRY}\nuserconfig=" + str(outside) + "\n")
    elif mode == "budget":
        path.write_text("registry=https://registry.npmjs.org/\n" * 257)
    else:
        path.symlink_to(outside)
    original = javascript_packages.read_text

    def guarded(path, **kwargs):
        assert Path(path) != outside, "target configuration escaped the repository"
        return original(path, **kwargs)

    monkeypatch.setattr(javascript_packages, "read_text", guarded)
    result = RepositoryScanner().scan(tmp_path)
    bundle = result.bundles[0]
    assert bundle.resolved[0].origin["public"] is False
    assert bundle.resolved[0].package.purl is None
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(d.code == "source.registry-incomplete" for d in result.diagnostics)
    assert "outside-secret" not in json.dumps(result.to_dict())


def test_npm_conflicting_ancestor_registries_remain_unknown_and_invalidate_selected_index(
    tmp_path,
):
    (tmp_path / ".npmrc").write_text("registry=https://private.example/npm/\n")
    child = tmp_path / "app"
    child.mkdir()
    (child / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    (child / "package.json").write_text('{"dependencies":{"tool":"1.0.0"}}')
    (child / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    result = RepositoryScanner().scan(tmp_path)
    bundle = result.bundles[0]
    assert bundle.resolved[0].origin["kind"] == "unknown"
    assertions = bundle.resolved[0].origin["configuration_assertions"]
    assert {a["source"]["path"] for a in assertions} == {".npmrc", "app/.npmrc"}
    assert all(a["source"]["line"] == 1 for a in assertions)
    assert any(d.code == "source.registry-ambiguous" for d in result.diagnostics)
    service = DependencyAgentService(tmp_path)
    service.index_repository(project_ids=(bundle.project.project_id,))
    assert not service.repository_context()["stale"]
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n")
    assert service.repository_context()["stale"]
    service.index_repository(project_ids=(bundle.project.project_id,))
    indexed = service.explain_dependency("tool")
    assert next(r["origin"]["public"] for r in indexed["resolutions"]) is True


@pytest.mark.parametrize("layout", ["packages", "legacy", "pnpm"])
def test_npm_lock_version_validation_preserves_valid_neighbors_and_unknowns(
    tmp_path, layout
):
    cases = [
        ("1.0.0", True),
        ("1.0.0-0", True),
        ("1.0.0-alpha.1", True),
        ("0.164.0-alpha.3", True),
        ("0.163.0-alpha.10.2", True),
        ("1.0.0-beta.0", True),
        ("1.0.0-rc.1+build.001", True),
        ("1.0.0-01alpha", True),
        ("1.0.0+001", True),
        ("1.0.0-1+001", True),
        ("9007199254740991.0.0", True),
        ("0.9007199254740991.0", True),
        ("0.0.9007199254740991", True),
        ("1.0.0+" + "b" * 250, True),
        ("1.0.0-" + "9" * 250, True),
        ("1.0.0-01", False),
        ("1.0.0-alpha.01", False),
        ("1.0.0-beta.01", False),
        ("1.0.0-rc.01", False),
        ("rust-v0.164.0-alpha.3", False),
        ("9007199254740992.0.0", False),
        ("0.9007199254740992.0", False),
        ("0.0.9007199254740992", False),
        ("1.0.0+" + "b" * 251, False),
        ("v1.0.0", False),
        ("1.0.0 ", False),
        ("01.0.0", False),
        ("1.0.0-alpha..1", False),
        ("1١.0.0", False),
        ("1.0.0-β", False),
    ]
    versions = {f"case-{i:02d}": version for i, (version, _) in enumerate(cases)}
    expected = {
        name: version for name, (version, accepted) in zip(versions, cases) if accepted
    }
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": dict.fromkeys(versions, "*")})
    )
    if layout == "pnpm":
        # Keep pnpm-style simple keys; PyYAML emits complex keys above 128 chars.
        lines = ["lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:"]
        for name, version in versions.items():
            lines.extend(
                [
                    f"      {name}:",
                    '        specifier: "*"',
                    f"        version: {json.dumps(version)}",
                ]
            )
        lines.append("packages:")
        for name, version in versions.items():
            lines.extend(
                [
                    f"  {json.dumps(name + '@' + version)}:",
                    "    resolution: {integrity: sha512-fixture}",
                ]
            )
        lines.append("snapshots:")
        lines.extend(
            f"  {json.dumps(name + '@' + version)}: {{}}"
            for name, version in versions.items()
        )
        (tmp_path / "pnpm-lock.yaml").write_text("\n".join(lines) + "\n")
    else:
        entries = {
            (f"node_modules/{name}" if layout == "packages" else name): {
                "version": version
            }
            for name, version in versions.items()
        }
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {"packages" if layout == "packages" else "dependencies": entries}
            )
        )

    class OSV:
        def __init__(self):
            self.queries = []

        def scan_ecosystem(self, packages, ecosystem):
            assert ecosystem == "npm"
            self.queries.append(dict(packages))
            return SimpleNamespace(
                vulnerabilities={}, diagnostics=(), queried=dict(packages)
            )

    client = OSV()
    result = RepositoryScanner(osv_client=client).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert client.queries == [expected]
    assert not result.capability("security").complete
    bundle = result.bundles[0]
    assert len(bundle.declarations) == len(cases)
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    exported = {
        r["identity"]["package"]: r
        for r in result.to_dict()["inventory"]["resolved_dependencies"]
    }
    if layout == "pnpm":
        assert set(exported) == set(expected)
        assert any(d.code == "lock.unsupported" for d in result.diagnostics)
    else:
        assert set(exported) == set(versions)
        assert any(d.code == "resolution.source-incomplete" for d in result.diagnostics)
        for name in set(versions) - set(expected):
            assert exported[name]["origin"]["public"] is False
            assert "purl" not in exported[name]["identity"]
    assert all(
        r["identity"]["version"] == versions[name] for name, r in exported.items()
    )


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
    from depcheck.ecosystems import javascript_yarn

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


def test_pep723_scripts_keep_independent_ownership_and_index_freshness(tmp_path):
    first = tmp_path / "one.py"
    first.write_text(
        '# /// script\n# requires-python = ">=3.11"\n# dependencies = ["requests[socks]==2.31.0"]\n# ///\nimport requests\n'
    )
    second = tmp_path / "two.py"
    second.write_text(
        '# /// script\n# dependencies = ["pyyaml==6.0.2"]\n# ///\nimport yaml\n'
    )
    (tmp_path / "example.py").write_text(
        'example = """\n# /// script\n# dependencies = ["not-real-package"]\n# ///\n"""\n'
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    scripts = {
        bundle.project.project_id: bundle
        for bundle in scan.bundles
        if bundle.project.manager == "pep723"
    }
    assert set(scripts) == {"pypi:pep723:one.py", "pypi:pep723:two.py"}
    one, two = scripts["pypi:pep723:one.py"], scripts["pypi:pep723:two.py"]
    assert [item.package.name for item in one.declarations] == ["requests"]
    assert [item.package.name for item in two.declarations] == ["pyyaml"]
    assert one.declarations[0].source.line == 3
    assert one.declarations[0].metadata["extras"] == ["socks"]
    assert one.source_files == (first,) and two.source_files == (second,)
    assert not any(f.code == "dependency.unused" for f in scan.findings)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert not service.repository_context()["stale"]
    records = service.query_dependencies(project_id="pypi:pep723:one.py")[
        "dependencies"
    ]
    assert len(records) == 1 and records[0]["package"] == "requests"
    first.write_text(first.read_text().replace("2.31.0", "2.32.0"))
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies(project_id="pypi:pep723:one.py")
    service.index_repository()
    assert service.explain_dependency("requests", project_id="pypi:pep723:one.py")[
        "resolved_versions"
    ] == ["2.32.0"]
