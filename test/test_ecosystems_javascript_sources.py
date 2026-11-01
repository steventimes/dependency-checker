"""Javascript sources collection, ownership, and qualified static evidence."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
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


def test_node_builtins_are_not_missing_npm_dependencies(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "app.js").write_text(
        "import a from 'async_hooks'; import b from 'diagnostics_channel';\n"
        "import c from 'http2'; import d from 'inspector/promises'; import e from 'node:test';\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles[0].usages == ()
    assert result.findings == ()


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


def test_javascript_regex_context_is_incremental_and_ignores_string_delimiters():
    from depcheck.ecosystems.javascript.source import _lex_javascript, _module_loads

    tokens, incomplete = _lex_javascript(
        'if (check("(")) /require("fake")/.test(x); "return" / divisor; import "real"; value / divisor;'
    )
    loads, _ = _module_loads(tokens)
    assert not incomplete
    assert [item.reference for item in loads] == ["real"]
    tokens, incomplete = _lex_javascript("value" + ")/x" * 20000)
    assert not incomplete
    assert len(tokens) > 40000
