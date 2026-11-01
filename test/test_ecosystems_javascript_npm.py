"""Javascript npm collection, ownership, and qualified static evidence."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions


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


@pytest.mark.parametrize("mode", ["dynamic", "budget", "aliased"])
def test_npm_registry_inputs_are_bounded_and_do_not_follow_external_configuration(
    tmp_path, monkeypatch, mode
):
    import depcheck.ecosystems.javascript.packages as javascript_packages

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


@pytest.mark.parametrize("layout", ["packages", "legacy"])
def test_npm_partial_lock_preserves_neighbors_instances_and_sources(tmp_path, layout):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "parent": "1.0.0",
                    "alias": "npm:real@1.0.0",
                    "private": "1.0.0",
                },
            }
        )
    )
    private = {
        "version": "1.0.0",
        "resolved": "https://private.example/private-1.0.0.tgz",
    }
    if layout == "packages":
        document = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "packages/workspace": {},
                "node_modules/alias": {"version": "1.0.0", "name": "real"},
                "node_modules/private": private,
                "node_modules/broken-edges": {"version": "1.0.0", "dependencies": []},
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": {
                        "child": "",
                        "ghost": "*",
                        "missing": "*",
                        "wrong": None,
                    },
                },
                "node_modules/parent/node_modules/child": {"version": "1.0.0"},
                "node_modules/parent/node_modules/ghost": {"version": 42},
                "node_modules/child": {"version": "2.0.0"},
                "node_modules/ghost": {"version": "3.0.0"},
            },
        }
    else:
        document = {
            "lockfileVersion": 1,
            "dependencies": {
                "alias": {"version": "npm:real@1.0.0"},
                "private": private,
                "broken-edges": {"version": "1.0.0", "dependencies": []},
                "parent": {
                    "version": "1.0.0",
                    "requires": {
                        "child": "",
                        "ghost": "*",
                        "missing": "*",
                        "wrong": None,
                    },
                    "dependencies": {
                        "child": {"version": "1.0.0"},
                        "ghost": {"version": 42},
                        "missing": {"optional": True, "peer": True},
                        "wrong": [],
                    },
                },
                "child": {"version": "2.0.0"},
                "ghost": {"version": "3.0.0"},
            },
        }
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(document))
    batches = []

    def scan(packages, ecosystem):
        batches.extend((name, version) for name, version in packages.items())
        return SimpleNamespace(
            vulnerabilities={}, diagnostics=(), queried=dict(packages)
        )

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=scan)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    bundle = result.bundles[0]
    assert {(item.package.name, item.version) for item in bundle.resolved} == {
        ("parent", "1.0.0"),
        ("child", "1.0.0"),
        ("child", "2.0.0"),
        ("ghost", "3.0.0"),
        ("real", "1.0.0"),
        ("private", "1.0.0"),
        ("broken-edges", "1.0.0"),
    }
    assert len({item.instance_id for item in bundle.resolved}) == 7
    parent = next(item for item in bundle.resolved if item.package.name == "parent")
    links = {item.package.name: item for item in parent.dependency_links}
    assert links["child"].version == "1.0.0"
    assert links["child"].instance_id == "node_modules/parent/node_modules/child"
    assert links["ghost"].version is None and links["ghost"].package.purl is None
    assert links["ghost"].instance_id == "node_modules/parent/node_modules/ghost"
    assert links["missing"].version is None and links["missing"].package.purl is None
    assert (
        next(item for item in bundle.resolved if item.package.name == "private").origin[
            "public"
        ]
        is False
    )
    assert ("real", "1.0.0") in batches
    assert ("child", "1.0.0") in batches and ("child", "2.0.0") in batches
    assert not any(
        name in {"alias", "private", "missing", "wrong"} for name, _ in batches
    )
    assert {item.code for item in result.diagnostics} >= {
        "lock.invalid",
        "lock.unsupported",
    }
    assert not result.capability("security").complete
    assert all(
        item.source.path == lock
        and item.source.line is None
        and item.source.column is None
        for item in bundle.resolved
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    explanation = service.explain_dependency("parent", ecosystem="npm")
    assert explanation["resolved_versions"] == ["1.0.0"]
    assert not explanation["evidence_complete"]


@pytest.mark.parametrize("layout", ["packages", "legacy"])
def test_npm_legal_omitted_versions_remain_unsupported(tmp_path, layout):
    (tmp_path / "package.json").write_text('{"dependencies":{"good":"1.0.0"}}')
    if layout == "packages":
        document = {
            "packages": {
                "": {},
                "packages/workspace": {},
                "node_modules/good": {"version": "1.0.0"},
                "node_modules/local": {"link": True, "resolved": "packages/workspace"},
                "node_modules/peer": {"optional": True, "peer": True},
            }
        }
    else:
        document = {
            "dependencies": {
                "good": {"version": "1.0.0"},
                "local": {"link": True, "resolved": "file:packages/workspace"},
                "peer": {"optional": True, "peer": True},
            }
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(document))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("good", "1.0.0")
    ]
    issues = [item for item in bundle.diagnostics if item.code.startswith("lock.")]
    assert len(issues) == 2 and all(item.code == "lock.unsupported" for item in issues)
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete


def test_npm_empty_request_context_keeps_static_resolution_complete(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"leaf":"1.0.0"}}')
    context = {
        "dependencies": {},
        "optionalDependencies": {},
        "peerDependencies": {},
        "peerDependenciesMeta": {},
    }
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/leaf": {"version": "1.0.0", **context}},
            }
        )
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    bundle = result.bundles[0]
    (leaf,) = bundle.resolved
    assert leaf.metadata["context"] == context
    assert leaf.metadata["activation"] == "unknown"
    assert not leaf.dependencies and not leaf.dependency_links
    assert next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete
    assert not any(item.code == "lock.unsupported" for item in bundle.diagnostics)


@pytest.mark.parametrize("case_id", ["lodash-4.17.20", "npm-registry-fetch-12.0.0"])
def test_real_npm_locks_preserve_context_without_changing_inventory(case_id):
    fixtures = Path(__file__).parent / "fixtures/projects"
    case = next(
        item
        for item in json.loads((fixtures / "truth.json").read_text())["cases"]
        if item["id"] == case_id
    )
    result = RepositoryScanner().scan(
        fixtures / case["directory"],
        RepositoryScanOptions(
            security=False, compatibility=False, enabled_ecosystems=("npm",)
        ),
    )
    bundle = result.bundles[0]
    inventory = sorted(
        [item.instance_id, item.package.name, item.version] for item in bundle.resolved
    )
    assert len(inventory) == case["expected_inventory_count"]
    assert (
        hashlib.sha256(
            json.dumps(inventory, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        == case["expected_inventory_sha256"]
    )
    by_instance = {item.instance_id: item for item in bundle.resolved}
    assert all(
        item.metadata["npm_kind"] == "lock-record"
        and item.metadata["lock_version_assertion"] == case["lockfile_version"]
        and item.metadata["activation"] == "unknown"
        for item in bundle.resolved
    )
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete
    assert any(
        "active graph is incomplete" in item.message for item in bundle.diagnostics
    )
    if case["lockfile_version"] == 1:
        chokidar = by_instance["node_modules/chokidar"]
        context = chokidar.metadata["context"]
        assert context["dev"] is True
        assert context["requires"]["fsevents"] == "^1.0.0"
        assert any(
            link.package.name == "fsevents" for link in chokidar.dependency_links
        )
        assert by_instance["node_modules/asn1"].metadata["context"]["optional"] is True
        assert all(
            item.metadata["lock_format"] == "legacy"
            and "dependencies" not in item.metadata["context"]
            for item in bundle.resolved
        )
    else:
        fetch = by_instance["node_modules/minipass-fetch"]
        assert fetch.metadata["context"]["optionalDependencies"] == {
            "encoding": "^0.1.12"
        }
        assert {link.package.name for link in fetch.dependency_links} == {
            "minipass",
            "minipass-sized",
            "minizlib",
        }
        assert (
            by_instance["node_modules/encoding"].metadata["context"]["optional"] is True
        )
        fsevents = by_instance["node_modules/fsevents"]
        assert fsevents.metadata["context"]["os"] == ["darwin"]
        assert fsevents.metadata["context"]["hasInstallScript"] is True
        assert (
            by_instance["node_modules/safer-buffer"].metadata["context"]["devOptional"]
            is True
        )
        tap = by_instance["node_modules/tap"]
        assert tap.metadata["context"]["peerDependenciesMeta"]["typescript"] == {
            "optional": True
        }
        assert "typescript" in tap.metadata["context"]["peerDependencies"]
        assert "typescript" not in {link.package.name for link in tap.dependency_links}
        assert (
            by_instance["node_modules/tap/node_modules/@babel/code-frame"].metadata[
                "context"
            ]["inBundle"]
            is True
        )


@pytest.mark.parametrize(
    "installation,required,optional",
    [
        ("lodash", "file:../private", "4.17.20"),
        ("selected", "npm:former@1.0.0", "npm:lodash@4.17.20"),
    ],
)
def test_npm_optional_override_keeps_assertions_and_effective_public_identity(
    tmp_path, installation, required, optional
):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"parent": "1.0.0", installation: required},
                "optionalDependencies": {installation: optional},
            }
        )
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/parent": {
                        "version": "1.0.0",
                        "dependencies": {installation: required, "healthy": "^2.0.0"},
                        "optionalDependencies": {installation: optional},
                    },
                    f"node_modules/{installation}": {
                        "name": "lodash",
                        "version": "4.17.20",
                        "optional": True,
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    },
                    "node_modules/healthy": {"version": "2.0.0"},
                },
            }
        )
    )
    (tmp_path / "app.js").write_text(f"import value from '{installation}';\n")
    queries = []

    def scan(packages, ecosystem):
        queries.extend((ecosystem, name, version) for name, version in packages.items())
        return SimpleNamespace(
            vulnerabilities={}, diagnostics=(), queried=dict(packages)
        )

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=scan)).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True, compatibility=False, enabled_ecosystems=("npm",)
        ),
    )
    bundle = result.bundles[0]
    declarations = [
        item
        for item in bundle.declarations
        if item.metadata["installation_name"] == installation
    ]
    shadowed, effective = declarations
    assert shadowed.kind == "hint" and shadowed.constraint.raw == required
    assert shadowed.metadata["overridden_by"] == "optionalDependencies"
    assert effective.kind == "direct" and effective.scope == "optional"
    assert effective.package.name == "lodash" and effective.constraint.raw == optional
    resolved = next(item for item in bundle.resolved if item.package.name == "lodash")
    assert (
        resolved.origin["public"] is True and resolved.package.purl == "pkg:npm/lodash"
    )
    assert ("npm", "lodash", "4.17.20") in queries
    assert not any(name == "former" for _, name, _ in queries)
    parent = next(item for item in bundle.resolved if item.package.name == "parent")
    assert {link.package.name for link in parent.dependency_links} == {"healthy"}
    assert parent.metadata["context"]["dependencies"][installation] == required
    assert parent.metadata["context"]["optionalDependencies"][installation] == optional
    assert bundle.usages[0].mapped_package.name == "lodash"
    assert bundle.usages[0].mapped_package.purl == "pkg:npm/lodash"
    assert not any(item.code == "manifest.invalid" for item in bundle.diagnostics)
    assert not any(item.code == "dependency.conflict" for item in result.findings)


@pytest.mark.parametrize("layout", ["packages", "legacy"])
def test_malformed_npm_context_keeps_raw_assertions_and_healthy_neighbors(
    tmp_path, layout
):
    (tmp_path / "package.json").write_text('{"dependencies":{"parent":"1.0.0"}}')
    context = {
        "optional": "unknown",
        "peer": None,
        "devOptional": [],
        "inBundle": {"unexpected": True},
        "os": {"linux": True},
        "cpu": ["x64", None],
        "libc": 42,
        "hasInstallScript": "yes",
    }
    parent = {"version": "1.0.0", **context}
    if layout == "packages":
        context.update(
            {
                "optionalDependencies": ["healthy"],
                "peerDependencies": {"host": 42},
                "peerDependenciesMeta": ["host"],
            }
        )
        parent.update(context)
        parent["dependencies"] = {"healthy": "^2.0.0"}
        document = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/parent": parent,
                "node_modules/healthy": {"version": "2.0.0"},
            },
        }
    else:
        parent["requires"] = {"healthy": "^2.0.0"}
        parent["dependencies"] = {"nested": {"version": "3.0.0"}}
        document = {
            "dependencies": {
                "parent": parent,
                "healthy": {"version": "2.0.0"},
            }
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(document))
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    bundle = result.bundles[0]
    resolved = next(item for item in bundle.resolved if item.package.name == "parent")
    assert all(
        resolved.metadata["context"][key] == value for key, value in context.items()
    )
    assert resolved.metadata["activation"] == "unknown"
    healthy = next(item for item in bundle.resolved if item.package.name == "healthy")
    assert healthy.version == "2.0.0" and healthy.origin["public"] is True
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete
    assert any(
        "unsupported context shape" in item.message for item in bundle.diagnostics
    )
    if layout == "packages":
        assert not resolved.dependency_links
        assert resolved.metadata["lock_version_assertion"] == 3
    else:
        assert "lock_version_assertion" not in resolved.metadata
        assert "dependencies" not in resolved.metadata["context"]
        assert {link.package.name for link in resolved.dependency_links} == {"healthy"}
        assert any(item.package.name == "nested" for item in bundle.resolved)


@pytest.mark.parametrize("header", ["x" * 129, 10**400, {"unexpected": "value"}])
def test_npm_unsupported_lock_header_is_not_multiplied_into_each_record(
    tmp_path, header
):
    (tmp_path / "package.json").write_text('{"dependencies":{"first":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": header,
                "packages": {
                    "node_modules/first": {"version": "1.0.0"},
                    "node_modules/second": {"version": "2.0.0"},
                },
            }
        )
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    bundle = result.bundles[0]
    assert {item.package.name for item in bundle.resolved} == {"first", "second"}
    assert all(
        "lock_version_assertion" not in item.metadata
        and item.metadata["lock_version_state"] == "omitted-with-budget"
        for item in bundle.resolved
    )
    assert any("lockfileVersion" in item.message for item in bundle.diagnostics)
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete


@pytest.mark.parametrize("legacy_version", [None, 1])
def test_npm_legacy_requires_tracks_hoisting_without_inventing_nested_edges(
    tmp_path, legacy_version
):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"parent":"1.0.0","healthy":"1.0.0"}}'
    )
    document = {
        "dependencies": {
            "parent": {
                "version": "1.0.0",
                "requires": {
                    "alias": "npm:real@^2.0.0",
                    "child": "^1.0.0",
                    "ghost": "*",
                    "missing": "*",
                    "private": "1.0.0",
                    "wrong": True,
                },
                "dependencies": {
                    "alias": {"version": "npm:real@2.0.0"},
                    "ghost": [],
                    "misplaced": {
                        "version": "9.0.0",
                        "requires": {"child": "^1.0.0"},
                    },
                },
            },
            "child": {"version": "1.0.0"},
            "ghost": {"version": "3.0.0"},
            "healthy": {"version": "1.0.0"},
            "private": {
                "version": "1.0.0",
                "resolved": "https://private.example/private-1.0.0.tgz",
            },
            "without-requires": {
                "version": "1.0.0",
                "dependencies": {"descendant": {"version": "1.0.0"}},
            },
            "bad-requires": {"version": "1.0.0", "requires": []},
        }
    }
    if legacy_version is not None:
        document["lockfileVersion"] = legacy_version
    (tmp_path / "package-lock.json").write_text(json.dumps(document))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    by_instance = {item.instance_id: item for item in bundle.resolved}
    parent = by_instance["node_modules/parent"]
    links = {item.package.name: item for item in parent.dependency_links}
    assert set(links) == {"real", "child", "ghost", "missing", "private"}
    assert links["real"].version == "2.0.0"
    assert links["real"].instance_id == "node_modules/parent/node_modules/alias"
    assert links["real"].package.purl == "pkg:npm/real"
    assert links["child"].instance_id == "node_modules/child"
    assert links["child"].version == "1.0.0"
    assert links["ghost"].instance_id == "node_modules/parent/node_modules/ghost"
    assert links["ghost"].version is None and links["ghost"].package.purl is None
    assert links["missing"].instance_id is None and links["missing"].version is None
    assert links["private"].instance_id == "node_modules/private"
    assert links["private"].version == "1.0.0"
    assert links["private"].package.purl is None
    misplaced = by_instance["node_modules/parent/node_modules/misplaced"]
    assert misplaced.dependency_links == (links["child"],)
    assert not by_instance["node_modules/without-requires"].dependency_links
    assert not by_instance["node_modules/bad-requires"].dependency_links
    assert (
        by_instance["node_modules/without-requires/node_modules/descendant"].version
        == "1.0.0"
    )
    assert by_instance["node_modules/healthy"].direct
    assert by_instance["node_modules/ghost"].version == "3.0.0"
    issues = [item for item in bundle.diagnostics if item.code.startswith("lock.")]
    assert any(
        item.code == "lock.invalid" and "specifier" in item.message for item in issues
    )
    assert any(
        item.code == "lock.invalid" and "requires must be an object" in item.message
        for item in issues
    )
    assert any(
        item.code == "lock.unsupported" and "no requires metadata" in item.message
        for item in issues
    )
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete


@pytest.mark.parametrize("layout", ["packages", "legacy"])
def test_npm_explicit_alias_conflict_keeps_inventory_and_unknown_target(
    tmp_path, layout
):
    (tmp_path / "package.json").write_text('{"dependencies":{"parent":"1.0.0"}}')
    requests = {
        "alias": "npm:expected@1.0.0",
        "private-alias": "npm:private-real@2.0.0",
        "plain": "3.0.0",
    }
    wrong_target = {
        "name": "other",
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz",
    }
    private_target = {
        "name": "private-real",
        "version": "2.0.0",
        "resolved": "https://private.example/private-real-2.0.0.tgz",
    }
    root_target = {"name": "expected", "version": "1.0.0"}
    ordinary_target = {"name": "plain-real", "version": "3.0.0"}
    if layout == "packages":
        document = {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": requests,
                },
                "node_modules/parent/node_modules/alias": wrong_target,
                "node_modules/parent/node_modules/private-alias": private_target,
                "node_modules/alias": root_target,
                "node_modules/plain": ordinary_target,
            },
        }
    else:
        document = {
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {
                    "version": "1.0.0",
                    "requires": requests,
                    "dependencies": {
                        "alias": wrong_target,
                        "private-alias": private_target,
                    },
                },
                "alias": root_target,
                "plain": ordinary_target,
            },
        }
    (tmp_path / "package-lock.json").write_text(json.dumps(document))
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    by_instance = {item.instance_id: item for item in bundle.resolved}
    links = {
        item.package.name: item
        for item in by_instance["node_modules/parent"].dependency_links
    }
    assert set(links) == {"expected", "plain-real", "private-real"}
    unknown = links["expected"]
    assert unknown.instance_id == "node_modules/parent/node_modules/alias"
    assert unknown.version is None and unknown.package.purl is None
    actual = by_instance[unknown.instance_id]
    assert actual.package.name == "other" and actual.version == "1.0.0"
    assert actual.package.purl == "pkg:npm/other" and actual.origin["public"]
    ancestor = by_instance["node_modules/alias"]
    assert ancestor.package.name == "expected" and ancestor.version == "1.0.0"
    assert links["plain-real"].instance_id == "node_modules/plain"
    assert links["plain-real"].version == "3.0.0"
    private = links["private-real"]
    assert private.instance_id == "node_modules/parent/node_modules/private-alias"
    assert private.version == "2.0.0" and private.package.purl is None
    assert by_instance[private.instance_id].origin["public"] is False
    issues = [item for item in bundle.diagnostics if item.code.startswith("lock.")]
    assert len(issues) == 1
    assert issues[0].code == "lock.invalid" and "alias request" in issues[0].message
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete


@pytest.mark.parametrize("layout", ["packages", "legacy"])
def test_npm_lookup_budget_is_shared_and_keeps_all_instances(
    tmp_path, monkeypatch, layout
):
    import depcheck.ecosystems.javascript.npm as npm

    first_child = "node_modules/a/node_modules/child"
    monkeypatch.setattr(npm, "_MAX_ANCESTOR_CANDIDATE_CHARACTERS", len(first_child))
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"dependencies": {name: "1.0.0" for name in ("a", "b", "c", "healthy")}}
        )
    )
    packages = {
        "node_modules/a": {"version": "1.0.0", "dependencies": {"child": "*"}},
        first_child: {"version": "1.0.0"},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"child": "*"}},
        "node_modules/b/node_modules/child": {"version": "2.0.0"},
        "node_modules/c": {"version": "1.0.0", "dependencies": {"child": "*"}},
        "node_modules/healthy": {"version": "1.0.0"},
    }
    lock = tmp_path / "package-lock.json"
    if layout == "packages":
        document = {"lockfileVersion": 3, "packages": packages}
    else:
        document = {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {
                    "version": "1.0.0",
                    "requires": {"child": "*"},
                    "dependencies": {"child": {"version": "1.0.0"}},
                },
                "b": {
                    "version": "1.0.0",
                    "requires": {"child": "*"},
                    "dependencies": {"child": {"version": "2.0.0"}},
                },
                "c": {"version": "1.0.0", "requires": {"child": "*"}},
                "healthy": {"version": "1.0.0"},
            },
        }
    lock.write_text(json.dumps(document))
    before = lock.read_bytes(), lock.stat().st_mtime_ns
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert {item.instance_id for item in bundle.resolved} == set(packages)
    assert {(item.instance_id, item.version) for item in bundle.resolved} == {
        (path, raw["version"]) for path, raw in packages.items()
    }
    by_instance = {item.instance_id: item for item in bundle.resolved}
    first = by_instance["node_modules/a"].dependency_links[0]
    assert first.instance_id == first_child and first.version == "1.0.0"
    for parent in ("node_modules/b", "node_modules/c"):
        link = by_instance[parent].dependency_links[0]
        assert (
            link.version is None
            and link.instance_id is None
            and link.package.purl is None
        )
    issues = [item for item in bundle.diagnostics if item.code.startswith("lock.")]
    assert len(issues) == 1
    assert issues[0].code == "lock.unsupported" and "budget" in issues[0].message
    assert not next(
        item for item in bundle.capabilities if item.name == "resolution"
    ).complete
    assert (lock.read_bytes(), lock.stat().st_mtime_ns) == before


def test_npm_noncanonical_instance_paths_cannot_stall_or_discard_neighbors(tmp_path):
    import subprocess
    import sys

    (tmp_path / "package.json").write_text('{"dependencies":{"good":"1.0.0"}}')
    paths = [
        "/node_modules/bad",
        "//node_modules/bad",
        "C:/node_modules/bad",
        "node_modules/../node_modules/bad",
        "./node_modules/bad",
        "node_modules//bad",
        "node_modules\\bad",
        "node_modules/bad/",
    ]
    document = {
        "packages": {
            path: {"version": "1.0.0", "dependencies": {"missing": "*"}}
            for path in paths
        }
    }
    document["packages"]["node_modules/good"] = {"version": "1.0.0"}
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps(document))
    before = lock.read_bytes(), lock.stat().st_mtime_ns
    program = (
        "import json,sys; sys.path.insert(0,sys.argv[1]); "
        "from pathlib import Path; from depcheck.engine import RepositoryScanner,RepositoryScanOptions; "
        "r=RepositoryScanner().scan(Path(sys.argv[2]),RepositoryScanOptions(security=False,compatibility=False)); "
        "print(json.dumps({'resolved':[(d.package.name,d.version) for b in r.bundles for d in b.resolved],"
        "'diagnostics':[d.code for d in r.diagnostics],"
        "'complete':[c.complete for b in r.bundles for c in b.capabilities if c.name=='resolution']}))"
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(Path(__file__).resolve().parents[1]),
            str(tmp_path),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    actual = json.loads(completed.stdout)
    assert actual["resolved"] == [["good", "1.0.0"]]
    assert actual["diagnostics"].count("lock.invalid") == len(paths)
    assert actual["complete"] == [False]
    assert (lock.read_bytes(), lock.stat().st_mtime_ns) == before
    assert not (tmp_path / ".depcheck").exists()


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
