from depcheck.model import MappingConfidence
import pytest
import json
import yaml
from pathlib import Path
from types import SimpleNamespace

from depcheck.ecosystems.base import ProviderContext
from depcheck.ecosystems.cpp import create_conan_pack, create_vcpkg_pack
from depcheck.ecosystems.java import create_maven_pack
from depcheck.engine import RepositoryScanner, RepositoryScanOptions


@pytest.mark.parametrize("fixture", [1, 2, 3])
def test_pnpm_real_locks_preserve_project_versions_and_edges(tmp_path, fixture):
    from depcheck.agent import DependencyAgentService
    from depcheck.output import build_cyclonedx

    text = (
        Path(__file__).parent / "fixtures/pnpm" / f"pnpm-real-{fixture}.yaml"
    ).read_text()
    document = yaml.safe_load(text)
    (tmp_path / "pnpm-lock.yaml").write_text(text)
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
    from depcheck.output import build_cyclonedx

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
    from depcheck.agent import DependencyAgentService

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
    from depcheck.agent import DependencyAgentService

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


@pytest.mark.parametrize("field", ["dependencies", "optional-dependencies"])
def test_dynamic_pyproject_dependencies_do_not_establish_missing_packages(
    tmp_path: Path, field
) -> None:
    from depcheck.agent import DependencyAgentService

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
    assert result.capability("dependency_hygiene").complete
    assert not result.findings
    assert result.bundles[0].resolved[0].version == "v1.0.0"
    assert result.bundles[0].declarations[0].kind == "direct"


def test_go_mod_retains_indirect_flag_after_comment_parsing(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module\texample.com/app // app\n"
        "require ( // dependencies\n\texample.com/dep v1.0.0 // indirect\n)\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert result.capability("dependency_hygiene").complete
    assert result.bundles[0].declarations[0].kind == "transitive"
    assert not result.bundles[0].resolved[0].direct


def test_go_mod_unterminated_dependency_block_is_incomplete(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire (\nexample.com/dep v1.0.0\n"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Go",))
    )
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)


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
    assert len(parsed.declarations) == 40
    assert not parsed.diagnostics

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
    from depcheck.model import MappingConfidence

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


def test_go_replace_uses_effective_coordinate_for_usage_and_security(
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
        "new.example/fork v1.2.3 h1:effective\n",
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
    assert osv.calls == [("Go", {"new.example/fork": "v1.2.3"})]
    assert bundle.resolved[0].package.name == "new.example/fork"
    assert bundle.resolved[0].integrity == "h1:effective"
    assert bundle.usages[0].mapped_package.name == "new.example/fork"


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


def test_ambiguous_javascript_marks_scan_incomplete(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "app.js").write_text(
        "const lazy = import(resolveName());\n",
        encoding="utf-8",
    )

    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(security=False, enabled_ecosystems=("npm",)),
    )

    assert result.complete is False
    assert result.capability("dependency_hygiene").state.value == "incomplete"
    assert {item.code for item in result.diagnostics} == {"usage.dynamic"}


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
    from depcheck.agent import DependencyAgentService

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
    from depcheck.analyzer.import_scanner import ImportScanner

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
    from depcheck.analyzer.import_scanner import ImportScanner

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


@pytest.mark.parametrize("layout", ["pkg", "src/pkg"])
def test_nested_python_module_does_not_hide_external_import(
    tmp_path: Path, layout: str
) -> None:
    from depcheck.analyzer.import_scanner import ImportScanner

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
    import json

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
    import json

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
    import json

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
    import json

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
