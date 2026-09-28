import pytest
import json
from pathlib import Path
from types import SimpleNamespace

from depcheck.ecosystems.base import ProviderContext
from depcheck.ecosystems.cpp import create_conan_pack, create_vcpkg_pack
from depcheck.ecosystems.java import create_maven_pack
from depcheck.engine import RepositoryScanner, RepositoryScanOptions


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
