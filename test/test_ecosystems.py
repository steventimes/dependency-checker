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
