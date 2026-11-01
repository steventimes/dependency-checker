"""Cpp collection, ownership, and qualified static evidence."""

import json
from pathlib import Path

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.cpp.collector import create_conan_pack, create_vcpkg_pack
from depcheck.ecosystems.registry import ProviderContext
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import MappingConfidence
from depcheck.output import build_cyclonedx


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
    from depcheck.ecosystems.cpp.source import CppInclude, cpp_includes

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
    from depcheck.ecosystems.cpp.source import CppInclude, CppSourceGap, cpp_includes

    text = "#include <gtest/gtest.h>\n// compiler-dependent " + translation
    text += "#include <ghost/header.h>\n"
    events = list(cpp_includes(text))
    assert any(isinstance(e, CppSourceGap) for e in events)
    assert [e.reference for e in events if isinstance(e, CppInclude)] == [
        "gtest/gtest.h"
    ]


def test_cpp_source_token_budget_qualifies_missing_usage(tmp_path, monkeypatch):
    import depcheck.ecosystems.cpp.source as source_module

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
