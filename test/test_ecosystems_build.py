"""Build collection, ownership, and qualified static evidence."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


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
    import depcheck.ecosystems.cpp.bazel as bazel_module

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
