"""Go collection, ownership, and qualified static evidence."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.registry import ProviderContext
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import MappingConfidence
from depcheck.output import build_cyclonedx


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
        pytest.param("tool", id="missing-tool-path"),
        pytest.param('tool ""', id="empty-tool-path"),
        pytest.param("tool example.com/tool@v1.0.0", id="versioned-tool-path"),
        pytest.param("tool example.com/tool/...", id="wildcard-tool-path"),
        pytest.param('tool "example.com/tool with spaces"', id="spaced-tool-path"),
        pytest.param(
            'require example.com/dep "v1.0.0', id="unterminated-require-quote"
        ),
        pytest.param("module example.com/other", id="duplicate-module"),
        pytest.param("require (\n require (\n)", id="nested-require-block"),
        pytest.param(
            "replace example.com/dep => ../one\nreplace example.com/dep => ../two",
            id="conflicting-replacements",
        ),
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
