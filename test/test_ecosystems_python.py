"""Python collection, ownership, and qualified static evidence."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.python.imports import ImportScanner
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


def test_python315_lazy_imports_remain_static_and_version_qualified(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nPyYAML==6.0.3\n")
    (tmp_path / "app.py").write_text(
        "# 字符位置\nlazy import requests\nlazy from yaml import safe_load\n"
        'raise RuntimeError("Target code must never run")\n',
        encoding="utf-8",
    )
    result = ImportScanner().scan_detailed(tmp_path)
    if sys.version_info < (3, 15):
        assert not result.imports and result.diagnostics
        return
    assert [
        (item.module, item.kind, item.source.line, item.source.column)
        for item in result.imports
    ] == [("requests", "lazy", 2, 1), ("yaml", "lazy", 3, 1)]
    assert not result.diagnostics
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {item.reference for bundle in scan.bundles for item in bundle.usages} == {
        "requests",
        "yaml",
    }


def test_pipenv_custom_categories_keep_unknown_scope_and_local_unknown_versions(
    tmp_path,
):
    (tmp_path / "Pipfile").write_text(
        '[packages]\nbase="1.2.3"\n[deploy]\nRequests={version="==2.31.0",extras=["socks"]}\n'
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "base": {"version": "==1.2.3"},
                    "Foo_Bar": {
                        "git": "https://user:password@example.invalid/repo.git",
                        "ref": "abcdef",
                    },
                },
                "deploy": {
                    "requests": {
                        "version": "==2.31.0",
                        "extras": ["socks"],
                        "markers": "sys_platform == 'win32'",
                    }
                },
            }
        )
    )
    (tmp_path / "app.py").write_text("import requests\n")
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declarations = [item for bundle in scan.bundles for item in bundle.declarations]
    custom = next(
        item
        for item in declarations
        if item.metadata.get("python_kind") == "pipenv-declaration"
        and item.metadata.get("category_kind") == "custom"
    )
    assert (custom.kind, custom.scope, custom.metadata["group"]) == (
        "conditional",
        "unknown",
        "pipenv:deploy",
    )
    assert any(
        item.package.name == "base" and item.constraint.raw == "==1.2.3"
        for item in declarations
    )
    unknown = next(item for item in declarations if item.package.name == "foo-bar")
    assert unknown.kind == "locked" and not unknown.constraint.raw
    resolved = [item for bundle in scan.bundles for item in bundle.resolved]
    assert {item.package.name for item in resolved} == {"base", "requests"}
    assert all(
        item.metadata["dependency_status"] == "uncollected"
        and not item.dependency_links
        for item in resolved
    )
    assert not any(item.code == "dependency.scope-mismatch" for item in scan.findings)
    assert "password" not in json.dumps(scan.to_dict())


@pytest.fixture
def hatch_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["ruff==0.11.0"]\n'
        '[dependency-groups]\ndev=["mypy==1.15.0"]\n'
        "[tool.hatch.envs.lint]\ndetached=true\ndependencies=[\n"
        ' "ruff==0.12.0",\n "ruff==0.12.0",\n "PyYAML==6.0.1; sys_platform == \'win32\'",\n]\n'
        '[tool.hatch.envs.lint.env-vars]\nPIP_INDEX_URL="https://user:secret@private.test/simple"\n'
        '[tool.hatch.envs.lint.scripts]\ncheck="ruff check ."\n'
        '[tool.poe.tasks]\ntypes={cmd="python -m mypy app.py",help="Types"}\n'
    )
    (tmp_path / "test_app.py").write_text("import yaml\n")
    return tmp_path


def test_hatch_environments_do_not_merge_with_application_or_host(hatch_project):
    from depcheck.security.osv_client import OSVScanResult

    queries = []

    def scan(packages, ecosystem):
        queries.append((ecosystem, dict(packages)))
        return OSVScanResult({}, (), dict(packages))

    client = SimpleNamespace(
        scan=lambda packages: scan(packages, "PyPI"), scan_ecosystem=scan
    )
    result = RepositoryScanner(osv_client=client).scan(
        hatch_project, RepositoryScanOptions(security=True, python_version="3.14")
    )
    bundle = result.bundles[0]
    environment = [d for d in bundle.declarations if d.kind == "environment"]
    assert len(environment) == 3
    duplicates = [d for d in environment if d.package.name == "ruff"]
    assert len({(d.source.line, d.source.column) for d in duplicates}) == 2
    assert all(
        d.metadata["group"] == "hatch:lint" and d.package.purl is None
        for d in environment
    )
    assert (
        next(d for d in environment if d.package.name == "pyyaml").marker
        == 'sys_platform == "win32"'
    )
    assert {d.version for d in bundle.resolved if d.package.name == "ruff"} == {
        "0.11.0"
    }
    assert [
        (u.mapped_package.name, u.scope)
        for u in bundle.usages
        if u.kind == "environment-command"
    ] == [("ruff", "hatch:lint")]
    assert any(
        u.kind == "command" and u.mapped_package.name == "mypy" for u in bundle.usages
    )
    assert any(
        f.code == "dependency.unused" and f.package.name == "ruff"
        for f in result.findings
    )
    assert not any(
        f.code
        in {"dependency.missing", "dependency.scope-mismatch", "dependency.conflict"}
        for f in result.findings
    )
    assert any(
        d.code == "analysis.python-environment-selection-unknown"
        for d in result.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert "secret" not in json.dumps(bundle.to_dict(hatch_project))
    assert queries == [("PyPI", {"ruff": "0.11.0", "mypy": "1.15.0"})]
    assert any(d.code == "security.collection-incomplete" for d in result.diagnostics)


def test_python_tasks_preserve_member_ownership_and_index_freshness(hatch_project):
    child = hatch_project / "child"
    child.mkdir()
    (child / "pyproject.toml").write_text(
        '[project]\nname="child"\nversion="1"\n[tool.poe.tasks]\ntypes="mypy app.py"\n'
    )
    (child / "app.py").write_text("print('child')\n")
    scan = RepositoryScanner().scan(
        hatch_project, RepositoryScanOptions(security=False)
    )
    member = next(b for b in scan.bundles if b.project.root == Path("child"))
    assert not any(u.kind == "command" for u in member.usages)
    service = DependencyAgentService(hatch_project)
    service.index_repository()
    explanation = service.explain_dependency(
        "ruff", ecosystem="PyPI", project_id="pypi:python:."
    )
    assert len(explanation["declarations"]) == 3
    assert any(u["kind"] == "environment-command" for u in explanation["usages"])
    assert not service.repository_context()["stale"]
    (hatch_project / "hatch.toml").write_text(
        '[envs.lint]\ndependencies=["ruff==99"]\n'
    )
    assert service.repository_context()["stale"]
    refreshed = service.scan_repository()
    explanation = service.explain_dependency(
        "ruff", ecosystem="PyPI", project_id="pypi:python:."
    )
    assert not any(u["kind"] == "environment-command" for u in explanation["usages"])
    assert any(d["code"] == "command.unsupported" for d in refreshed["diagnostics"])


def test_python_task_unknown_expansions_and_shared_budget_are_qualified(tmp_path):
    from depcheck.ecosystems.python.parsers.pyproject import PyProjectParser

    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[project]\nname="demo"\nversion="1"\n[tool.hatch.envs.one]\ntemplate="two"\n'
        'dependencies=["{env:EXTRA}"]\n[tool.hatch.envs.two]\ntemplate="one"\n'
        '[tool.hatch.envs.one.scripts]\ncheck="echo $(touch SHOULD_NOT_EXIST)"\n'
        '[tool.poe.tasks]\ndynamic={cmd="pytest",cwd="child"}\nshell_like="echo $(touch SHOULD_NOT_EXIST)"\n'
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        d.code == "configuration.python-task-unsupported" for d in scan.diagnostics
    )
    assert any(d.code == "command.unsupported" for d in scan.diagnostics)
    assert not scan.bundles[0].usages
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
    path.write_text(
        '[project]\nname="demo"\nversion="1"\n[tool.hatch.envs.large]\ndependencies=['
        + ",".join('"click"' for _ in range(4200))
        + "]\n"
    )
    parsed = PyProjectParser(path).parse_detailed()
    assert len(parsed.declarations) < 4200
    assert any(
        d.severity == "error" and "limit" in d.message for d in parsed.diagnostics
    )


def test_hatch_aliases_and_multiline_poe_do_not_invent_tool_usage(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["ruff==0.11.0"]\n'
        '[tool.hatch.envs.lint]\ndetached=true\ndependencies=["ruff==0.12.0"]\n'
        '[tool.hatch.envs.lint.scripts]\nruff="echo no-package"\ncheck="ruff check ."\n'
        '[tool.poe.tasks]\nmultiline="""echo\nruff check ."""\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.bundles[0].usages
    assert any("aliases" in d.message for d in result.diagnostics)
    assert any("Multiline Poe" in d.message for d in result.diagnostics)


@pytest.mark.parametrize(
    "preamble,query",
    [
        (
            "from importlib.metadata import entry_points as discover",
            "discover(group='demo.plugins')",
        ),
        (
            "from importlib import metadata as md",
            "md.entry_points().select(group='demo.plugins')",
        ),
        (
            "import importlib.metadata",
            "importlib.metadata.entry_points(group='demo.plugins')",
        ),
    ],
)
def test_plugin_discovery_cannot_prove_declared_plugins_unused(
    tmp_path, preamble, query
):
    (tmp_path / "requirements.txt").write_text("demo-plugin==1.0\n")
    source = tmp_path / "app.py"
    source.write_text(
        preamble + "\n" + query + "\nraise RuntimeError('target must not run')\n"
    )
    scan = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        d.code == "usage.dynamic" and "entry-point" in d.message
        for d in scan.diagnostics
    )
    assert not any(f.code == "dependency.unused" for f in scan.findings)
    assert not next(
        c for c in scan.bundles[0].capabilities if c.name == "usage"
    ).complete
    source.write_text(preamble + "\n")
    plain = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(f.code == "dependency.unused" for f in plain.findings)


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


@pytest.mark.parametrize("filename", ["uv.lock", "poetry.lock", "pdm.lock"])
@pytest.mark.parametrize(
    "versions,expected",
    [
        (("1.0.0", "3.0.0"), (True, False)),
        (("3.0.0",), (False,)),
        (("1.0.0", "1.0.0"), (False, False)),
        (("1.5b1", "3.0.0"), (True, False)),
        (("2.0rc1",), (False,)),
    ],
)
def test_multilingual_python_direct_binding_uses_versions_and_occurrences(
    tmp_path, filename, versions, expected
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["foo<2"]\n'
    )
    source = (
        '\nsource={registry="https://pypi.org/simple"}' if filename == "uv.lock" else ""
    )
    header = "version=1\n" if filename == "uv.lock" else ""
    (tmp_path / filename).write_text(
        header
        + "".join(
            f'[[package]]\nname="foo"\nversion="{version}"{source}\n'
            for version in versions
        )
    )
    originals = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in tmp_path.iterdir()}
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    rows = scan.bundles[0].resolved
    assert [row.version for row in rows] == list(versions)
    assert tuple(row.direct for row in rows) == expected
    assert len({row.instance_id for row in rows}) == len(versions)
    assert all(row.origin["public"] is True for row in rows)
    if not any(expected):
        assert all(row.metadata["directness_status"] == "unknown" for row in rows)
        assert any(
            d.code == "resolution.python-directness-unknown" for d in scan.diagnostics
        )
        assert not next(
            c for c in scan.bundles[0].capabilities if c.name == "resolution"
        ).complete
    else:
        assert rows[0].metadata["directness_status"] == "matched-declaration"
        assert rows[1].metadata["directness_status"] == "not-bound-to-declaration"
    assert all(
        (p.read_bytes(), p.stat().st_mtime_ns) == value
        for p, value in originals.items()
    )


def test_multilingual_python_binding_survives_cache_refresh_and_keeps_public_queries(
    tmp_path,
):
    class PublicQueries:
        def __init__(self):
            self.versions = set()

        def scan(self, packages):
            self.versions.update(packages.values())
            return SimpleNamespace(vulnerabilities={}, diagnostics=(), queried=packages)

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[project]\nname="app"\nversion="1"\ndependencies=["foo<2"]\n')
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version=1\n[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        '[[package]]\nname="foo"\nversion="3.0.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    client = PublicQueries()
    scan = RepositoryScanner(osv_client=client).scan(
        tmp_path, RepositoryScanOptions(compatibility=False)
    )
    assert client.versions == {"1.0.0", "3.0.0"}
    rows = scan.bundles[0].resolved
    assert [(row.version, row.direct) for row in rows] == [
        ("1.0.0", True),
        ("3.0.0", False),
    ]
    bom = build_cyclonedx(scan)
    components = [
        c
        for c in bom["components"]
        if c["name"] == "foo" and c.get("version") in {"1.0.0", "3.0.0"}
    ]
    assert len(components) == 2
    for component in components:
        row = next(row for row in rows if row.version == component["version"])
        metadata = next(
            p["value"]
            for p in component["properties"]
            if p["name"] == "depcheck:resolution:metadata"
        )
        assert json.loads(metadata) == dict(row.metadata)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    explanation = service.explain_dependency("foo")
    assert {row["version"]: row["metadata"] for row in explanation["resolutions"]} == {
        row.version: dict(row.metadata) for row in rows
    }
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original
    assert service.index_repository()["parsed_manifest_files"] == 0
    assert (
        service.explain_dependency("foo")["resolutions"] == explanation["resolutions"]
    )
    lock_before = lock.read_bytes(), lock.stat().st_mtime_ns
    manifest.write_text(manifest.read_text().replace("foo<2", "foo>=3"))
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("foo")
    service.index_repository()
    refreshed = service.explain_dependency("foo")["resolutions"]
    assert {r["version"]: r["metadata"]["directness_status"] for r in refreshed} == {
        "1.0.0": "not-bound-to-declaration",
        "3.0.0": "matched-declaration",
    }
    assert {r["instance"] for r in refreshed} == {
        r["instance"] for r in explanation["resolutions"]
    }
    assert (lock.read_bytes(), lock.stat().st_mtime_ns) == lock_before


def test_multilingual_python_pipenv_binding_keeps_categories_separate(tmp_path):
    (tmp_path / "Pipfile").write_text(
        '[packages]\nfoo="==1.0.0"\n[dev-packages]\nfoo="==1.0.0"\n'
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                category: {"foo": {"version": "==1.0.0"}}
                for category in ("default", "develop", "docs")
            }
        )
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert {
        r.metadata["pipenv_category"]: r.direct for r in scan.bundles[0].resolved
    } == {"default": True, "develop": True, "docs": False}
    assert all(r.metadata["activation"] == "unknown" for r in scan.bundles[0].resolved)


@pytest.mark.parametrize("budget", [False, True])
def test_multilingual_python_binding_keeps_private_and_budget_states_unknown(
    tmp_path, monkeypatch, budget
):
    from depcheck.ecosystems.python import collector

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["foo<2"]\n'
        + (
            '[tool.uv.sources]\nfoo={git="https://example.invalid/foo"}\n'
            if not budget
            else ""
        )
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="foo"\nversion="1.0.0"\nsource={'
        + (
            'registry="https://pypi.org/simple"'
            if budget
            else 'git="https://example.invalid/foo"'
        )
        + "}\n"
    )
    if budget:
        monkeypatch.setattr(collector, "_PYTHON_DIRECT_BINDING_WORK", 0)
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    (row,) = scan.bundles[0].resolved
    assert not row.direct and row.metadata["directness_status"] == "unknown"
    if budget:
        assert row.metadata["directness_reason"] == "work-budget-exceeded"
        assert row.origin["public"] is True
    else:
        assert row.origin["public"] is False and row.package.purl is None
    assert not next(
        c for c in scan.bundles[0].capabilities if c.name == "resolution"
    ).complete


@pytest.mark.parametrize(
    "lock_format,dependency_assertion",
    [
        ("poetry", 'dependencies={child={version="*",optional=[]}}'),
        ("poetry", 'dependencies={child={version="*",markers={}}}'),
        ("uv", 'dependencies=[{name="child",marker=false}]'),
    ],
)
def test_multilingual_python_malformed_conditions_never_create_required_edges(
    tmp_path, lock_format, dependency_assertion
):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\n')
    (tmp_path / (lock_format + ".lock")).write_text(
        'version=1\n[[package]]\nname="parent"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        + dependency_assertion
        + '\n[[package]]\nname="child"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("PyPI",))
    )
    parent = next(
        item
        for bundle in scan.bundles
        for item in bundle.resolved
        if item.package.name == "parent"
    )
    assert not parent.dependency_links
    assert parent.metadata["dependency_status"] == "incomplete"
    assert parent.metadata["context"]["package"]["dependencies"]


def test_multilingual_python_redacted_source_does_not_prove_equality(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\n')
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="parent"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        'dependencies=[{name="child",source={url="https://example.invalid/child.whl?artifact=requested"}}]\n'
        '[[package]]\nname="child"\nversion="1.0.0"\nsource={url="https://example.invalid/child.whl?artifact=other"}\n'
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("PyPI",))
    )
    parent = next(
        item
        for bundle in scan.bundles
        for item in bundle.resolved
        if item.package.name == "parent"
    )
    assert not parent.dependency_links
    assert parent.metadata["dependency_status"] == "incomplete"


def test_multilingual_python_dependency_lookup_budget_is_shared(tmp_path, monkeypatch):
    from depcheck.ecosystems.python import collector

    monkeypatch.setattr(collector, "_PYTHON_LOCK_EDGE_WORK", 3)
    (tmp_path / "pyproject.toml").write_text('[project]\nname="demo"\nversion="1"\n')
    (tmp_path / "uv.lock").write_text(
        "version=1\n"
        + "".join(
            "[[package]]\nname="
            + json.dumps(name)
            + '\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
            + ('dependencies=[{name="child"}]\n' if name != "child" else "")
            for name in ["parent-one", "parent-two", "child"]
        )
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("PyPI",))
    )
    rows = {
        item.package.name: item for bundle in scan.bundles for item in bundle.resolved
    }
    assert rows["parent-one"].dependency_links
    assert not rows["parent-two"].dependency_links
    assert rows["parent-two"].metadata["dependency_work_limit"]


def test_multilingual_pdm_instances_context_and_compatibility_remain_conditional(
    tmp_path,
):
    import shutil
    from depcheck.compatibility.checker import CompatibilityChecker
    from depcheck.ecosystems.python.manifest import PythonManifestCollector
    from scripts.evaluate_corpus import _multilingual_inventory

    fixtures = Path(__file__).parent / "fixtures/projects/multilingual"
    shutil.copytree(fixtures / "pdm-2.16.1", tmp_path, dirs_exist_ok=True)
    case = next(
        case
        for case in json.loads((fixtures / "truth.json").read_bytes())["cases"]
        if case["id"] == "pdm-2.16.1"
    )
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("PyPI",))
    )
    assert not _multilingual_inventory(scan, case)
    (bundle,) = scan.bundles
    variants = [item for item in bundle.resolved if item.package.name == "httpx"]
    assert len(variants) == 2 and variants[0].instance_id != variants[1].instance_id
    assert {
        tuple(item.metadata["context"]["package"].get("extras", []))
        for item in variants
    } == {(), ("socks",)}
    manifest = PythonManifestCollector(tmp_path).collect()
    report = CompatibilityChecker().check_detailed(manifest)
    assert report.resolution_status == "incomplete"
    assert any(
        d.code == "compatibility.python-lock-selection-unknown"
        for d in report.diagnostics
    )


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
