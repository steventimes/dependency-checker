import json
import sqlite3
import tomllib
from pathlib import Path

import pytest

from depcheck.config import ConfigurationError, load_project_config
from depcheck.indexing.models import INDEX_SCHEMA
from depcheck.indexing.store import IndexStore
from depcheck.path_policy import ProjectPathError, require_within_project


ROOT = Path(__file__).resolve().parents[1]


def test_configuration_rejects_unknown_or_unsafe_values(tmp_path: Path) -> None:
    (tmp_path / ".depcheck.toml").write_text(
        'securty = false\nexcluded-directories = ["../outside"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unknown key: securty"):
        load_project_config(tmp_path)

    (tmp_path / ".depcheck.toml").write_text(
        'excluded-directories = ["../outside"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="must contain relative"):
        load_project_config(tmp_path)


def test_project_path_policy_rejects_parent_and_symlink_escape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)

    assert (
        require_within_project(
            root,
            root / "child",
            operation="read",
        )
        == (root / "child").resolve()
    )
    with pytest.raises(ProjectPathError):
        require_within_project(root, root / "escape" / "secret", operation="read")
    with pytest.raises(ProjectPathError):
        require_within_project(root, root / ".." / "outside", operation="read")


def test_incompatible_index_schema_is_rebuilt_as_a_cache(tmp_path: Path) -> None:
    path = tmp_path / ".depcheck" / "index.sqlite3"
    path.parent.mkdir()
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO metadata VALUES ('schema', 'depcheck.index.v1');"
        "CREATE TABLE legacy_marker(value TEXT);"
    )
    connection.commit()
    connection.close()

    with IndexStore(tmp_path) as store:
        tables = {
            row[0]
            for row in store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        metadata = store.metadata()

    assert INDEX_SCHEMA == "depcheck.index.v3"
    assert metadata["schema"] == INDEX_SCHEMA
    assert "legacy_marker" not in tables


def test_query_connections_are_read_only_and_do_not_rebuild_old_caches(
    tmp_path: Path,
) -> None:
    from depcheck.agent import DependencyAgentService

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    path = tmp_path / ".depcheck" / "index.sqlite3"
    snapshot = path.read_bytes()
    modified_at = path.stat().st_mtime_ns
    service.repository_context()
    service.query_dependencies()
    service.explain_dependency("requests")
    service.dependency_impact("requests")
    assert path.read_bytes() == snapshot
    assert path.stat().st_mtime_ns == modified_at
    with IndexStore(tmp_path, read_only=True) as store:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            store.set_metadata({"unexpected": "mutation"})
    with IndexStore(tmp_path) as store:
        store.set_metadata({"schema": "depcheck.index.legacy"})
        store.connection.commit()
    legacy_snapshot = path.read_bytes()
    with pytest.raises(RuntimeError, match="depcheck index"):
        service.repository_context()
    assert path.read_bytes() == legacy_snapshot
    service.index_repository()
    assert service.repository_context()["complete"]


def test_release_and_plugin_metadata_share_one_version_and_entrypoint() -> None:
    package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = package["project"]["version"]
    portable = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    codex = json.loads(
        (ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    workflow = json.loads(
        (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    )

    assert version == portable["version"] == codex["version"]
    assert package["project"]["scripts"]["depcheck"] == "depcheck.command:cli"
    commands = "\n".join(
        str(step.get("run", ""))
        for job in workflow["jobs"].values()
        for step in job["steps"]
    )
    assert "pytest test" in commands
    assert "ruff check depcheck test" in commands
    assert "python -m mypy" in commands
    assert "python -m build" in commands


def test_suite_is_intentionally_bounded_to_five_files() -> None:
    tests = sorted(ROOT.glob("test/test_*.py"))
    assert [path.name for path in tests] == [
        "test_core.py",
        "test_ecosystems.py",
        "test_engineering.py",
        "test_interfaces.py",
        "test_outputs.py",
    ]


def test_skill_scorer_accepts_real_diagnostic_fields_and_rejects_wrong_claims() -> None:
    import copy
    import runpy

    evals = ROOT / "skills" / "check-dependencies" / "evals"
    scorer = runpy.run_path(str(evals / "score.py"))
    cases = scorer["load_cases"](evals / "cases.json")
    traces = scorer["load_traces"](evals / "traces.example.json")
    diagnostic = traces["unsupported-pyproject-preview"]["tool_calls"][0]["result"][
        "diagnostics"
    ][0]
    diagnostic["message"] = "Only requirements*.txt version entries are supported."
    assert scorer["score_suite"](cases, traces).passed

    invented_resolution = copy.deepcopy(traces)
    invented_resolution["missing-lockfile"]["tool_calls"][1]["result"][
        "resolved_versions"
    ] = ["4.17.21"]
    assert not scorer["score_suite"](cases, invented_resolution).passed

    wrong_code = copy.deepcopy(traces)
    wrong_code["unsupported-pyproject-preview"]["tool_calls"][0]["result"][
        "diagnostics"
    ][0]["code"] = "unrelated"
    assert not scorer["score_suite"](cases, wrong_code).passed
    for malformed in ([], {}, 1, "false"):
        traces["unsupported-pyproject-preview"]["claims"]["security_safe"] = malformed
        assert not scorer["score_suite"](cases, traces).passed


def test_new_exclusions_remove_previously_indexed_manifests(tmp_path: Path) -> None:
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "requirements.txt").write_text("requests==2.31.0\n")
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path)
    (tmp_path / ".depcheck.toml").write_text('excluded-directories = ["generated"]\n')
    indexer.refresh(tmp_path)
    (generated / "requirements.txt").write_text("requests==2.32.4\n")
    assert RepositoryIndex(tmp_path).context()["stale"] is False
    assert RepositoryIndex(tmp_path).dependencies() == []


def test_index_does_not_invent_a_python_project_from_cmake(tmp_path: Path) -> None:
    from depcheck.engine import RepositoryScanner, RepositoryScanOptions
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    (tmp_path / "CMakeLists.txt").write_text("find_package(fmt REQUIRED)\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    RepositoryIndexer().refresh(tmp_path)
    indexed = RepositoryIndex(tmp_path).context()
    assert {bundle.project.project_id for bundle in result.bundles} == {
        project["project_id"] for project in indexed["projects"]
    }


@pytest.mark.parametrize("target", [".depcheck.toml", "pyproject.toml", ".depcheck"])
def test_config_and_default_index_reject_symlink_escape(
    tmp_path: Path, target: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    if target == ".depcheck":
        outside.mkdir()
    else:
        outside.write_text("security = false\n")
    (root / target).symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises(ProjectPathError):
        if target == ".depcheck":
            with IndexStore(root):
                pass
        else:
            load_project_config(root)
    if target == ".depcheck":
        assert list(outside.iterdir()) == []


def test_summary_counts_are_not_multiplied_by_other_evidence(tmp_path: Path) -> None:
    from depcheck.indexing import RepositoryIndexer

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nhttpx==0.27.0\n")
    (tmp_path / "app.py").write_text("import requests\nimport httpx\n")
    (tmp_path / "other.py").write_text("import requests\n")
    RepositoryIndexer().refresh(tmp_path)
    with IndexStore(tmp_path) as store:
        assert store.ecosystem_summary() == {
            "PyPI": {
                "project_count": 1,
                "declaration_count": 2,
                "usage_count": 3,
                "source_file_count": 2,
            }
        }


def test_python_source_discovery_does_not_read_symlink_targets(tmp_path: Path) -> None:
    from depcheck.analyzer.import_scanner import ImportScanner
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("import secret_external_module\n")
    (root / "linked.py").symlink_to(outside)
    scanner = ImportScanner()
    assert scanner.scan_detailed(root).imports == ()
    with pytest.raises(ProjectPathError):
        scanner.scan_files(root, [outside])
    RepositoryIndexer().refresh(root)
    assert RepositoryIndex(root).dependencies() == []


def test_release_license_and_http_identity_are_consistent() -> None:
    from depcheck import __version__
    from depcheck.compatibility.pypi_client import PyPIClient
    from depcheck.security.osv_client import OSVClient

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert metadata["license"] == "Apache-2.0"
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    for name in ("plugin.json", ".codex-plugin/plugin.json"):
        assert json.loads((ROOT / name).read_text())["license"] == metadata["license"]
    assert __version__ == metadata["version"]
    for client in (OSVClient, PyPIClient):
        assert client.DEFAULT_HEADERS["User-Agent"].startswith(
            f"depcheck/{__version__} "
        )


@pytest.mark.parametrize("relative_path", [False, True])
def test_index_and_companion_reject_git_from_target_repository(
    tmp_path: Path, monkeypatch, relative_path: bool
) -> None:
    from depcheck.indexing import RepositoryIndexer
    from depcheck.agent.gitnexus import GitNexusCompanion

    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", "." if relative_path else str(tmp_path))

    def reject_execution(*args, **kwargs):
        pytest.fail("executed an untrusted repository program")

    monkeypatch.setattr("subprocess.run", reject_execution)
    RepositoryIndexer().refresh(tmp_path)
    assert GitNexusCompanion().inspect(tmp_path).current_head is None


def test_index_still_reads_git_head_using_an_external_executable(
    tmp_path: Path, monkeypatch
) -> None:
    from types import SimpleNamespace
    from depcheck.indexing.indexer import _git_head
    from depcheck.path_policy import external_path_executable

    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path))
    resolved = external_path_executable(repository, "git")
    assert resolved == str(executable.resolve())

    def run(args, **kwargs):
        assert args == [resolved, "-C", str(repository), "rev-parse", "HEAD"]
        return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n")

    monkeypatch.setattr("subprocess.run", run)
    assert _git_head(repository) == "a" * 40


def test_optimized_wheel_smoke_rejects_source_checkout(tmp_path: Path) -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-O", str(ROOT / "scripts" / "smoke_installed.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "Expected an installed wheel" in result.stderr
    assert "exports passed" not in result.stdout
