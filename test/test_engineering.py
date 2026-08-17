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
