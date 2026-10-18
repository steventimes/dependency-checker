import json
import copy
import os
import runpy
import sqlite3
import subprocess
import sys
import tomllib
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.bounded_io import read_bytes
from depcheck.config import ConfigurationError, load_project_config
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.python_manifest import PythonManifestCollector
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.indexing.models import INDEX_SCHEMA
from depcheck.indexing.store import IndexStore
from depcheck.model import CapabilityState
from depcheck.path_policy import ProjectPathError, require_within_project

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "lock_name", ["gradle.lockfile", "buildscript-gradle.lockfile"]
)
def test_gradle_lock_regular_file_requirement(tmp_path, lock_name):
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation "example:lib:1" }\n'
    )
    (tmp_path / lock_name).mkdir()
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(d.code == "lock.invalid" for d in result.diagnostics)
    assert not result.bundles[0].resolved
    assert (tmp_path / lock_name).is_dir()


def test_gradle_catalog_bounded_discovery_rejects_outside_aliases(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.versions.toml"
    outside.write_text('[libraries]\nsecret="outside:secret:1"\n')
    try:
        (root / "linked.versions.toml").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable on this platform")
    (root / "libs.versions.toml").write_text('[libraries]\nreal="example:real:1"\n')
    (root / "directory.versions.toml").mkdir()
    result = RepositoryScanner().scan(root, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert [d.package.name for d in bundle.declarations] == ["example:real"]
    assert bundle.project.manifests == (Path("libs.versions.toml"),)
    assert outside.read_text() == '[libraries]\nsecret="outside:secret:1"\n'


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_gradle_catalog_regular_file_requirement_rejects_fifo(tmp_path):
    os.mkfifo(tmp_path / "libs.versions.toml")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles and not result.bundles[0].declarations
    assert any(d.code == "manifest.gradle-catalog-invalid" for d in result.diagnostics)


@pytest.mark.parametrize("same_command", [False, True])
def test_agent_scorer_independent_calls_still_require_each_call_and_result(
    same_command,
):
    scorer = runpy.run_path(str(ROOT / "skills/check-dependencies/evals/score.py"))
    checker = scorer["_check_tool_calls"]
    expected = [
        {
            "name": "cli",
            "arguments_contains": {"command": cmd},
            "result_contains": {"evidence_complete": False, "project_id": project},
        }
        for cmd, project in (
            ("explain", "one"),
            ("explain" if same_command else "impact", "two"),
        )
    ]
    actual = [
        {
            "name": "cli",
            "arguments": {"command": cmd},
            "result": {"evidence_complete": False, "project_id": project},
        }
        for cmd, project in (
            ("explain" if same_command else "impact", "two"),
            ("explain", "one"),
        )
    ]
    assert checker(expected, actual, ordered=False) == []
    assert checker(expected, actual)
    assert checker(expected, actual[:1], ordered=False)
    assert checker([expected[0], expected[0]], [actual[1]], ordered=False)
    wrong = copy.deepcopy(actual)
    wrong[0]["result"]["evidence_complete"] = True
    assert checker(expected, wrong, ordered=False)


def test_agent_scorer_unordered_overlapping_expectations_keep_distinct_calls():
    scorer = runpy.run_path(str(ROOT / "skills/check-dependencies/evals/score.py"))
    checker = scorer["_check_tool_calls"]
    expected = [
        {
            "name": "cli",
            "arguments_contains": {"command": "explain"},
            "result_contains": {},
        },
        {
            "name": "cli",
            "arguments_contains": {"command": "explain"},
            "result_contains": {"project_id": "one"},
        },
    ]
    actual = [
        {
            "name": "cli",
            "arguments": {"command": "explain"},
            "result": {"project_id": project},
        }
        for project in ("one", "two")
    ]
    assert checker(expected, actual, ordered=False) == []
    assert checker(expected, actual[:1], ordered=False)
    assert checker(expected, [actual[1], actual[1]], ordered=False)


@pytest.mark.parametrize("relative", ["../parent", "..\\parent"])
def test_maven_parent_directory_paths_retain_local_plugin_and_dependency_evidence(
    tmp_path, relative
):
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "pom.xml").write_text(
        "<project><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>2</version></dependency></dependencies><build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>"
        + relative
        + "</relativePath></parent><artifactId>child</artifactId></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.root == Path("child"))
    assert {d.package.name for d in bundle.declarations} == {
        "example:library",
        "org.apache.maven.plugins:maven-compiler-plugin",
    }
    assert all(d.source.path == parent / "pom.xml" for d in bundle.declarations)
    assert not any(d.code == "manifest.parent-unavailable" for d in bundle.diagnostics)


def test_maven_directory_parent_pom_symlink_does_not_read_outside_root(
    tmp_path, monkeypatch
):
    from depcheck.ecosystems import java_maven

    audited = tmp_path / "repo"
    audited.mkdir()
    parent = audited / "parent"
    parent.mkdir()
    outside = tmp_path / "private.xml"
    outside.write_text("<project>private</project>", encoding="utf-8")
    try:
        (parent / "pom.xml").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    child = audited / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>../parent</relativePath></parent><artifactId>child</artifactId></project>",
        encoding="utf-8",
    )
    original = java_maven.read_text

    def read(path, *args, **kwargs):
        assert path.resolve() != outside
        return original(path, *args, **kwargs)

    monkeypatch.setattr(java_maven, "read_text", read)
    result = RepositoryScanner().scan(
        audited, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.parent-path-invalid" for d in result.diagnostics)


def test_maven_xml_node_budget_precedes_dom_allocation(tmp_path, monkeypatch):
    from depcheck.ecosystems import java_maven

    (tmp_path / "pom.xml").write_text(
        "<project>" + "<x/>" * 100001 + "</project>", encoding="utf-8"
    )
    monkeypatch.setattr(
        java_maven.ET,
        "fromstring",
        lambda *args, **kwargs: pytest.fail("DOM allocated before XML node budget"),
    )
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, enabled_ecosystems=("Maven",)
        ),
    )
    assert any(
        d.code == "manifest.invalid" and "element budget" in d.message
        for d in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete


def test_json_position_limits_and_replaced_subtrees_keep_reliable_fallback(tmp_path):
    from depcheck.source_locations import SourcePositions

    path = tmp_path / "manifest.json"
    ambiguous = '{"dependencies":["decoy","stale"],"dependencies":["actual"]}'
    positions = SourcePositions.json_keys(path, ambiguous, frozenset({"dependencies"}))
    assert positions.value("dependencies", 0).column == ambiguous.index('"actual"') + 1
    assert positions.value("dependencies", 1).line is None
    deep = '{"dependencies":' + "[" * 20 + '"nested"' + "]" * 20 + "}"
    positions = SourcePositions.json_keys(
        path, deep, frozenset({"dependencies"}), max_depth=100
    )
    assert positions.value("dependencies", *([0] * 20)).line is None
    large = json.dumps({"dependencies": ["package"] * 100_005})
    positions = SourcePositions.json_keys(path, large, frozenset({"dependencies"}))
    assert positions.value("dependencies", 0).line is None
    assert positions.value("dependencies", 100_004).line is None


def test_deep_json_reports_bounded_parser_failure(tmp_path):
    (tmp_path / "vcpkg.json").write_text(
        '{"dependencies":' + "[" * 2000 + '"fmt"' + "]" * 2000 + "}", encoding="utf-8"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize("alias_kind", ["directory", "file", "hardlink"])
def test_default_cache_alias_cannot_overwrite_project_data(tmp_path, alias_kind):
    import hashlib

    source = tmp_path / "data"
    source.mkdir()
    database = source / "index.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE valuable_data(value TEXT)")
    connection.execute("INSERT INTO valuable_data VALUES ('preserve this')")
    connection.commit()
    connection.close()
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    cache = tmp_path / ".depcheck"
    try:
        if alias_kind == "directory":
            cache.symlink_to(source, target_is_directory=True)
        else:
            cache.mkdir()
            if alias_kind == "file":
                (cache / "index.sqlite3").symlink_to(database)
            else:
                os.link(database, cache / "index.sqlite3")
    except OSError:
        pytest.skip("filesystem aliases unavailable")
    with pytest.raises(PermissionError):
        IndexStore(tmp_path)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == digest


def test_index_scan_refresh_mode_does_not_survive_full_incremental_refresh(tmp_path):

    (tmp_path / "requirements.txt").write_text("PyYAML==6.0.2\n")
    (tmp_path / "app.py").write_text("import yaml\n")
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path, ecosystems=("PyPI",))
    assert not RepositoryIndex(tmp_path).context()["stale"]
    indexer.refresh(tmp_path)
    assert not RepositoryIndex(tmp_path).context()["stale"]


@pytest.mark.parametrize(
    "filename",
    [
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "uv.lock",
        "setup.cfg",
        "setup.py",
        "Dockerfile",
    ],
)
def test_legacy_manifest_read_limit_is_qualified(tmp_path, filename):

    (tmp_path / filename).write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    result = PythonManifestCollector(tmp_path).collect()
    assert result.diagnostics and any(
        "exceeds" in d.message for d in result.diagnostics
    )
    assert not result.declarations


@pytest.mark.parametrize("filename", ["app.py", "app.ipynb"])
def test_python_source_read_limit_is_qualified(tmp_path, filename):

    (tmp_path / filename).write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    result = ImportScanner().scan_detailed(tmp_path)
    assert any("exceeds" in d.message for d in result.diagnostics)
    assert not result.imports


def test_repository_config_read_limit(tmp_path):
    (tmp_path / ".depcheck.toml").write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(ConfigurationError, match="exceeds"):
        load_project_config(tmp_path)


def test_same_handle_read_rejects_growth_and_nonregular_inputs(tmp_path, monkeypatch):
    from depcheck import bounded_io

    path = tmp_path / "data.txt"
    path.write_bytes(b"ok")
    original = bounded_io.os.fstat
    grown = False

    def grow_after_stat(fd):
        nonlocal grown
        result = original(fd)
        if not grown and result.st_size == 2:
            grown = True
            path.write_bytes(b"x" * 33)
        return result

    monkeypatch.setattr(bounded_io.os, "fstat", grow_after_stat)
    with pytest.raises(OSError, match="exceeds"):
        bounded_io.read_bytes(path, project_root=tmp_path, max_bytes=32)
    assert grown


def test_bounded_read_does_not_follow_replaced_file(tmp_path, monkeypatch):
    import io

    from depcheck.ecosystems.static import read_text

    if os.name == "nt":
        pytest.skip("POSIX open interception; Windows uses native handles")

    root = tmp_path / "repo"
    root.mkdir()
    path = root / "manifest.json"
    path.write_text("inside")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside bytes")
    original_io = io.open
    original_os = os.open
    replaced = False

    def replace_if_target(value):
        nonlocal replaced
        if not replaced and Path(value).name == path.name:
            path.unlink()
            path.symlink_to(outside)
            replaced = True

    def intercepted_io(value, *args, **kwargs):
        replace_if_target(value)
        return original_io(value, *args, **kwargs)

    def intercepted_os(value, *args, **kwargs):
        replace_if_target(value)
        return original_os(value, *args, **kwargs)

    monkeypatch.setattr(io, "open", intercepted_io)
    monkeypatch.setattr(os, "open", intercepted_os)
    with pytest.raises((OSError, ValueError)):
        read_text(path)
    assert replaced


def test_default_sqlite_uses_private_snapshot_not_replaced_repository_path(
    tmp_path, monkeypatch
):
    original = sqlite3.connect
    outside = tmp_path / "outside.sqlite3"
    root = tmp_path / "repo"
    root.mkdir()
    with original(outside) as connection:
        connection.execute("CREATE TABLE private_data(value TEXT)")
    before = outside.read_bytes()
    connected = []

    def swap_before_sqlite(database, *args, **kwargs):
        connected.append(str(database))
        cache = root / ".depcheck" / "index.sqlite3"
        cache.parent.mkdir(exist_ok=True)
        if not cache.exists():
            cache.symlink_to(outside)
        return original(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swap_before_sqlite)
    try:
        with IndexStore(root):
            pass
    except PermissionError:
        pass
    assert outside.read_bytes() == before
    assert all(str(root / ".depcheck") not in value for value in connected)


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("temporary_parent", ["repository", "sibling"])
def test_default_sqlite_ignores_attacker_controlled_temporary_directory(
    tmp_path, monkeypatch, read_only, temporary_parent
):
    import tempfile

    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "index.sqlite3"
    with closing(sqlite3.connect(victim)) as connection, connection:
        connection.execute("CREATE TABLE valuable_data(value TEXT)")
    before = victim.read_bytes()
    with IndexStore(root):
        pass
    cache = root / ".depcheck" / "index.sqlite3"
    original_cache = cache.read_bytes()
    staging = root if temporary_parent == "repository" else tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    monkeypatch.setenv("TMPDIR", str(staging))
    monkeypatch.setenv("SQLITE_TMPDIR", str(staging))
    monkeypatch.setattr(tempfile, "tempdir", str(staging))
    factory = tempfile.TemporaryDirectory

    class RedirectedDirectory:
        def __init__(self, temporary, parked):
            self.temporary = temporary
            self.parked = parked
            self.name = temporary.name

        def cleanup(self):
            stage = Path(self.name)
            stage.unlink()
            self.parked.rename(stage)
            self.temporary.cleanup()

    def redirect_stage(*args, **kwargs):
        temporary = factory(*args, **kwargs)
        stage = Path(temporary.name)
        parked = stage.with_name(stage.name + "-parked")
        stage.rename(parked)
        stage.symlink_to(outside, target_is_directory=True)
        return RedirectedDirectory(temporary, parked)

    monkeypatch.setattr(tempfile, "TemporaryDirectory", redirect_stage)
    with IndexStore(root, read_only=read_only) as store:
        assert store.metadata()["schema"] == INDEX_SCHEMA
        temporary_storage = store.connection.execute("PRAGMA temp_store").fetchone()[0]
        if not read_only:
            store.set_metadata({"control": "persisted"})
            store.connection.commit()
    assert victim.read_bytes() == before
    assert temporary_storage == 2
    assert list(staging.iterdir()) == ([root / ".depcheck"] if staging == root else [])
    if read_only:
        assert cache.read_bytes() == original_cache
    else:
        with IndexStore(root, read_only=True) as store:
            assert store.metadata()["control"] == "persisted"


def test_default_sqlite_close_rolls_back_pending_changes(tmp_path):
    with IndexStore(tmp_path) as store:
        store.set_metadata({"committed": "yes"})
        store.connection.commit()
        store.set_metadata({"pending": "must roll back"})
    with IndexStore(tmp_path, read_only=True) as store:
        assert store.metadata()["committed"] == "yes"
        assert "pending" not in store.metadata()


@pytest.mark.parametrize("read_only", [False, True])
def test_default_sqlite_empty_cache_preserves_schema_handling(tmp_path, read_only):
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    cache.parent.mkdir()
    cache.touch()
    if read_only:
        with pytest.raises(RuntimeError, match="index schema is incompatible"):
            IndexStore(tmp_path, read_only=True)
        assert cache.read_bytes() == b""
    else:
        with IndexStore(tmp_path) as store:
            assert store.metadata()["schema"] == INDEX_SCHEMA
        assert cache.read_bytes().startswith(b"SQLite format 3\x00")


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("contents", [b"not a database", "wal"])
def test_default_sqlite_invalid_snapshot_is_not_published(
    tmp_path, read_only, contents
):
    with IndexStore(tmp_path):
        pass
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    if contents == "wal":
        original = cache.read_bytes()
        contents = original[:18] + b"\x02\x02" + original[20:]
    cache.write_bytes(contents)
    with pytest.raises(sqlite3.DatabaseError):
        IndexStore(tmp_path, read_only=read_only)
    assert cache.read_bytes() == contents


@pytest.mark.parametrize("method", ["serialize", "deserialize"])
def test_default_sqlite_requires_snapshot_support_but_explicit_paths_do_not(
    tmp_path, monkeypatch, method
):
    class WithoutSnapshots(sqlite3.Connection):
        def __getattribute__(self, name):
            return None if name == method else super().__getattribute__(name)

    connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: connect(*args, factory=WithoutSnapshots, **kwargs),
    )
    with pytest.raises(RuntimeError, match="serialize/deserialize support"):
        IndexStore(tmp_path)
    assert not (tmp_path / ".depcheck" / "index.sqlite3").exists()
    external = tmp_path.parent / (tmp_path.name + "-explicit.sqlite3")
    try:
        with IndexStore(tmp_path, external) as store:
            store.set_metadata({"control": "explicit"})
            store.connection.commit()
        with IndexStore(tmp_path, external, read_only=True) as store:
            assert store.metadata()["control"] == "explicit"
    finally:
        external.unlink(missing_ok=True)


@pytest.mark.parametrize("options", [[("TEMP_STORE=0",)], []])
def test_default_sqlite_requires_verified_memory_temporary_storage(
    tmp_path, monkeypatch, options
):
    class DiskTemporaryStorage(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "PRAGMA compile_options":
                return options
            return super().execute(sql, *args, **kwargs)

    connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: connect(*args, factory=DiskTemporaryStorage, **kwargs),
    )
    with pytest.raises(RuntimeError, match="in-memory temporary storage"):
        IndexStore(tmp_path)
    assert not (tmp_path / ".depcheck" / "index.sqlite3").exists()


def test_default_sqlite_growth_respects_snapshot_limit(tmp_path, monkeypatch):
    from depcheck.indexing import store as store_module

    with IndexStore(tmp_path):
        pass
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    limit = cache.stat().st_size
    monkeypatch.setattr(store_module, "MAX_INDEX_BYTES", limit)
    with IndexStore(tmp_path) as store:
        with pytest.raises(sqlite3.OperationalError, match="full"):
            store.connection.execute("CREATE TABLE huge(value BLOB)")
            store.connection.execute("INSERT INTO huge VALUES (zeroblob(?))", (limit,))
    assert cache.stat().st_size <= limit
    with IndexStore(tmp_path, read_only=True) as store:
        assert store.metadata()["schema"] == INDEX_SCHEMA


def test_anchored_read_rejects_parent_replacement(tmp_path, monkeypatch):

    if os.name == "nt":
        pytest.skip("POSIX open interception; Windows uses native handles")

    root = tmp_path / "repo"
    root.mkdir()
    directory = root / "nested"
    directory.mkdir()
    (directory / "input.txt").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input.txt").write_text("outside")
    original = os.open
    changed = False

    def intercept(value, *args, **kwargs):
        nonlocal changed
        if not changed and Path(value).name == "nested":
            directory.rename(root / "old")
            directory.symlink_to(outside, target_is_directory=True)
            changed = True
        return original(value, *args, **kwargs)

    monkeypatch.setattr(os, "open", intercept)
    with pytest.raises(OSError):
        read_bytes(directory / "input.txt", project_root=root)
    assert changed


def test_regular_file_requirement_rejects_fifo_without_waiting(tmp_path):

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    pipe = tmp_path / "input"
    os.mkfifo(pipe)
    with pytest.raises(PermissionError, match="regular"):
        read_bytes(pipe, project_root=tmp_path)


def test_python_encoding_and_in_root_manifest_alias_still_work(tmp_path):

    (tmp_path / "app.py").write_bytes(
        b"# coding: latin-1\n# caf\xe9\nimport requests\n"
    )
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfimport requests\n")
    result = ImportScanner().scan_detailed(tmp_path)
    assert len(result.imports) == 2 and not result.diagnostics
    actual = tmp_path / "data"
    actual.mkdir()
    (actual / "deps.txt").write_text("requests==2.31.0\n")
    try:
        (tmp_path / "requirements.txt").symlink_to(actual / "deps.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    manifest = PythonManifestCollector(tmp_path).collect()
    assert any(d.name == "requests" for d in manifest.declarations)
    assert not manifest.diagnostics


def test_sqlite_rebuild_cannot_follow_repository_journal_links(tmp_path):
    root = tmp_path / "repo"
    cache = root / ".depcheck"
    cache.mkdir(parents=True)
    database = cache / "index.sqlite3"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO metadata VALUES ('schema', 'old')")
    outside = tmp_path / "private.bin"
    outside.write_bytes(b"keep this outside data")
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            (cache / (database.name + suffix)).symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
    with IndexStore(root) as store:
        assert store.rebuilt
    assert outside.read_bytes() == b"keep this outside data"


def test_preview_limits_preserve_crlf_and_block_oversized_targets(tmp_path):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater
    from depcheck.compatibility.safe_updater import RequirementsUpdater

    requirements = tmp_path / "requirements.txt"
    requirements.write_bytes(b"requests==1\r\n")
    plan = RequirementsUpdater(tmp_path).plan(requirements, {"requests": "2"})
    assert plan.updated_content == "requests==2\r\n"
    requirements.write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds"):
        RequirementsUpdater(tmp_path).plan(requirements, {"requests": "2"})
    project = tmp_path / "pyproject.toml"
    project.write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds"):
        PyprojectUpdater(tmp_path).plan(project, {"requests": "2"})


def test_explicit_symlink_repository_root_remains_supported(tmp_path):
    from depcheck.indexing.indexer import RepositoryIndexer

    root = tmp_path / "actual"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    (root / "app.py").write_text("import requests\n")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert load_project_config(alias) == load_project_config(root)
    result = RepositoryScanner().scan(alias, RepositoryScanOptions(security=False))
    assert result.root == root
    RepositoryIndexer().refresh(alias)
    assert (root / ".depcheck/index.sqlite3").is_file()


def test_bounded_read_preserves_execute_only_ancestor_access(tmp_path):

    if not hasattr(os, "O_PATH") and not hasattr(os, "O_SEARCH"):
        pytest.skip("platform has no search-only directory open")
    directory = tmp_path / "search-only"
    directory.mkdir()
    root = directory / "repo"
    root.mkdir()
    path = root / "data.txt"
    path.write_bytes(b"readable control")
    directory.chmod(0o111)
    try:
        assert path.read_bytes() == b"readable control"
        assert read_bytes(path, project_root=root) == b"readable control"
    finally:
        directory.chmod(0o700)


def test_windows_atomic_write_has_no_pathname_chmod(tmp_path, monkeypatch):
    from depcheck.bounded_io import atomic_write

    if os.name != "nt":
        pytest.skip("native Windows file attribute contract")
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"requests==1\r\n")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"preserve outside data")
    outside.chmod(0o444)
    original = os.chmod

    def swap_before_chmod(target, mode, *args, **kwargs):
        if Path(target).name.startswith(".depcheck-"):
            Path(target).unlink()
            os.link(outside, target)
        return original(target, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", swap_before_chmod)
    try:
        atomic_write(path, b"requests==2\r\n", project_root=tmp_path)
        assert path.read_bytes() == b"requests==2\r\n"
        assert not outside.stat().st_mode & 0o222
        assert outside.read_bytes() == b"preserve outside data"
    finally:
        original(outside, 0o600)


@pytest.mark.parametrize(
    "path,inside,relative",
    [
        (r"c:\repo\child\file.py", True, "child/file.py"),
        (r"C:\repo-other\file.py", False, None),
        (r"D:\repo\file.py", False, None),
    ],
)
def test_path_boundary_optimization_preserves_windows_drive_and_case_rules(
    monkeypatch, path, inside, relative
):
    import ntpath
    from pathlib import PureWindowsPath

    from depcheck.ecosystems import static
    from depcheck.indexing import fingerprints

    class ResolvedWindowsPath(PureWindowsPath):
        def resolve(self):
            return self

    win_os = SimpleNamespace(path=ntpath)
    monkeypatch.setattr(static, "os", win_os)
    monkeypatch.setattr(fingerprints, "os", win_os)
    monkeypatch.setattr(fingerprints, "Path", ResolvedWindowsPath)
    root = ResolvedWindowsPath(r"C:\Repo")
    candidate = ResolvedWindowsPath(path)
    assert static._inside(root, candidate) is inside
    if inside:
        assert fingerprints._relative(root, candidate) == relative
    else:
        with pytest.raises(ValueError):
            fingerprints._relative(root, candidate)


@pytest.mark.parametrize("suffix", ["nested/目录/file.py", "a b/c/file.js", "."])
def test_discovery_and_index_paths_keep_component_boundary(tmp_path, suffix):
    from depcheck.ecosystems.static import _inside
    from depcheck.indexing.indexer import _relative

    root = tmp_path / "repository"
    root.mkdir()
    path = root / suffix
    assert _inside(root, path)
    assert _relative(root, path) == Path(suffix).as_posix()
    outside = tmp_path / "repository-other" / "file.py"
    assert not _inside(root, outside)
    with pytest.raises(ValueError):
        _relative(root, outside)


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


def test_tool_usage_config_is_scoped_and_validated(tmp_path: Path) -> None:
    from dataclasses import asdict

    config_path = tmp_path / ".depcheck.toml"
    valid = (
        '[[tool-usage]]\necosystem="pYpI"\nproject-id="pypi:python:."\n'
        'package="My_Tool"\nscope="test"\nreason="Runs in CI"\n'
    )
    config_path.write_text(valid)
    config = load_project_config(tmp_path)
    assert json.loads(json.dumps(asdict(config)))["tool_usage"] == [
        {
            "ecosystem": "PyPI",
            "project_id": "pypi:python:.",
            "package": "my-tool",
            "scope": "test",
            "reason": "Runs in CI",
        }
    ]
    for invalid in (
        valid + 'typo="unexpected"\n',
        valid.replace('reason="Runs in CI"', 'reason=""'),
        valid.replace('reason="Runs in CI"\n', ""),
        valid.replace('scope="test"', 'scope="all"'),
        valid.replace('package="My_Tool"', 'package="bad package"'),
        valid.replace('ecosystem="pYpI"', 'ecosystem="unknown"'),
        valid.replace('project-id="pypi:python:."', 'project-id="*"'),
        valid + valid,
        'tool-usage="ruff"\n',
        'tool-usage=["ruff"]\n',
        '[tool-usage]\npackage="ruff"\n',
    ):
        config_path.write_text(invalid)
        with pytest.raises(ConfigurationError):
            load_project_config(tmp_path)
    config_path.unlink()
    assert load_project_config(tmp_path).tool_usage == ()
    (tmp_path / "pyproject.toml").write_text("[tool.depcheck]\ntool-usage=[]\n")
    with pytest.raises(ConfigurationError, match="unknown key"):
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

    assert INDEX_SCHEMA == "depcheck.index.v4"
    assert metadata["schema"] == INDEX_SCHEMA
    assert "legacy_marker" not in tables


def test_query_connections_are_read_only_and_do_not_rebuild_old_caches(
    tmp_path: Path,
) -> None:

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


def test_wheel_install_runner_rejects_missing_wheel(tmp_path: Path) -> None:

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_wheel_install.py"),
            "--wheel",
            str(tmp_path / "missing.whl"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "Expected an existing .whl file" in result.stderr


def test_skill_scorer_accepts_real_diagnostic_fields_and_rejects_wrong_claims() -> None:
    import copy

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


@pytest.mark.parametrize("field", ["security_safe", "release_ready"])
@pytest.mark.parametrize(
    "claim,accepted",
    [(None, True), (False, True), (True, False), (0, False), ("false", False)],
)
def test_skill_scorer_accepts_unknown_claims_without_accepting_safe_claims(
    field, claim, accepted
) -> None:
    from dataclasses import replace

    evals = ROOT / "skills" / "check-dependencies" / "evals"
    scorer = runpy.run_path(str(evals / "score.py"))
    case = next(
        c
        for c in scorer["load_cases"](evals / "cases.json")
        if c.case_id == "missing-lockfile"
    )
    case = replace(case, expected_claims={**case.expected_claims, field: [False, None]})
    trace = scorer["load_traces"](evals / "traces.example.json")[case.case_id]
    trace["claims"][field] = claim
    assert scorer["score_suite"]([case], {case.case_id: trace}).passed is accepted
    trace["claims"].pop(field)
    assert not scorer["score_suite"]([case], {case.case_id: trace}).passed


def test_skill_scorer_matches_cli_operation_before_checking_response() -> None:

    scorer = runpy.run_path(str(ROOT / "skills/check-dependencies/evals/score.py"))
    expected = [
        {
            "name": "cli",
            "arguments": {"command": "update"},
            "result_contains": {"read_only": True},
        }
    ]
    calls = [
        {"name": "cli", "arguments": {"command": "context"}, "result": {}},
        {
            "name": "cli",
            "arguments": {"command": "update"},
            "result": {"read_only": True},
        },
    ]
    assert not scorer["_check_tool_calls"](expected, calls)
    calls[1]["arguments"]["argv"] = ["update", "/repo", "urllib3==2.2.3"]
    assert scorer["_check_tool_calls"](expected, calls)
    expected[0]["arguments_contains"] = {"command": "update"}
    assert not scorer["_check_tool_calls"](expected, calls)
    calls[1]["result"]["read_only"] = False
    assert scorer["_check_tool_calls"](expected, calls)
    assert scorer["_check_tool_calls"](expected, calls[:1])


def test_analysis_change_reparses_cached_python_usage(tmp_path: Path) -> None:
    from depcheck.model import ImportEvidence, SourceLocation

    class OldScanner(ImportScanner):
        def _scan_file_detailed(self, path, scope):
            return [ImportEvidence("obsolete", SourceLocation(path, 1), scope)], []

    (tmp_path / "app.py").write_text("import requests\n")
    RepositoryIndexer(import_scanner=OldScanner()).refresh(tmp_path)
    with IndexStore(tmp_path) as store, store.transaction():
        store.set_metadata({"config_digest": "older-analysis-semantics"})

    RepositoryIndexer().refresh(tmp_path)

    assert [item["package"] for item in RepositoryIndex(tmp_path).dependencies()] == [
        "requests"
    ]


def test_new_exclusions_remove_previously_indexed_manifests(tmp_path: Path) -> None:

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


@pytest.mark.parametrize("filtered", [False, True])
def test_tool_usage_scan_and_index_agree_after_config_change(
    tmp_path: Path, filtered: bool
) -> None:

    (tmp_path / "requirements.txt").write_text("ruff==0.11.0\n")
    config = tmp_path / ".depcheck.toml"
    config.write_text(
        '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
        'package="ruff"\nscope="test"\nreason="Lint"\n'
    )
    indexer = RepositoryIndexer()
    selection = {"ecosystems": ("PyPI",)} if filtered else {}
    indexer.refresh(tmp_path, **selection)
    assert indexer.refresh(tmp_path, **selection).status == "current"
    service = DependencyAgentService(tmp_path)
    explanation = service.explain_dependency("ruff")
    assert explanation["usages"][0]["kind"] == "tool"
    assert explanation["usages"][0]["mapping_confidence"] == "configured"
    assert explanation["imports"] == []
    assert explanation["imported"] is False
    assert service.dependency_impact("ruff")["usage_count"] == 1
    assert RepositoryIndex(tmp_path).context()["counts"]["import_location_count"] == 0
    assert explanation["findings"] == []
    assert (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False))
        .findings
        == ()
    )
    config.unlink()
    assert RepositoryIndex(tmp_path).context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies()
    indexer.refresh(tmp_path, **selection)
    assert service.explain_dependency("ruff")["usages"] == []
    assert [f["code"] for f in service.explain_dependency("ruff")["findings"]] == [
        "dependency.unused"
    ]
    config.write_text('excluded-directories=["generated"]\n')
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "requirements.txt").write_text("other==1.0\n")
    indexer.refresh(tmp_path, **selection)
    assert [r["package"] for r in service.query_dependencies()["dependencies"]] == [
        "ruff"
    ]


def test_index_does_not_invent_a_python_project_from_cmake(tmp_path: Path) -> None:

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


@pytest.mark.parametrize("probe", ["index", "companion-head", "companion-status"])
def test_metadata_commands_finish_while_caller_stdin_remains_open(tmp_path, probe):

    command = tmp_path / "metadata.py"
    command.write_text(
        "import sys\nsys.stdin.read()\n"
        "print('1234567890abcdef1234567890abcdef12345678')\n"
    )
    driver = """
import subprocess
import sys
from pathlib import Path
from depcheck.indexing import indexer
from depcheck.agent import gitnexus

root, command, probe = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
run = subprocess.run
def metadata_run(args, **kwargs):
    return run([sys.executable, command], **kwargs)
subprocess.run = metadata_run
indexer.external_path_executable = lambda *args: sys.executable
try:
    if probe == 'index':
        result = indexer._git_head(root)
    elif probe == 'companion-head':
        result = gitnexus._git_head(root, 2, executable=sys.executable)
    else:
        result = gitnexus.GitNexusCompanion(timeout=2)._run(
            (sys.executable, command), root, 'status'
        ).stdout.strip()
except subprocess.TimeoutExpired:
    result = None
print(result)
"""
    with subprocess.Popen(
        [sys.executable, "-c", driver, str(tmp_path), str(command), probe],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        # Wait before communicate() so the caller's input stays open during the probe.
        process.wait(timeout=5)
        stdout, stderr = process.communicate(timeout=2)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "1234567890abcdef1234567890abcdef12345678"


def test_release_metadata_entrypoints_and_http_identity_are_consistent() -> None:
    from depcheck import __version__
    from depcheck.compatibility.pypi_client import PyPIClient
    from depcheck.security.osv_client import OSVClient

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert metadata["scripts"]["depcheck"] == "depcheck.command:cli"
    assert metadata["license"] == "Apache-2.0"
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    for name in ("plugin.json", ".codex-plugin/plugin.json"):
        plugin = json.loads((ROOT / name).read_text())
        assert plugin["license"] == metadata["license"]
        assert plugin["version"] == metadata["version"]
    assert __version__ == metadata["version"]
    for client in (OSVClient, PyPIClient):
        assert client.DEFAULT_HEADERS["User-Agent"].startswith(
            f"depcheck/{__version__} "
        )


@pytest.mark.parametrize("relative_path", [False, True])
def test_index_and_companion_reject_git_from_target_repository(
    tmp_path: Path, monkeypatch, relative_path: bool
) -> None:
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


@pytest.mark.parametrize("filtered", [False, True])
@pytest.mark.parametrize("mutation", ["package", "delete", "condition", "local-delete"])
def test_package_import_change_invalidates_full_and_filtered_indexes(
    tmp_path, filtered, mutation
):

    manifest = tmp_path / "package.json"
    document = {
        "dependencies": {"lodash": "1.0.0", "other": "1.0.0"},
        "imports": {"#alias": "./util.js" if mutation == "local-delete" else "lodash"},
    }
    manifest.write_text(json.dumps(document))
    (tmp_path / "app.js").write_text("import a from '#alias';\n")
    (tmp_path / "util.js").write_text("export default 1;\n")
    selection = {"ecosystems": ("npm",)} if filtered else {}
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path, **selection)
    if mutation == "package":
        document["imports"]["#alias"] = "other"
    if mutation == "delete":
        document.pop("imports")
    if mutation == "condition":
        document["imports"]["#alias"] = {"default": "lodash"}
    if mutation == "local-delete":
        (tmp_path / "util.js").unlink()
    else:
        manifest.write_text(json.dumps(document))
    assert RepositoryIndex(tmp_path).context()["stale"]
    service = DependencyAgentService(tmp_path)
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies()
    indexer.refresh(tmp_path, **selection)
    context = RepositoryIndex(tmp_path).context()
    assert not context["stale"]
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    assert (
        context["projects"][0]["capabilities"]["usage"]["complete"]
        == scan.capability("dependency_hygiene").complete
    )
    assert context["projects"][0]["capabilities"]["usage"]["complete"] == (
        mutation == "package"
    )
    assert not service.explain_dependency(
        "lodash", ecosystem="npm", project_id="npm:npm:."
    )["usages"]
    explanation = service.explain_dependency(
        "other", ecosystem="npm", project_id="npm:npm:."
    )
    assert bool(explanation["usages"]) == (mutation == "package")
    assert {
        (f["code"], f["package"]) for f in RepositoryIndex(tmp_path).findings()
    } == {(f.code, f.package.name) for f in scan.findings}


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_benchmark_mutation_preserves_rebuild_equivalence(tmp_path, ecosystem):
    from scripts.benchmark_monorepo import build_fixture, measure_mutation

    build_fixture(tmp_path, projects=1, files_per_project=2, seed=1729, depth=1)
    result = measure_mutation(tmp_path, ecosystem)
    assert result["rebuild_equivalent"] is True
    assert result["ecosystem"] == ecosystem
    assert result["status"] == "updated"
    assert result["wall_seconds"] >= 0
    assert result["changed_reference"] == "benchmarknewpackage"
    assert result["changed_usage_detected"] is True
    assert result["counters"]["npm_parse_reuse"] == "not available"


@pytest.mark.parametrize("filtered", [False, True])
def test_pnpm_lock_changes_invalidate_index_and_refresh_versions(tmp_path, filtered):
    import yaml

    (tmp_path / "package.json").write_text('{"dependencies":{"dep":"^1.0.0"}}')
    lock = tmp_path / "pnpm-lock.yaml"

    def write_lock(version):
        lock.write_text(
            yaml.safe_dump(
                {
                    "lockfileVersion": "9.0",
                    "importers": {
                        ".": {
                            "dependencies": {
                                "dep": {"specifier": "^1.0.0", "version": version}
                            }
                        }
                    },
                    "packages": {
                        f"dep@{version}": {"resolution": {"integrity": "sha512-test"}}
                    },
                    "snapshots": {f"dep@{version}": {}},
                }
            )
        )

    write_lock("1.0.0")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ("npm",)} if filtered else {}
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    write_lock("1.1.0")
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies("dep")
    assert service.index_repository(**selection)["status"] == "updated"
    assert service.query_dependencies("dep")["dependencies"][0][
        "resolved_versions"
    ] == ["1.1.0"]
    assert not service.repository_context()["stale"]


def test_unsupported_yarn_lock_addition_invalidates_full_index(tmp_path):

    (tmp_path / "package.json").write_text("{}")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    assert service.repository_context()["stale"]
    assert service.index_repository()["status"] == "updated"
    assert not service.repository_context()["stale"]
    project = service.repository_context()["projects"][0]
    assert not project["capabilities"]["resolution"]["complete"]


def test_filtered_queries_reuse_evidence_and_revalidate_ownership_changes(
    tmp_path, monkeypatch
):
    from depcheck.engine import RepositoryScanner

    for name in ("one", "two"):
        project = tmp_path / name
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"lib":"1.0.0"}}')
        (project / "app.js").write_text('import "lib";\n')
    RepositoryIndexer().refresh(tmp_path, project_ids=("npm:npm:one",))
    index = RepositoryIndex(tmp_path)
    before = index.index_path.read_bytes()
    original_scan = RepositoryScanner.scan
    calls = []

    def scan(self, *args, **kwargs):
        calls.append(1)
        return original_scan(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryScanner, "scan", scan)
    assert index.dependencies()[0]["usages"]
    assert not index.context()["stale"]
    assert calls == []
    (tmp_path / "two/app.js").write_text('import "other";\n')
    assert not index.context()["stale"]
    (tmp_path / "one/new.vue").write_text('<script>import "lib";</script>')
    assert index.context()["stale"]
    assert calls
    assert index.index_path.read_bytes() == before


def test_filtered_freshness_keeps_python_files_in_static_excluded_directories(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\nversion="1"\n')
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "app.py").write_text("import requests\n")
    RepositoryIndexer().refresh(tmp_path, ecosystems=("PyPI",))
    index = RepositoryIndex(tmp_path)
    assert not index.context()["stale"]
    (vendor / "new.py").write_text("import another\n")
    assert index.context()["stale"]


@pytest.mark.parametrize("filtered", [False, True])
def test_unsupported_frontend_component_changes_invalidate_index(tmp_path, filtered):

    (tmp_path / "package.json").write_text("{}")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ("npm",)} if filtered else {}
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    (tmp_path / "Component.astro").write_text("<div>example</div>\n")
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    project = service.repository_context()["projects"][0]
    assert project["capabilities"]["usage"]["complete"]


def test_compiled_requirements_lock_changes_invalidate_index(tmp_path):

    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["urllib3>=2"]\n')
    lock = tmp_path / "requirements-production.lock"
    lock.write_text("urllib3==2.7.0\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert service.explain_dependency("urllib3")["resolved_version"] == "2.7.0"
    lock.write_text("urllib3==2.8.0\n")
    assert service.repository_context()["stale"]
    service.index_repository()
    assert service.explain_dependency("urllib3")["resolved_version"] == "2.8.0"


def test_command_script_scan_removes_only_the_used_candidate(tmp_path):

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"vitest": "1.0.0", "eslint": "9.0.0"},
                "scripts": {"test": "vitest run"},
            }
        )
    )
    report = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [
        item.package.name
        for item in report.findings
        if item.code == "dependency.unused"
    ] == ["eslint"]


def _collect_command_bundle(root, ecosystem="npm", project_id=None):
    from depcheck.ecosystems import ProviderContext, create_default_registry
    from depcheck.ecosystems.commands import apply_command_usage

    registry = create_default_registry()
    projects = registry.discover(root)
    project = next(
        item
        for item in projects
        if item.ecosystem.lower() == ecosystem.lower()
        and (project_id is None or item.project_id == project_id)
    )
    pack = registry.get(ecosystem)
    bundle = pack.collector.collect(ProviderContext(root), project, pack)
    return apply_command_usage(bundle, root, projects)


def test_command_direct_collector_preserves_unused_and_does_not_execute(
    tmp_path, monkeypatch
):

    from depcheck.model import MappingConfidence

    (tmp_path / "package.json").write_text(
        '{\n"devDependencies":{"vitest":"1.0.0","eslint":"9.0.0"},\n'
        '"scripts":{"test":"vitest run"}\n}'
    )

    def no_execution(*args, **kwargs):
        raise AssertionError("static command evidence must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", no_execution)
    monkeypatch.setattr(subprocess, "Popen", no_execution)
    bundle = _collect_command_bundle(tmp_path)
    commands = [item for item in bundle.usages if item.kind == "command"]
    assert len(commands) == 1
    usage = commands[0]
    assert usage.mapped_package.name == "vitest"
    assert usage.mapping_confidence is MappingConfidence.EXACT
    assert usage.scope == "test"
    assert usage.source.path == tmp_path / "package.json"
    assert usage.source.line == 3
    assert "static" in usage.mapping_reason.lower()
    assert "execution" in usage.mapping_reason.lower()
    assert [
        item.package.name
        for item in EvidenceAnalyzer().analyze(bundle).findings
        if item.code == "dependency.unused"
    ] == ["eslint"]


@pytest.mark.parametrize(
    "command,package,scope",
    [
        ("pytest -q", "pytest", "test"),
        ("python -m ruff check .", "ruff", "test"),
        ("python3 -m mypy src", "mypy", "test"),
        ("uv run --frozen --extra test python -m pytest -q", "pytest", "test"),
        ("uv run --locked --offline --no-sync ruff check .", "ruff", "test"),
        ("sphinx-build docs out", "sphinx", "build"),
        ("mkdocs build", "mkdocs", "build"),
    ],
)
def test_command_python_workflow_literal_mapping(tmp_path, command, package, scope):
    (tmp_path / "requirements.txt").write_text(f"{package}==1.0\nother==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yml"
    workflow.write_text(f"jobs:\n  test:\n    steps:\n      - run: {command}\n")
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    usages = [item for item in bundle.usages if item.kind == "command"]
    assert len(usages) == 1
    assert usages[0].mapped_package.name == package
    assert usages[0].scope == scope
    assert usages[0].source.path == workflow
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


@pytest.mark.parametrize("runner", ["npm", "pnpm", "yarn"])
def test_command_script_references_and_installation_aliases(tmp_path, runner):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"checker": "npm:vitest@1.0.0"},
                "scripts": {
                    "test": f"{runner} run checks -- --run",
                    "checks": "vitest run",
                },
            }
        )
    )
    bundle = _collect_command_bundle(tmp_path)
    assert {item.mapped_package.name for item in bundle.usages} == {"vitest"}
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


def test_command_workflow_directory_precedence_and_nearest_npm_owner(tmp_path):
    for relative in (".", "web", "web/nested"):
        directory = tmp_path / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(
            '{"devDependencies":{"vitest":"1.0.0"}}'
        )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "defaults:\n  run:\n    working-directory: web\n"
        "jobs:\n  test:\n    defaults:\n      run:\n"
        "        working-directory: web/nested\n    steps:\n"
        "      - run: vitest run\n"
        "      - run: vitest run\n        working-directory: web\n"
        "  inherited:\n    steps:\n      - run: vitest run\n"
    )
    root = _collect_command_bundle(tmp_path, project_id="npm:npm:.")
    web = _collect_command_bundle(tmp_path, project_id="npm:npm:web")
    nested = _collect_command_bundle(tmp_path, project_id="npm:npm:web/nested")
    assert not root.usages
    assert len(web.usages) == 2
    assert len(nested.usages) == 1


@pytest.mark.parametrize(
    "command,code",
    [
        ("vitest && eslint .", "command.unsupported"),
        ("vitest $FLAGS", "command.unsupported"),
        ("vitest $(echo run)", "command.unsupported"),
        ("cd other\nvitest run", "command.unsupported"),
        ("uv run --directory other ruff check .", "command.unsupported"),
        ("npx vitest run", "command.unsupported"),
        ("custom-cli --check", "command.unmapped"),
        ("vitest 'unterminated", "command.unsupported"),
    ],
)
def test_command_unsupported_scripts_preserve_incomplete(tmp_path, command, code):

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"vitest": "1.0.0", "ruff": "1.0.0"},
                "scripts": {"test": command},
            }
        )
    )
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert any(item.code == code and item.source for item in bundle.diagnostics)
    assert (
        next(item for item in bundle.capabilities if item.name == "usage").state
        is CapabilityState.INCOMPLETE
    )
    assert not any(
        item.code in {"dependency.unused", "dependency.missing"}
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


def test_command_cycle_is_bounded_and_undeclared_commands_do_not_invent_missing(
    tmp_path,
):

    (tmp_path / "package.json").write_text(
        '{"scripts":{"a":"npm run b","b":"npm run a","lint":"eslint ."}}'
    )
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert any(item.code == "command.script-cycle" for item in bundle.diagnostics)
    assert not any(
        item.code == "dependency.missing"
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


@pytest.mark.parametrize(
    "document",
    [
        "jobs: [\n",
        "jobs:\n  test:\n    steps: &steps []\n  second:\n    steps: *steps\n",
        "jobs: {}\njobs: {}\n",
        "jobs:\n  test:\n    steps:\n      - run: [pytest]\n",
        "jobs:\n  test:\n    steps:\n      - run: pytest\n        working-directory: ../outside\n",
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: ${{ matrix.directory }}\n",
    ],
)
def test_command_workflow_invalid_data_is_incomplete_with_provenance(
    tmp_path, document
):

    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yaml"
    workflow.write_text(document)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(
        item.code.startswith("command.") and item.source.path == workflow
        for item in bundle.diagnostics
    )
    assert (
        next(item for item in bundle.capabilities if item.name == "usage").state
        is CapabilityState.INCOMPLETE
    )


def test_command_python_independent_components_do_not_share_usage(tmp_path):
    for name in ("first", "second"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1.0"\ndependencies=["pytest==1.0"]\n'
        )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: first\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert bundle.project.project_id == "pypi:python:first"
    assert [u.mapped_package.name for u in bundle.usages] == ["pytest"]
    second = _collect_command_bundle(tmp_path, "PyPI", "pypi:python:second")
    assert not second.usages


def test_command_directory_and_workflow_symlinks_are_not_followed(tmp_path):
    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    directory = tmp_path / "real"
    directory.mkdir()
    (tmp_path / "alias").symlink_to(directory, target_is_directory=True)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: alias\n"
    )
    target = tmp_path / "hidden.yml"
    target.write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n")
    (workflows / "link.yml").symlink_to(target)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(item.code == "command.invalid" for item in bundle.diagnostics)


def test_command_discovery_uses_only_workflows_and_honors_exclusions(tmp_path):
    from depcheck.ecosystems.commands import discover_command_files

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yml"
    workflow.write_text("jobs: {}\n")
    (tmp_path / "config.yml").write_text("jobs: {}\n")
    nested = workflows / "nested"
    nested.mkdir()
    (nested / "other.yaml").write_text("jobs: {}\n")
    assert discover_command_files(tmp_path) == (workflow,)
    assert not discover_command_files(tmp_path, {"excluded_directories": [".github"]})


def test_command_foreign_complex_step_does_not_hide_root_unused(tmp_path):

    (tmp_path / "package.json").write_text('{"devDependencies":{"vitest":"1.0.0"}}')
    web = tmp_path / "web"
    web.mkdir()
    (web / "package.json").write_text("{}")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: vitest && echo done\n"
        "        working-directory: web\n"
    )
    bundle = _collect_command_bundle(tmp_path, project_id="npm:npm:.")
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)
    assert [
        item.package.name
        for item in EvidenceAnalyzer().analyze(bundle).findings
        if item.code == "dependency.unused"
    ] == ["vitest"]


def test_command_build_backend_declaration_does_not_invent_missing(tmp_path):

    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires=["sphinx==1.0"]\n'
    )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "docs.yml").write_text(
        "jobs:\n  docs:\n    steps:\n      - run: sphinx-build docs out\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert not any(
        item.code == "dependency.missing"
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


def test_command_rejected_symlink_is_not_added_to_evidence_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = tmp_path / "hidden.yml"
    target.write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n")
    link = workflows / "link.yml"
    link.symlink_to(target)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert link not in bundle.evidence_files
    assert not bundle.usages
    assert any(item.code == "command.invalid" for item in bundle.diagnostics)


@pytest.mark.parametrize(
    "executable,package,scope",
    [
        ("vitest", "vitest", "test"),
        ("jest", "jest", "test"),
        ("eslint", "eslint", "test"),
        ("prettier", "prettier", "test"),
        ("tsc", "typescript", "test"),
        ("vite", "vite", "build"),
        ("webpack", "webpack", "build"),
        ("vitepress", "vitepress", "build"),
    ],
)
def test_command_npm_literal_mapping(tmp_path, executable, package, scope):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"devDependencies": {package: "1.0.0"}, "scripts": {"check": executable}}
        )
    )
    usage = _collect_command_bundle(tmp_path).usages[0]
    assert usage.mapped_package.name == package
    assert usage.scope == scope


def test_command_shell_install_and_local_script_are_not_package_usage(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"vitest":"1.0.0"},"scripts":'
        '{"install":"npm install","message":"echo hello","local":"node tools.js"}}'
    )
    (tmp_path / "tools.js").write_text("console.log('local');\n")
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


def test_command_python_nested_requirements_do_not_borrow_root_declaration(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="root"\nversion="1.0"\ndependencies=["pytest==1.0"]\n'
    )
    web = tmp_path / "component"
    web.mkdir()
    (web / "requirements.txt").write_text("other==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: component\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(item.code == "command.owner-ambiguous" for item in bundle.diagnostics)


@pytest.mark.parametrize(
    "mutation",
    [None, "retry", "conflicting-retry", "missing", "duplicate", "foreign", "count"],
)
def test_agent_scorer_checks_observed_pages_not_answer_claims(tmp_path, mutation):
    import runpy

    scorer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "skills/check-dependencies/evals/score.py"
        )
    )
    cases = scorer["load_cases"](
        Path(__file__).resolve().parents[1]
        / "skills/check-dependencies/evals/cases.agent.json"
    )
    case = next(c for c in cases if c.case_id == "pages-identity")
    calls = []
    for offset in (0, 20, 40, 60):
        entries = [
            {
                "project_id": "npm:npm:one",
                "ecosystem": "npm",
                "package": f"package-{i:03d}",
            }
            for i in range(offset, min(offset + 20, 65))
        ]
        calls.append(
            {
                "name": "cli",
                "arguments": {"command": "query"},
                "result": {
                    "query": "package-",
                    "project_id": "npm:npm:one",
                    "ecosystem": "npm",
                    "offset": offset,
                    "count": len(entries),
                    "dependencies": entries,
                    "next_offset": offset + 20 if offset < 60 else None,
                    "truncated": offset < 60,
                },
            }
        )
    if mutation == "missing":
        calls = calls[:1]
    elif mutation == "duplicate":
        calls[1] = copy.deepcopy(calls[0])
    elif mutation == "foreign":
        calls[0]["result"]["dependencies"][0]["project_id"] = "npm:npm:two"
    elif mutation == "count":
        calls[0]["result"]["count"] = 65
    elif mutation in {"retry", "conflicting-retry"}:
        repeated = copy.deepcopy(calls[0])
        if mutation == "conflicting-retry":
            repeated["result"]["dependencies"][0]["package"] = "unexpected"
        calls.append(repeated)
    calls.append(
        {
            "name": "cli",
            "arguments": {"command": "explain"},
            "result": {
                "project_id": "npm:npm:two",
                "ecosystem": "npm",
                "package": "shared",
            },
        }
    )
    trace = {
        "task": case.task,
        "initial_state": dict(case.initial_state),
        "fixtures": dict(case.fixtures),
        "skills_loaded": ["check-dependencies"],
        "tool_calls": calls,
        "events": ["skill.activate", "tool.cli"],
        "final_status": "pass",
        "final_answer": "65 packages; shared in npm:npm:two",
        "claims": {"security_safe": False, "release_ready": False, "limitations": []},
    }
    result = scorer["score_suite"]([case], {case.case_id: trace})
    assert result.passed is (mutation in {None, "retry"})


def test_agent_scorer_classifies_known_external_commands():
    import runpy

    scorer = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "skills/check-dependencies/evals/score.py"
        )
    )
    for command in (
        "npm install example",
        "pipenv lock",
        "poetry install",
        "pdm sync",
        "cmake -S . -B build",
        "cmake --build build",
        "cmake -DNAME=value -P fetch.cmake",
        "cmake -E env python build.py",
    ):
        assert "tool.package-manager" in scorer["command_events"](
            [{"type": "command_execution", "command": command, "exit_code": 0}]
        )
    assert "tool.network" in scorer["command_events"](
        [
            {
                "type": "command_execution",
                "command": "curl https://example.invalid",
                "exit_code": 1,
            }
        ]
    )
