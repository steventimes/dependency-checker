import json
import asyncio
from pathlib import Path
import pytest


from depcheck.agent import DependencyAgentService
from depcheck.agent.mcp_server import create_server
from depcheck.command import main


def make_python_project(root: Path) -> None:
    (root / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (root / "app.py").write_text("import requests\n", encoding="utf-8")


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
    tool_names = {tool.name for tool in asyncio.run(server.list_tools())}

    assert tool_names == {
        "dependency_impact",
        "explain_dependency",
        "index_repository",
        "plan_dependency_updates",
        "query_dependencies",
        "repository_context",
        "scan_repository",
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
    import sys
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    make_python_project(tmp_path)

    async def exercise():
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "depcheck.agent.mcp_server", "--allow-root", str(tmp_path)],
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
    from depcheck.agent import mcp_server

    monkeypatch.setattr(mcp_server, "FastMCP", None)
    with pytest.raises(SystemExit) as exit_info:
        mcp_server.cli([])
    assert exit_info.value.code == 2
    error = capsys.readouterr().err
    assert "depcheck[agent]" in error
    assert "Traceback" not in error
