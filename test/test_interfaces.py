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
    (tmp_path / ".depcheck.toml").write_text('fail-on = ["missing"]\n')
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
