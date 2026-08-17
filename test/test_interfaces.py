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
