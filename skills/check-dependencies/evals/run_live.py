"""Exercise real MCP contracts used by the skill; this does not grade agent prose.

Run with a depcheck[agent] environment from the repository root:
    python skills/check-dependencies/evals/run_live.py --output .tmp/depcheck-live.json
All fixtures are temporary, and every scan is offline.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def exercise(root: Path, calls: list[dict], passed: list[str]) -> None:
    fixtures = {
        "python": {
            "requirements.txt": "requests==2.31.0\n",
            "app.py": "import requests\n",
        },
        "preview": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\n'
            'dependencies=["requests==2.31.0"]\n'
        },
        "preview-ambiguous": {
            "pyproject.toml": '[project]\ndependencies=["requests==1"]\n[project.optional-dependencies]\ntest=["requests==1"]\n'
        },
        "preview-url": {
            "pyproject.toml": '[project]\ndependencies=["requests @ https://example.org/r.whl"]\n'
        },
        "npm": {
            "package.json": '{"dependencies":{"lodash":"^4.17.0"}}',
            "app.js": "import lodash from 'lodash';\n",
        },
        "pages": {
            "requirements.txt": "".join(f"package-{i:03d}==1.0\n" for i in range(65))
        },
        "ambiguous": {
            "one/package.json": '{"dependencies":{"shared":"1.0"}}',
            "two/package.json": '{"dependencies":{"shared":"2.0"}}',
        },
        "dynamic": {
            "requirements.txt": "requests==2.31.0\n",
            "app.py": "import importlib\nimportlib.import_module(name)\n",
        },
        "alias": {
            "package.json": '{"dependencies":{"lodash":"4.17.21"}}',
            "app.js": "import lodash from '#lodash';\n",
        },
        "alias-known": {
            "package.json": '{"dependencies":{"lodash":"4.17.21","other":"1.0.0"},"imports":{"#alias":"lodash/fp"}}',
            "app.js": "import a from '#alias';\n",
        },
        "tool": {
            "requirements.txt": "ruff==0.11.0\n",
            ".depcheck.toml": '[[tool-usage]]\necosystem="PyPI"\n'
            'project-id="pypi:python:."\npackage="ruff"\nscope="test"\nreason="CI lint"\n',
        },
    }
    for folder, files in fixtures.items():
        for name, content in files.items():
            path = root / folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "depcheck.agent.mcp_server", "--allow-root", str(root)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            definitions = await session.list_tools()
            for tool in definitions.tools:
                check(
                    tool.annotations is not None, f"Missing annotations for {tool.name}"
                )
                check(
                    tool.annotations.openWorldHint is False, "Unexpected network tool"
                )
                check(
                    tool.annotations.readOnlyHint
                    == (tool.name not in {"index_repository", "scan_repository"}),
                    f"Incorrect side effects for {tool.name}",
                )

            async def call(name: str, fixture: str, **arguments) -> dict:
                arguments = {"project_root": str(root / fixture), **arguments}
                result = await session.call_tool(name, arguments)
                check(not result.isError, f"{name}: {result.content}")
                payload = json.loads(result.content[0].text)
                calls.append({"name": name, "arguments": arguments, "result": payload})
                return payload

            scan = await call("scan_repository", "python")
            check(
                not scan["summary"]["complete"], "Offline summary must stay incomplete"
            )
            check(
                scan["capabilities"]["security"]["state"] == "skipped", "Security ran"
            )
            check(
                scan["capabilities"]["dependency_hygiene"]["state"] == "complete",
                "Hygiene incomplete",
            )
            check(
                scan["context"]["complete"] and not scan["context"]["stale"],
                "Stale index",
            )
            passed.append("offline-freshness-vs-security")

            await call("index_repository", "npm")
            cache = root / "npm" / ".depcheck" / "index.sqlite3"
            cache_before = (cache.read_bytes(), cache.stat().st_mtime_ns)
            npm = await call("explain_dependency", "npm", package="lodash")
            impact = await call("dependency_impact", "npm", package="lodash")
            check(
                npm["resolved_versions"] == [], "Range treated as an exact resolution"
            )
            check(
                impact["usage_count"] == 1 and impact["files"] == ["app.js"],
                "Lost usage",
            )
            passed.append("default-npm-index-without-lock")
            check(
                (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before,
                "Read-only MCP queries changed the index",
            )
            passed.append("read-only-tool-contracts")

            await call("index_repository", "pages")
            names = []
            offset = 0
            while True:
                page = await call(
                    "query_dependencies", "pages", limit=20, offset=offset
                )
                names.extend(item["package"] for item in page["dependencies"])
                if not page["truncated"]:
                    check(page["next_offset"] is None, "Unexpected next page")
                    break
                check(page["next_offset"] > offset, "Pagination did not advance")
                offset = page["next_offset"]
            check(
                names == [f"package-{i:03d}" for i in range(65)],
                "Missing/duplicate packages",
            )
            passed.append("complete-paginated-inventory")

            await call("index_repository", "ambiguous")
            ambiguous = await call("explain_dependency", "ambiguous", package="shared")
            check(
                ambiguous["error"]["code"] == "dependency.ambiguous", "Lost ambiguity"
            )
            chosen = next(
                item
                for item in ambiguous["error"]["choices"]
                if item["project_id"] == "npm:npm:two"
            )
            qualified = await call(
                "explain_dependency",
                "ambiguous",
                **{key: chosen[key] for key in ("project_id", "ecosystem", "package")},
            )
            check(qualified["project_id"] == "npm:npm:two", "Wrong project selected")
            passed.append("qualified-ambiguous-identity")

            preview = await call(
                "plan_dependency_updates", "preview", updates={"requests": "2.32.4"}
            )
            check(preview["plans"] == [], "Unsupported preview produced a plan")
            check(
                preview["diagnostics"][0]["code"] == "update.unsupported-target",
                "Missing unsupported-target diagnostic",
            )
            check(
                (root / "preview" / "pyproject.toml").read_text()
                == fixtures["preview"]["pyproject.toml"],
                "Preview changed the manifest",
            )
            passed.append("unsupported-preview-is-not-noop")
            explicit = await call(
                "plan_dependency_updates",
                "preview",
                updates={"requests": "2.32.4"},
                target_file="pyproject.toml",
                group="project",
            )
            check(explicit["plans"][0]["groups"] == ["project"], "Wrong explicit group")
            check(
                "2.32.4" in explicit["plans"][0]["preview"], "Missing pyproject preview"
            )
            passed.append("explicit-pyproject-preview")
            explicit_noop = await call(
                "plan_dependency_updates",
                "preview",
                updates={"requests": "2.31.0"},
                target_file="pyproject.toml",
                group="project",
            )
            check(
                not explicit_noop["plans"] and not explicit_noop["diagnostics"],
                "Pyproject noop failed",
            )
            passed.append("explicit-pyproject-noop")
            for folder, code in [
                ("preview-ambiguous", "update.ambiguous-target"),
                ("preview-url", "update.unsupported-target"),
            ]:
                rejected = await call(
                    "plan_dependency_updates",
                    folder,
                    updates={"requests": "2"},
                    target_file="pyproject.toml",
                )
                check(
                    not rejected["plans"]
                    and rejected["diagnostics"][0]["code"] == code,
                    "Incorrect pyproject rejection",
                )
                passed.append(folder)
            for folder in ("preview", "preview-ambiguous", "preview-url"):
                check(
                    (root / folder / "pyproject.toml").read_bytes()
                    == fixtures[folder]["pyproject.toml"].encode(),
                    "Pyproject preview wrote target",
                )

            noop = await call(
                "plan_dependency_updates", "python", updates={"requests": "2.31.0"}
            )
            check(
                not noop["plans"] and not noop["diagnostics"],
                "No-op treated as failure",
            )
            passed.append("supported-preview-noop")

            await call("scan_repository", "tool")
            tool = await call("explain_dependency", "tool", package="ruff")
            check(not tool["findings"], "Tool use reported as unused")
            check(
                not tool["imports"] and not tool["imported"],
                "Tool use became an import",
            )
            check(
                tool["usages"][0]["kind"] == "tool"
                and tool["usages"][0]["mapping_confidence"] == "configured"
                and tool["usages"][0]["mapping_reason"] == "CI lint",
                "Tool explanation lost configured provenance",
            )
            passed.append("configured-tool-usage")

            (root / "python" / "requirements.txt").write_text("requests==2.32.4\n")
            stale = await call("repository_context", "python")
            check(stale["stale"], "Manifest edit did not stale the index")
            refreshed = await call("scan_repository", "python")
            check(not refreshed["context"]["stale"], "Scan did not refresh the index")
            passed.append("refresh-after-manifest-change")

            await call("scan_repository", "alias-known")
            known = await call(
                "explain_dependency",
                "alias-known",
                package="lodash",
                ecosystem="npm",
                project_id="npm:npm:.",
            )
            check(
                known["usages"][0]["mapping_confidence"] == "exact",
                "Known alias not exact",
            )
            original_alias = (root / "alias-known" / "package.json").read_text()
            (root / "alias-known" / "package.json").write_text(
                original_alias.replace("lodash/fp", "other")
            )
            check(
                (await call("repository_context", "alias-known"))["stale"],
                "Alias change did not invalidate index",
            )
            await call("index_repository", "alias-known")
            changed_alias = await call(
                "explain_dependency",
                "alias-known",
                package="other",
                ecosystem="npm",
                project_id="npm:npm:.",
            )
            check(
                changed_alias["usages"][0]["reference"] == "#alias",
                "Alias refresh lost usage",
            )
            passed.append("known-alias-and-refresh")
            for fixture in ("dynamic", "alias"):
                partial = await call("scan_repository", fixture)
                check(
                    partial["capabilities"]["dependency_hygiene"]["state"]
                    == "incomplete",
                    f"{fixture} lost its coverage limitation",
                )
                check(
                    not any(
                        f["code"] == "dependency.unused" for f in partial["findings"]
                    ),
                    f"{fixture} asserted an unsupported unused dependency",
                )
                check(
                    not partial["context"]["stale"],
                    "Fresh partial evidence marked stale",
                )
                passed.append(f"{fixture}-usage-incomplete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="Write actual tool calls and results"
    )
    args = parser.parse_args()
    calls: list[dict] = []
    passed: list[str] = []
    result = {
        "kind": "live-mcp-contracts",
        "passed_scenarios": passed,
        "tool_calls": calls,
    }
    try:
        with TemporaryDirectory(prefix="depcheck-skill-") as directory:

            async def bounded():
                async with asyncio.timeout(60):
                    await exercise(Path(directory), calls, passed)

            asyncio.run(bounded())
    finally:
        if args.output:
            args.output.write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
    print(json.dumps({"passed_scenarios": passed, "tool_call_count": len(calls)}))


if __name__ == "__main__":
    main()
