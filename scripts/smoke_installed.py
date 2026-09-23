"""Run with a wheel-only environment's Python, outside the source import path."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory


def check(condition: object, message: object) -> None:
    if not condition:
        raise RuntimeError(str(message))


def main() -> None:
    package = find_spec("depcheck")
    if package is None or package.origin is None:
        raise RuntimeError("depcheck is not installed")
    checkout = Path(__file__).resolve().parents[1]
    check(
        not Path(package.origin).resolve().is_relative_to(checkout),
        f"Expected an installed wheel, imported {package.origin}",
    )
    check(find_spec("mcp") is None, "Run in a base-install environment without extras")

    with TemporaryDirectory(prefix="depcheck-wheel-") as directory:
        root = Path(directory)
        (root / "requirements.txt").write_text("requests==2.31.0\n")
        (root / "app.py").write_text("import requests\n")

        def run(*args: str, expected: int = 0) -> str:
            result = subprocess.run(
                [sys.executable, "-m", "depcheck", *args],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            check(result.returncode == expected, (args, result.stdout, result.stderr))
            return result.stdout

        check(run("--version").startswith("depcheck "), "Unexpected CLI version output")
        scan = json.loads(run("scan", ".", "--offline", "--format", "json"))
        check(scan["schema"] == "depcheck.scan.v1", "Unexpected scan schema")
        check(
            scan["capabilities"]["security"]["state"] == "skipped",
            "Offline security was not skipped",
        )
        run("index", ".")
        check(not json.loads(run("context", "."))["stale"], "Fresh index is stale")
        check(
            json.loads(run("query", ".", "requests"))["count"] == 1,
            "Dependency query lost requests",
        )
        check(
            json.loads(run("explain", ".", "requests"))["resolved_version"] == "2.31.0",
            "Unexpected resolved version",
        )
        check(
            json.loads(run("impact", ".", "requests"))["usage_count"] == 1,
            "Usage count is incorrect",
        )
        preview = json.loads(run("update", ".", "requests=2.32.4"))
        check(
            preview["plans"] and preview["diagnostics"] == [], "Update preview failed"
        )
        check(
            (root / "requirements.txt").read_text() == "requests==2.31.0\n",
            "Update preview changed a manifest",
        )
        run("update", ".", "missing=1.0", expected=2)
        check(
            not json.loads(run("doctor", "."))["mcp"]["installed"],
            "Doctor incorrectly detected MCP",
        )
        for format_name in ("sarif", "cyclonedx-json"):
            check(
                json.loads(run("scan", ".", "--offline", "--format", format_name)),
                f"Empty {format_name} export",
            )

    print(
        "Installed wheel: base CLI, offline scan, index, query, update, and exports passed"
    )


if __name__ == "__main__":
    main()
