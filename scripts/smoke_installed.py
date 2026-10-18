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
        evidence = root / ".tmp"
        evidence.mkdir()
        (evidence / "before.json").write_text(json.dumps(scan))
        (evidence / "after.json").write_text(json.dumps(scan))
        comparison = json.loads(
            run("compare", ".", ".tmp/before.json", ".tmp/after.json")
        )
        check(
            comparison["comparable"] and comparison["read_only"],
            "Snapshot comparison failed",
        )
        check(
            not comparison["remediation_verified"]
            and comparison["capabilities"]["security"]["state"] == "incomplete",
            "Offline comparison overstated security verification",
        )
        bom = run("scan", ".", "--offline", "--format", "cyclonedx-json")
        (evidence / "bom.json").write_text(bom)
        imported = json.loads(run("sbom", ".", ".tmp/bom.json"))
        check(imported["total"] == 1, "SBOM inventory lost a component")
        check(
            imported["components"][0]["identity"]["package"] == "requests"
            and imported["components"][0]["identity"]["version"] == "2.31.0"
            and imported["components"][0]["identity_provenance"] == "sbom-asserted",
            "SBOM inventory lost identity or provenance",
        )
        check(
            imported["capabilities"]["usage"]["state"] == "unsupported"
            and imported["capabilities"]["security"]["state"] == "skipped",
            "SBOM inventory overstated usage or security evidence",
        )
        cmake_reply = evidence / "cmake"
        cmake_reply.mkdir()
        version = {"major": 2, "minor": 9}
        (cmake_reply / "index-selected.json").write_text(
            json.dumps(
                {
                    "objects": [
                        {
                            "kind": "codemodel",
                            "version": version,
                            "jsonFile": "model.json",
                        }
                    ]
                }
            )
        )
        (cmake_reply / "model.json").write_text(
            json.dumps(
                {
                    "kind": "codemodel",
                    "version": version,
                    "paths": {"source": "/recorded", "build": "/recorded/build"},
                    "configurations": [
                        {
                            "name": "",
                            "abstractTargets": [
                                {
                                    "id": "vendor::id",
                                    "name": "Vendor::lib",
                                    "jsonFile": "vendor.json",
                                }
                            ],
                        }
                    ],
                }
            )
        )
        (cmake_reply / "vendor.json").write_text(
            json.dumps(
                {
                    "id": "vendor::id",
                    "name": "Vendor::lib",
                    "type": "INTERFACE_LIBRARY",
                    "paths": {"source": ".", "build": "."},
                    "codemodelVersion": version,
                    "imported": True,
                    "abstract": True,
                }
            )
        )
        cmake = json.loads(run("cmake-model", ".", ".tmp/cmake/index-selected.json"))
        check(
            cmake["import_complete"]
            and cmake["targets"][0]["imported"]
            and cmake["targets"][0]["abstract"],
            "Base wheel lost the CMake model inspector",
        )
        check(
            not cmake["evidence_complete"]
            and cmake["coverage"]["security"] == "skipped"
            and not (root / ".depcheck").exists(),
            "CMake inspection claimed security evidence or created an index",
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
        original = b'[project]\ndependencies=["requests==2.31.0"]\n'
        (root / "pyproject.toml").write_bytes(original)
        explicit = json.loads(
            run(
                "update",
                ".",
                "requests==2.32.4",
                "--file",
                "pyproject.toml",
                "--group",
                "project",
            )
        )
        check(explicit["plans"][0]["groups"] == ["project"], "Pyproject group missing")
        check(
            explicit["plans"][0]["preview"].encode()
            == original.replace(b"2.31.0", b"2.32.4"),
            "Pyproject preview wrong",
        )
        check(
            (root / "pyproject.toml").read_bytes() == original,
            "Pyproject preview wrote manifest",
        )
        check(
            not json.loads(run("doctor", "."))["mcp"]["installed"],
            "Doctor incorrectly detected MCP",
        )
        for format_name in ("sarif", "cyclonedx-json"):
            check(
                json.loads(run("scan", ".", "--offline", "--format", format_name)),
                f"Empty {format_name} export",
            )
        (root / "pyproject.toml").unlink()
        (root / "requirements.txt").write_text("requests==2.31.0\nruff==0.11.0\n")
        (root / ".depcheck.toml").write_text(
            '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
            'package="ruff"\nscope="test"\nreason="CI lint"\n'
        )
        tools = json.loads(run("scan", ".", "--offline", "--format", "json"))
        check(not tools["findings"], "Configured tool reported as unused")
        run("index", ".")
        explanation = json.loads(run("explain", ".", "ruff"))
        check(explanation["usages"][0]["kind"] == "tool", "Tool usage missing")
        check(not explanation["imports"], "Tool use misreported as source import")

    print(
        "Installed wheel: base CLI, offline scan, index, query, update, exports, comparison, and SBOM passed"
    )


if __name__ == "__main__":
    main()
