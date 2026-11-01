"""Install one built wheel into a temporary base environment and smoke test it."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file() or wheel.suffix != ".whl":
        parser.error("Expected an existing .whl file")
    smoke = Path(__file__).resolve().with_name("smoke_installed.py")
    environment = os.environ.copy()
    for variable in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(variable, None)
    try:
        with tempfile.TemporaryDirectory(prefix="depcheck-wheel-install-") as directory:
            root = Path(directory)
            venv.EnvBuilder(with_pip=True).create(root)
            python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(
                [
                    str(python),
                    "-I",
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--report",
                    str(root / "installation-report.json"),
                    str(wheel),
                ],
                cwd=root,
                env=environment,
                check=True,
                timeout=180,
            )
            subprocess.run(
                [str(python), "-I", str(smoke)],
                cwd=root,
                env=environment,
                check=True,
                timeout=120,
            )
            result = subprocess.run(
                [
                    str(python),
                    "-I",
                    "-m",
                    "depcheck",
                    "evidence",
                    str(root),
                    "pip-install-report",
                    "installation-report.json",
                    "--limit",
                    "1000",
                ],
                cwd=root,
                env=environment,
                check=True,
                timeout=30,
                stdout=subprocess.PIPE,
                text=True,
            )
            evidence = json.loads(result.stdout)
            records = evidence["tables"]["distributions"]
            assert evidence["next_offset"] is None
            assert any(r["name"] == "depcheck" for r in records)
            assert all(
                r["public_identity_status"] == "unverified" and "purl" not in r
                for r in records
            )
            assert (
                evidence["metadata"]["current_project_installation"]
                == "not-established"
            )
            print(
                "Native pip installation report: supplied plan retained without installation or public-origin inference"
            )
    except (OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Wheel installation/smoke failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
