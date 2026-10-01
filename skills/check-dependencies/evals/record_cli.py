"""Record actual installed depcheck CLI calls for independent agent evaluations."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Example: --root /repo --trace calls.json -- explain requests. The wrapper inserts the repository root; do not repeat it after the operation.",
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--cli", default="depcheck")
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Operation and arguments without a repository path",
    )
    options = parser.parse_args()
    args = options.args[1:] if options.args[:1] == ["--"] else options.args
    allowed = {
        "context",
        "index",
        "scan",
        "query",
        "explain",
        "impact",
        "update",
        "doctor",
    }
    if not args or args[0] not in allowed:
        parser.error("Supply a depcheck operation after --")
    if args[0] == "scan" and "--offline" not in args:
        parser.error("Agent trial scans must use --offline")
    root = options.root.resolve()
    if not root.is_dir():
        parser.error("Trial root must be an existing directory")
    command = [options.cli, args[0], str(root), *args[1:]]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        payload = {"stdout": result.stdout, "stderr": result.stderr}
    if not isinstance(payload, dict):
        payload = {"output": payload}
    calls = json.loads(options.trace.read_text()) if options.trace.exists() else []
    calls.append(
        {
            "name": "cli",
            "arguments": {"command": args[0], "argv": command[1:]},
            "result": payload,
            "exit_code": result.returncode,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
    )
    options.trace.parent.mkdir(parents=True, exist_ok=True)
    options.trace.write_text(json.dumps(calls, indent=2) + "\n")
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
