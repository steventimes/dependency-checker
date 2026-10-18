"""Unsigned provenance and policy inputs over explicitly selected evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from depcheck._version import __version__
from depcheck.bounded_io import read_bytes
from depcheck.model import ANALYSIS_REVISION
from depcheck.path_policy import require_within_project
from depcheck.snapshots import read_evidence_json


def export_evidence(
    root: Path,
    snapshot_file: str,
    *,
    kind: str,
    input_files: tuple[str, ...] = (),
    configuration_file: str | None = None,
) -> dict[str, Any]:
    snapshot, digest = read_evidence_json(root, snapshot_file)
    if snapshot.get("schema") != "depcheck.scan.v1":
        raise ValueError("Evidence export requires a canonical depcheck scan")
    if len(input_files) > 512 or len(set(input_files)) != len(input_files):
        raise ValueError(
            "Explicit input paths must be unique and within the 512-file budget"
        )
    inputs = []
    work = 0
    configuration = None
    requested = [*input_files, *([configuration_file] if configuration_file else [])]
    for value in requested:
        path = Path(value)
        if path.is_absolute():
            raise ValueError("Evidence input paths must be repository-relative")
        candidate = root / path
        require_within_project(
            root, candidate, operation="hash explicit provenance input"
        )
        raw = read_bytes(candidate)
        work += len(raw)
        if work > 16 * 1024 * 1024:
            raise ValueError("Provenance input byte budget exhausted")
        record = {
            "name": path.as_posix(),
            "digest": {"sha256": hashlib.sha256(raw).hexdigest()},
        }
        if value == configuration_file:
            configuration = record
        else:
            inputs.append(record)
    common = {
        "exporter": {
            "name": "depcheck",
            "version": __version__,
            "analysis_revision": ANALYSIS_REVISION,
        },
        "snapshot_tool": snapshot.get("tool"),
        "snapshot_path": snapshot_file,
        "snapshot_sha256": digest,
        "configuration": configuration,
        "inputs": inputs,
        "input_completeness": "explicitly-selected-only",
        "source_authenticity": "unverified",
        "signature_status": "unsigned",
        "input_freshness": "not-compared-to-snapshot-capture",
        "invocation_exit_status": "not-captured",
    }
    if kind == "provenance":
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": snapshot_file, "digest": {"sha256": digest}}],
            "predicateType": "https://github.com/steventimes/dependency-checker/evidence/v1",
            "predicate": common,
        }
    if kind == "policy":
        return {
            "schema": "depcheck.policy-input.v1",
            "read_only": True,
            "provenance": common,
            "summary": snapshot.get("summary"),
            "capabilities": snapshot.get("capabilities"),
            "findings": snapshot.get("findings"),
            "vulnerabilities": snapshot.get("vulnerabilities"),
            "coverage": snapshot.get("metadata", {}).get("coverage"),
            "diagnostics": snapshot.get("diagnostics"),
            "evaluation_status": "not-evaluated",
            "external_evaluator_invoked": False,
        }
    raise ValueError("Export kind must be provenance or policy")
