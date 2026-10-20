"""Published output contracts and semantic checks for canonical scan exports."""

from __future__ import annotations

from collections import Counter
from importlib.resources import files
import json
from typing import Any, cast

from depcheck.evidence_input import objects

SCHEMA_NAMES = ("scan", "policy-input", "provenance")


def output_schema(name: str) -> dict[str, Any]:
    if name not in SCHEMA_NAMES:
        raise ValueError("Unknown output schema")
    return json.loads(files("depcheck").joinpath("schemas", name + ".json").read_text())


def validate_scan_export(snapshot: dict[str, Any]) -> None:
    """Reject inconsistent or partial scans before projecting policy/provenance.

    This checks producer invariants, not arbitrary JSON Schema documents. The
    published schemas provide structural validation for external consumers.
    """
    if snapshot.get("schema") != "depcheck.scan.v1":
        raise ValueError("Evidence export requires a canonical depcheck scan")
    for field in ("summary", "capabilities", "metadata", "inventory"):
        if not isinstance(snapshot.get(field), dict):
            raise ValueError(f"Scan {field} must be an object")
    findings = objects(snapshot.get("findings"), "Scan findings")
    diagnostics = objects(snapshot.get("diagnostics"), "Scan diagnostics")
    projects = objects(snapshot.get("projects"), "Scan projects")
    objects(snapshot.get("vulnerabilities"), "Scan vulnerabilities")
    complete = _scan_complete(snapshot["capabilities"], diagnostics)
    _validate_summary(snapshot, findings, diagnostics, complete=complete)
    _validate_inventory(snapshot["inventory"], _project_ids(projects))


def _scan_complete(states: dict[str, Any], diagnostics: list[dict[str, Any]]) -> bool:
    if not {"dependency_hygiene", "security"} <= states.keys() or any(
        not isinstance(value, dict)
        or value.get("state")
        not in {"complete", "incomplete", "skipped", "unsupported"}
        for value in states.values()
    ):
        raise ValueError("Scan capability states must be explicit")
    return all(value["state"] == "complete" for value in states.values()) and not any(
        item.get("severity") == "error" for item in diagnostics
    )


def _validate_summary(
    snapshot: dict[str, Any],
    findings: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    *,
    complete: bool,
) -> None:
    summary = snapshot["summary"]
    counts = Counter(item.get("code") for item in findings)
    status = "incomplete"
    if complete:
        status = "fail" if findings else "pass"
    if (
        summary.get("complete") is not complete
        or type(summary.get("risk_count")) is not int
        or summary["risk_count"] != len(findings)
        or type(summary.get("diagnostic_count")) is not int
        or summary["diagnostic_count"] != len(diagnostics)
        or summary.get("counts") != dict(counts)
        or not isinstance(summary.get("counts"), dict)
        or any(type(value) is not int for value in summary["counts"].values())
        or summary.get("status") != status
        or snapshot.get("truncated", False) is not False
    ):
        raise ValueError(
            "Scan summary disagrees with captured evidence or is truncated"
        )


def _project_ids(projects: list[dict[str, Any]]) -> set[str]:
    identities = [item.get("project_id") for item in projects]
    if any(not isinstance(value, str) or not value for value in identities) or len(
        set(identities)
    ) != len(identities):
        raise ValueError("Scan project identities must be unique and qualified")
    return cast(set[str], set(identities))


def _validate_inventory(inventory: dict[str, Any], project_ids: set[str]) -> None:
    for collection, count in (
        ("declarations", "declaration_count"),
        ("resolved_dependencies", "resolved_count"),
    ):
        records = objects(inventory.get(collection), "Scan " + collection)
        if type(inventory.get(count)) is not int or inventory[count] != len(records):
            raise ValueError("Scan inventory count disagrees with captured records")
        for record in records:
            identity = (
                record.get("identity")
                if collection == "resolved_dependencies"
                else record
            )
            if (
                not isinstance(identity, dict)
                or identity.get("project_id") not in project_ids
            ):
                raise ValueError("Scan record refers to an unknown project")
