"""Read-only comparisons of explicitly selected canonical scan reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depcheck.evidence_input import (
    parse_evidence_json as parse_evidence_json,
)
from depcheck.evidence_input import (
    read_evidence_json as read_evidence_json,
)
from depcheck.model import ANALYSIS_REVISION


def compare_snapshots(
    root: Path, before: str, after: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    left, left_digest = read_evidence_json(root, before)
    right, right_digest = read_evidence_json(root, after)
    for snapshot in (left, right):
        if snapshot.get("schema") != "depcheck.scan.v1":
            raise ValueError("Snapshot must use depcheck.scan.v1")
        if not isinstance(snapshot.get("metadata"), dict) or not isinstance(
            snapshot.get("capabilities"), dict
        ):
            raise ValueError("Snapshot metadata and capabilities must be objects")
    keys = [s["metadata"].get("snapshot") for s in (left, right)]
    comparable = (
        all(
            isinstance(k, dict)
            and k.get("analysis_revision") == ANALYSIS_REVISION
            and all(
                isinstance(k.get(f), str)
                and len(k[f]) == 64
                and all(c in "0123456789abcdef" for c in k[f])
                for f in ("repository_key", "selection_key")
            )
            for k in keys
        )
        and keys[0] == keys[1]
    )
    diagnostics: list[dict[str, Any]] = []
    changes: dict[str, list[dict[str, Any]]] = {}
    inventory_complete = comparable and all(
        _complete(s, "dependency_hygiene") for s in (left, right)
    )
    security_complete = inventory_complete and all(
        _complete(s, "security") for s in (left, right)
    )
    if not comparable:
        diagnostics.append(
            {
                "code": "snapshot.incompatible",
                "severity": "warning",
                "message": "Snapshot revision, repository identity or scan selection differs or is missing; no changes were inferred.",
            }
        )
    else:
        for category, extractor in (
            ("resolved", _resolved),
            ("declarations", _declarations),
            ("edges", _edges),
            ("vulnerabilities", _vulnerabilities),
        ):
            old, new = extractor(left), extractor(right)
            changes[category + "_added"] = [
                new[k] for k in sorted(new.keys() - old.keys())
            ]
            changes[category + "_removed"] = [
                old[k] for k in sorted(old.keys() - new.keys())
            ]
    if not inventory_complete or not security_complete:
        diagnostics.append(
            {
                "code": "snapshot.incomplete",
                "severity": "warning",
                "message": "Changes describe observed static evidence; incomplete or skipped stages cannot establish absence or remediation.",
            }
        )
    counts = {name: len(items) for name, items in changes.items()}
    # One offset traverses each named change collection. Counts retain totals.
    changes = {name: items[offset : offset + limit] for name, items in changes.items()}
    more = any(count > offset + limit for count in counts.values())
    return {
        "schema": "depcheck.agent.snapshot-comparison.v1",
        "read_only": True,
        "comparable": bool(comparable),
        "remediation_verified": False,
        "before": {"path": before, "sha256": left_digest},
        "after": {"path": after, "sha256": right_digest},
        "capabilities": {
            "inventory": {"state": "complete" if inventory_complete else "incomplete"},
            "security": {"state": "complete" if security_complete else "incomplete"},
        },
        "changes": changes,
        "counts": counts,
        "offset": offset,
        "truncated": more,
        "next_offset": offset + limit if more else None,
        "diagnostics": diagnostics,
        "coverage": {
            "before": left["metadata"].get("coverage"),
            "after": right["metadata"].get("coverage"),
        },
    }


def _complete(snapshot: dict[str, Any], name: str) -> bool:
    value = snapshot["capabilities"].get(name)
    return isinstance(value, dict) and value.get("state") == "complete"


def _list(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ValueError(f"Snapshot {label} must be a list of objects")
    return value


def _identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(
        isinstance(value.get(k), str) and value[k]
        for k in ("project_id", "ecosystem", "package")
    ):
        raise ValueError("Snapshot dependency identity is not qualified")
    if any(
        value.get(k) is not None and not isinstance(value[k], str)
        for k in ("version", "instance")
    ):
        raise ValueError("Snapshot version and instance must be strings")
    return {
        k: value[k]
        for k in ("project_id", "ecosystem", "package", "version", "instance")
        if value.get(k) is not None
    }


def _key(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _inventory(snapshot: dict[str, Any]) -> dict[str, Any]:
    value = snapshot.get("inventory")
    if not isinstance(value, dict):
        raise ValueError("Snapshot inventory must be an object")
    return value


def _resolved(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in _list(
        _inventory(snapshot).get("resolved_dependencies"), "resolved_dependencies"
    ):
        identity = _identity(item.get("identity"))
        result[_key(identity)] = identity
    return result


def _declarations(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    occurrences: dict[str, int] = {}
    for item in _list(_inventory(snapshot).get("declarations"), "declarations"):
        package = item.get("package")
        if not isinstance(package, dict):
            raise ValueError("Snapshot declaration package must be an object")
        identity = _identity(
            {
                "project_id": item.get("project_id"),
                "ecosystem": package.get("ecosystem"),
                "package": package.get("name"),
            }
        )
        location = item.get("location")
        if not isinstance(location, dict) or not isinstance(location.get("path"), str):
            raise ValueError("Snapshot declaration location must have a path")
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Snapshot declaration metadata must be an object")
        value = {
            **identity,
            "constraint": item.get("constraint"),
            "scope": item.get("scope"),
            "kind": item.get("kind"),
            "marker": item.get("marker"),
            "metadata": metadata,
            "location": location["path"],
        }
        key = _key(value)
        occurrences[key] = occurrences.get(key, 0) + 1
        result[key + f"#{occurrences[key]}"] = {
            **value,
            "occurrence": occurrences[key],
            "source": location,
        }
    return result


def _edges(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in _list(
        _inventory(snapshot).get("resolved_dependencies"), "resolved_dependencies"
    ):
        source = _identity(item.get("identity"))
        for link in _list(item.get("dependencies"), "dependency links"):
            target = _identity({**link, "project_id": source["project_id"]})
            value = {"source": source, "target": target}
            result[_key(value)] = value
    return result


def _vulnerabilities(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in _list(snapshot.get("vulnerabilities"), "vulnerabilities"):
        identity = _identity(item.get("identity"))
        for issue in _list(item.get("issues"), "vulnerability issues"):
            if not isinstance(issue.get("id"), str) or not issue["id"]:
                raise ValueError("Snapshot vulnerability must have an ID")
            value = {**identity, "advisory_id": issue["id"]}
            result[_key(value)] = value
    return result
