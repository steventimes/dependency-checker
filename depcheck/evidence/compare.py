"""Read-only comparisons of explicitly selected canonical scan reports."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from depcheck.evidence.input import parse_evidence_json as parse_evidence_json
from depcheck.evidence.input import read_evidence_json as read_evidence_json
from depcheck.model import ANALYSIS_REVISION
from depcheck.security.offline import inventory_identities


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
        changes["declarations_changed"] = (
            _changed_declarations(left, right)
            if inventory_complete
            and all(
                _declaration_identities_complete(snapshot) for snapshot in (left, right)
            )
            else []
        )
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
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Snapshot resolution metadata must be an object")
        value = {**identity, **({"metadata": metadata} if metadata else {})}
        result[_key(value)] = value
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


def _changed_declarations(
    before: dict[str, Any], after: dict[str, Any]
) -> list[dict[str, Any]]:
    def raw_constraint(declaration: dict[str, Any]) -> Any:
        value = declaration["constraint"]
        return value.get("raw") if isinstance(value, dict) else value

    def grouped(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for declaration in _declarations(snapshot).values():
            if not all(
                isinstance(declaration[field], str) and declaration[field].strip()
                for field in (
                    "project_id",
                    "ecosystem",
                    "package",
                    "location",
                    "kind",
                    "scope",
                )
            ):
                continue
            ecosystem = declaration["ecosystem"].lower()
            package = declaration["package"]
            metadata = declaration["metadata"]
            if ecosystem == "pypi":
                package = str(canonicalize_name(package))
                origin = metadata.get("origin")
                if isinstance(origin, dict) and origin.get("kind") == "registry":
                    registry_location = origin.get("location")
                    registry_assertion = origin.get("assertion")
                    has_registry_identity = (
                        isinstance(registry_location, str)
                        and bool(registry_location.strip())
                    ) or (
                        isinstance(registry_assertion, dict)
                        and isinstance(registry_assertion.get("registry"), str)
                        and bool(registry_assertion["registry"].strip())
                    )
                    raw_requirement = metadata.get("raw_requirement")
                    extras = metadata.get("extras")
                    group = metadata.get("group")
                    constraint = declaration["constraint"]
                    constraint_raw = raw_constraint(declaration)
                    valid_constraint = (
                        isinstance(constraint, dict)
                        and constraint.get("scheme") == "pep440"
                        and isinstance(constraint_raw, str)
                        and (
                            constraint.get("normalized") == constraint_raw
                            if constraint_raw.strip()
                            else constraint_raw == ""
                            and constraint.get("normalized") is None
                        )
                    )
                    if (
                        not isinstance(raw_requirement, str)
                        or not raw_requirement.strip()
                        or not isinstance(extras, list)
                        or not all(isinstance(extra, str) and extra for extra in extras)
                        or not isinstance(group, str)
                        or not group.strip()
                        or not isinstance(origin.get("public"), bool)
                        or not has_registry_identity
                        or not valid_constraint
                    ):
                        continue
                    # Keep valid unbounded declarations in the identity group;
                    # the output step below requires a nonempty constraint.
                    try:
                        requirement = Requirement(raw_requirement)
                    except InvalidRequirement:
                        continue
                    requirement_marker = (
                        str(requirement.marker)
                        if requirement.marker is not None
                        else None
                    )
                    if (
                        requirement.url is not None
                        or str(canonicalize_name(requirement.name)) != package
                        or sorted(requirement.extras) != sorted(extras)
                        or requirement_marker != declaration["marker"]
                        or str(requirement.specifier) != constraint_raw
                    ):
                        continue
                    metadata = {
                        key: value
                        for key, value in metadata.items()
                        if key != "raw_requirement"
                    }
            identity = {
                "project_id": declaration["project_id"],
                "ecosystem": ecosystem,
                "package": package,
                "path": declaration["location"],
                "kind": declaration["kind"],
                "scope": declaration["scope"],
                "marker": declaration["marker"],
                "metadata": metadata,
            }
            groups.setdefault(_key(identity), []).append(declaration)
        return groups

    old, new = grouped(before), grouped(after)
    changes = []

    for key in sorted(old.keys() & new.keys()):
        if len(old[key]) != 1 or len(new[key]) != 1:
            continue
        previous, current = old[key][0], new[key][0]
        before_constraint = raw_constraint(previous)
        after_constraint = raw_constraint(current)
        if (
            not isinstance(before_constraint, str)
            or not before_constraint.strip()
            or not isinstance(after_constraint, str)
            or not after_constraint.strip()
        ):
            continue
        if before_constraint == after_constraint:
            continue
        changes.append(
            {
                "identity": {
                    "project_id": previous["project_id"],
                    "ecosystem": previous["ecosystem"].lower(),
                    "package": previous["package"],
                },
                "before_constraint": before_constraint,
                "after_constraint": after_constraint,
                "before_source": previous["source"],
                "after_source": current["source"],
                "interpretation": "declared-constraint-change; resolved-version-and-remediation-not-established",
            }
        )
    return changes


def _declaration_identities_complete(snapshot: dict[str, Any]) -> bool:
    declarations = _inventory(snapshot).get("declarations")
    if not isinstance(declarations, list):
        return False
    for declaration in declarations:
        if not isinstance(declaration, dict):
            return False
        package = declaration.get("package")
        location = declaration.get("location")
        if (
            not all(
                isinstance(declaration.get(field), str) and declaration[field].strip()
                for field in ("project_id", "scope", "kind")
            )
            or not isinstance(package, dict)
            or not isinstance(package.get("name"), str)
            or not package["name"].strip()
            or not isinstance(package.get("ecosystem"), str)
            or not package["ecosystem"].strip()
            or "marker" not in declaration
            or declaration["marker"] is not None
            and not isinstance(declaration["marker"], str)
            or not isinstance(declaration.get("metadata"), dict)
            or not isinstance(location, dict)
            or not isinstance(location.get("path"), str)
            or not location["path"].strip()
        ):
            return False
    return True


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


def compare_inventories(
    root: Path, before_file: str, after_file: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Invalid inventory comparison pagination")
    before, before_digest, before_diagnostics = inventory_identities(root, before_file)
    after, after_digest, after_diagnostics = inventory_identities(root, after_file)

    def coordinates(
        records: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> tuple[Counter[str], list[dict[str, Any]]]:
        counts: Counter[str] = Counter()
        unknown = []
        for identity, metadata in records:
            ecosystem, package = identity.get("ecosystem"), identity.get("package")
            if (
                not isinstance(ecosystem, str)
                or not isinstance(package, str)
                or ecosystem == "unknown"
            ):
                unknown.append(identity)
                continue
            canonical = (
                str(canonicalize_name(package))
                if ecosystem.lower() == "pypi"
                else package
            )
            coordinate = {
                "ecosystem": ecosystem.lower(),
                "package": canonical,
                "version": identity.get("version"),
                "qualifiers": identity.get("qualifiers"),
                "subpath": identity.get("subpath"),
                "origin": identity.get("origin"),
                **({"metadata": metadata} if metadata else {}),
            }
            # Producer-local project/instance IDs do not establish cross-tool equivalence.
            # Multiplicity is counted instead, and ambiguous occurrences remain qualified.
            counts[json.dumps(coordinate, sort_keys=True, ensure_ascii=False)] += 1
        return counts, unknown

    old, old_unknown = coordinates(before)
    new, new_unknown = coordinates(after)
    rows = []
    matched = 0
    for key in sorted(old.keys() | new.keys()):
        matched += min(old[key], new[key])
        if old[key] != new[key]:
            rows.append(
                {
                    "coordinate": json.loads(key),
                    "before_occurrences": old[key],
                    "after_occurrences": new[key],
                    "difference": new[key] - old[key],
                    "interpretation": "inventory-disagreement; correctness-not-established",
                }
            )
    diagnostics = [
        {**diagnostic, "input_side": side}
        for side, notes in (
            ("before", before_diagnostics),
            ("after", after_diagnostics),
        )
        for diagnostic in notes
    ]
    return {
        "schema": "depcheck.inventory-comparison.v1",
        "read_only": True,
        "inputs": [
            {"path": before_file, "sha256": before_digest},
            {"path": after_file, "sha256": after_digest},
        ],
        "comparison_profile": "ecosystem-package-version-qualifiers-origin-metadata-and-multiplicity",
        "matched_occurrences": matched,
        "differences": rows[offset : offset + limit],
        "total": len(rows),
        "offset": offset,
        "next_offset": offset + limit if len(rows) > offset + limit else None,
        "unknown_identity_counts": {
            "before": len(old_unknown),
            "after": len(new_unknown),
        },
        "diagnostics": diagnostics,
        "instance_alignment": "unknown; producer-local IDs not equated",
        "scope_alignment": "not-established",
        "path_alignment": "not-established",
        "false_positive_rate": None,
        "false_negative_rate": None,
    }
