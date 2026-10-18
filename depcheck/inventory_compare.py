"""Cross-producer inventory comparison without assigning ground truth."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.security.offline import inventory_identities


def compare_inventories(
    root: Path, before_file: str, after_file: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Invalid inventory comparison pagination")
    before, before_digest, before_diagnostics = inventory_identities(root, before_file)
    after, after_digest, after_diagnostics = inventory_identities(root, after_file)

    def coordinates(
        records: list[dict[str, Any]],
    ) -> tuple[Counter[str], list[dict[str, Any]]]:
        counts: Counter[str] = Counter()
        unknown = []
        for identity in records:
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
        "comparison_profile": "ecosystem-package-version-qualifiers-origin-and-multiplicity",
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
