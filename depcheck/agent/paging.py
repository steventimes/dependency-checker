"""Bound nested evidence independently of the dependency inventory page."""

from __future__ import annotations

import json
from typing import Any

MAX_RESPONSE_BYTES = 256 * 1024
EVIDENCE_FIELDS = (
    "declarations",
    "resolutions",
    "usages",
    "imports",
    "findings",
    "files",
)


def bounded_response(payload: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(payload, indent=2).encode()) <= MAX_RESPONSE_BYTES:
        return payload
    return {
        "error": {
            "code": "response.budget-exceeded",
            "message": "Tool output exceeds 256 KiB. The operation may already have refreshed the cache; inspect context or export a CLI scan to a local file. Narrow query/evidence/origin limits for read-only queries.",
        },
        "truncated": True,
        "tool_result_omitted": True,
    }


def evidence_page(
    payload: dict[str, Any], *, limit: int, offset: int
) -> dict[str, Any]:
    if not 1 <= limit <= 100 or offset < 0:
        raise ValueError(
            "evidence_limit must be 1..100 and evidence_offset non-negative"
        )
    if "error" in payload:
        return bounded_response(payload)
    while True:
        result = dict(payload)
        records = (
            [dict(r) for r in result["dependencies"]]
            if "dependencies" in result
            else [result]
        )
        if "dependencies" in result:
            result["dependencies"] = records
        for record in records:
            counts = {
                key: len(record[key])
                for key in EVIDENCE_FIELDS
                if isinstance(record.get(key), list)
            }
            for key in counts:
                record[key] = record[key][offset : offset + limit]
            more = any(total > offset + limit for total in counts.values())
            record["evidence_page"] = {
                "offset": offset,
                "limit": limit,
                "counts": counts,
                "truncated": more,
                "next_offset": offset + limit if more else None,
            }
        more = any(r["evidence_page"]["truncated"] for r in records)
        if "dependencies" in result:
            result["inventory_truncated"] = bool(payload.get("truncated"))
        result["evidence_truncated"] = more
        result["truncated"] = bool(payload.get("truncated")) or more
        if len(json.dumps(result, indent=2).encode()) <= MAX_RESPONSE_BYTES:
            return result
        if limit == 1:
            return {
                "error": {
                    "code": "response.budget-exceeded",
                    "message": "Evidence exceeds the 256 KiB response budget. Narrow the inventory/origin limits or export a full CLI scan to a local file.",
                },
                "truncated": True,
            }
        limit = max(1, limit // 2)
