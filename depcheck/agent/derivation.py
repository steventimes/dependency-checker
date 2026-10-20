"""Page-local source references and bounded explanations over indexed assertions."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from depcheck.model import ANALYSIS_REVISION


def explain_derivation(record: dict[str, Any]) -> dict[str, Any]:
    """Explain observed presence, without inventing support for analyzer findings."""
    page = record["evidence_page"]
    identity = {key: record[key] for key in ("project_id", "ecosystem", "package")}
    facts = []
    supports: dict[str, list[list[str]]] = {"declared": [], "imported": []}
    for collection in ("declarations", "resolutions", "usages", "findings"):
        for index, assertion in enumerate(record.get(collection, []), page["offset"]):
            pointer = f"/{collection}/{index}"
            encoded = json.dumps(
                [ANALYSIS_REVISION, identity, pointer, assertion],
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode()
            reference = "sha256:" + hashlib.sha256(encoded).hexdigest()
            facts.append(
                {
                    "id": reference,
                    "assertion_pointer": pointer,
                    "where": assertion.get("location", assertion.get("locations")),
                }
            )
            if collection == "declarations":
                supports["declared"].append([reference])
            if collection == "usages" and assertion.get("kind") not in {
                "tool",
                "command",
                "configuration",
            }:
                supports["imported"].append([reference])
    return {
        "schema": "depcheck.derivation.v1",
        "analysis_revision": ANALYSIS_REVISION,
        "identity": identity,
        "facts": facts,
        "claims": [
            {
                "field": field,
                "value": record.get(field),
                "rule": "indexed-assertion-presence.v1",
                "support_alternatives": alternatives,
                "support_status": "page-local" if alternatives else "not-on-this-page",
            }
            for field, alternatives in supports.items()
        ],
        "support_semantics": "outer list: alternatives; inner list: jointly required facts",
        "finding_support": "not-captured; rule codes and locations remain assertions",
        "scope": "returned-evidence-page",
        "truncated": page["truncated"],
        "activation": "not-established",
        "source_authenticity": "unverified",
        "minimal_proof": False,
    }
