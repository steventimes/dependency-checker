"""Evidence metadata shared by transactional index publishers."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from depcheck.model import AnalysisReport, EvidenceBundle

from .models import INDEX_SCHEMA


def evidence_metadata(
    root: Path, report: AnalysisReport, bundles: Sequence[EvidenceBundle]
) -> dict[str, str]:
    return {
        "schema": INDEX_SCHEMA,
        "root": root.as_posix(),
        "indexed_at": datetime.now(UTC).isoformat(),
        "import_mapping": json.dumps(dict(report.import_mapping), sort_keys=True),
        "finding_count": str(len(report.findings)),
        "diagnostic_count": str(len(report.diagnostics)),
        "import_location_count": str(
            sum(
                (
                    usage.kind not in {"tool", "command", "configuration"}
                    for item in bundles
                    for usage in item.usages
                )
            )
        ),
        "declaration_count": str(sum((len(item.declarations) for item in bundles))),
    }
