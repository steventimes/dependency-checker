"""Evidence metadata shared by transactional index publishers."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from depcheck.model import AnalysisReport, EvidenceBundle

INDEX_SCHEMA = "depcheck.index.v8"


@dataclass(frozen=True, slots=True)
class IndexRefreshResult:
    """一次索引刷新的可观察结果，便于 agent 判断成本与完整性。"""

    index_path: Path
    status: str
    scanned_python_files: int
    reused_python_files: int
    parsed_manifest_files: int
    reused_manifest_files: int
    removed_files: int
    complete: bool
    finding_count: int
    diagnostic_count: int
    scope: Mapping[str, Any]


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
