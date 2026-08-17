from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

INDEX_SCHEMA = "depcheck.index.v3"


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
