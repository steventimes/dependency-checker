"""SARIF projection over captured scan evidence, without source reads."""

from __future__ import annotations

import os
import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

from depcheck._version import __version__
from depcheck.model import Finding, ScanResult, SourceLocation


def build_sarif(result: ScanResult) -> dict[str, Any]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        grouped[finding.code].append(finding)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depcheck",
                        "semanticVersion": __version__,
                        "rules": [
                            _sarif_rule(code, findings)
                            for code, findings in sorted(grouped.items())
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": result.complete,
                        "properties": result.summary,
                        "toolExecutionNotifications": [
                            {
                                "descriptor": {"id": item.code},
                                "level": _sarif_level(item.severity),
                                "message": {"text": item.message},
                                **(
                                    {
                                        "locations": [
                                            _sarif_location(item.source, result.root)
                                        ]
                                    }
                                    if item.source is not None
                                    else {}
                                ),
                            }
                            for item in result.diagnostics
                        ],
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "description": {
                            "text": "Root of the audited repository; map this base ID to the checkout."
                        }
                    }
                },
                "columnKind": "unicodeCodePoints",
                "newlineSequences": ["\r\n", "\r", "\n"],
                "results": [
                    _sarif_result(result, finding) for finding in result.findings
                ],
            }
        ],
    }


def _sarif_rule(code: str, findings: Sequence[Finding]) -> dict[str, Any]:
    severity = max(
        (item.severity for item in findings),
        key=lambda value: {"info": 0, "warning": 1, "error": 2}.get(value, 0),
    )
    return {
        "id": _rule_id(code),
        "name": code,
        "shortDescription": {"text": code.replace(".", " ").title()},
        "defaultConfiguration": {"level": _sarif_level(severity)},
        "properties": {"tags": ["dependencies", code.split(".", 1)[0]]},
    }


def _sarif_location(location: SourceLocation, root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(root))
    candidate = Path(os.path.abspath(root / location.path))
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError:
        artifact = {"uri": candidate.as_uri()}
    else:
        artifact = {"uri": quote(relative, safe="/"), "uriBaseId": "%SRCROOT%"}
    physical: dict[str, Any] = {"artifactLocation": artifact}
    if location.path.suffix.lower() == ".ipynb" and location.line is not None:
        return {
            "physicalLocation": physical,
            "properties": {
                "depcheck:region-status": "notebook-virtual",
                "depcheck:reported-region": {
                    "line": location.line,
                    "column": location.column,
                    "column_kind": "unicodeCodePoints",
                },
            },
        }
    if location.line is not None:
        region = {"startLine": location.line}
        if location.column is not None:
            region["startColumn"] = location.column
        physical["region"] = region
    return {"physicalLocation": physical}


def _sarif_result(result: ScanResult, finding: Finding) -> dict[str, Any]:
    locations = [
        _sarif_location(location, result.root) for location in finding.locations
    ]
    if not locations:
        manifests = [
            path
            for bundle in result.bundles
            if bundle.project.project_id == finding.package.project_id
            for path in bundle.project.manifests
        ]
        if manifests:
            locations.append(_sarif_location(SourceLocation(manifests[0]), result.root))
    return {
        "ruleId": _rule_id(finding.code),
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": locations,
        "properties": {
            **finding.package.to_dict(),
            "finding_code": finding.code,
            **dict(finding.details),
            **({"depcheck:location-status": "unavailable"} if not locations else {}),
        },
    }


def _rule_id(code: str) -> str:
    return "DEPCHECK-" + re.sub(
        r"[^A-Z0-9]+",
        "-",
        code.upper(),
    ).strip("-")


def _sarif_level(severity: str) -> str:
    return {
        "error": "error",
        "warning": "warning",
    }.get(severity, "note")
