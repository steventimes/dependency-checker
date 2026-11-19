from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from depcheck.model import ScanResult
from depcheck.reporting.cyclonedx import build_cyclonedx as build_cyclonedx
from depcheck.reporting.policy import PolicyEvaluation as PolicyEvaluation
from depcheck.reporting.policy import evaluate_policy as evaluate_policy
from depcheck.reporting.policy import load_policy as load_policy
from depcheck.reporting.sarif import build_sarif as build_sarif


def render_json(result: ScanResult) -> str:
    return json.dumps(
        result.to_dict(),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def render_snapshot_comparison(result: dict[str, Any]) -> str:
    """Render the existing paginated snapshot comparison for terminal readers."""
    lines = [
        f"Comparable: {result['comparable']}",
        f"Inventory and security: {json.dumps(result['capabilities'], sort_keys=True)}",
        f"Remediation verified: {result['remediation_verified']}",
        f"Coverage: {json.dumps(result['coverage'], sort_keys=True)}",
        f"Before: {json.dumps(result['before'], sort_keys=True)}",
        f"After: {json.dumps(result['after'], sort_keys=True)}",
        f"Change counts: {json.dumps(result['counts'], sort_keys=True)}",
    ]
    for name, rows in result["changes"].items():
        for row in rows:
            lines.append(f"{name}: {json.dumps(row, sort_keys=True)}")
    for diagnostic in result["diagnostics"]:
        lines.append(f"Diagnostic: {json.dumps(diagnostic, sort_keys=True)}")
    lines.append(f"Next offset: {result['next_offset']}")
    return "\n".join(escape_terminal(line) for line in lines)


def render_text(result: ScanResult) -> str:
    inventory = result.to_dict()["inventory"]
    lines = [
        f"depcheck: {result.status.upper()}",
        (
            f"{len(result.findings)} findings, "
            f"{len(result.diagnostics)} diagnostics, "
            f"{inventory['source_file_count']} source files, "
            f"{inventory['manifest_file_count']} manifests"
        ),
    ]
    if result.findings:
        lines.extend(("", "Findings"))
        for finding in result.findings:
            identity = finding.package
            qualified = f"{identity.project_id}/{identity.ecosystem}/{identity.name}"
            if identity.version:
                qualified += f"@{identity.version}"
            lines.append(
                f" [{finding.severity.upper()}] {finding.code}: "
                f"{qualified} — {finding.message}"
            )
            if finding.code == "security.vulnerability":
                references = {
                    (item["type"], item["id"], item["url"])
                    for item in finding.details.get("identifier_references", [])
                }
                for kind, identifier, url in sorted(references):
                    lines.append(f"   {kind} assertion: {identifier} ({url})")
                if finding.details.get("weaknesses_status") in {
                    "not-provided",
                    "incomplete",
                }:
                    lines.append(
                        "   Weakness classification: "
                        + finding.details["weaknesses_status"]
                    )
                severity_status = finding.details.get("severity_status", "unknown")
                lines.append(
                    "   OSV severity evidence (not finding level): "
                    + str(severity_status)
                )
                for assertion in finding.details.get("severity_assertions", []):
                    package = json.dumps(
                        assertion.get("package"), sort_keys=True, ensure_ascii=False
                    )
                    lines.append(
                        f"     {assertion.get('advisory_id', 'unknown')} "
                        f"{assertion.get('field', 'unknown field')}: "
                        f"applicability={assertion.get('applicability', 'unknown')}; "
                        f"package={package}"
                    )
                    raw_scores = assertion.get("severity")
                    scores = (
                        raw_scores if isinstance(raw_scores, list) else [raw_scores]
                    )
                    for score in scores:
                        if isinstance(score, Mapping):
                            source = (
                                json.dumps(score["source"], ensure_ascii=False)
                                if "source" in score
                                else "not supplied"
                            )
                            lines.append(
                                "       type="
                                f"{json.dumps(score.get('type'), ensure_ascii=False)} "
                                "score="
                                f"{json.dumps(score.get('score'), ensure_ascii=False)} "
                                f"source={source}"
                            )
                        else:
                            lines.append(
                                "       raw severity assertion: "
                                + json.dumps(score, sort_keys=True, ensure_ascii=False)
                                + "; source=not supplied"
                            )
                omitted = {
                    key: finding.details[key]
                    for key in (
                        "severity_assertions_omitted",
                        "severity_scores_omitted",
                        "severity_scopes_omitted",
                    )
                    if finding.details.get(key)
                }
                if omitted:
                    lines.append(
                        "   OSV severity evidence omitted: "
                        + json.dumps(omitted, sort_keys=True)
                    )
            for location in finding.locations:
                rendered = _relative(location.path, result.root)
                if location.line is not None:
                    rendered += f":{location.line}"
                    if location.column is not None:
                        rendered += f":{location.column}"
                lines.append(f"   at {rendered}")
    if result.diagnostics:
        lines.extend(("", "Diagnostics"))
        for diagnostic in result.diagnostics:
            diagnostic_location = ""
            if diagnostic.source is not None:
                diagnostic_location = (
                    f" ({_relative(diagnostic.source.path, result.root)}"
                )
                if diagnostic.source.line is not None:
                    diagnostic_location += f":{diagnostic.source.line}"
                diagnostic_location += ")"
            lines.append(
                f" [{diagnostic.severity.upper()}] "
                f"{diagnostic.code}{diagnostic_location}: {diagnostic.message}"
            )
    policy = result.metadata.get("policy")
    if isinstance(policy, Mapping):
        lines.extend(("", f"Policy: {str(policy['status']).upper()}"))
        for group in (
            "invalid_exemptions",
            "expired_exemptions",
            "unmatched_exemptions",
        ):
            for exemption in policy.get(group, []):
                lines.append(
                    f" {exemption['id']}: "
                    f"{exemption.get('validation_error', group.replace('_', ' '))}"
                )
    return "\n".join(escape_terminal(line) for line in lines)


def _relative(path: Path, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return candidate.name


def escape_terminal(value: str) -> str:
    """Escape data controls; the renderer adds its own line separators."""
    return "".join(
        f"\\u{ord(c):04x}"
        if ord(c) < 32
        or 127 <= ord(c) < 160
        or c
        in "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        else c
        for c in value
    )
