from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from depcheck.cyclonedx import build_cyclonedx as build_cyclonedx
from depcheck.model import ScanResult
from depcheck.policy import (
    PolicyEvaluation as PolicyEvaluation,
)
from depcheck.policy import (
    evaluate_policy as evaluate_policy,
)
from depcheck.policy import (
    load_policy as load_policy,
)
from depcheck.sarif import build_sarif as build_sarif


def render_json(result: ScanResult) -> str:
    return json.dumps(
        result.to_dict(),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


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
    return "\n".join(lines)


def _relative(path: Path, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return candidate.name
