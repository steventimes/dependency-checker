from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from packaging.utils import canonicalize_name

from depcheck.model import Finding, PackageIdentity, ScanResult
from depcheck.policy_codes import matches_risk, normalize_fail_on


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
    return "\n".join(lines)


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
                        "semanticVersion": "0.4.0",
                        "rules": [
                            _sarif_rule(code, findings)
                            for code, findings in sorted(grouped.items())
                        ],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": result.complete,
                        "properties": result.to_dict()["summary"],
                    }
                ],
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


def _sarif_result(result: ScanResult, finding: Finding) -> dict[str, Any]:
    locations = []
    for location in finding.locations:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": _relative(location.path, result.root)}
        }
        if location.line is not None:
            region = {"startLine": location.line}
            if location.column is not None:
                region["startColumn"] = location.column
            physical["region"] = region
        locations.append({"physicalLocation": physical})
    if not locations:
        manifests = [
            path for bundle in result.bundles for path in bundle.project.manifests
        ]
        fallback = manifests[0].as_posix() if manifests else "."
        locations.append({"physicalLocation": {"artifactLocation": {"uri": fallback}}})
    return {
        "ruleId": _rule_id(finding.code),
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": locations,
        "properties": {
            **finding.package.to_dict(),
            "finding_code": finding.code,
            **dict(finding.details),
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


def build_cyclonedx(
    result: ScanResult,
    *,
    timestamp: str | None = None,
    serial_number: str | None = None,
) -> dict[str, Any]:
    component_by_identity: dict[PackageIdentity, dict[str, Any]] = {}
    reference_by_identity: dict[PackageIdentity, str] = {}
    for bundle in result.bundles:
        for resolution in bundle.resolved:
            identity = resolution.identity
            reference = _component_reference(identity)
            reference_by_identity[identity] = reference
            component_by_identity[identity] = _component(
                identity,
                reference,
                direct=resolution.direct,
            )
        for declaration in bundle.declarations:
            matching = [
                item
                for item in bundle.resolved
                if item.package.name == declaration.package.name
            ]
            if matching:
                continue
            identity = PackageIdentity(
                declaration.project_id,
                declaration.package.ecosystem,
                declaration.package.name,
                purl=declaration.package.purl,
            )
            reference = _component_reference(identity)
            reference_by_identity.setdefault(identity, reference)
            component_by_identity.setdefault(
                identity,
                _component(identity, reference, direct=True),
            )

    project_ref = "application:" + quote(result.root.name or "repository", safe="-._~")
    direct_refs = sorted(
        {
            reference_by_identity[resolution.identity]
            for bundle in result.bundles
            for resolution in bundle.resolved
            if resolution.direct
        }
        | {
            reference_by_identity[identity]
            for identity in component_by_identity
            if identity.version is None
        }
    )
    dependency_entries = [{"ref": project_ref, "dependsOn": direct_refs}]
    for bundle in result.bundles:
        for resolution in bundle.resolved:
            identity = resolution.identity
            children = []
            for link in resolution.dependency_links:
                target = PackageIdentity(
                    resolution.project_id,
                    link.package.ecosystem,
                    link.package.name,
                    link.version,
                    link.instance_id,
                    link.package.purl,
                )
                component_ref = reference_by_identity.get(target)
                if component_ref is None:
                    candidates = [
                        value
                        for key, value in reference_by_identity.items()
                        if key.project_id == target.project_id
                        and key.ecosystem.lower() == target.ecosystem.lower()
                        and key.name == target.name
                        and (target.version is None or key.version == target.version)
                    ]
                    component_ref = candidates[0] if len(candidates) == 1 else None
                if component_ref is not None:
                    children.append(component_ref)
            dependency_entries.append(
                {
                    "ref": reference_by_identity[identity],
                    "dependsOn": sorted(set(children)),
                }
            )

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial_number or f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "depcheck",
                        "version": "0.4.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": project_ref,
                "name": result.root.name or "repository",
            },
        },
        "components": [
            component_by_identity[identity]
            for identity in sorted(
                component_by_identity,
                key=lambda item: item.sort_key,
            )
        ],
        "dependencies": dependency_entries,
    }


def _component_reference(identity: PackageIdentity) -> str:
    if identity.purl:
        reference = identity.purl
        if identity.version:
            reference += f"@{quote(identity.version, safe='-._~+')}"
    else:
        reference = (
            "urn:depcheck:"
            f"{quote(identity.project_id, safe='')}:"
            f"{quote(identity.ecosystem, safe='')}:"
            f"{quote(identity.name, safe='')}"
        )
        if identity.version:
            reference += f"@{quote(identity.version, safe='-._~+')}"
    if identity.instance:
        reference += f"#instance={quote(identity.instance, safe='-._~/')}"
    return reference


def _component(
    identity: PackageIdentity,
    reference: str,
    *,
    direct: bool,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": reference,
        "name": identity.name,
        "scope": "required" if direct else "optional",
        "properties": [
            {
                "name": "depcheck:identity:project-id",
                "value": identity.project_id,
            },
            {
                "name": "depcheck:identity:ecosystem",
                "value": identity.ecosystem,
            },
        ],
    }
    if identity.version:
        component["version"] = identity.version
    if identity.purl:
        purl = identity.purl
        if identity.version:
            purl += f"@{quote(identity.version, safe='-._~+')}"
        component["purl"] = purl
    return component


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    result: ScanResult
    fail_on: tuple[str, ...]
    effective_findings: tuple[Finding, ...]
    active_exemptions: tuple[dict[str, Any], ...]
    expired_exemptions: tuple[dict[str, Any], ...]
    invalid_exemptions: tuple[dict[str, Any], ...]
    unmatched_exemptions: tuple[dict[str, Any], ...]

    @property
    def governance_risk_count(self) -> int:
        return len(self.expired_exemptions) + len(self.invalid_exemptions)

    def should_fail(self, extra: Sequence[str] = ()) -> bool:
        policies = set(self.fail_on) | set(normalize_fail_on(extra))
        if self.governance_risk_count:
            return True
        if "incomplete" in policies and not self.result.complete:
            return True
        if "any" in policies and self.effective_findings:
            return True
        return any(
            policy in policies
            and any(
                matches_risk(finding.code, policy)
                for finding in self.effective_findings
            )
            for policy in policies
        )

    def to_dict(self, extra: Sequence[str] = ()) -> dict[str, Any]:
        return {
            "schema": "depcheck.policy.v1",
            "status": "fail" if self.should_fail(extra) else "pass",
            "fail_on": sorted(set(self.fail_on) | set(extra)),
            "effective_risk_count": len(self.effective_findings),
            "governance_risk_count": self.governance_risk_count,
            "effective_findings": [
                item.to_dict(self.result.root) for item in self.effective_findings
            ],
            "active_exemptions": list(self.active_exemptions),
            "expired_exemptions": list(self.expired_exemptions),
            "invalid_exemptions": list(self.invalid_exemptions),
            "unmatched_exemptions": list(self.unmatched_exemptions),
        }


def evaluate_policy(
    result: ScanResult,
    policy: Mapping[str, Any],
    *,
    today: date | None = None,
) -> PolicyEvaluation:
    current_date = today or datetime.now(UTC).date()
    fail_on = normalize_fail_on(policy.get("fail_on", ()))
    raw_exemptions = policy.get("exemptions", [])
    if not isinstance(raw_exemptions, list):
        raw_exemptions = [raw_exemptions]

    remaining = set(range(len(result.findings)))
    active: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_exemptions):
        if not isinstance(raw, Mapping):
            invalid.append(
                _invalid_exemption(index, raw, "exemption must be an object")
            )
            continue
        exemption = _normalize_exemption(index, raw)
        error = _validate_exemption(exemption)
        if error:
            invalid.append({**exemption, "validation_error": error})
            continue
        try:
            expires_at = date.fromisoformat(str(exemption["expires_at"]))
        except ValueError:
            invalid.append(
                {
                    **exemption,
                    "validation_error": "expires_at must be YYYY-MM-DD",
                }
            )
            continue
        if expires_at < current_date:
            expired.append(exemption)
            continue
        matched = [
            finding_index
            for finding_index in sorted(remaining)
            if _matches_exemption(
                result.findings[finding_index],
                exemption,
            )
        ]
        if not matched:
            unmatched.append(exemption)
            continue
        remaining.difference_update(matched)
        active.append(
            {
                **exemption,
                "matched_findings": [result.findings[item].code for item in matched],
            }
        )
    return PolicyEvaluation(
        result=result,
        fail_on=fail_on,
        effective_findings=tuple(result.findings[index] for index in sorted(remaining)),
        active_exemptions=tuple(active),
        expired_exemptions=tuple(expired),
        invalid_exemptions=tuple(invalid),
        unmatched_exemptions=tuple(unmatched),
    )


def load_policy(path: Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError("policy file must contain a JSON object")
    return value


def _normalize_exemption(
    index: int,
    value: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": str(value.get("id", f"exemption-{index + 1}")),
        "risk": str(value.get("risk", "")).lower(),
        "package": str(canonicalize_name(str(value.get("package", "")))),
        "project_id": (str(value["project_id"]) if value.get("project_id") else None),
        "ecosystem": (str(value["ecosystem"]) if value.get("ecosystem") else None),
        "reason": str(value.get("reason", "")),
        "owner": str(value.get("owner", "")),
        "expires_at": value.get("expires_at"),
    }


def _validate_exemption(value: Mapping[str, Any]) -> str | None:
    if not value.get("risk"):
        return "risk is required"
    for field in ("package", "reason", "owner", "expires_at"):
        if not value.get(field):
            return f"{field} is required"
    return None


def _matches_exemption(
    finding: Finding,
    exemption: Mapping[str, Any],
) -> bool:
    identity = finding.package
    return (
        identity.name == exemption["package"]
        and (
            exemption["project_id"] is None
            or identity.project_id == exemption["project_id"]
        )
        and (
            exemption["ecosystem"] is None
            or identity.ecosystem.lower() == str(exemption["ecosystem"]).lower()
        )
        and matches_risk(finding.code, str(exemption["risk"]))
    )


def _invalid_exemption(
    index: int,
    value: object,
    message: str,
) -> dict[str, Any]:
    return {
        "id": f"exemption-{index + 1}",
        "risk": "policy",
        "package": "*",
        "project_id": None,
        "ecosystem": None,
        "reason": repr(value),
        "owner": "unknown",
        "expires_at": None,
        "validation_error": message,
    }


def _relative(path: Path, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return candidate.name
