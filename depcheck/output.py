from __future__ import annotations

import json
import os
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

from depcheck._version import __version__
from depcheck.model import Finding, PackageIdentity, ScanResult, SourceLocation
from depcheck.policy_codes import RISK_CODES, matches_risk, normalize_fail_on


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


def build_cyclonedx(
    result: ScanResult,
    *,
    timestamp: str | None = None,
    serial_number: str | None = None,
) -> dict[str, Any]:
    component_by_identity: dict[PackageIdentity, dict[str, Any]] = {}
    reference_by_identity: dict[PackageIdentity, str] = {}
    direct_identities: set[PackageIdentity] = set()
    for bundle in result.bundles:
        resolved_names = {item.package.name for item in bundle.resolved}
        for resolution in bundle.resolved:
            identity = resolution.identity
            if resolution.direct:
                direct_identities.add(identity)
            reference = _component_reference(identity)
            reference_by_identity[identity] = reference
            component_by_identity[identity] = _component(
                identity,
                reference,
                direct=resolution.direct,
            )
            if resolution.origin:
                component_by_identity[identity]["properties"].append(
                    {
                        "name": "depcheck:source:origin",
                        "value": json.dumps(dict(resolution.origin), sort_keys=True),
                    }
                )
        for declaration in bundle.declarations:
            if declaration.kind in {"constraint", "hint"} or (
                declaration.package.name in resolved_names
                and declaration.kind not in {"conditional", "checksum"}
            ):
                continue
            identity = PackageIdentity(
                declaration.project_id,
                declaration.package.ecosystem,
                declaration.package.name,
                purl=declaration.package.purl,
            )
            reference = _component_reference(identity)
            if declaration.kind in {"direct", "local"}:
                direct_identities.add(identity)
            reference_by_identity.setdefault(identity, reference)
            component = component_by_identity.setdefault(
                identity,
                _component(identity, reference, direct=identity in direct_identities),
            )
            if identity in direct_identities:
                component.pop("scope", None)
                for prop in component["properties"]:
                    if prop["name"] == "depcheck:dependency:direct":
                        prop["value"] = "true"
                        break
            if declaration.kind in {"conditional", "checksum"}:
                component["properties"].append(
                    {
                        "name": "depcheck:checksum-assertion"
                        if declaration.kind == "checksum"
                        else "depcheck:conditional-declaration",
                        "value": json.dumps(
                            {
                                "scope": declaration.scope,
                                "marker": declaration.marker,
                                "constraint": declaration.constraint.raw,
                                "source": declaration.source.to_dict(result.root),
                                "metadata": dict(declaration.metadata),
                            },
                            sort_keys=True,
                        ),
                    }
                )
                if identity not in direct_identities:
                    component["scope"] = "optional"

    project_ref = "application:" + quote(result.root.name or "repository", safe="-._~")
    direct_refs = sorted(
        {reference_by_identity[identity] for identity in direct_identities}
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
                        "version": __version__,
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
    # purl 标识发布包；bom-ref 还必须区分项目和安装实例。
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
        "properties": [
            {
                "name": "depcheck:identity:project-id",
                "value": identity.project_id,
            },
            {
                "name": "depcheck:identity:ecosystem",
                "value": identity.ecosystem,
            },
            {"name": "depcheck:dependency:direct", "value": str(direct).lower()},
        ],
    }
    if identity.version:
        component["version"] = identity.version
    if identity.instance:
        component["properties"].append(
            {"name": "depcheck:identity:instance", "value": identity.instance}
        )
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
        if "hygiene-incomplete" in policies and not any(
            capability.name == "dependency_hygiene" and capability.complete
            for capability in self.result.capabilities
        ):
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
                "matched_identities": [
                    {
                        **result.findings[item].package.to_dict(),
                        "advisory_id": result.findings[item].details.get("id"),
                    }
                    for item in matched
                ],
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
    from depcheck.bounded_io import read_text

    value = json.loads(
        read_text(path, project_root=path.resolve().parent, allow_aliases=True)
    )
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
        "package": str(value.get("package", "")).strip(),
        "project_id": (str(value["project_id"]) if value.get("project_id") else None),
        "ecosystem": (str(value["ecosystem"]) if value.get("ecosystem") else None),
        "reason": str(value.get("reason", "")),
        "owner": str(value.get("owner", "")),
        "expires_at": value.get("expires_at"),
        **{key: value[key] for key in ("advisory_ids", "versions") if key in value},
    }


def _validate_exemption(value: Mapping[str, Any]) -> str | None:
    if not value.get("risk"):
        return "risk is required"
    if value["risk"] not in RISK_CODES:
        return "unknown exemption risk"
    for field in ("package", "reason", "owner", "expires_at"):
        if not value.get(field):
            return f"{field} is required"
    for field in ("advisory_ids", "versions"):
        if field not in value:
            continue
        items = value[field]
        if (
            not isinstance(items, list)
            or not 1 <= len(items) <= 100
            or any(
                not isinstance(item, str) or not item.strip() or item != item.strip()
                for item in items
            )
        ):
            return f"{field} must contain 1..100 non-empty strings without surrounding whitespace"
    if "advisory_ids" in value and value["risk"] != "vuln":
        return "advisory_ids requires risk vuln"
    return None


def _matches_exemption(
    finding: Finding,
    exemption: Mapping[str, Any],
) -> bool:
    identity = finding.package
    if "versions" in exemption and identity.version not in exemption["versions"]:
        return False
    if "advisory_ids" in exemption:
        identifiers = {finding.details.get("id")}
        aliases = finding.details.get("aliases", ())
        if isinstance(aliases, (list, tuple)):
            identifiers.update(alias for alias in aliases if isinstance(alias, str))
        if not identifiers.intersection(exemption["advisory_ids"]):
            return False
    normalize = canonicalize_name if identity.ecosystem.lower() == "pypi" else str
    return (
        normalize(identity.name) == normalize(str(exemption["package"]))
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
