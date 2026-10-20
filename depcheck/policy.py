"""Risk policy evaluation and audited, scoped exemptions."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from depcheck.model import Finding, ScanResult
from depcheck.policy_codes import RISK_CODES, matches_risk, normalize_fail_on


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
