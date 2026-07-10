from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .scan_summary import ScanSummary

VALID_RISKS = {"missing", "unused", "vuln", "compat", "any"}
PACKAGE_RISKS = {"missing", "unused", "vuln"}


@dataclass(frozen=True)
class PolicyEvaluation:
    schema: str
    fail_on: list[str]
    active_exemptions: list[dict[str, Any]]
    expired_exemptions: list[dict[str, Any]]
    invalid_exemptions: list[dict[str, Any]]
    unmatched_exemptions: list[dict[str, Any]]
    effective: dict[str, Any]

    @property
    def governance_risk_count(self) -> int:
        return len(self.expired_exemptions) + len(self.invalid_exemptions)

    @property
    def effective_risk_count(self) -> int:
        return int(self.effective["risk_count"]) + self.governance_risk_count

    @property
    def status(self) -> str:
        return "fail" if self.effective_risk_count else "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "status": self.status,
            "fail_on": self.fail_on,
            "effective_risk_count": self.effective_risk_count,
            "governance_risk_count": self.governance_risk_count,
            "active_exemptions": self.active_exemptions,
            "expired_exemptions": self.expired_exemptions,
            "invalid_exemptions": self.invalid_exemptions,
            "unmatched_exemptions": self.unmatched_exemptions,
            "effective_summary": self.effective,
        }


def load_policy(path: Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict):
        raise ValueError("Policy file must contain a JSON object.")
    return policy


def evaluate_policy(
    summary: ScanSummary,
    policy: Mapping[str, Any],
    *,
    today: date | None = None,
) -> PolicyEvaluation:
    current_date = today or datetime.now(UTC).date()
    fail_on = _normalise_fail_on(policy.get("fail_on", []))
    raw_exemptions = policy.get("exemptions", [])
    if raw_exemptions is None:
        raw_exemptions = []
    if not isinstance(raw_exemptions, list):
        raw_exemptions = [
            {
                "risk": "policy",
                "package": "*",
                "reason": "exemptions must be a list",
                "owner": "unknown",
                "expires_at": None,
            }
        ]

    risk_packages = {
        "missing": set(summary.missing),
        "unused": set(summary.unused),
        "vuln": set(summary.vulnerable),
    }
    active: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []

    for index, exemption in enumerate(raw_exemptions):
        if not isinstance(exemption, dict):
            invalid.append(_invalid(index, exemption, "exemption must be an object"))
            continue

        normalized = _normalize_exemption(index, exemption)
        validation_error = _validate_exemption(normalized)
        if validation_error:
            invalid.append({**normalized, "validation_error": validation_error})
            continue

        expires_at = _parse_date(str(normalized["expires_at"]))
        if expires_at is None:
            invalid.append({**normalized, "validation_error": "expires_at must be YYYY-MM-DD"})
            continue
        if expires_at < current_date:
            expired.append(normalized)
            continue

        risk = normalized["risk"]
        package = normalized["package"]
        if risk in PACKAGE_RISKS and package not in risk_packages[risk]:
            unmatched.append(normalized)
            continue

        if risk in PACKAGE_RISKS:
            risk_packages[risk].discard(package)
        active.append(normalized)

    effective = {
        "risk_count": (
            len(risk_packages["missing"])
            + len(risk_packages["unused"])
            + sum(1 for name in summary.vulnerable if name in risk_packages["vuln"])
            + summary.compatibility_conflict_count
            + summary.compatibility_missing_count
            + summary.compatibility_unconstrained_count
        ),
        "missing": sorted(risk_packages["missing"]),
        "unused": sorted(risk_packages["unused"]),
        "vulnerable": sorted(risk_packages["vuln"]),
        "missing_count": len(risk_packages["missing"]),
        "unused_count": len(risk_packages["unused"]),
        "vulnerable_package_count": len(risk_packages["vuln"]),
        "compatibility_conflict_count": summary.compatibility_conflict_count,
        "compatibility_missing_count": summary.compatibility_missing_count,
        "compatibility_unconstrained_count": summary.compatibility_unconstrained_count,
    }

    return PolicyEvaluation(
        schema=str(policy.get("schema", "depcheck.policy.v1")),
        fail_on=fail_on,
        active_exemptions=active,
        expired_exemptions=expired,
        invalid_exemptions=invalid,
        unmatched_exemptions=unmatched,
        effective=effective,
    )


def should_fail_policy(evaluation: PolicyEvaluation, cli_policies: Sequence[str] = ()) -> bool:
    policies = set(evaluation.fail_on) | set(cli_policies)
    if evaluation.governance_risk_count > 0:
        return True
    effective = evaluation.effective
    return any(
        [
            "any" in policies and int(effective["risk_count"]) > 0,
            "missing" in policies and bool(effective["missing"]),
            "unused" in policies and bool(effective["unused"]),
            "vuln" in policies and bool(effective["vulnerable"]),
            "compat" in policies
            and (
                int(effective["compatibility_conflict_count"])
                + int(effective["compatibility_missing_count"])
                + int(effective["compatibility_unconstrained_count"])
            )
            > 0,
        ]
    )


def _normalise_fail_on(value: object) -> list[str]:
    if isinstance(value, str):
        values: Iterable[object] = [value]
    elif isinstance(value, Iterable):
        values = value
    else:
        values = []
    return sorted({str(item) for item in values if str(item) in VALID_RISKS})


def _normalize_exemption(index: int, exemption: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(exemption.get("id", f"exemption-{index + 1}")),
        "risk": str(exemption.get("risk", "")).lower(),
        "package": str(exemption.get("package", "")),
        "reason": str(exemption.get("reason", "")),
        "owner": str(exemption.get("owner", "")),
        "expires_at": exemption.get("expires_at"),
    }


def _validate_exemption(exemption: Mapping[str, Any]) -> str | None:
    risk = exemption.get("risk")
    if risk not in PACKAGE_RISKS:
        return "risk must be one of missing, unused, vuln"
    for field in ["package", "reason", "owner", "expires_at"]:
        if not exemption.get(field):
            return f"{field} is required"
    return None


def _invalid(index: int, value: object, message: str) -> dict[str, Any]:
    return {
        "id": f"exemption-{index + 1}",
        "risk": "policy",
        "package": "*",
        "reason": repr(value),
        "owner": "unknown",
        "expires_at": None,
        "validation_error": message,
    }


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
