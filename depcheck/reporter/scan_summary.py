from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class ScanSummary:
    imported_count: int
    declared_count: int
    missing: list[str] = field(default_factory=list)
    unused: list[str] = field(default_factory=list)
    vulnerable: list[str] = field(default_factory=list)
    vulnerability_count: int = 0
    compatibility_conflict_count: int = 0
    compatibility_missing_count: int = 0
    compatibility_unconstrained_count: int = 0

    @property
    def risk_count(self) -> int:
        return (
            len(self.missing)
            + len(self.unused)
            + self.vulnerability_count
            + self.compatibility_conflict_count
            + self.compatibility_missing_count
            + self.compatibility_unconstrained_count
        )

    @property
    def has_compatibility_risk(self) -> bool:
        return (
            self.compatibility_conflict_count
            + self.compatibility_missing_count
            + self.compatibility_unconstrained_count
        ) > 0

    @property
    def status(self) -> str:
        return "fail" if self.risk_count else "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "risk_count": self.risk_count,
            "imported_count": self.imported_count,
            "declared_count": self.declared_count,
            "missing_count": len(self.missing),
            "unused_count": len(self.unused),
            "vulnerable_package_count": len(self.vulnerable),
            "vulnerability_count": self.vulnerability_count,
            "compatibility_conflict_count": self.compatibility_conflict_count,
            "compatibility_missing_count": self.compatibility_missing_count,
            "compatibility_unconstrained_count": self.compatibility_unconstrained_count,
            "missing": self.missing,
            "unused": self.unused,
            "vulnerable": self.vulnerable,
        }


def build_scan_summary(
    imports: Sequence[str] | set[str],
    declared: Mapping[str, object],
    vulns: Mapping[str, Sequence[object]],
    compatibility: object | None = None,
) -> ScanSummary:
    import_lookup = {_key(name) for name in imports}
    declared_lookup = {_key(name): name for name in declared.keys()}

    missing = sorted(
        str(name)
        for name in imports
        if _key(name) not in declared_lookup
    )
    unused = sorted(
        str(name)
        for key, name in declared_lookup.items()
        if key not in import_lookup
    )
    vulnerable = sorted(str(name) for name, issues in vulns.items() if issues)
    vulnerability_count = sum(len(issues) for issues in vulns.values())

    return ScanSummary(
        imported_count=len(import_lookup),
        declared_count=len(declared_lookup),
        missing=missing,
        unused=unused,
        vulnerable=vulnerable,
        vulnerability_count=vulnerability_count,
        compatibility_conflict_count=_len_attr(compatibility, "conflicts"),
        compatibility_missing_count=_len_attr(compatibility, "missing"),
        compatibility_unconstrained_count=_len_attr(compatibility, "unconstrained"),
    )


def should_fail(summary: ScanSummary, policies: Sequence[str]) -> bool:
    active = set(policies)
    return any(
        [
            "any" in active and summary.risk_count > 0,
            "missing" in active and bool(summary.missing),
            "unused" in active and bool(summary.unused),
            "vuln" in active and summary.vulnerability_count > 0,
            "compat" in active and summary.has_compatibility_risk,
        ]
    )


def _key(value: object) -> str:
    return str(value).replace("_", "-").lower()


def _len_attr(value: object | None, attr: str) -> int:
    if value is None:
        return 0
    return len(getattr(value, attr, []) or [])
