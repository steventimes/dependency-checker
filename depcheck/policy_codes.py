from __future__ import annotations

from collections.abc import Iterable

RISK_CODES: dict[str, tuple[str, ...]] = {
    "missing": ("dependency.missing",),
    "unused": ("dependency.unused",),
    "unpinned": ("dependency.unpinned",),
    "scope": ("dependency.scope-mismatch",),
    "duplicate": ("declaration.duplicate", "declaration.conflict"),
    "vuln": ("security.vulnerability",),
    "compat": ("compatibility.",),
}
VALID_FAIL_ON = frozenset({"any", "incomplete", *RISK_CODES})
EXEMPTABLE_PACKAGE_RISKS = frozenset({"missing", "unused", "vuln"})


def normalize_fail_on(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values: Iterable[object] = (value,)
    elif isinstance(value, Iterable):
        values = value
    else:
        values = ()
    normalized = {str(item).lower() for item in values}
    unknown = normalized - VALID_FAIL_ON
    if unknown:
        raise ValueError(f"unknown fail_on values: {', '.join(sorted(unknown))}")
    return tuple(sorted(normalized))


def matches_risk(code: str, risk: str) -> bool:
    return any(
        code == prefix or code.startswith(prefix) for prefix in RISK_CODES.get(risk, ())
    )
