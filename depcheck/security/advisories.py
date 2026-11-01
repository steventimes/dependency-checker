"""Pure OSV advisory, version-range, fix and alias interpretation.

Online and offline callers supply validated source records. No network client
or session is constructed while interpreting their assertions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import Version
from semver import Version as SemVersion

from depcheck.model import Diagnostic

from .maven import MavenVersion
from .rubygems import RubyGemsVersion

MAX_SEVERITY_SCORES = 256
MAX_SEVERITY_BYTES = 256 * 1024
MAX_GROUP_SEVERITY_ASSERTIONS = 4096


def advisory_timestamp(value: Any) -> tuple[datetime, Decimal]:
    """Compare OSV UTC revisions without truncating sub-microsecond updates."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("OSV timestamp must be a bounded RFC3339 UTC string")
    match = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?[Zz]",
        value,
    )
    if match is None:
        raise ValueError("OSV timestamp must be a bounded RFC3339 UTC string")
    return (
        datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc),
        Decimal("0." + (match[2] or "0")),
    )


@dataclass
class _VersionRange:
    parse: Callable[[str], Any]
    events: list[tuple[Any, str]]
    limits: list[Any]

    def includes(self, raw: str) -> bool:
        version = self.parse(raw)
        if self.limits and not any(
            limit is None or version < limit for limit in self.limits
        ):
            return False
        affected = False
        for boundary, kind in self.events:
            if boundary is None or version >= boundary:
                if kind == "introduced":
                    affected = True
                elif kind == "fixed" or version > boundary:
                    affected = False
        return affected


def identifier_metadata(
    detail: Mapping[str, Any],
) -> tuple[dict[str, Any], Diagnostic | None]:
    """Retain provider assertions without claiming to validate CVE/CWE records."""
    advisory_id = str(detail["id"])
    references: list[dict[str, str]] = []
    cves: set[str] = set()
    for field, identifiers in (
        ("id", [advisory_id]),
        ("aliases", detail.get("aliases", [])),
    ):
        for identifier in sorted(set(identifiers)):
            if len(identifier) <= 256 and re.fullmatch(
                r"CVE-[0-9]{4}-[0-9]{4,}", identifier
            ):
                cves.add(identifier)
                references.append(
                    {
                        "type": "CVE",
                        "id": identifier,
                        "url": f"https://www.cve.org/CVERecord?id={identifier}",
                        "advisory_id": advisory_id,
                        "field": field,
                    }
                )
    cwes: set[str] = set()
    invalid = False
    database = detail.get("database_specific", {})
    if not isinstance(database, dict):
        invalid = True
    else:
        assertions = database.get("cwe_ids", [])
        if not isinstance(assertions, list):
            invalid = True
        else:
            invalid = len(assertions) > 256
            for identifier in assertions[:256]:
                if (
                    isinstance(identifier, str)
                    and len(identifier) <= 64
                    and re.fullmatch(r"CWE-[1-9][0-9]*", identifier)
                ):
                    cwes.add(identifier)
                else:
                    invalid = True
    references.extend(
        {
            "type": "CWE",
            "id": identifier,
            "url": f"https://cwe.mitre.org/data/definitions/{identifier[4:]}.html",
            "advisory_id": advisory_id,
            "field": "database_specific.cwe_ids",
        }
        for identifier in sorted(cwes)
    )
    return {
        "cve_ids": sorted(cves),
        "cwe_ids": sorted(cwes),
        "weaknesses_status": (
            "incomplete" if invalid else "reported" if cwes else "not-provided"
        ),
        "identifier_references": references,
    }, (
        Diagnostic(
            code="osv.invalid-weakness-metadata",
            severity="warning",
            message=f"OSV advisory {advisory_id} has malformed or over-budget CWE assertions; retained valid IDs within the 256-entry budget. Weakness classification is incomplete.",
        )
        if invalid
        else None
    )


@dataclass(frozen=True)
class _VersionEvidence:
    fixes: list[str]
    ranges: list[_VersionRange]
    versions: list[str]
    unsupported: bool
    schemes: set[str]
    matched_package: bool
    incomplete_entries: bool


def _version_text(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("invalid or oversized advisory version")
    return value


def _go_version(value: str) -> SemVersion:
    """Compare full Go module versions without coercing shorthand or toolchains."""
    return SemVersion.parse(value.removeprefix("v"))


def _version_evidence(
    detail: Mapping[str, Any],
    package: str,
    ecosystem: str,
    *,
    work_budget: list[int] | None = None,
) -> _VersionEvidence:
    """Parse one package's bounded assertions for matching and fix selection."""
    fixes: list[str] = []
    ranges: list[_VersionRange] = []
    listed_versions: list[str] = []
    unsupported = False
    schemes: set[str] = set()
    remaining = work_budget if work_budget is not None else [4096]
    incomplete_entries = False
    matched_package = False

    def array(value: Any) -> list[Any]:
        if not isinstance(value, list):
            raise ValueError("affected/ranges/events/versions must be arrays")
        remaining[0] -= len(value)
        if remaining[0] < 0:
            raise ValueError("advisory fix metadata exceeds the 4096-item budget")
        return value

    for affected in array(detail.get("affected", [])):
        if not isinstance(affected, dict):
            raise ValueError("affected entries must be objects")
        coordinate = affected.get("package")
        # Git-only entries without package coordinates cannot supply package fixes.
        if coordinate is None:
            continue
        if not isinstance(coordinate, dict) or not all(
            isinstance(coordinate.get(k), str) and coordinate[k]
            for k in ("ecosystem", "name")
        ):
            raise ValueError("affected package requires an ecosystem and name")
        if coordinate["ecosystem"].lower() != ecosystem.lower() or (
            coordinate["name"] != "*"
            and normalize_package(coordinate["name"], ecosystem) != package
        ):
            continue
        matched_package = True
        if not affected.get("versions") and not affected.get("ranges"):
            incomplete_entries = True
        listed_versions.extend(
            _version_text(v) for v in array(affected.get("versions", []))
        )
        for record in array(affected.get("ranges", [])):
            if not isinstance(record, dict):
                raise ValueError("range entries must be objects")
            kind = record.get("type")
            if kind == "SEMVER":
                parse: Callable[[str], Any] = SemVersion.parse
                schemes.add("semver")
                comparable = True
            elif kind == "ECOSYSTEM" and ecosystem.lower() == "pypi":
                parse = Version
                schemes.add("pep440")
                comparable = True
            elif kind == "ECOSYSTEM" and ecosystem.lower() in {"npm", "crates.io"}:
                # These ecosystems order OSV boundaries by SemVer precedence.
                # Keep strict parsing: legacy/coerced versions remain unknown.
                parse = SemVersion.parse
                schemes.add("semver")
                comparable = True
            elif kind == "ECOSYSTEM" and ecosystem.lower() == "go":
                parse = _go_version
                schemes.add("semver")
                comparable = True
            elif kind == "ECOSYSTEM" and ecosystem.lower() == "maven":
                parse = MavenVersion
                schemes.add("maven-comparable-version")
                comparable = True
            elif kind == "ECOSYSTEM" and ecosystem.lower() == "rubygems":
                parse = RubyGemsVersion
                schemes.add("rubygems-version")
                comparable = True
            else:
                unsupported = True
                comparable = False
            events: list[tuple[Any, str]] = []
            limits: list[Any] = []
            event_kinds: set[str] = set()
            for event in array(record.get("events", [])):
                if not isinstance(event, dict) or len(event) != 1:
                    raise ValueError("each range event must have exactly one boundary")
                event_kind, raw = next(iter(event.items()))
                if event_kind not in {"introduced", "fixed", "last_affected", "limit"}:
                    raise ValueError("unknown range event")
                raw = _version_text(raw)
                event_kinds.add(event_kind)
                if event_kind == "fixed" and raw not in fixes:
                    fixes.append(raw)
                if not comparable:
                    continue
                try:
                    if event_kind == "limit":
                        limits.append(None if raw == "*" else parse(raw))
                    else:
                        boundary = (
                            None
                            if event_kind == "introduced" and raw == "0"
                            else parse(raw)
                        )
                        events.append((boundary, event_kind))
                except ValueError:
                    if kind != "ECOSYSTEM" or ecosystem.lower() not in {
                        "maven",
                        "go",
                        "rubygems",
                    }:
                        raise
                    # Unsupported native boundaries cannot establish negative
                    # coverage, but must not erase another positive assertion.
                    unsupported = True
                    comparable = False
            if (
                "introduced" not in event_kinds
                or {"fixed", "last_affected"} <= event_kinds
            ):
                raise ValueError(
                    "range needs introduced and cannot mix fixed/last_affected"
                )
            if comparable:
                events.sort(key=lambda e: (e[0] is not None, e[0], e[1]))
                for previous, current in zip(events, events[1:]):
                    if previous[0] == current[0] and previous[1] != current[1]:
                        raise ValueError("conflicting events at the same version")
                ranges.append(_VersionRange(parse, events, limits))

    return _VersionEvidence(
        fixes,
        ranges,
        listed_versions,
        unsupported,
        schemes,
        matched_package,
        incomplete_entries,
    )


def match_affected_version(
    detail: Mapping[str, Any],
    package: str,
    ecosystem: str,
    queried_version: str,
    *,
    _work_budget: list[int] | None = None,
) -> tuple[str, str]:
    """Return affected/not-affected/unknown within the supplied record only.

    Membership does not require a forward fix. A supported positive assertion
    remains useful alongside unsupported ranges; unsupported negative coverage
    cannot establish a nonmatch. Native equality never uses generic lexical order.
    """
    evidence = _version_evidence(detail, package, ecosystem, work_budget=_work_budget)
    queried_version = _version_text(queried_version)
    if not evidence.matched_package:
        return "unknown", "No matching package assertion"
    native: Callable[[str], Any] | None = None
    if ecosystem.lower() == "pypi":
        native = Version
    elif ecosystem.lower() in {"npm", "crates.io"}:
        native = SemVersion.parse
    elif ecosystem.lower() == "go":
        native = _go_version
    elif ecosystem.lower() == "maven":
        native = MavenVersion
    elif ecosystem.lower() == "rubygems":
        native = RubyGemsVersion
    raw = (
        queried_version.removeprefix("v")
        if ecosystem.lower() == "go"
        else queried_version
    )
    if queried_version in evidence.versions:
        return "affected", "Exact affected-version assertion"
    current = native(queried_version) if native else None
    incomparable = False
    if native is not None and evidence.versions:
        for version in evidence.versions:
            try:
                if current == native(version):
                    return "affected", "Ecosystem-normalized affected-version assertion"
            except ValueError:
                incomparable = True
    for interval in evidence.ranges:
        try:
            if interval.includes(raw):
                return "affected", "Within a supported affected-version range"
        except ValueError:
            incomparable = True
    if evidence.unsupported or evidence.incomplete_entries or incomparable:
        return "unknown", "Missing or unsupported version evidence for this package"
    if native is None and evidence.versions:
        return (
            "unknown",
            "Ecosystem version equality is unsupported for nonliteral versions",
        )
    if not evidence.ranges and not evidence.versions:
        return "unknown", "No affected-version assertions were supplied"
    return "not-affected", "Outside the supplied comparable ranges and version list"


def _json_size(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, ensure_ascii=True).encode("utf-8"))


def _severity_metadata(
    detail: Mapping[str, Any], package: str, ecosystem: str, version: str
) -> tuple[dict[str, Any], list[Diagnostic]]:
    """Retain bounded provider scores without interpreting their scoring method."""
    advisory_id = str(detail["id"])
    affected = detail.get("affected", [])
    incomplete = not isinstance(affected, list)
    entries = affected[:4096] if isinstance(affected, list) else []
    scopes_omitted = (
        max(0, len(affected) - len(entries)) if isinstance(affected, list) else 0
    )
    incomplete |= bool(scopes_omitted)
    nested = any(isinstance(entry, dict) and "severity" in entry for entry in entries)
    conflict = "severity" in detail and nested
    incomplete |= conflict
    assertions: list[dict[str, Any]] = []
    effective: list[dict[str, Any]] = []
    remaining_scores = MAX_SEVERITY_SCORES
    remaining_bytes = MAX_SEVERITY_BYTES - 2
    work = [4096]
    assertions_omitted = 0
    scores_omitted = 0

    def retain(raw: Any, field: str, coordinate: Any, status: str, reason: str) -> None:
        nonlocal incomplete, remaining_scores, remaining_bytes
        nonlocal assertions_omitted, scores_omitted
        valid_scores: list[dict[str, Any]] = []
        if isinstance(raw, list):
            retained = raw[:remaining_scores]
            omitted = len(raw) - len(retained)
            scores_omitted += omitted
            remaining_scores -= len(retained)
            incomplete |= bool(omitted)
            for score in retained:
                if (
                    isinstance(score, dict)
                    and isinstance(score.get("type"), str)
                    and bool(score["type"])
                    and isinstance(score.get("score"), str)
                    and bool(score["score"])
                    and ("source" not in score or isinstance(score["source"], str))
                ):
                    valid_scores.append(score)
                else:
                    incomplete = True
        else:
            if remaining_scores < 1:
                incomplete = True
                assertions_omitted += 1
                scores_omitted += 1
                return
            remaining_scores -= 1
            retained = raw
            incomplete = True
        assertion = {
            "advisory_id": advisory_id,
            "field": field,
            "package": coordinate,
            "applicability": "unknown" if conflict else status,
            "reason": "Top-level and package-level severity conflict in this source record."
            if conflict
            else reason,
            "severity": retained,
        }
        try:
            size = _json_size(assertion) + 2
        except (TypeError, ValueError, RecursionError):
            size = remaining_bytes + 1
        if size > remaining_bytes:
            incomplete = True
            assertions_omitted += 1
            scores_omitted += len(retained) if isinstance(retained, list) else 1
            return
        remaining_bytes -= size
        assertions.append(assertion)
        if status == "unknown":
            incomplete = True
        if status == "affected" and not conflict:
            effective.extend(valid_scores)

    if "severity" in detail:
        retain(
            detail["severity"],
            "/severity",
            None,
            "unknown" if scopes_omitted else "affected",
            "Affected-entry inspection exceeded its work budget."
            if scopes_omitted
            else "Top-level source score applies to the queried vulnerability.",
        )
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or "severity" not in entry:
            work[0] -= 1
            continue
        coordinate = entry.get("package")
        if not isinstance(coordinate, dict) or not all(
            isinstance(coordinate.get(key), str) and coordinate[key]
            for key in ("ecosystem", "name")
        ):
            work[0] -= 1
            status, reason = (
                "unknown",
                "A package coordinate is unavailable for this score.",
            )
        elif coordinate["ecosystem"].lower() != ecosystem.lower() or (
            coordinate["name"] != "*"
            and normalize_package(coordinate["name"], ecosystem) != package
        ):
            work[0] -= 1
            status, reason = (
                "not-affected",
                "This score describes a different package coordinate.",
            )
        else:
            try:
                status, reason = match_affected_version(
                    {"affected": [entry]},
                    package,
                    ecosystem,
                    version,
                    _work_budget=work,
                )
            except (TypeError, ValueError) as exc:
                status, reason = "unknown", str(exc)
        retain(
            entry["severity"], f"/affected/{index}/severity", coordinate, status, reason
        )
    incomplete |= work[0] < 0
    metadata: dict[str, Any] = {
        "severity": effective,
        "severity_assertions": assertions,
        "severity_status": "incomplete"
        if incomplete
        else "reported"
        if effective
        else "not-provided",
    }
    for field, omitted in (
        ("severity_assertions_omitted", assertions_omitted),
        ("severity_scores_omitted", scores_omitted),
        ("severity_scopes_omitted", scopes_omitted),
    ):
        if omitted:
            metadata[field] = omitted
    return metadata, (
        [
            Diagnostic(
                code="osv.incomplete-severity",
                severity="warning",
                message=f"OSV advisory {advisory_id} has malformed, conflicting, unknown-scope or over-budget severity assertions; retained bounded source assertions. Severity metadata is incomplete; affected-version matching is unchanged.",
            )
        ]
        if incomplete
        else []
    )


def _fix_metadata(
    detail: Mapping[str, Any], package: str, ecosystem: str, queried_version: str
) -> tuple[dict[str, Any], bool]:
    """Return fix assertions and whether version evidence can constrain a group."""
    evidence = _version_evidence(detail, package, ecosystem)
    fixes, ranges, listed_versions = evidence.fixes, evidence.ranges, evidence.versions
    unsupported, schemes = evidence.unsupported, evidence.schemes

    def unknown(
        reason: str, *, comparable: bool = False
    ) -> tuple[dict[str, Any], bool]:
        return {
            "fix_version": None,
            "fix_versions": fixes,
            "fix_version_status": "unknown",
            "fix_version_reason": reason,
        }, comparable

    if evidence.incomplete_entries:
        return unknown(
            "A matching package entry has no affected-version evidence; its unknown coverage prevents a fix candidate."
        )
    if unsupported or len(schemes) > 1:
        return unknown("Range ordering is unsupported or uses mixed version schemes.")
    if not ranges:
        return unknown(
            "No comparable package-version ranges establish a fixed boundary.",
            comparable=queried_version in listed_versions,
        )
    parse = ranges[0].parse
    # Go's native lists and ECOSYSTEM boundaries may use v; SEMVER boundaries
    # were validated without it. Normalize comparison operands, not assertions.
    if ecosystem.lower() == "go" and schemes == {"semver"}:
        parse = _go_version
    current = parse(_version_text(queried_version))
    listed = {parse(v) for v in listed_versions}
    comparison = (
        queried_version.removeprefix("v")
        if ecosystem.lower() == "go"
        else queried_version
    )
    if current not in listed and not any(r.includes(comparison) for r in ranges):
        return unknown(
            "Advisory details do not establish this queried version's affected range."
        )
    candidates = sorted({(parse(raw), raw) for raw in fixes})
    work = 0
    for candidate, raw in candidates:
        if candidate <= current or candidate in listed:
            continue
        work += sum(len(r.events) + len(r.limits) for r in ranges)
        if work > 65536:
            raise ValueError("advisory fix comparison exceeds the work budget")
        comparison = raw.removeprefix("v") if ecosystem.lower() == "go" else raw
        if not any(r.includes(comparison) for r in ranges):
            return {
                "fix_version": raw,
                "fix_versions": fixes,
                "fix_version_status": "candidate",
                "fix_version_reason": "Forward fixed boundary outside this advisory's known affected ranges; compatibility and other advisories are unverified.",
            }, True
    return unknown(
        "No forward fixed boundary outside all known affected ranges was established.",
        comparable=True,
    )


def _merge_severity_metadata(
    members: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[Diagnostic]]:
    assertions: list[dict[str, Any]] = []
    scores: dict[str, dict[str, Any]] = {}
    assertion_bytes = score_bytes = MAX_SEVERITY_BYTES - 2
    remaining = MAX_GROUP_SEVERITY_ASSERTIONS
    omissions = {
        field: sum(member.get(field, 0) for member in members)
        for field in (
            "severity_assertions_omitted",
            "severity_scores_omitted",
            "severity_scopes_omitted",
        )
    }
    effective_omitted = 0
    projection_incomplete = False
    for member in members:
        for assertion in member.get("severity_assertions", []):
            raw = assertion["severity"]
            count = max(1, len(raw)) if isinstance(raw, list) else 1
            if len(assertions) >= MAX_GROUP_SEVERITY_ASSERTIONS or remaining < 1:
                omissions["severity_assertions_omitted"] += 1
                omissions["severity_scores_omitted"] += (
                    len(raw) if isinstance(raw, list) else 1
                )
                projection_incomplete = True
                continue
            projected = assertion
            if count > remaining:
                projected = {**assertion, "severity": raw[:remaining]}
                omissions["severity_scores_omitted"] += count - remaining
                projection_incomplete = True
                count = remaining
            size = _json_size(projected) + 2
            if size > assertion_bytes:
                omissions["severity_assertions_omitted"] += 1
                omissions["severity_scores_omitted"] += (
                    len(projected["severity"])
                    if isinstance(projected["severity"], list)
                    else 1
                )
                projection_incomplete = True
                continue
            assertion_bytes -= size
            remaining -= count
            assertions.append(projected)
        for score in member.get("severity", []):
            key = json.dumps(score, sort_keys=True)
            if key in scores:
                continue
            size = len(key.encode("utf-8")) + 2
            if len(scores) >= MAX_GROUP_SEVERITY_ASSERTIONS or size > score_bytes:
                effective_omitted += 1
                projection_incomplete = True
                continue
            score_bytes -= size
            scores[key] = score
    incomplete = projection_incomplete or any(
        member.get("severity_status") == "incomplete" for member in members
    )
    metadata: dict[str, Any] = {
        "severity": [scores[key] for key in sorted(scores)],
        "severity_assertions": assertions,
        "severity_status": "incomplete"
        if incomplete
        else "reported"
        if scores
        else "not-provided",
        **{field: count for field, count in omissions.items() if count},
        **(
            {"severity_effective_omitted": effective_omitted}
            if effective_omitted
            else {}
        ),
    }
    return metadata, (
        [
            Diagnostic(
                code="osv.severity-group-incomplete",
                severity="warning",
                message=f"Alias group {members[0]['id']} exceeded its 4096-score or 256 KiB severity projection budget; inspect per-source advisories for all retained assertions. Severity metadata is incomplete.",
            )
        ]
        if projection_incomplete
        else []
    )


def group_aliases(
    issues: list[dict[str, Any]],
    details: Mapping[str, tuple[dict[str, Any], Diagnostic | None]],
    package: str,
    ecosystem: str,
    version: str,
) -> tuple[list[dict[str, Any]], list[Diagnostic]]:
    # Only aliases assert equivalence; related/upstream records stay distinct.
    parents: dict[str, str] = {}

    def find(identifier: str) -> str:
        parents.setdefault(identifier, identifier)
        root = identifier
        while parents[root] != root:
            root = parents[root]
        while parents[identifier] != identifier:
            previous = parents[identifier]
            parents[identifier] = root
            identifier = previous
        return root

    for issue in issues:
        for alias in issue.get("aliases", []):
            parents[find(alias)] = find(issue["id"])
    groups: dict[str, list[dict[str, Any]]] = {}
    for issue in issues:
        groups.setdefault(find(issue["id"]), []).append(issue)

    result: list[dict[str, Any]] = []
    diagnostics: list[Diagnostic] = []
    for members in groups.values():
        members = sorted(members, key=lambda member: member["id"])
        if len(members) == 1:
            result.append(members[0])
            continue
        available = [m for m in members if details.get(m["id"], ({}, None))[0]]
        primary = (available or members)[0]
        identifiers = {
            identifier
            for member in members
            for identifier in [member["id"], *member.get("aliases", [])]
        }
        merged = {
            **primary,
            "aliases": sorted(identifiers - {primary["id"]}),
            "advisory_ids": [member["id"] for member in members],
            "advisories": members,
            "grouping_basis": "osv-aliases",
        }
        for field in ("cve_ids", "cwe_ids"):
            merged[field] = sorted(
                {identifier for member in members for identifier in member[field]}
            )
        merged["weaknesses_status"] = (
            "incomplete"
            if any(m["weaknesses_status"] == "incomplete" for m in members)
            else "reported"
            if merged["cwe_ids"]
            else "not-provided"
        )
        references: list[dict[str, str]] = []
        omitted = 0
        for member in members:
            assertions = member["identifier_references"]
            retained = assertions[: 4096 - len(references)]
            references.extend(retained)
            omitted += len(assertions) - len(retained)
        merged["identifier_references"] = references
        if omitted:
            merged["identifier_references_omitted"] = omitted
            diagnostics.append(
                Diagnostic(
                    code="osv.identifier-group-incomplete",
                    severity="warning",
                    message=f"Alias group {primary['id']} omitted {omitted} identifier references from its 4096-entry projection; inspect per-source advisories for all assertions.",
                )
            )
        # Withdrawal and timestamps describe individual source records.
        # The representative's dates do not describe the whole group.
        for field in ("withdrawn", "published", "modified"):
            merged.pop(field, None)
        severity, severity_diagnostics = _merge_severity_metadata(members)
        merged.update(severity)
        diagnostics.extend(severity_diagnostics)
        merged["fix_versions"] = sorted(
            {fix for member in members for fix in member.get("fix_versions", [])}
        )
        merged["fix_version"] = None
        merged["fix_version_status"] = "unknown"
        merged["fix_version_reason"] = (
            "Some alias-linked details are unavailable; inspect source advisories and diagnostics."
        )
        if len(available) == len(members):
            try:
                comparable = True
                for member in members:
                    if member.get("fix_version_status") != "candidate":
                        metadata, supported = _fix_metadata(
                            details[member["id"]][0], package, ecosystem, version
                        )
                        if not supported:
                            merged["fix_version_reason"] = (
                                f"Alias source {member['id']}: {metadata['fix_version_reason']}"
                            )
                            comparable = False
                            break
                if not comparable:
                    result.append(merged)
                    continue
                affected: list[Any] = []
                for member in members:
                    assertions = details[member["id"]][0].get("affected", [])
                    if len(affected) + len(assertions) > 4096:
                        raise ValueError(
                            "alias-group fix metadata exceeds the 4096-item budget"
                        )
                    affected.extend(assertions)
                metadata, _ = _fix_metadata(
                    {"affected": affected}, package, ecosystem, version
                )
                merged.update(metadata)
                if merged["fix_version_status"] == "candidate":
                    merged["fix_version_reason"] = (
                        "Forward fixed boundary outside every alias-linked source's known affected ranges and versions; compatibility and unrelated advisories are unverified."
                    )
            except (ValueError, TypeError) as exc:
                merged["fix_version_reason"] = str(exc)
                diagnostics.append(
                    Diagnostic(
                        code="osv.alias-group-incomplete",
                        severity="error",
                        message=f"Cannot establish a combined fix candidate for {primary['id']}: {exc}",
                    )
                )
        result.append(merged)
    return sorted(result, key=lambda issue: issue["id"]), diagnostics


def invalid_result(package: str, reason: str) -> Diagnostic:
    return Diagnostic(
        code="osv.invalid-response",
        severity="error",
        message=f"Invalid OSV result for {package}: {reason}",
    )


def parse_advisory(
    detail: Mapping[str, Any],
    package: str,
    ecosystem: str,
    queried_version: str,
) -> tuple[dict[str, Any], list[Diagnostic]]:
    identifiers, identifier_diagnostic = identifier_metadata(detail)
    diagnostics = [identifier_diagnostic] if identifier_diagnostic else []
    severity, severity_diagnostics = _severity_metadata(
        detail, package, ecosystem, queried_version
    )
    diagnostics.extend(severity_diagnostics)
    try:
        fixes, _ = _fix_metadata(detail, package, ecosystem, queried_version)
    except (ValueError, TypeError) as exc:
        fixes = {
            "fix_version": None,
            "fix_versions": [],
            "fix_version_status": "unknown",
            "fix_version_reason": str(exc),
        }
        diagnostics.append(invalid_result(str(detail.get("id")), str(exc)))
    return {
        "id": str(detail.get("id") or "unknown"),
        "summary": str(
            detail.get("summary") or detail.get("details") or "No summary available"
        ),
        **severity,
        "aliases": list(detail.get("aliases", []) or []),
        **fixes,
        **identifiers,
        "published": detail.get("published"),
        "modified": detail.get("modified"),
        **({"withdrawn": detail["withdrawn"]} if "withdrawn" in detail else {}),
    }, diagnostics


def normalize_package(package: str, ecosystem: str) -> str:
    if ecosystem.lower() == "pypi":
        return str(canonicalize_name(package))
    return package
