from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, ClassVar
from urllib.parse import quote

import requests  # type: ignore[import-untyped]
from packaging.utils import canonicalize_name
from packaging.version import Version
from semver import Version as SemVersion

from depcheck._version import USER_AGENT
from depcheck.model import Diagnostic


def _timestamp(value: Any) -> tuple[datetime, Decimal]:
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


@dataclass(frozen=True, slots=True)
class OSVScanResult:
    """批量安全扫描结果；diagnostics 非空时不会伪装成安全通过。"""

    vulnerabilities: dict[str, list[dict[str, Any]]]
    diagnostics: tuple[Diagnostic, ...]
    queried: dict[str, str]

    @property
    def complete(self) -> bool:
        return not any(item.severity == "error" for item in self.diagnostics)


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


def _identifier_metadata(
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


def _version_evidence(
    detail: Mapping[str, Any], package: str, ecosystem: str
) -> _VersionEvidence:
    """Parse one package's bounded assertions for matching and fix selection."""
    fixes: list[str] = []
    ranges: list[_VersionRange] = []
    listed_versions: list[str] = []
    unsupported = False
    schemes: set[str] = set()
    remaining = 4096
    incomplete_entries = False
    matched_package = False

    def array(value: Any) -> list[Any]:
        nonlocal remaining
        if not isinstance(value, list):
            raise ValueError("affected/ranges/events/versions must be arrays")
        remaining -= len(value)
        if remaining < 0:
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
            and OSVClient._normalize_package(coordinate["name"], ecosystem) != package
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
                if event_kind == "limit":
                    limits.append(None if "*" in raw else parse(raw))
                else:
                    boundary = (
                        None
                        if event_kind == "introduced" and raw == "0"
                        else parse(raw)
                    )
                    events.append((boundary, event_kind))
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
    detail: Mapping[str, Any], package: str, ecosystem: str, queried_version: str
) -> tuple[str, str]:
    """Return affected/not-affected/unknown within the supplied record only.

    Membership does not require a forward fix. A supported positive assertion
    remains useful alongside unsupported ranges; unsupported negative coverage
    cannot establish a nonmatch. Native equality never uses generic lexical order.
    """
    evidence = _version_evidence(detail, package, ecosystem)
    queried_version = _version_text(queried_version)
    if not evidence.matched_package:
        return "unknown", "No matching package assertion"
    native: Callable[[str], Any] | None = None
    if ecosystem.lower() == "pypi":
        native = Version
    elif ecosystem.lower() in {"npm", "crates.io", "go"}:
        native = SemVersion.parse
    raw = (
        queried_version.removeprefix("v")
        if ecosystem.lower() == "go"
        else queried_version
    )
    current = native(raw) if native else None
    if queried_version in evidence.versions:
        return "affected", "Exact affected-version assertion"
    if native is not None and evidence.versions:
        versions = (
            version.removeprefix("v") if ecosystem.lower() == "go" else version
            for version in evidence.versions
        )
        if any(current == native(version) for version in versions):
            return "affected", "Ecosystem-normalized affected-version assertion"
    if any(interval.includes(raw) for interval in evidence.ranges):
        return "affected", "Within a supported affected-version range"
    if evidence.unsupported or evidence.incomplete_entries:
        return "unknown", "Missing or unsupported version evidence for this package"
    if native is None and evidence.versions:
        return (
            "unknown",
            "Ecosystem version equality is unsupported for nonliteral versions",
        )
    if not evidence.ranges and not evidence.versions:
        return "unknown", "No affected-version assertions were supplied"
    return "not-affected", "Outside the supplied comparable ranges and version list"


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

    if unsupported or len(schemes) > 1:
        return unknown("Range ordering is unsupported or uses mixed version schemes.")
    if not ranges:
        return unknown(
            "No comparable package-version ranges establish a fixed boundary.",
            comparable=queried_version in listed_versions,
        )
    parse = ranges[0].parse
    # OSV SEMVER boundaries have no v prefix; Go module queries commonly do.
    if ecosystem.lower() == "go" and schemes == {"semver"}:
        queried_version = queried_version.removeprefix("v")
    current = parse(_version_text(queried_version))
    listed = {parse(v) for v in listed_versions}
    if current not in listed and not any(r.includes(queried_version) for r in ranges):
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
        if not any(r.includes(raw) for r in ranges):
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


class OSVClient:
    QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    DETAIL_BASE_URL = "https://api.osv.dev/v1/vulns"
    DEFAULT_HEADERS: ClassVar[dict[str, str]] = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }

    def __init__(
        self,
        *,
        session: Any | None = None,
        timeout_s: float = 10,
        max_attempts: int = 3,
        batch_size: int = 500,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout_s = timeout_s
        self.max_attempts = max(1, max_attempts)
        self.batch_size = max(1, batch_size)
        self.sleep = sleep
        self._detail_cache: dict[str, dict[str, Any]] = {}

    def scan(self, packages: Mapping[str, str]) -> OSVScanResult:
        return self.scan_ecosystem(packages, "PyPI")

    def _group_aliases(
        self,
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
            scores = {
                json.dumps(score, sort_keys=True): score
                for member in members
                for score in member.get("severity", [])
            }
            merged["severity"] = [scores[key] for key in sorted(scores)]
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

    def scan_ecosystem(
        self,
        packages: Mapping[str, str],
        ecosystem: str,
    ) -> OSVScanResult:
        queried: dict[str, str] = {}
        for package, version in packages.items():
            normalized = self._normalize_package(str(package), ecosystem)
            if version:
                queried[normalized] = str(version)

        if not queried:
            return OSVScanResult({}, (), queried)

        ids_by_package: dict[str, list[str]] = {package: [] for package in queried}
        pending = [
            (
                package,
                {
                    "package": {"name": package, "ecosystem": ecosystem},
                    "version": version,
                },
            )
            for package, version in queried.items()
        ]
        diagnostics: list[Diagnostic] = []
        seen_tokens: dict[str, set[str]] = {package: set() for package in queried}
        revisions: dict[str, tuple[datetime, Decimal]] = {}
        unversioned: set[str] = set()
        observed_at = datetime.now(timezone.utc)
        observation = (
            observed_at.replace(microsecond=0),
            Decimal(f"0.{observed_at.microsecond:06d}"),
        )

        # querybatch 的分页令每个查询拥有独立 token，因此下一轮只重发未完成项。
        while pending:
            next_page: list[tuple[str, dict[str, Any]]] = []
            for offset in range(0, len(pending), self.batch_size):
                chunk = pending[offset : offset + self.batch_size]
                payload = {"queries": [query for _, query in chunk]}
                data, diagnostic = self._request_json(
                    "post", self.QUERY_BATCH_URL, payload
                )
                if diagnostic is not None:
                    diagnostics.append(diagnostic)
                    continue

                results = data.get("results") if data else None
                if not isinstance(results, list) or len(results) != len(chunk):
                    diagnostics.append(
                        Diagnostic(
                            code="osv.invalid-response",
                            severity="error",
                            message="OSV 批量响应数量与查询数量不一致",
                        )
                    )
                    continue

                for (package, query), result in zip(chunk, results):
                    if not isinstance(result, dict):
                        diagnostics.append(
                            Diagnostic(
                                code="osv.invalid-response",
                                severity="error",
                                message=f"OSV 返回了无效结果：{package}",
                            )
                        )
                        continue
                    vulns = result.get("vulns", [])
                    if not isinstance(vulns, list):
                        diagnostics.append(
                            self._invalid_result(package, "vulns must be an array")
                        )
                        continue
                    for item in vulns:
                        if (
                            not isinstance(item, dict)
                            or not isinstance(item.get("id"), str)
                            or not item["id"]
                        ):
                            diagnostics.append(
                                self._invalid_result(
                                    package, "vulnerability id is missing"
                                )
                            )
                            continue
                        vuln_id = item["id"]
                        if vuln_id not in ids_by_package[package]:
                            ids_by_package[package].append(vuln_id)
                        revision = None
                        if "modified" in item:
                            try:
                                revision = _timestamp(item["modified"])
                            except ValueError as exc:
                                diagnostics.append(
                                    self._invalid_result(vuln_id, str(exc))
                                )
                        if revision is None:
                            unversioned.add(vuln_id)
                        else:
                            revisions[vuln_id] = max(
                                revisions.get(vuln_id, revision), revision
                            )
                    token = result.get("next_page_token")
                    if token:
                        if not isinstance(token, str) or token in seen_tokens[package]:
                            diagnostics.append(
                                self._invalid_result(
                                    package, "invalid or repeated pagination token"
                                )
                            )
                            continue
                        seen_tokens[package].add(token)
                        next_page.append((package, {**query, "page_token": token}))
            pending = next_page

        vulnerabilities: dict[str, list[dict[str, Any]]] = {}
        # Share one observation across packages in this batch, even when no
        # usable revision was supplied. Unversioned details do not cross calls.
        observed_details: dict[str, tuple[dict[str, Any], Diagnostic | None]] = {}
        for package, vuln_ids in ids_by_package.items():
            issues: list[dict[str, Any]] = []
            for vuln_id in vuln_ids:
                if vuln_id not in observed_details:
                    observed_details[vuln_id] = self._get_detail(
                        vuln_id,
                        revisions.get(vuln_id),
                        allow_cached=vuln_id not in unversioned,
                    )
                detail, diagnostic = observed_details[vuln_id]
                if diagnostic is not None:
                    diagnostics.append(diagnostic)
                    identifiers, _ = _identifier_metadata({"id": vuln_id})
                    issues.append(
                        {
                            "id": vuln_id,
                            "summary": "Vulnerability details unavailable",
                            "severity": [],
                            "aliases": [],
                            "fix_version": None,
                            "fix_versions": [],
                            "fix_version_status": "unknown",
                            "fix_version_reason": "Vulnerability details unavailable or invalid.",
                            **identifiers,
                            "weaknesses_status": "incomplete",
                        }
                    )
                    continue
                if "withdrawn" in detail:
                    if _timestamp(detail["withdrawn"]) <= observation:
                        diagnostics.append(
                            Diagnostic(
                                code="osv.withdrawn-advisory",
                                severity="info",
                                message=f"OSV advisory {vuln_id} was withdrawn at {detail['withdrawn']}; excluded this record from active findings.",
                            )
                        )
                        continue
                    diagnostics.append(
                        Diagnostic(
                            code="osv.withdrawal-pending",
                            severity="warning",
                            message=f"OSV advisory {vuln_id} has a future withdrawal at {detail['withdrawn']}; it remains active as of {observed_at.isoformat()}.",
                        )
                    )
                issue, detail_diagnostics = self._parse_detail(
                    detail, package, ecosystem, queried[package]
                )
                diagnostics.extend(detail_diagnostics)
                issues.append(issue)
            if issues:
                grouped, group_diagnostics = self._group_aliases(
                    issues, observed_details, package, ecosystem, queried[package]
                )
                vulnerabilities[package] = grouped
                diagnostics.extend(group_diagnostics)

        return OSVScanResult(vulnerabilities, tuple(diagnostics), queried)

    @staticmethod
    def _invalid_result(package: str, reason: str) -> Diagnostic:
        return Diagnostic(
            code="osv.invalid-response",
            severity="error",
            message=f"Invalid OSV result for {package}: {reason}",
        )

    def _get_detail(
        self,
        vuln_id: str,
        revision: tuple[datetime, Decimal] | None,
        *,
        allow_cached: bool,
    ) -> tuple[dict[str, Any], Diagnostic | None]:
        cached = self._detail_cache.get(vuln_id)
        if (
            allow_cached
            and cached is not None
            and revision is not None
            and "modified" in cached
        ):
            if _timestamp(cached["modified"]) >= revision:
                return cached, None
        # A new/unknown revision must not fall back to old metadata after a
        # failed refresh, including on a later call with an older batch result.
        self._detail_cache.pop(vuln_id, None)
        url = f"{self.DETAIL_BASE_URL}/{quote(vuln_id, safe='')}"
        data, diagnostic = self._request_json("get", url)
        if diagnostic is not None:
            return {}, diagnostic
        if not data:
            return {}, Diagnostic(
                code="osv.invalid-response",
                severity="error",
                message=f"OSV 漏洞详情为空：{vuln_id}",
            )
        if (
            data.get("id") != vuln_id
            or any(
                not isinstance(data.get(field, []), list)
                for field in ("affected", "severity", "aliases")
            )
            or len(data.get("aliases", [])) > 4096
            or any(
                not isinstance(alias, str)
                or len(alias) > 256
                or re.fullmatch(r"[a-zA-Z0-9:_.-]+", alias) is None
                for alias in data.get("aliases", [])
            )
            or any(
                not isinstance(severity, dict) for severity in data.get("severity", [])
            )
        ):
            return {}, self._invalid_result(
                vuln_id, "invalid advisory identity or fields"
            )
        try:
            detail_revision = (
                _timestamp(data["modified"]) if "modified" in data else None
            )
            if "withdrawn" in data:
                _timestamp(data["withdrawn"])
        except ValueError as exc:
            return {}, self._invalid_result(vuln_id, str(exc))
        if revision is not None and (
            detail_revision is None or detail_revision < revision
        ):
            return {}, Diagnostic(
                code="osv.stale-detail",
                severity="error",
                message=f"OSV detail for {vuln_id} is older than or lacks the querybatch revision; stale metadata was not reused.",
            )
        self._detail_cache[vuln_id] = data
        return data, None

    def _request_json(
        self,
        method: str,
        url: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, Diagnostic | None]:
        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                if method == "post":
                    response = self.session.post(
                        url,
                        json=dict(payload or {}),
                        timeout=self.timeout_s,
                        headers=self.DEFAULT_HEADERS,
                    )
                else:
                    response = self.session.get(
                        url,
                        timeout=self.timeout_s,
                        headers=self.DEFAULT_HEADERS,
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    return None, Diagnostic(
                        code="osv.invalid-response",
                        severity="error",
                        message="OSV 响应不是 JSON 对象",
                    )
                return data, None
            except (requests.RequestException, OSError) as exc:
                last_error = exc
                if attempt + 1 < self.max_attempts:
                    self.sleep(0.25 * (2**attempt))
            except (TypeError, ValueError) as exc:
                return None, Diagnostic(
                    code="osv.invalid-response",
                    severity="error",
                    message=f"无法解析 OSV 响应：{exc}",
                )

        return None, Diagnostic(
            code="osv.request-failed",
            severity="error",
            message=f"OSV 请求在 {self.max_attempts} 次尝试后失败：{last_error}",
        )

    def _parse_detail(
        self,
        detail: Mapping[str, Any],
        package: str,
        ecosystem: str,
        queried_version: str,
    ) -> tuple[dict[str, Any], list[Diagnostic]]:
        identifiers, identifier_diagnostic = _identifier_metadata(detail)
        diagnostics = [identifier_diagnostic] if identifier_diagnostic else []
        try:
            fixes, _ = _fix_metadata(detail, package, ecosystem, queried_version)
        except (ValueError, TypeError) as exc:
            fixes = {
                "fix_version": None,
                "fix_versions": [],
                "fix_version_status": "unknown",
                "fix_version_reason": str(exc),
            }
            diagnostics.append(self._invalid_result(str(detail.get("id")), str(exc)))
        return {
            "id": str(detail.get("id") or "unknown"),
            "summary": str(
                detail.get("summary") or detail.get("details") or "No summary available"
            ),
            "severity": list(detail.get("severity", []) or []),
            "aliases": list(detail.get("aliases", []) or []),
            **fixes,
            **identifiers,
            "published": detail.get("published"),
            "modified": detail.get("modified"),
            **({"withdrawn": detail["withdrawn"]} if "withdrawn" in detail else {}),
        }, diagnostics

    @staticmethod
    def _normalize_package(package: str, ecosystem: str) -> str:
        if ecosystem.lower() == "pypi":
            return str(canonicalize_name(package))
        return package
