from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, ClassVar
from urllib.parse import quote

import requests  # type: ignore[import-untyped]

from depcheck._version import USER_AGENT
from depcheck.model import Diagnostic

from .advisories import (
    advisory_timestamp as _timestamp,
)
from .advisories import (
    group_aliases,
    identifier_metadata,
    invalid_result,
    normalize_package,
    parse_advisory,
)
from .advisories import (
    match_affected_version as match_affected_version,
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


class OSVClient:
    _normalize_package = staticmethod(normalize_package)
    _group_aliases = staticmethod(group_aliases)
    _parse_detail = staticmethod(parse_advisory)
    _invalid_result = staticmethod(invalid_result)

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
                    identifiers, _ = identifier_metadata({"id": vuln_id})
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
