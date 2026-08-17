from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

import requests  # type: ignore[import-untyped]
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.model import Diagnostic


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
    QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    DETAIL_BASE_URL = "https://api.osv.dev/v1/vulns"
    DEFAULT_HEADERS: ClassVar[dict[str, str]] = {
        "Accept": "application/json",
        "User-Agent": "depcheck/0.3 (+https://pypi.org/project/depcheck/)",
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
                    return OSVScanResult({}, tuple(diagnostics), queried)

                results = data.get("results") if data else None
                if not isinstance(results, list) or len(results) != len(chunk):
                    diagnostics.append(
                        Diagnostic(
                            code="osv.invalid-response",
                            severity="error",
                            message="OSV 批量响应数量与查询数量不一致",
                        )
                    )
                    return OSVScanResult({}, tuple(diagnostics), queried)

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
                    for item in result.get("vulns", []) or []:
                        if isinstance(item, dict) and item.get("id"):
                            vuln_id = str(item["id"])
                            if vuln_id not in ids_by_package[package]:
                                ids_by_package[package].append(vuln_id)
                    token = result.get("next_page_token")
                    if token:
                        next_page.append((package, {**query, "page_token": str(token)}))
            pending = next_page

        vulnerabilities: dict[str, list[dict[str, Any]]] = {}
        for package, vuln_ids in ids_by_package.items():
            issues: list[dict[str, Any]] = []
            for vuln_id in vuln_ids:
                detail, diagnostic = self._get_detail(vuln_id)
                if diagnostic is not None:
                    diagnostics.append(diagnostic)
                    issues.append(
                        {
                            "id": vuln_id,
                            "summary": "Vulnerability details unavailable",
                            "severity": [],
                            "aliases": [],
                            "fix_version": None,
                        }
                    )
                    continue
                issues.append(self._parse_detail(detail, package, ecosystem))
            if issues:
                vulnerabilities[package] = issues

        return OSVScanResult(vulnerabilities, tuple(diagnostics), queried)

    def _get_detail(self, vuln_id: str) -> tuple[dict[str, Any], Diagnostic | None]:
        if vuln_id in self._detail_cache:
            return self._detail_cache[vuln_id], None
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
    ) -> dict[str, Any]:
        fix_versions: list[str] = []
        for affected in detail.get("affected", []) or []:
            if not isinstance(affected, dict):
                continue
            affected_package = affected.get("package") or {}
            affected_name = (
                affected_package.get("name")
                if isinstance(affected_package, dict)
                else None
            )
            affected_ecosystem = (
                affected_package.get("ecosystem")
                if isinstance(affected_package, dict)
                else None
            )
            if (
                affected_ecosystem
                and str(affected_ecosystem).lower() != ecosystem.lower()
            ):
                continue
            if (
                affected_name
                and self._normalize_package(str(affected_name), ecosystem) != package
            ):
                continue
            for range_data in affected.get("ranges", []) or []:
                if (
                    not isinstance(range_data, dict)
                    or range_data.get("type") != "ECOSYSTEM"
                ):
                    continue
                for event in range_data.get("events", []) or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fix_versions.append(str(event["fixed"]))

        return {
            "id": str(detail.get("id") or "unknown"),
            "summary": str(
                detail.get("summary") or detail.get("details") or "No summary available"
            ),
            "severity": list(detail.get("severity", []) or []),
            "aliases": list(detail.get("aliases", []) or []),
            "fix_version": self._lowest_version(fix_versions),
            "published": detail.get("published"),
            "modified": detail.get("modified"),
        }

    @staticmethod
    def _normalize_package(package: str, ecosystem: str) -> str:
        if ecosystem.lower() == "pypi":
            return str(canonicalize_name(package))
        return package

    @staticmethod
    def _lowest_version(versions: Sequence[str]) -> str | None:
        parsed: list[tuple[Version, str]] = []
        for raw in versions:
            try:
                parsed.append((Version(raw), raw))
            except InvalidVersion:
                continue
        if parsed:
            return min(parsed, key=lambda item: item[0])[1]
        return min(versions) if versions else None
