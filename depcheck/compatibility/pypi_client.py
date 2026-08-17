from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

import requests  # type: ignore[import-untyped]
from packaging.utils import canonicalize_name

from depcheck.model import Diagnostic

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PyPIFetchResult:
    data: dict[str, Any] | None
    diagnostic: Diagnostic | None = None

    @property
    def complete(self) -> bool:
        return self.diagnostic is None


class PyPIClient:
    DEFAULT_HEADERS: ClassVar[dict[str, str]] = {
        "Accept": "application/json",
        "User-Agent": "depcheck/0.3 (+https://pypi.org/project/depcheck/)",
    }

    def __init__(
        self,
        timeout_s: float = 10,
        *,
        session: Any | None = None,
        max_attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout_s = timeout_s
        self.session = session or requests.Session()
        self.max_attempts = max(1, max_attempts)
        self.sleep = sleep
        self._metadata_cache: dict[str, dict[str, Any]] = {}
        self._versions_cache: dict[str, list[str]] = {}

    def fetch_metadata(
        self, package: str, version: str | None = None
    ) -> PyPIFetchResult:
        normalized = str(canonicalize_name(package))
        key = f"{normalized}=={version}" if version else normalized
        if key in self._metadata_cache:
            return PyPIFetchResult(self._metadata_cache[key])

        url = self._build_url(normalized, version)
        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout_s,
                    headers=self.DEFAULT_HEADERS,
                )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    return PyPIFetchResult(
                        None,
                        Diagnostic(
                            code="pypi.invalid-response",
                            severity="error",
                            message=f"PyPI 元数据不是 JSON 对象：{normalized}",
                        ),
                    )
                self._metadata_cache[key] = data
                return PyPIFetchResult(data)
            except (requests.RequestException, OSError) as exc:
                last_error = exc
                if attempt + 1 < self.max_attempts:
                    self.sleep(0.25 * (2**attempt))
            except (TypeError, ValueError) as exc:
                return PyPIFetchResult(
                    None,
                    Diagnostic(
                        code="pypi.invalid-response",
                        severity="error",
                        message=f"无法解析 PyPI 元数据 {normalized}：{exc}",
                    ),
                )

        return PyPIFetchResult(
            None,
            Diagnostic(
                code="pypi.request-failed",
                severity="error",
                message=f"PyPI 请求在 {self.max_attempts} 次尝试后失败：{last_error}",
            ),
        )

    def get_metadata(self, package: str, version: str | None = None) -> dict | None:
        """旧兼容接口；新调用方应读取 fetch_metadata 的诊断。"""
        result = self.fetch_metadata(package, version)
        if result.diagnostic is not None:
            logger.warning(result.diagnostic.message)
        return result.data

    def get_versions(self, package: str) -> list[str]:
        normalized = str(canonicalize_name(package))
        if normalized in self._versions_cache:
            return self._versions_cache[normalized]

        data = self.get_metadata(normalized)
        if not data:
            return []

        releases = data.get("releases", {})
        versions: list[str] = []
        if isinstance(releases, dict):
            for version, files in releases.items():
                if not isinstance(files, list) or not files:
                    continue
                # 仅当至少一个文件未撤回时，该版本才可作为升级候选。
                if any(
                    isinstance(item, dict) and not item.get("yanked", False)
                    for item in files
                ):
                    versions.append(str(version))
        self._versions_cache[normalized] = versions
        return versions

    @staticmethod
    def _build_url(package: str, version: str | None = None) -> str:
        package_part = quote(package, safe="")
        if version:
            return (
                f"https://pypi.org/pypi/{package_part}/{quote(version, safe='')}/json"
            )
        return f"https://pypi.org/pypi/{package_part}/json"
