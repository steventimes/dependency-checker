"""Release metadata access shared by the bounded resolver and its facade."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from packaging.utils import NormalizedName

from depcheck.model import Diagnostic

from .models import append_diagnostic
from .pypi_client import PyPIClient, PyPIFetchResult


class ReleaseMetadata:
    def __init__(self, client: PyPIClient) -> None:
        self.client = client

    def info(
        self,
        package: NormalizedName,
        version: str,
        diagnostics: list[Diagnostic],
    ) -> Mapping[str, Any] | None:
        result = self.fetch(str(package), version)
        if result.diagnostic is not None:
            append_diagnostic(diagnostics, result.diagnostic)
            return None
        data = result.data or {}
        info = data.get("info")
        if not isinstance(info, dict):
            append_diagnostic(
                diagnostics,
                Diagnostic(
                    code="pypi.invalid-response",
                    severity="error",
                    message=f"PyPI 元数据缺少 info 对象：{package}=={version}",
                ),
            )
            return None
        return info

    def versions(
        self,
        package: str,
    ) -> tuple[list[str], Diagnostic | None]:
        result = self.fetch(package)
        if result.diagnostic is not None:
            return [], result.diagnostic
        data = result.data or {}
        releases = data.get("releases")
        if not isinstance(releases, dict):
            return [], Diagnostic(
                code="pypi.invalid-response",
                severity="error",
                message=f"PyPI releases 不是对象：{package}",
            )

        versions: list[str] = []
        for raw, files in releases.items():
            if not isinstance(files, list) or not files:
                continue
            if any(
                isinstance(file_data, dict) and not file_data.get("yanked", False)
                for file_data in files
            ):
                versions.append(str(raw))
        return versions, None

    def fetch(
        self,
        package: str,
        version: str | None = None,
    ) -> PyPIFetchResult:
        fetch = getattr(self.client, "fetch_metadata", None)
        if callable(fetch):
            return fetch(package, version)
        legacy_fetch = getattr(self.client, "get_metadata", None)
        if callable(legacy_fetch):
            data = legacy_fetch(package, version)
            if isinstance(data, dict):
                return PyPIFetchResult(data)
        return PyPIFetchResult(
            None,
            Diagnostic(
                code="pypi.metadata-unavailable",
                severity="error",
                message=f"无法读取 PyPI 元数据：{package}",
            ),
        )
