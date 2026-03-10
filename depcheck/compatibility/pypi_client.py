from __future__ import annotations

from typing import Dict, Optional, List
import logging

import requests  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class PyPIClient:
    def __init__(self, timeout_s: int = 10) -> None:
        self.timeout_s = timeout_s
        self._metadata_cache: Dict[str, Dict] = {}
        self._versions_cache: Dict[str, List[str]] = {}

    def get_metadata(self, package: str, version: Optional[str] = None) -> Optional[Dict]:
        key = f"{package}=={version}" if version else package
        if key in self._metadata_cache:
            return self._metadata_cache[key]

        url = self._build_url(package, version)
        try:
            response = requests.get(url, timeout=self.timeout_s)
            response.raise_for_status()
        except requests.RequestException as exc:
            logger.warning(f"Failed to fetch metadata for {package}: {exc}")
            return None

        data = response.json()
        self._metadata_cache[key] = data
        return data

    def get_versions(self, package: str) -> List[str]:
        if package in self._versions_cache:
            return self._versions_cache[package]

        data = self.get_metadata(package)
        if not data:
            return []

        releases = data.get("releases", {})
        versions = list(releases.keys())
        self._versions_cache[package] = versions
        return versions

    @staticmethod
    def _build_url(package: str, version: Optional[str] = None) -> str:
        if version:
            return f"https://pypi.org/pypi/{package}/{version}/json"
        return f"https://pypi.org/pypi/{package}/json"
