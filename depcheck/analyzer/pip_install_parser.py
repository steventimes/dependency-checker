from __future__ import annotations

from typing import Dict, Optional, Iterable, List
import logging
import re
import shlex

from .base_parser import BaseDependencyParser

logger = logging.getLogger(__name__)


class PipInstallParser(BaseDependencyParser):
    _PIP_INSTALL_RE = re.compile(
        r"(?:^|\s)(?:python\s+-m\s+)?pip(?:3)?\s+install\s+(?P<args>.+)",
        re.IGNORECASE,
    )
    _SKIP_NEXT = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}

    def parse(self) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}

        if not self.path.exists():
            logger.warning(f"Dependency hint file not found: {self.path}")
            return deps

        try:
            text = self.path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.error(f"Error parsing dependency hints {self.path}: {exc}")
            return deps

        for line in self._combine_lines(text.splitlines()):
            cleaned = self._strip_comments(line).strip()
            if not cleaned:
                continue

            match = self._PIP_INSTALL_RE.search(cleaned)
            if not match:
                continue

            args = match.group("args")
            self._merge_deps(deps, self._parse_args(args))

        return deps

    def _combine_lines(self, lines: Iterable[str]) -> List[str]:
        combined: List[str] = []
        buffer = ""
        for line in lines:
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            if buffer:
                combined.append(buffer + stripped)
                buffer = ""
            else:
                combined.append(stripped)
        if buffer:
            combined.append(buffer)
        return combined

    def _strip_comments(self, line: str) -> str:
        return line.split("#", 1)[0]

    def _parse_args(self, args: str) -> Dict[str, Optional[str]]:
        deps: Dict[str, Optional[str]] = {}
        try:
            tokens = shlex.split(args, posix=True)
        except ValueError:
            tokens = args.split()

        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue

            if token in self._SKIP_NEXT:
                skip_next = True
                continue

            if token.startswith("-"):
                continue

            if token.startswith(("./", "../", "/")):
                continue

            lower = token.lower()
            if "git+" in lower or lower.startswith(("http://", "https://")) or "@" in token:
                continue

            name, version = self.parse_line(token)
            name = name.split("[", 1)[0].strip().lower()
            if not name:
                continue

            if name not in deps or (deps[name] is None and version):
                deps[name] = version

        return deps

    def _merge_deps(
        self, base: Dict[str, Optional[str]], incoming: Dict[str, Optional[str]]
    ) -> None:
        for name, version in incoming.items():
            if name not in base or (base[name] is None and version):
                base[name] = version
