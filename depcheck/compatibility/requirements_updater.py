from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


@dataclass(frozen=True)
class RequirementUpdate:
    file_path: Path
    updated: Dict[str, str]
    added: Dict[str, str]


class RequirementsUpdater:
    def apply(self, file_path: Path, updates: Dict[str, str]) -> RequirementUpdate:
        lines = file_path.read_text(encoding="utf-8").splitlines()
        updated: Dict[str, str] = {}
        remaining = updates.copy()
        new_lines: List[str] = []

        for line in lines:
            content, comment = self._split_comment(line)
            stripped = content.strip()

            if not stripped or stripped.startswith("-"):
                new_lines.append(line)
                continue

            try:
                req = Requirement(stripped)
            except Exception:
                new_lines.append(line)
                continue

            name = canonicalize_name(req.name)
            if name not in remaining:
                new_lines.append(line)
                continue

            new_req = self._format_requirement(req, remaining[name])
            updated[name] = remaining.pop(name)
            rebuilt = self._rebuild_line(new_req, comment)
            new_lines.append(rebuilt)

        added: Dict[str, str] = {}
        if remaining:
            new_lines.append("")
            for name, spec in sorted(remaining.items()):
                new_line = f"{name}{spec}"
                new_lines.append(new_line)
                added[name] = spec

        file_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return RequirementUpdate(file_path=file_path, updated=updated, added=added)

    @staticmethod
    def _split_comment(line: str) -> tuple[str, str]:
        if "#" not in line:
            return line, ""
        content, comment = line.split("#", 1)
        return content.rstrip(), comment.strip()

    @staticmethod
    def _format_requirement(req: Requirement, spec: str) -> str:
        base = req.name
        if req.extras:
            extras = ",".join(sorted(req.extras))
            base = f"{base}[{extras}]"
        return f"{base}{spec}"

    @staticmethod
    def _rebuild_line(content: str, comment: str) -> str:
        if comment:
            return f"{content}  # {comment}"
        return content
