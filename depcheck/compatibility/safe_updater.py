from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import NormalizedName, canonicalize_name

from depcheck.path_policy import require_within_project


@dataclass(frozen=True)
class RequirementUpdate:
    file_path: Path
    updated: dict[str, str]
    added: dict[str, str]


@dataclass(frozen=True)
class RequirementUpdatePlan:
    file_path: Path
    original_digest: str
    original_content: str
    updated_content: str
    updated: dict[str, str]
    added: dict[str, str]
    project_root: Path | None = None


class ConcurrentModificationError(RuntimeError):
    """计划生成后文件发生变化时拒绝覆盖。"""


class RequirementsUpdater:
    def __init__(self, project_root: Path | None = None) -> None:
        self.project_root = (
            Path(project_root).resolve() if project_root is not None else None
        )

    def plan(
        self,
        file_path: Path,
        updates: dict[str, str],
        *,
        add_missing: bool = False,
    ) -> RequirementUpdatePlan:
        path = Path(file_path)
        project_root = self.project_root or path.parent.resolve()
        require_within_project(
            project_root,
            path,
            operation="read requirements update target",
        )
        original_bytes = path.read_bytes()
        original = original_bytes.decode("utf-8")
        normalized: dict[NormalizedName, str] = {
            canonicalize_name(name): self._normalize_spec(spec)
            for name, spec in updates.items()
        }
        updated: dict[str, str] = {}
        matched: set[NormalizedName] = set()
        new_lines: list[str] = []

        for raw_line in original.splitlines(keepends=True):
            line, ending = self._without_ending(raw_line)
            content, comment = self._split_comment(line)
            indentation = content[: len(content) - len(content.lstrip())]
            stripped = content.strip()
            continuation = ""
            if stripped.endswith("\\"):
                stripped = stripped[:-1].rstrip()
                continuation = " \\"

            if not stripped or stripped.startswith("-"):
                new_lines.append(raw_line)
                continue

            try:
                requirement = Requirement(stripped)
            except InvalidRequirement:
                new_lines.append(raw_line)
                continue

            name = canonicalize_name(requirement.name)
            if name not in normalized or requirement.url is not None:
                new_lines.append(raw_line)
                continue

            marker_suffix = ""
            if ";" in stripped:
                marker_suffix = stripped[stripped.index(";") :]
            rebuilt = (
                indentation
                + self._format_requirement(requirement, normalized[name], marker_suffix)
                + continuation
                + comment
                + ending
            )
            new_lines.append(rebuilt)
            matched.add(name)
            updated[str(name)] = normalized[name]

        # splitlines 对空文件返回空数组；统一沿用原文件换行风格。
        newline = "\r\n" if "\r\n" in original else "\n"
        added: dict[str, str] = {}
        missing = {
            name: spec for name, spec in normalized.items() if name not in matched
        }
        if add_missing and missing:
            if new_lines and not new_lines[-1].endswith(("\n", "\r")):
                new_lines[-1] += newline
            for name, spec in sorted(missing.items()):
                new_lines.append(f"{name}{spec}{newline}")
                added[str(name)] = spec

        return RequirementUpdatePlan(
            file_path=path,
            original_digest=self._digest(original_bytes),
            original_content=original,
            updated_content="".join(new_lines),
            updated=updated,
            added=added,
            project_root=project_root,
        )

    def apply_plan(self, plan: RequirementUpdatePlan) -> RequirementUpdate:
        path = plan.file_path
        project_root = plan.project_root or self.project_root or path.parent.resolve()
        require_within_project(
            project_root,
            path,
            operation="read requirements update target",
        )
        current = path.read_bytes()
        if self._digest(current) != plan.original_digest:
            raise ConcurrentModificationError(
                f"{path} changed after the update plan was created"
            )

        if plan.updated_content != plan.original_content:
            require_within_project(
                project_root,
                path,
                operation="write requirements update target",
            )
            self._atomic_write(path, plan.updated_content.encode("utf-8"))
        return RequirementUpdate(path, dict(plan.updated), dict(plan.added))

    def apply(
        self,
        file_path: Path,
        updates: dict[str, str],
        *,
        add_missing: bool = False,
    ) -> RequirementUpdate:
        """兼容便捷接口；内部仍先生成计划并执行并发校验。"""
        plan = self.plan(file_path, updates, add_missing=add_missing)
        return self.apply_plan(plan)

    @staticmethod
    def _normalize_spec(spec: str) -> str:
        value = str(spec).strip()
        if value and value[0].isdigit():
            value = f"=={value}"
        try:
            SpecifierSet(value)
        except InvalidSpecifier as exc:
            raise ValueError(f"invalid update specifier {spec!r}") from exc
        return value

    @staticmethod
    def _without_ending(line: str) -> tuple[str, str]:
        if line.endswith("\r\n"):
            return line[:-2], "\r\n"
        if line.endswith(("\n", "\r")):
            return line[:-1], line[-1]
        return line, ""

    @staticmethod
    def _split_comment(line: str) -> tuple[str, str]:
        # 只有前面带空白的 # 才视为注释，避免截断 URL fragment。
        match = re.match(r"^(.*?)(\s+#.*)$", line)
        if match:
            return match.group(1), match.group(2)
        return line, ""

    @staticmethod
    def _format_requirement(
        requirement: Requirement,
        spec: str,
        marker_suffix: str = "",
    ) -> str:
        base = requirement.name
        if requirement.extras:
            extras = ",".join(sorted(requirement.extras))
            base = f"{base}[{extras}]"
        return f"{base}{spec}{marker_suffix}"

    @staticmethod
    def _digest(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        mode = stat.S_IMODE(path.stat().st_mode)
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".depcheck-",
            dir=path.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, mode)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
