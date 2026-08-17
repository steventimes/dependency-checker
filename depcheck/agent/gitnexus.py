from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_COMMIT_PATTERN = re.compile(r"\b[0-9a-fA-F]{40}\b")
_CURRENT_STATUSES = {"current", "ready", "up-to-date", "up_to_date", "uptodate"}
_MISSING_STATUSES = {"absent", "missing", "not-indexed", "not_indexed", "unindexed"}
_STALE_STATUSES = {"behind", "dirty", "out-of-date", "out_of_date", "stale"}


@dataclass(frozen=True)
class GitNexusStatus:
    """GitNexus 可选代码图的可验证状态。"""

    available: bool
    indexed: bool
    stale: bool
    head_aligned: bool | None
    index_commit: str | None = None
    current_head: str | None = None
    command: tuple[str, ...] | None = None
    status: str = "unavailable"
    remediation: str | None = None
    diagnostics: tuple[str, ...] = ()
    provider: str = "gitnexus"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        if self.command is not None:
            payload["command"] = list(self.command)
        payload["diagnostics"] = list(self.diagnostics)
        return payload


class GitNexusCompanion:
    """只读探测 GitNexus；不会下载依赖或修改其索引。"""

    def __init__(
        self,
        command: Sequence[str] | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        if command is not None and not command:
            raise ValueError("command must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.command = tuple(command) if command is not None else None
        self.timeout = timeout

    def inspect(self, project_root: Path) -> GitNexusStatus:
        root = Path(project_root).resolve()
        current_head = _git_head(
            root,
            self.timeout,
            executable=_external_path_executable(root, "git"),
        )
        command = self.command or self._resolve_command(root)
        if command is None:
            return GitNexusStatus(
                available=False,
                indexed=False,
                stale=False,
                head_aligned=None,
                current_head=current_head,
                remediation=(
                    "Install a trusted external GitNexus executable and place it on PATH."
                ),
            )

        diagnostics: list[str] = []
        try:
            structured = self._run(command, root, "status", "--json")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._failed(command, current_head, exc)

        if structured.returncode == 0:
            try:
                payload = json.loads(structured.stdout)
            except json.JSONDecodeError:
                diagnostics.append("GitNexus status --json returned invalid JSON.")
            else:
                if isinstance(payload, Mapping):
                    return self._from_structured(
                        command,
                        current_head,
                        payload,
                        diagnostics,
                    )
                diagnostics.append("GitNexus status --json did not return an object.")
        elif structured.stderr.strip():
            diagnostics.append(structured.stderr.strip())

        try:
            human = self._run(command, root, "status")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._failed(command, current_head, exc, diagnostics)
        return self._from_human(command, current_head, human, diagnostics)

    def _resolve_command(self, root: Path) -> tuple[str, ...] | None:
        executable = _external_path_executable(root, "gitnexus")
        if not executable:
            return None
        return (executable,)

    def _run(
        self,
        command: tuple[str, ...],
        root: Path,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*command, *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

    def _from_structured(
        self,
        command: tuple[str, ...],
        current_head: str | None,
        payload: Mapping[str, Any],
        diagnostics: list[str],
    ) -> GitNexusStatus:
        index_value = payload.get("index")
        index = index_value if isinstance(index_value, Mapping) else {}
        raw_status = payload.get("status", index.get("status", "unknown"))
        status = str(raw_status).strip().lower().replace(" ", "-")
        index_commit = _first_text(
            index.get("commit"),
            index.get("indexedCommit"),
            payload.get("indexedCommit"),
            payload.get("commit"),
        )
        reasons = _string_items(
            index.get("incompleteReasons", payload.get("incompleteReasons"))
        )
        runner_status = _first_text(
            index.get("runnerIdentityStatus"), payload.get("runnerIdentityStatus")
        )
        explicitly_missing = status in _MISSING_STATUSES
        indexed = not explicitly_missing and (
            bool(index) or status in _CURRENT_STATUSES or status in _STALE_STATUSES
        )
        head_aligned = (
            current_head == index_commit
            if current_head is not None and index_commit is not None
            else None
        )
        stale = indexed and (
            status not in _CURRENT_STATUSES
            or bool(reasons)
            or (runner_status is not None and runner_status.lower() != "current")
            or head_aligned is False
        )
        if reasons:
            diagnostics.extend(reasons)
        remediation = None
        if not indexed:
            remediation = "Run GitNexus analyze for this repository."
        elif stale:
            remediation = (
                "Refresh the GitNexus index before relying on code-graph results."
            )
        return GitNexusStatus(
            available=True,
            indexed=indexed,
            stale=stale,
            head_aligned=head_aligned,
            index_commit=index_commit,
            current_head=current_head,
            command=command,
            status=status,
            remediation=remediation,
            diagnostics=tuple(diagnostics),
        )

    def _from_human(
        self,
        command: tuple[str, ...],
        current_head: str | None,
        result: subprocess.CompletedProcess[str],
        diagnostics: list[str],
    ) -> GitNexusStatus:
        output = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        ).strip()
        lowered = output.lower()
        if result.returncode != 0:
            if output:
                diagnostics.append(output)
            return GitNexusStatus(
                available=True,
                indexed=False,
                stale=False,
                head_aligned=None,
                current_head=current_head,
                command=command,
                status="error",
                remediation="Run GitNexus status manually and repair its local index.",
                diagnostics=tuple(diagnostics),
            )

        indexed = not any(
            phrase in lowered
            for phrase in ("not indexed", "no index", "index missing", "unindexed")
        )
        stale = indexed and any(
            phrase in lowered
            for phrase in ("stale", "out of date", "out-of-date", "behind")
        )
        match = _COMMIT_PATTERN.search(output)
        index_commit = match.group(0).lower() if match else None
        head_aligned = (
            current_head == index_commit
            if current_head is not None and index_commit is not None
            else None
        )
        stale = stale or head_aligned is False
        return GitNexusStatus(
            available=True,
            indexed=indexed,
            stale=stale,
            head_aligned=head_aligned,
            index_commit=index_commit,
            current_head=current_head,
            command=command,
            status="stale" if stale else ("ready" if indexed else "not-indexed"),
            remediation=(
                "Refresh the GitNexus index before relying on code-graph results."
                if stale
                else (
                    "Run GitNexus analyze for this repository." if not indexed else None
                )
            ),
            diagnostics=tuple(diagnostics),
        )

    @staticmethod
    def _failed(
        command: tuple[str, ...],
        current_head: str | None,
        error: BaseException,
        diagnostics: list[str] | None = None,
    ) -> GitNexusStatus:
        details = [*(diagnostics or ()), f"{type(error).__name__}: {error}"]
        return GitNexusStatus(
            available=True,
            indexed=False,
            stale=False,
            head_aligned=None,
            current_head=current_head,
            command=command,
            status="error",
            remediation="Run GitNexus status manually and repair its local index.",
            diagnostics=tuple(details),
        )


def _first_text(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def _string_items(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [str(item) for item in value if str(item).strip()]


def _external_path_executable(root: Path, name: str) -> str | None:
    executable = shutil.which(name)
    if not executable:
        return None
    resolved = Path(executable).resolve()
    if resolved == root or root in resolved.parents:
        return None
    return str(resolved)


def _git_head(
    root: Path,
    timeout: float,
    *,
    executable: str | None,
) -> str | None:
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "-C", str(root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    head = result.stdout.strip().lower()
    return head if _COMMIT_PATTERN.fullmatch(head) else None
