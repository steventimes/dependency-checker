from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True, slots=True)
class AliasResolution:
    kind: Literal["unmatched", "local", "builtin", "package", "unknown"]
    target: str | None
    reason: str


def resolve_package_import(
    reference: str,
    imports: object,
    project_root: Path,
    source_files: frozenset[Path],
    *,
    builtin_names: frozenset[str],
) -> AliasResolution:
    """Resolve against canonical source paths discovered for this project."""
    if not reference.startswith("#"):
        return AliasResolution("unmatched", None, "ordinary module specifier")
    if reference == "#" or reference.endswith("/"):
        return AliasResolution("unknown", None, "Invalid package imports specifier")
    if not isinstance(imports, Mapping) or reference not in imports or "*" in reference:
        return AliasResolution(
            "unknown", None, "No supported exact package.json imports key"
        )
    target = imports[reference]
    if (
        not isinstance(target, str)
        or not target
        or any(c in target for c in "*?#")
        or any(ord(c) < 32 for c in target)
    ):
        return AliasResolution(
            "unknown",
            None,
            "package.json imports requires a non-pattern string target; conditions, arrays and alias chains are unsupported",
        )
    segment_target = target[2:] if target.startswith("./") else target
    segments = segment_target.split("/")
    if any(
        segment.lower() in {".", "..", "node_modules", ""}
        or "%" in segment
        or "\\" in segment
        for segment in segments
    ):
        return AliasResolution(
            "unknown",
            None,
            "Invalid imports target path segment; traversal, encoded paths and node_modules are unsupported",
        )
    reason = f"package.json imports {reference!r} maps to {target!r}"
    if target.startswith("./"):
        root = project_root.resolve()
        try:
            candidate = (root / target).resolve()
            if (
                candidate.is_relative_to(root)
                and candidate in source_files
                and candidate.is_file()
            ):
                return AliasResolution("local", target, reason)
        except (OSError, RuntimeError, ValueError):
            return AliasResolution(
                "unknown", None, "Cannot safely resolve local imports target"
            )
        return AliasResolution(
            "unknown",
            None,
            "Local imports target is absent or outside safely discovered project sources",
        )
    # Unlike a source import, an imports target cannot be a node: URL.
    if target in builtin_names:
        return AliasResolution("builtin", target, reason)
    if not re.fullmatch(
        r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*", target
    ) or target.startswith((".", "/")):
        return AliasResolution(
            "unknown",
            None,
            "Unsupported imports target; expected a bare npm package or explicit local file",
        )
    parts = target.split("/")
    package = "/".join(parts[:2]) if target.startswith("@") else parts[0]
    return AliasResolution("package", package, reason)
