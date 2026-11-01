"""Report recognized evidence gaps independently of index selection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from depcheck.ecosystems.static import discover_files
from depcheck.model import Diagnostic, EvidenceBundle, SourceLocation

UNCOVERED_MANIFEST_NAMES = frozenset(
    {
        "composer.json",
        "composer.lock",
        "Gemfile",
        "Gemfile.lock",
        "pubspec.yaml",
        "pubspec.lock",
        "packages.config",
        "go.work",
        "go.work.sum",
        "settings.gradle",
        "settings.gradle.kts",
        "WORKSPACE",
        "WORKSPACE.bazel",
        "BUILD",
        "BUILD.bazel",
        "MODULE.bazel.lock",
        "pylock.toml",
    }
)
UNCOVERED_MANIFEST_SUFFIXES = frozenset(
    {
        ".csproj",
        ".fsproj",
        ".vbproj",
        ".versions.toml",
        ".gradle",
        ".gradle.kts",
        ".bzl",
    }
)


def is_pylock_file(path: Path) -> bool:
    """Recognize the PEP 751 default and named lock filename forms."""
    return re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", path.name) is not None


def uncovered_manifest_files(
    root: Path, excluded_directories: tuple[str, ...] = ()
) -> tuple[Path, ...]:
    return tuple(
        path
        for path in discover_files(
            root,
            names=UNCOVERED_MANIFEST_NAMES,
            suffixes=frozenset(
                "." + suffix.rsplit(".", 1)[1] for suffix in UNCOVERED_MANIFEST_SUFFIXES
            ),
            excluded_directories=excluded_directories,
        )
        if path.name not in {"build.gradle", "build.gradle.kts"}
        and (
            path.name in UNCOVERED_MANIFEST_NAMES
            or is_pylock_file(path)
            or any(
                path.name.lower().endswith(suffix)
                for suffix in UNCOVERED_MANIFEST_SUFFIXES
            )
        )
    )


def repository_coverage(
    root: Path,
    bundles: tuple[EvidenceBundle, ...],
    *,
    selected: bool = False,
    excluded_directories: tuple[str, ...] = (),
) -> tuple[dict[str, Any], tuple[Diagnostic, ...]]:
    catalog_files = {
        root / path
        for bundle in bundles
        if bundle.project.manager == "gradle-catalog"
        for path in bundle.project.manifests
    }
    reported_pylocks = {
        root / path
        for bundle in bundles
        if bundle.project.manager == "python"
        for path in bundle.project.locks
        if is_pylock_file(path)
    }
    diagnostics = tuple(
        Diagnostic(
            code="coverage.unsupported-manifest",
            severity="error",
            message=f"No enabled collector supplied evidence for {path.name}; dependency coverage is incomplete.",
            source=SourceLocation(path),
        )
        for path in (
            () if selected else uncovered_manifest_files(root, excluded_directories)
        )
        if path not in catalog_files and path not in reported_pylocks
    )
    gaps: dict[tuple[str, str, str], dict[str, Any]] = {}
    for diagnostic in diagnostics:
        assert diagnostic.source is not None
        path = diagnostic.source.path.relative_to(root).as_posix()
        gaps[(path, diagnostic.code, "")] = {
            "path": path,
            "reason": diagnostic.code,
            "project_id": None,
        }
    for bundle in bundles:
        for diagnostic in bundle.diagnostics:
            if diagnostic.source is None or not (
                diagnostic.code.startswith("command.")
                or diagnostic.code.startswith("usage.rust-")
                or diagnostic.code.startswith("manifest.gradle-catalog-")
                or diagnostic.code.startswith("manifest.yarn-lock-")
                or "unsupported" in diagnostic.code
                or "uncollected" in diagnostic.code
                or (
                    is_pylock_file(diagnostic.source.path)
                    and diagnostic.severity == "error"
                )
                or diagnostic.code
                in {
                    "resolution.cargo-activation-unknown",
                    "resolution.package-manager-ambiguous",
                    "resolution.workspace-ambiguous",
                    "resolution.uv-workspace-activation-unknown",
                    "resolution.pylock-activation-unknown",
                    "resolution.python-source-unverified",
                    "resolution.cmake-activation-unknown",
                    "resolution.bazel-module-graph-unknown",
                    "resolution.go-build-list-unknown",
                    "resolution.gradle-build-graph-unknown",
                    "resolution.gradle-catalog-activation-unknown",
                    "resolution.yarn-activation-unknown",
                    "resolution.script-environment-unknown",
                    "analysis.python-group-selection-unknown",
                    "analysis.python-environment-selection-unknown",
                    "resolution.hatch-environment-activation-unknown",
                    "analysis.constraint-intersection-unknown",
                    "configuration.go-tool-owner-unresolved",
                    "configuration.go-tool-budget",
                    "manifest.cmake-dynamic",
                }
            ):
                continue
            candidate = diagnostic.source.path
            try:
                path = (
                    candidate.relative_to(root).as_posix()
                    if candidate.is_absolute()
                    else candidate.as_posix()
                )
            except ValueError:
                continue
            gaps[(path, diagnostic.code, bundle.project.project_id)] = {
                "path": path,
                "reason": diagnostic.code,
                "project_id": bundle.project.project_id,
            }
        for capability in bundle.capabilities:
            if capability.state.value == "unsupported":
                path = bundle.project.root.as_posix()
                reason = f"capability.{capability.name}-unsupported"
                gaps[(path, reason, bundle.project.project_id)] = {
                    "path": path,
                    "reason": reason,
                    "project_id": bundle.project.project_id,
                }
    return {
        "scope": "selection" if selected else "repository",
        "uncovered": [value for _, value in sorted(gaps.items())],
    }, diagnostics
