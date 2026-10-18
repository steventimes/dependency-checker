"""Content and topology fingerprints for read-only index freshness checks."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path

from depcheck.bounded_io import ReadLimitError, read_bytes
from depcheck.config import DepcheckConfig, load_project_config
from depcheck.ecosystems.commands import discover_command_files
from depcheck.ecosystems.coverage import uncovered_manifest_files
from depcheck.ecosystems.python_manifest import (
    IGNORED_DIRECTORIES as PYTHON_IGNORED_DIRECTORIES,
)
from depcheck.ecosystems.python_manifest import (
    is_requirements_file,
    parser_map,
)
from depcheck.ecosystems.static import (
    DEFAULT_EXCLUDED_DIRECTORIES,
    discover_files,
    is_excluded,
)
from depcheck.ecosystems.tool_configs import discover_tool_config_files
from depcheck.model import ANALYSIS_REVISION, EvidenceBundle
from depcheck.path_policy import require_within_project
from depcheck.profiling import measured

_ECOSYSTEM_MANIFEST_NAMES = frozenset(
    {
        "CMakeLists.txt",
        "MODULE.bazel",
        "MODULE.bazel.lock",
        "build.gradle",
        "build.gradle.kts",
        "conan.lock",
        "conanfile.py",
        "conanfile.txt",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "npm-shrinkwrap.json",
        ".npmrc",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "pom.xml",
        "vcpkg-lock.json",
        "vcpkg.json",
        "yarn.lock",
        "Cargo.toml",
        "Cargo.lock",
    }
)


_ECOSYSTEM_SOURCE_SUFFIXES = frozenset(
    {
        ".astro",
        ".bazel",
        ".c",
        ".cc",
        ".cpp",
        ".cmake",
        ".cmake.in",
        ".cxx",
        ".go",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        ".css",
        ".scss",
        ".sass",
        ".rs",
    }
)


def freshness_guard(root: Path, config: DepcheckConfig, index_path: Path) -> str:
    """One topology walk, with content hashes for potential ownership controls."""
    values = {"config": _config_digest(config)}
    control_names = (
        _ECOSYSTEM_MANIFEST_NAMES
        | set(parser_map)
        | {"pnpm-workspace.yaml", "uv.toml", "pytest.ini", ".pytest.ini", "tox.ini"}
    )
    ignored_cache = {
        index_path,
        *(Path(str(index_path) + suffix) for suffix in ("-wal", "-shm", "-journal")),
    }
    for current, directories, filenames in os.walk(
        root, topdown=True, followlinks=False
    ):
        parent = Path(current)
        directories[:] = sorted(
            d
            for d in directories
            if not (
                d in DEFAULT_EXCLUDED_DIRECTORIES
                and (d.startswith(".") or d in PYTHON_IGNORED_DIRECTORIES)
            )
            and not is_excluded(
                (parent / d).relative_to(root), config.excluded_directories
            )
        )
        for directory in tuple(directories):
            path = parent / directory
            if path.is_symlink():
                values["alias:" + path.relative_to(root).as_posix()] = os.readlink(path)
                directories.remove(directory)
        for filename in sorted(filenames):
            path = parent / filename
            if path in ignored_cache:
                continue
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                values["alias:" + relative] = os.readlink(path)
            else:
                values["file:" + relative] = (
                    _file_digest(path)
                    if filename in control_names
                    or is_requirements_file(path)
                    or path.suffix.lower()
                    in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
                    else "present"
                )
    return _mapping_digest(values)


def _freshness_unchanged(
    root: Path, config: DepcheckConfig, metadata: dict[str, str], index_path: Path
) -> bool:
    """Fall back to a full selected scan whenever topology or ownership may differ."""
    if not metadata.get("freshness_guard"):
        return False
    try:
        previous = json.loads(metadata.get("freshness_files", "null"))
        if not isinstance(previous, dict) or not all(
            isinstance(p, str) and isinstance(d, str) for p, d in previous.items()
        ):
            return False
        if metadata["freshness_guard"] != freshness_guard(root, config, index_path):
            return False
        for relative, digest in previous.items():
            path = root / relative
            require_within_project(root, path, operation="validate indexed evidence")
            current = (
                "symlink:" + os.readlink(path)
                if path.is_symlink()
                else _file_digest(path)
            )
            if current != digest:
                return False
        return True
    except (OSError, ValueError, TypeError):
        return False


def _config_digest(config: DepcheckConfig) -> str:
    payload = asdict(config)
    # 数据表结构未变时，也要使旧分析语义生成的缓存失效。
    payload["analysis_revision"] = ANALYSIS_REVISION
    payload["import_mapping"] = dict(sorted(config.import_mapping.items()))
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _manifest_digests(
    root: Path, candidates: set[str], excluded_directories: tuple[str, ...]
) -> dict[str, str]:
    result = {}
    for relative in sorted(candidates):
        if is_excluded(Path(relative), excluded_directories):
            continue
        path = require_within_project(root, root / relative, operation="hash manifest")
        if path.is_file():
            result[relative] = _file_digest(path)
    return result


@measured("hashing.files")
def _file_digest(path: Path) -> str:
    try:
        content = read_bytes(path, allow_aliases=True)
    except ReadLimitError:
        return "oversized"
    return hashlib.sha256(content).hexdigest()


def _mapping_digest(values: dict[str, str]) -> str:
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _bundle_file_digests(
    root: Path,
    bundles: tuple[EvidenceBundle, ...],
) -> dict[str, str]:
    candidates = {
        path
        for bundle in bundles
        for path in (
            *bundle.source_files,
            *bundle.evidence_files,
            *bundle.project.manifests,
            *bundle.project.locks,
        )
    }
    result: dict[str, str] = {}
    for path in candidates:
        candidate = Path(path) if Path(path).is_absolute() else root / path
        try:
            relative = candidate.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if candidate.is_file():
            result[relative] = _file_digest(candidate)
    result.update(_command_digests(root, load_project_config(root)))
    result.update(
        {
            _relative(root, p): _file_digest(p)
            for p in uncovered_manifest_files(
                root, load_project_config(root).excluded_directories
            )
        }
    )
    result.update(_tool_config_digests(root, load_project_config(root)))
    return dict(sorted(result.items()))


def _filtered_workspace_digest(
    file_digests: dict[str, str],
    config_digest: str,
    selection_digest: str,
) -> str:
    return _mapping_digest(
        {
            **{f"selected:{key}": value for key, value in file_digests.items()},
            "config": config_digest,
            "selection": selection_digest,
        }
    )


def _state_digest(
    python_digests: dict[str, str],
    manifest_digests: dict[str, str],
    config_digest: str,
    ecosystem_digests: dict[str, str] | None = None,
) -> str:
    return _mapping_digest(
        {
            **{f"python:{key}": value for key, value in python_digests.items()},
            **{f"manifest:{key}": value for key, value in manifest_digests.items()},
            **{
                f"ecosystem:{key}": value
                for key, value in (ecosystem_digests or {}).items()
            },
            "config": config_digest,
        }
    )


def _ecosystem_digests(
    root: Path,
    config: DepcheckConfig,
) -> dict[str, str]:
    paths = discover_files(
        root,
        names=_ECOSYSTEM_MANIFEST_NAMES,
        suffixes=_ECOSYSTEM_SOURCE_SUFFIXES,
        excluded_directories=config.excluded_directories,
    )
    paths = (*paths, *uncovered_manifest_files(root, config.excluded_directories))
    result = {_relative(root, path): _file_digest(path) for path in paths}
    result.update(_tool_config_digests(root, config))
    result.update(_command_digests(root, config))
    return result


def _tool_config_digests(root: Path, config: DepcheckConfig) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): "symlink:" + os.readlink(p)
        if p.is_symlink()
        else _file_digest(p)
        for p in discover_tool_config_files(
            root, {"excluded_directories": config.excluded_directories}
        )
    }


def _command_digests(root: Path, config: DepcheckConfig) -> dict[str, str]:
    settings = {"excluded_directories": config.excluded_directories}
    paths = discover_command_files(root, settings)
    result = {}
    for path in (root / ".github", root / ".github/workflows", *paths):
        unsafe_parent = False
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink():
                unsafe_parent = True
                break
        if unsafe_parent:
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = "symlink:" + os.readlink(path)
        elif path.is_file():
            result[relative] = _file_digest(path)
    return result


def _relative(root: Path, path: Path) -> str:
    relative = Path(os.path.relpath(Path(path).resolve(), root))
    if relative.parts and relative.parts[0] == "..":
        raise ValueError("path is outside the repository root")
    return relative.as_posix()
