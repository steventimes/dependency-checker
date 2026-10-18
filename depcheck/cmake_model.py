"""Inspect supplied CMake File API replies without running CMake or shell fragments."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath
import hashlib
from typing import Any

from depcheck.bounded_io import DEFAULT_MAX_BYTES, ReadLimitError, read_bytes
from depcheck.path_policy import require_within_project
from depcheck.snapshots import parse_evidence_json

_MAX_FILES = 1_024
_MAX_BYTES = 16 * 1024 * 1024
_MAX_ITEMS = 20_000
_MAX_RECORDS = 100_000
_MAX_DIAGNOSTICS = 256
_RELATIONSHIPS = (
    "dependencies",
    "linkLibraries",
    "interfaceLinkLibraries",
    "compileDependencies",
    "interfaceCompileDependencies",
    "objectDependencies",
    "orderDependencies",
)
_TABLES = ("targets", "relationships", "sources", "command_fragments")
_TARGET_FLAGS = ("imported", "local", "abstract", "symbolic", "isGeneratorProvided")


class _BudgetError(ValueError):
    pass


class _Reader:
    def __init__(self, root: Path, index: Path) -> None:
        self.root = root
        self.directory = index.parent
        self.files: list[dict[str, Any]] = []
        self.bytes = 0
        self.attempts = 0
        self.cache: dict[Path, dict[str, Any]] = {}

    def reference(self, name: Any) -> Path:
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 4096
            or not name.endswith(".json")
            or name in {".", ".."}
            or any(c in name for c in ("/", "\\", ":"))
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("CMake reply jsonFile must be a plain JSON filename")
        return self.directory / name

    def read(self, relative: Path) -> dict[str, Any]:
        if relative in self.cache:
            return self.cache[relative]
        if self.attempts >= _MAX_FILES or self.bytes >= _MAX_BYTES:
            raise _BudgetError("CMake reply file/context budget exhausted")
        self.attempts += 1
        candidate = self.root / relative
        require_within_project(self.root, candidate, operation="inspect CMake reply")
        raw = read_bytes(
            candidate, max_bytes=min(DEFAULT_MAX_BYTES, _MAX_BYTES - self.bytes)
        )
        self.bytes += len(raw)
        self.files.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
            }
        )
        data = parse_evidence_json(raw)
        self.cache[relative] = data
        return data


def inspect_cmake_model(
    root: Path,
    index_file: str,
    *,
    configuration: str | None = None,
    target: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    if not 1 <= limit <= 200 or offset < 0:
        raise ValueError("limit must be 1..200 and offset non-negative")
    index = Path(index_file)
    if index.is_absolute() or PureWindowsPath(index_file).is_absolute():
        raise ValueError("CMake index path must be relative to the repository")
    if not (index.name.startswith("index-") and index.name.endswith(".json")):
        raise ValueError("Select an explicit CMake index-*.json reply")
    reader = _Reader(root, index)
    data = reader.read(index)
    objects = _objects(data.get("objects"), "index objects")
    candidates = [
        o
        for o in objects
        if o.get("kind") == "codemodel" and _version(o.get("version"))[0] == 2
    ]
    if len(candidates) != 1:
        raise ValueError(
            "CMake index must reference exactly one codemodel version 2 object"
        )
    reference = candidates[0]
    model_file = reader.reference(reference.get("jsonFile"))
    model = reader.read(model_file)
    version = _version(model.get("version"))
    if model.get("kind") != "codemodel" or version != _version(
        reference.get("version")
    ):
        raise ValueError(
            "CMake codemodel kind/version disagrees with its index reference"
        )
    configurations = _objects(model.get("configurations"), "configurations")
    names = [
        _string(c.get("name"), "configuration name", empty=True) for c in configurations
    ]
    if len(names) != len(set(names)):
        raise ValueError("CMake configuration names must be unique")
    if configuration is None and len(configurations) == 1:
        selected_index = 0
    elif configuration in names:
        selected_index = names.index(configuration)
    else:
        raise ValueError(f"Choose an explicit available CMake configuration: {names!r}")
    selected = configurations[selected_index]
    identities: dict[str, dict[str, Any]] = {}
    target_locations: dict[str, str] = {}
    for collection in ("targets", "abstractTargets"):
        for i, item in enumerate(_objects(selected.get(collection, []), collection)):
            identity = _string(item.get("id"), "target id")
            _string(item.get("name"), "target name")
            reader.reference(item.get("jsonFile"))
            if identity in identities:
                raise ValueError(
                    "CMake target ids must be unique within a configuration"
                )
            identities[identity] = item
            target_locations[identity] = (
                f"/configurations/{selected_index}/{collection}/{i}"
            )
    if target is not None and target not in identities:
        raise ValueError(
            "target must identify an id in the selected CMake configuration"
        )
    tables: dict[str, list[dict[str, Any]]] = {key: [] for key in _TABLES}
    diagnostics: list[dict[str, Any]] = []
    omitted = 0

    def diagnostic(code: str, message: str, path: Path) -> None:
        nonlocal omitted
        if len(diagnostics) < _MAX_DIAGNOSTICS:
            diagnostics.append(
                {
                    "code": code,
                    "severity": "warning",
                    "message": message,
                    "location": {"path": path.as_posix()},
                }
            )
        else:
            omitted += 1

    if "abstractTargets" in selected and version[1] < 9:
        diagnostic(
            "cmake-model.version-field",
            "abstractTargets requires codemodel 2.9; retained assertions have inconsistent version provenance",
            model_file,
        )
    for identity, item in identities.items():
        if target is not None and identity != target:
            continue
        path = reader.reference(item["jsonFile"])
        record = {
            "id": identity,
            "name": item["name"],
            "detail_status": "unavailable",
            "collection": target_locations[identity].split("/")[-2],
            "location": _location(model_file, target_locations[identity]),
        }
        tables["targets"].append(record)
        try:
            detail = reader.read(path)
            if detail.get("id") != identity or detail.get("name") != item["name"]:
                raise ValueError(
                    "CMake target id/name disagrees with its codemodel reference"
                )
            if (
                "codemodelVersion" in detail
                and _version(detail["codemodelVersion"]) != version
            ):
                raise ValueError(
                    "CMake target codemodelVersion disagrees with its codemodel"
                )
            rows = _target_rows(detail, path, identity)
            if (
                sum(len(v) for v in tables.values())
                + sum(len(v) for v in rows.values())
                > _MAX_RECORDS
            ):
                raise _BudgetError("CMake evidence record budget exhausted")
            for key, values in rows.items():
                tables[key].extend(values)
            record.update(
                type=_string(detail.get("type"), "target type"),
                detail_status="reported",
                reported_paths=_paths(detail.get("paths")),
                **{
                    flag: _boolean(detail.get(flag, False), flag)
                    for flag in _TARGET_FLAGS
                },
            )
            if _version_fields(detail, version[1]):
                diagnostic(
                    "cmake-model.version-field",
                    "Retained target fields have inconsistent codemodel version provenance",
                    path,
                )
            if version[1] >= 9 and "codemodelVersion" not in detail:
                diagnostic(
                    "cmake-model.version-field",
                    "Target does not report its codemodelVersion (required since 2.9)",
                    path,
                )
            if record["abstract"] != (record["collection"] == "abstractTargets"):
                diagnostic(
                    "cmake-model.target-kind",
                    "Target abstract flag disagrees with its configuration collection",
                    path,
                )
        except _BudgetError as exc:
            diagnostic("cmake-model.budget", str(exc), path)
            break
        except ReadLimitError as exc:
            diagnostic("cmake-model.budget", str(exc), path)
        except (OSError, ValueError) as exc:
            diagnostic("cmake-model.target-unavailable", str(exc), path)
    detail_states = {row["id"]: row["detail_status"] for row in tables["targets"]}
    for row in tables["relationships"]:
        for field, prefix in (
            ("id", "target"),
            ("from_dependency_id", "from_dependency"),
        ):
            if field not in row:
                continue
            row[f"{prefix}_present"] = row[field] in identities
            row[f"{prefix}_detail_status"] = "absent"
            if row[f"{prefix}_present"]:
                row[f"{prefix}_detail_status"] = detail_states.get(
                    row[field], "not-selected" if target is not None else "not-read"
                )
            else:
                diagnostic(
                    "cmake-model.target-unresolved",
                    f"Relationship {field} references absent target {row[field]!r}",
                    Path(row["location"]["path"]),
                )
    if omitted:
        diagnostics.append(
            {
                "code": "cmake-model.budget",
                "severity": "warning",
                "message": f"Omitted {omitted} additional diagnostics",
            }
        )
    tables["input_files"] = reader.files
    tables["diagnostics"] = diagnostics
    counts = {key: len(value) for key, value in tables.items()}
    more = any(n > offset + limit for n in counts.values())
    return {
        "schema": "depcheck.cmake-model.v1",
        "evidence_kind": "external-build-model",
        "index_file": index.as_posix(),
        "codemodel_version": {"major": version[0], "minor": version[1]},
        "configurations": names,
        "configuration": names[selected_index],
        "target": target,
        "reported_target_count": 1 if target is not None else len(identities),
        "omitted_target_count": (1 if target is not None else len(identities))
        - len(tables["targets"]),
        "reported_paths": _paths(model.get("paths")),
        **{key: rows[offset : offset + limit] for key, rows in tables.items()},
        "counts": counts,
        "offset": offset,
        "limit": limit,
        "truncated": more,
        "next_offset": offset + limit if more else None,
        "import_complete": not diagnostics,
        "evidence_complete": False,
        "coverage": {
            "source_freshness": "unknown",
            "build_execution": "unknown",
            "package_mapping": "unsupported",
            "security": "skipped",
            "legacy_dependencies_semantics": "build ordering, including transitive edges; not a link graph",
            "link_relationships": "supported from codemodel 2.9; absent fields do not prove no linkage",
            "uncollected": [
                "directory objects",
                "compile groups",
                "artifact contents",
                "resolved backtrace graph",
                "source contents",
                "installed packages",
                "interface include directories",
            ],
        },
    }


def _target_rows(
    data: dict[str, Any], path: Path, identity: str
) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {key: [] for key in _TABLES[1:]}
    _string(data.get("type"), "target type")
    _paths(data.get("paths"))
    for flag in _TARGET_FLAGS:
        _boolean(data.get(flag, False), flag)
    for kind in _RELATIONSHIPS:
        for i, raw in enumerate(_objects(data.get(kind, []), kind)):
            is_link = kind in {"linkLibraries", "interfaceLinkLibraries"}
            if is_link and ("id" in raw) == ("fragment" in raw):
                raise ValueError(
                    "CMake link relationship needs exactly one id or fragment"
                )
            key = "fragment" if is_link and "fragment" in raw else "id"
            value = _string(raw.get(key), f"{kind} {key}", empty=key == "fragment")
            record: dict[str, Any] = {
                "target_id": identity,
                "kind": kind,
                key: value,
                "location": _location(path, f"/{kind}/{i}"),
            }
            _backtrace(raw, record)
            if "fromDependency" in raw:
                source = raw["fromDependency"]
                if not isinstance(source, dict):
                    raise ValueError("CMake fromDependency must be an object")
                record["from_dependency_id"] = _string(
                    source.get("id"), "fromDependency id"
                )
            rows["relationships"].append(record)
    for collection in ("sources", "interfaceSources"):
        for i, raw in enumerate(_objects(data.get(collection, []), collection)):
            record = {
                "target_id": identity,
                "collection": collection,
                "reported_path": _string(raw.get("path"), "source path"),
                "generated": _boolean(raw.get("isGenerated", False), "isGenerated"),
                "location": _location(path, f"/{collection}/{i}"),
            }
            _backtrace(raw, record)
            for field in ("compileGroupIndex", "sourceGroupIndex", "fileSetIndex"):
                if field in raw:
                    record[field] = _index(raw[field], field)
            for field in ("backtraces", "fileSetIndexes"):
                if field in raw:
                    if not isinstance(raw[field], list) or len(raw[field]) > _MAX_ITEMS:
                        raise ValueError(f"CMake {field} must be a bounded array")
                    record[field] = [_index(value, field) for value in raw[field]]
            rows["sources"].append(record)
    for step in ("link", "archive"):
        if step not in data:
            continue
        section = data[step]
        if not isinstance(section, dict):
            raise ValueError(f"CMake {step} must be an object")
        for i, raw in enumerate(
            _objects(section.get("commandFragments", []), "commandFragments")
        ):
            record = {
                "target_id": identity,
                "step": step,
                "role": _string(raw.get("role"), "fragment role"),
                "fragment": _string(
                    raw.get("fragment"), "command fragment", empty=True
                ),
                "location": _location(path, f"/{step}/commandFragments/{i}"),
            }
            _backtrace(raw, record)
            rows["command_fragments"].append(record)
    return rows


def _version_fields(data: dict[str, Any], minor: int) -> bool:
    if minor < 9 and any(
        field in data
        for field in (*_RELATIONSHIPS[1:], *_TARGET_FLAGS[:4], "codemodelVersion")
    ):
        return True
    if minor < 10 and "interfaceSources" in data:
        return True
    for collection in ("sources", "interfaceSources"):
        for source in data.get(collection, []):
            if minor < 5 and "fileSetIndex" in source:
                return True
            if minor < 11 and any(
                field in source for field in ("backtraces", "fileSetIndexes")
            ):
                return True
    return False


def _objects(value: Any, label: str) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_ITEMS
        or not all(isinstance(item, dict) for item in value)
    ):
        raise ValueError(f"CMake {label} must be a bounded array of objects")
    return value


def _string(value: Any, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value) > 65_536:
        raise ValueError(f"CMake {label} must be a bounded string")
    return value


def _index(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"CMake {label} must be a non-negative integer")
    return value


def _version(value: Any) -> tuple[int, int]:
    if not isinstance(value, dict):
        raise ValueError("CMake object version must be an object")
    return _index(value.get("major"), "major"), _index(value.get("minor"), "minor")


def _paths(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("CMake paths must be an object")
    return {key: _string(value.get(key), f"{key} path") for key in ("source", "build")}


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"CMake {label} must be boolean")
    return value


def _backtrace(raw: dict[str, Any], record: dict[str, Any]) -> None:
    if "backtrace" in raw:
        record["backtrace_index"] = _index(raw["backtrace"], "backtrace")


def _location(path: Path, pointer: str) -> dict[str, str]:
    return {"path": path.as_posix(), "json_pointer": pointer}
