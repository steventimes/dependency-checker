"""Bounded PEP 751 inventory; never select an environment or open artifacts."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import date, datetime, time
from typing import Any
from urllib.parse import unquote, urlsplit

from packaging.pylock import Pylock, PylockValidationError
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.ecosystems.python.parsers.lock import LockfileParser
from depcheck.evidence.origins import python_origin, redact_source
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import Diagnostic, PythonRequirement, SourceLocation

_MAX_PACKAGES = 20_000
_MAX_DETAILS = 1_048_576
_MAX_RECORD = 16_384
_MAX_WORK = 100_000
_ROOT_FIELDS = frozenset(
    {
        "lock-version",
        "created-by",
        "environments",
        "requires-python",
        "extras",
        "dependency-groups",
        "default-groups",
    }
)
_SOURCE_FIELDS = frozenset({"vcs", "directory", "archive", "index", "sdist", "wheels"})
_PACKAGE_FIELDS = _SOURCE_FIELDS | {"name", "version", "marker", "requires-python"}


def _toml_json(value: Any) -> dict[str, str]:
    if isinstance(value, (datetime, date, time)):
        return {"toml." + type(value).__name__: value.isoformat()}
    raise TypeError("Unsupported TOML value")


def _digest(value: Any) -> str | None:
    try:
        return hashlib.sha256(
            json.dumps(
                value,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                default=_toml_json,
            ).encode()
        ).hexdigest()
    except (ValueError, TypeError, RecursionError):
        return None


def _literal(value: Any, budget: int) -> tuple[Any, bool]:
    """Project bounded literals and safe keys before the shared value redactor."""
    remaining = 2048
    omitted = False

    def project(item: Any, depth: int) -> Any:
        nonlocal remaining, omitted
        remaining -= 1
        if remaining < 0 or depth > 8:
            omitted = True
            return None
        if isinstance(item, str):
            if len(item) > 8192:
                omitted = True
                return None
            return item
        if isinstance(item, (datetime, date, time)):
            return item.isoformat()
        if item is None or type(item) in {bool, int}:
            return item
        if isinstance(item, float) and math.isfinite(item):
            return item
        if isinstance(item, list):
            return (
                [project(v, depth + 1) for v in item[:2048]]
                if len(item) <= 2048
                else project(None, 9)
            )
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if remaining <= 0:
                    omitted = True
                    break
                if (
                    not isinstance(key, str)
                    or len(key) > 256
                    or redact_source(key) != key
                ):
                    omitted = True
                    continue
                result[key] = project(child, depth + 1)
            return result
        omitted = True
        return None

    result = redact_source(project(value, 0))
    if len(json.dumps(result, ensure_ascii=True).encode()) > budget:
        return {}, True
    return result, omitted


def _wheel_work(record: dict[str, Any], work: list[int]) -> bool:
    """Bound compressed-tag expansion before packaging validates filenames."""
    wheels = record.get("wheels", [])
    if not isinstance(wheels, list) or len(wheels) > 128:
        return False
    for wheel in wheels:
        if not isinstance(wheel, dict):
            continue
        filename = wheel.get("name")
        if not filename and isinstance(wheel.get("path"), str):
            path = wheel["path"]
            filename = (
                path.rsplit("/", 1)[-1] if "/" in path else path.rsplit("\\", 1)[-1]
            )
        if not filename and isinstance(wheel.get("url"), str):
            try:
                filename = unquote(urlsplit(wheel["url"]).path.rsplit("/", 1)[-1])
            except ValueError:
                return False
        if isinstance(filename, str):
            parts = filename.removesuffix(".whl").rsplit("-", 3)
            cost = math.prod(part.count(".") + 1 for part in parts[-3:])
            work[0] -= cost
            if cost > 4096 or work[0] < 0:
                return False
    return True


def _origin(record: dict[str, Any], valid: bool) -> dict[str, Any]:
    if not valid:
        return {"kind": "unknown", "public": False}
    if isinstance(record.get("directory"), dict):
        directory = record["directory"]
        return python_origin(
            {
                "path": directory["path"],
                **(
                    {"editable": directory["editable"]}
                    if "editable" in directory
                    else {}
                ),
            }
        )
    if isinstance(record.get("vcs"), dict):
        vcs = record["vcs"]
        return (
            python_origin({"path": vcs["path"]})
            if vcs.get("path")
            else {"kind": "vcs", "public": False}
        )
    if isinstance(record.get("archive"), dict):
        archive = record["archive"]
        return (
            python_origin({"path": archive["path"]})
            if archive.get("path")
            else python_origin({"url": archive["url"]})
        )
    artifacts = [
        *record.get("wheels", []),
        *([record["sdist"]] if "sdist" in record else []),
    ]
    if any(artifact.get("path") for artifact in artifacts):
        return {"kind": "path", "public": False}
    # Only an explicit public index plus canonical remote artifacts qualifies.
    # A CDN URL alone never supplies the absent index identity.
    origin = (
        python_origin({"registry": record["index"]})
        if "index" in record
        else {"kind": "unknown", "public": False}
    )
    for artifact in artifacts:
        try:
            url = urlsplit(artifact.get("url", ""))
            if (
                url.scheme != "https"
                or url.netloc != "files.pythonhosted.org"
                or url.query
                or url.fragment
            ):
                origin["public"] = False
        except ValueError:
            origin["public"] = False
    return origin


def _informational(
    selectors: Any, packages: list[Any], names: dict[str, list[int]], work: list[int]
) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(selectors, list):
        return [], True
    result = []
    incomplete = len(selectors) > 128
    for index, selector in enumerate(selectors[:128]):
        projected, omitted = _literal(selector, 8192)
        row: dict[str, Any] = {
            "selector_index": index,
            "selector": projected,
            "activation": "unknown",
        }
        matches = []
        if (
            omitted
            or not isinstance(selector, dict)
            or not isinstance(selector.get("name"), str)
        ):
            row["status"] = "unsupported"
            incomplete = True
        else:
            for candidate in names.get(selector["name"], []):
                pending = [(selector, packages[candidate])]
                equal = True
                while pending:
                    work[0] -= 1
                    if work[0] < 0:
                        equal = False
                        break
                    expected, actual = pending.pop()
                    if isinstance(expected, dict) and isinstance(actual, dict):
                        if not all(key in actual for key in expected):
                            equal = False
                            break
                        pending.extend(
                            (value, actual[key]) for key, value in expected.items()
                        )
                    elif type(expected) is not type(actual) or expected != actual:
                        equal = False
                        break
                if equal:
                    matches.append(candidate)
                if work[0] < 0:
                    break
            row["status"] = (
                "budget-exceeded"
                if work[0] < 0
                else "matched-record"
                if len(matches) == 1
                else "ambiguous"
                if matches
                else "unresolved"
            )
            if len(matches) <= 20 and work[0] >= 0:
                row["target_package_indices"] = matches
            else:
                incomplete = True
            incomplete = incomplete or row["status"] != "matched-record"
        result.append(row)
    return result, incomplete


class PylockParser(LockfileParser):
    def _parse_toml_lock(
        self,
        data: object,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
    ) -> None:
        location = SourceLocation(self.path)
        if not isinstance(data, dict) or data.get("lock-version") != "1.0":
            diagnostics.append(
                Diagnostic(
                    "manifest.pylock-unsupported",
                    "error",
                    "Only PEP 751 lock-version 1.0 is interpreted; package inventory is unsupported.",
                    location,
                )
            )
            return
        packages = data.get("packages")
        if not isinstance(packages, list):
            diagnostics.append(
                self._invalid("pylock packages must be an array", location)
            )
            return
        root = {key: data[key] for key in _ROOT_FIELDS if key in data}
        root_display, clipped = _literal(root, 8192)
        try:
            if clipped:
                raise ValueError("root budget")
            Pylock.from_dict({**root, "packages": []})
        except (PylockValidationError, ValueError, TypeError, RecursionError):
            diagnostics.append(
                self._invalid(
                    "pylock header is malformed or over budget; package interpretation is unverified",
                    location,
                )
            )
            return
        diagnostics.append(
            Diagnostic(
                "resolution.pylock-activation-unknown",
                "warning",
                "PEP 751 records are supplied lock inventory; environments, extras, groups, artifact selection and installation are not selected.",
                location,
            )
        )
        unknown_root = bool(set(data) - (_ROOT_FIELDS | {"packages", "tool"}))
        limited = len(packages) > _MAX_PACKAGES or unknown_root
        packages = packages[:_MAX_PACKAGES]
        names: dict[str, list[int]] = {}
        for index, item in enumerate(packages):
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.setdefault(item["name"], []).append(index)
        details = _MAX_DETAILS
        validation_work = [_MAX_WORK]
        binding_work = [_MAX_WORK]
        for index, item in enumerate(packages):
            source = positions.value("packages", index, "name")
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("name"), str)
                or len(item["name"]) > 256
            ):
                diagnostics.append(
                    self._invalid("pylock package requires a bounded name", source)
                )
                continue
            try:
                canonicalize_name(item["name"], validate=True)
            except InvalidName:
                diagnostics.append(
                    self._invalid("pylock package name is invalid", source)
                )
                continue
            core = {key: item[key] for key in _PACKAGE_FIELDS if key in item}
            core_display, clipped = _literal(core, _MAX_RECORD)
            unknown_fields = bool(
                set(item)
                - (_PACKAGE_FIELDS | {"dependencies", "attestation-identities", "tool"})
            )
            valid = (
                not clipped
                and not unknown_root
                and not unknown_fields
                and _wheel_work(core, validation_work)
            )
            if valid:
                try:
                    Pylock.from_dict(
                        {
                            "lock-version": "1.0",
                            "created-by": root["created-by"],
                            "packages": [core],
                        }
                    )
                except (PylockValidationError, ValueError, TypeError, RecursionError):
                    valid = False
            if not valid:
                diagnostics.append(
                    self._invalid(
                        "pylock package source/identity is malformed, unsupported or over budget; its origin remains unverified",
                        source,
                    )
                )
            projection, omitted = _literal(
                {
                    key: value
                    for key, value in item.items()
                    if key
                    in _PACKAGE_FIELDS | {"dependencies", "attestation-identities"}
                },
                _MAX_RECORD,
            )
            bindings, incomplete = _informational(
                item.get("dependencies", []), packages, names, binding_work
            )
            for binding in bindings:
                binding["source_pointer"] = (
                    f"/packages/{index}/dependencies/{binding['selector_index']}"
                )
            origin = _origin(core, valid)
            origin["pylock_source"] = {
                key: core_display[key] for key in _SOURCE_FIELDS if key in core_display
            }
            digest = _digest(item)
            source_digest = _digest(
                {key: item[key] for key in _SOURCE_FIELDS if key in item}
            )
            metadata: dict[str, Any] = {
                "python_kind": "lock-record",
                "lock_format": "pylock",
                "package_index": index,
                "source_pointer": f"/packages/{index}",
                "conditional": True,
                "activation": "unknown",
                "context": {"root": root_display, "package": projection},
                "informational_dependencies": bindings,
                "dependency_binding_status": (
                    "not-provided"
                    if "dependencies" not in item
                    else "incomplete"
                    if incomplete
                    else "reported"
                ),
                "tool_present": "tool" in item,
                "root_tool_present": "tool" in data,
            }
            if source_digest is not None:
                origin["source_assertion_sha256"] = source_digest
            if digest is not None:
                metadata["package_assertion_sha256"] = digest
            if "attestation-identities" in item:
                identities = item["attestation-identities"]
                valid_identities = isinstance(identities, list) and all(
                    isinstance(identity, dict)
                    and isinstance(identity.get("kind"), str)
                    and bool(identity["kind"].strip())
                    for identity in identities
                )
                metadata["attestation_identities_status"] = (
                    "reported" if valid_identities else "unverified"
                )
                if not valid_identities:
                    diagnostics.append(
                        Diagnostic(
                            "manifest.pylock-attestation-unverified",
                            "warning",
                            "Optional pylock attestation identities are malformed; identity, provenance verification and package-version matching remain separate.",
                            source,
                        )
                    )
            if omitted or set(item) - (
                _PACKAGE_FIELDS | {"dependencies", "attestation-identities", "tool"}
            ):
                metadata["details_omitted"] = True
                limited = True
            size = len(json.dumps([origin, metadata], ensure_ascii=True).encode())
            details -= size
            if details < 0:
                limited = True
                origin = {
                    "kind": "unknown",
                    "public": False,
                    "details_omitted": True,
                    **(
                        {"source_assertion_sha256": source_digest}
                        if source_digest
                        else {}
                    ),
                }
                metadata = {
                    **metadata,
                    "context": {},
                    "informational_dependencies": [],
                    "details_omitted": True,
                    "dependency_binding_status": "incomplete",
                }
            version = item.get("version")
            known_version = False
            if (
                isinstance(version, str)
                and len(version) <= 256
                and not any(key in item for key in ("vcs", "directory"))
            ):
                try:
                    Version(version)
                    known_version = True
                except InvalidVersion:
                    pass
            if version is not None and not known_version:
                diagnostics.append(
                    self._invalid(
                        "pylock version is invalid or cannot establish a stable source-tree version; retained as an unversioned assertion",
                        source,
                    )
                )
            requirement = item["name"]
            if known_version and isinstance(version, str):
                requirement += "==" + version
            declarations.append(
                PythonRequirement.from_requirement(
                    requirement,
                    source=source,
                    group="lock",
                    kind="locked",
                    origin=origin,
                    metadata=metadata,
                )
            )
        if limited or binding_work[0] < 0 or validation_work[0] < 0:
            diagnostics.append(
                Diagnostic(
                    "manifest.pylock-context-limit",
                    "error",
                    "pylock inventory/context exceeded supported budgets or contains omitted extensions; retained records do not establish complete coverage.",
                    location,
                )
            )
