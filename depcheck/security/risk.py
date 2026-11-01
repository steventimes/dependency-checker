"""Read supplied KEV/EPSS snapshots without changing vulnerability conclusions."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import zlib
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from depcheck.evidence.input import objects, parse_evidence_json, read_evidence_bytes
from depcheck.evidence.origins import redact_source

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_MAX_CSV_BYTES = 32 * 1024 * 1024
_MAX_EPSS_INPUT_BYTES = 32 * 1024 * 1024
_MAX_CSV_ROWS = 1_000_000
_MAX_GZIP_MEMBERS = 64
_MAX_CVES = 4096
_MAX_ASSOCIATIONS = 20_000
_MAX_ASSOCIATION_WORK = 100_000
_DETAIL_BYTES = 16_384


@dataclass
class _Snapshot:
    metadata: dict[str, Any]
    records: dict[str, dict[str, Any]]
    data_time: datetime | None


def _cve(value: object) -> str:
    if not isinstance(value, str) or _CVE.fullmatch(value) is None:
        raise ValueError("Risk feed requires a bounded canonical CVE identifier")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 16_384:
        raise ValueError(f"{label} must be a bounded string")
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("Risk data date must be an ISO date or RFC 3339 timestamp")
    if _DATE.fullmatch(value):
        return datetime.combine(
            date.fromisoformat(value), datetime.min.time(), timezone.utc
        )
    if _TIME.fullmatch(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    raise ValueError("Risk data date must be an ISO date or RFC 3339 timestamp")


def _calendar_date(value: object) -> None:
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        raise ValueError("KEV entry dates must be ISO calendar dates")
    date.fromisoformat(value)


def _fingerprint(value: object) -> bytes:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
    ).digest()


def _project(value: dict[str, Any]) -> dict[str, Any]:
    """Bound display details, retaining membership and source hashes separately."""
    if len(json.dumps(value, ensure_ascii=False).encode()) > _DETAIL_BYTES:
        return {"details_omitted": True}
    pending: list[Any] = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            # URL-shaped extension keys cannot be retained as unredacted keys.
            if any(redact_source(key) != key for key in item):
                return {"details_omitted": True}
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    result = redact_source(value)
    return (
        result
        if len(json.dumps(result, ensure_ascii=False).encode()) <= _DETAIL_BYTES
        else {"details_omitted": True}
    )


def _kev(raw: bytes, desired: set[str]) -> _Snapshot:
    data = parse_evidence_json(raw)
    version = _string(data.get("catalogVersion"), "KEV catalogVersion")
    released = data.get("dateReleased")
    if not isinstance(released, str) or _TIME.fullmatch(released) is None:
        raise ValueError("KEV dateReleased requires an RFC 3339 timestamp")
    data_time = _time(released)
    entries = objects(data.get("vulnerabilities"), "KEV vulnerabilities")
    if type(data.get("count")) is not int or data["count"] != len(entries):
        raise ValueError("KEV count must equal the complete supplied entry count")
    seen: dict[str, bytes] = {}
    selected = {}
    duplicates = 0
    for index, entry in enumerate(entries):
        identifier = _cve(entry.get("cveID"))
        for field in (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
        ):
            _string(entry.get(field), "KEV " + field)
        for field in ("dateAdded", "dueDate"):
            _calendar_date(entry.get(field))
        for field in ("knownRansomwareCampaignUse", "forensicTriage", "notes"):
            if field in entry:
                _string(entry[field], "KEV " + field)
        if "cwes" in entry and (
            not isinstance(entry["cwes"], list)
            or len(entry["cwes"]) > 256
            or not all(
                isinstance(v, str) and re.fullmatch(r"CWE-[0-9]+", v)
                for v in entry["cwes"]
            )
        ):
            raise ValueError("KEV cwes must contain bounded CWE identifiers")
        signature = _fingerprint(entry)
        if identifier in seen:
            if seen[identifier] != signature:
                raise ValueError("KEV has conflicting duplicate CVE records")
            duplicates += 1
            continue
        seen[identifier] = signature
        if identifier in desired:
            selected[identifier] = {
                "record": _project(entry),
                "record_sha256": signature.hex(),
                "source_pointer": f"/vulnerabilities/{index}",
            }
    return _Snapshot(
        {
            "format": "cisa-kev-json",
            "provider": "CISA",
            "catalog_version": redact_source(version),
            "data_date": released,
            "raw_record_count": len(entries),
            "record_count": len(seen),
            "identical_duplicates": duplicates,
            "fields": _project(
                {key: value for key, value in data.items() if key != "vulnerabilities"}
            ),
            "parsed_completely": True,
            "upstream_completeness": "unverified",
            "record_sha256_basis": "canonical JSON of parsed record fields",
        },
        selected,
        data_time,
    )


def _csv_bytes(raw: bytes) -> bytes:
    if not raw.startswith(b"\x1f\x8b"):
        return raw
    remaining = raw
    output = bytearray()
    for _ in range(_MAX_GZIP_MEMBERS):
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        output.extend(decoder.decompress(remaining, _MAX_CSV_BYTES - len(output) + 1))
        if len(output) > _MAX_CSV_BYTES:
            raise ValueError("Expanded EPSS data exceeds its byte budget")
        if not decoder.eof:
            raise ValueError("EPSS gzip is truncated or exceeds its expansion budget")
        remaining = decoder.unused_data
        if not remaining:
            return bytes(output)
    raise ValueError("EPSS gzip member budget exhausted")


def _score(value: str) -> float:
    if not value or len(value) > 128:
        raise ValueError("EPSS numbers must be bounded, finite and within [0,1]")
    try:
        number = Decimal(value)
        if not number.is_finite() or not 0 <= number <= 1:
            raise ValueError("EPSS numbers must be finite and within [0,1]")
        result = float(number)
        if not math.isfinite(result) or Decimal(str(result)) != number:
            raise ValueError(
                "EPSS number cannot be represented without decimal precision loss"
            )
        return result
    except InvalidOperation as exc:
        raise ValueError("EPSS numbers must be finite and within [0,1]") from exc


def _epss(raw: bytes, desired: set[str]) -> _Snapshot:
    decoded = _csv_bytes(raw)
    if len(decoded) > _MAX_CSV_BYTES:
        raise ValueError("EPSS CSV exceeds its byte budget")
    stream = io.StringIO(decoded.decode("utf-8-sig"), newline="")
    metadata: dict[str, str] = {}
    comments = 0
    while True:
        position = stream.tell()
        line = stream.readline(16_385)
        if len(line) > 16_384:
            raise ValueError("EPSS metadata/header line exceeds its budget")
        if not line.startswith("#"):
            stream.seek(position)
            break
        comments += 1
        if comments > 16:
            raise ValueError("EPSS comment budget exhausted")
        fields = next(csv.reader([line[1:]], strict=True))
        for field in fields:
            key, separator, value = field.partition(":")
            if not separator or not key or key in metadata or len(metadata) == 64:
                raise ValueError(
                    "EPSS comment metadata must have unique key:value fields"
                )
            metadata[key] = value
    reader = csv.reader(stream, strict=True)
    headers = next(reader, [])
    if (
        not 3 <= len(headers) <= 64
        or len(set(headers)) != len(headers)
        or not {"cve", "epss", "percentile"}.issubset(headers)
        or any(not value or len(value) > 256 for value in headers)
    ):
        raise ValueError("EPSS CSV requires unique cve, epss and percentile columns")
    data_date = metadata.get("score_date")
    data_time = _time(data_date) if data_date is not None else None
    seen: dict[str, bytes] = {}
    selected = {}
    count = duplicates = 0
    for values in reader:
        count += 1
        if count > _MAX_CSV_ROWS:
            raise ValueError("EPSS row budget exhausted")
        if len(values) != len(headers) or any(len(v) > 16_384 for v in values):
            raise ValueError("EPSS rows must match the bounded header columns")
        row = dict(zip(headers, values))
        identifier = _cve(row["cve"])
        probability, percentile = _score(row["epss"]), _score(row["percentile"])
        signature = _fingerprint(row)
        if identifier in seen:
            if seen[identifier] != signature:
                raise ValueError("EPSS has conflicting duplicate CVE records")
            duplicates += 1
            continue
        seen[identifier] = signature
        if identifier in desired:
            selected[identifier] = {
                "probability": probability,
                "percentile": percentile,
                "probability_raw": row["epss"],
                "percentile_raw": row["percentile"],
                "record_sha256": signature.hex(),
                "csv_record": count,
                "csv_record_end_line": reader.line_num + comments,
                "fields": _project(row),
            }
    return _Snapshot(
        {
            "format": "first-epss-csv",
            "provider": "FIRST EPSS / Empirical Security",
            "attribution_url": "https://www.first.org/epss/data",
            "model_version": redact_source(metadata.get("model_version")),
            "data_date": data_date,
            "metadata": _project(metadata),
            "columns": redact_source(headers),
            "raw_record_count": count,
            "record_count": len(seen),
            "identical_duplicates": duplicates,
            "parsed_completely": True,
            "upstream_completeness": "unverified",
            "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
            "probability_horizon_days": 30,
            "record_sha256_basis": "canonical JSON of parsed CSV fields",
        },
        selected,
        data_time,
    )


def _attempt(
    root: Path, path: str | None, kind: str, desired: set[str], as_of: datetime
) -> tuple[_Snapshot | None, dict[str, Any]]:
    digest = None
    if path is None:
        return None, {"status": "not-supplied"}
    try:
        raw, digest = (
            read_evidence_bytes(root, path, max_bytes=_MAX_EPSS_INPUT_BYTES)
            if kind == "epss"
            else read_evidence_bytes(root, path)
        )
        snapshot = _kev(raw, desired) if kind == "kev" else _epss(raw, desired)
        if snapshot.data_time is not None and snapshot.data_time > as_of:
            raise ValueError(
                "Risk snapshot data date is later than the selected as-of time"
            )
        snapshot.metadata["source"] = {
            "path": redact_source(path),
            "sha256": digest,
            "snapshot_id": f"{kind}:sha256:{digest}",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "retrieved_at": None,
            "source_url": None,
            "upstream_commit": None,
            "authenticity": "unverified",
        }
        return snapshot, {
            "status": "validated",
            "path": redact_source(path),
            "sha256": digest,
        }
    except (
        OSError,
        ValueError,
        UnicodeError,
        csv.Error,
        zlib.error,
        RecursionError,
    ) as exc:
        return None, {
            "status": "invalid",
            "path": redact_source(path),
            "sha256": digest,
            "reason": redact_source(str(exc))[:1000],
        }


def _select(
    root: Path,
    kind: str,
    current: str | None,
    previous: str | None,
    desired: set[str],
    as_of: datetime,
    max_age_days: int | None,
) -> tuple[_Snapshot | None, _Snapshot | None, dict[str, Any]]:
    candidate, attempt = _attempt(root, current, kind, desired, as_of)
    old, old_attempt = _attempt(root, previous, kind, desired, as_of)
    selected = candidate or old
    age = (
        (as_of - selected.data_time).total_seconds()
        if selected and selected.data_time
        else None
    )
    fallback = selected is not None and candidate is None
    stale = (
        True
        if fallback
        else (
            age > max_age_days * 86400
            if age is not None and max_age_days is not None
            else None
        )
    )
    freshness = (
        "stale"
        if stale is True
        else "within-explicit-age-limit"
        if stale is False
        else "unknown"
        if age is None
        else "not-evaluated"
    )
    diagnostics = [
        {
            "code": f"risk.{kind}.snapshot-invalid",
            "severity": "warning",
            "role": role,
            "message": note["reason"],
        }
        for role, note in [("current", attempt), ("previous", old_attempt)]
        if note["status"] == "invalid"
    ]
    if selected and selected.metadata["identical_duplicates"]:
        diagnostics.append(
            {
                "code": f"risk.{kind}.identical-duplicates",
                "severity": "warning",
                "message": "Identical duplicate rows were counted separately and deduplicated after complete validation.",
            }
        )
    return (
        selected,
        old if candidate else None,
        {
            "status": "available" if selected else "unavailable",
            "selection": "current" if candidate else "previous" if old else "none",
            "selection_basis": "explicit-file-order; no upstream revision precedence inferred",
            "stale": stale,
            "freshness": freshness,
            "age_seconds": age,
            "snapshot": selected.metadata if selected else None,
            "previous_snapshot": old.metadata if candidate and old else None,
            "attempts": {"current": attempt, "previous": old_attempt},
            "diagnostics": diagnostics,
        },
    )


def _associations(
    observations: list[dict[str, Any]], offset: int
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    result: dict[str, list[dict[str, Any]]] = {}
    work = retained = 0
    for index, observation in enumerate(observations, offset):
        for issue in observation.get("vulnerabilities", []):
            for source in issue.get("advisories", [issue]):
                for reference in source.get("identifier_references", []):
                    work += 1
                    if work > _MAX_ASSOCIATION_WORK:
                        return result, False
                    identifier = reference.get("id")
                    if reference.get("type") != "CVE" or reference.get("field") not in {
                        "id",
                        "aliases",
                    }:
                        continue
                    if (
                        not isinstance(identifier, str)
                        or _CVE.fullmatch(identifier) is None
                    ):
                        return result, False
                    if (
                        retained == _MAX_ASSOCIATIONS
                        or identifier not in result
                        and len(result) == _MAX_CVES
                    ):
                        return result, False
                    result.setdefault(identifier, []).append(
                        {
                            "observation_index": index,
                            "issue_id": issue["id"],
                            "source_advisory_id": reference["advisory_id"],
                            "field": reference["field"],
                        }
                    )
                    retained += 1
    return result, True


def cve_risk_context(
    root: Path,
    observations: list[dict[str, Any]],
    *,
    offset: int,
    kev_file: str | None = None,
    epss_file: str | None = None,
    previous_kev_file: str | None = None,
    previous_epss_file: str | None = None,
    as_of: str | None = None,
    max_age_days: int | None = None,
) -> dict[str, Any]:
    if max_age_days is not None and (type(max_age_days) is not int or max_age_days < 0):
        raise ValueError(
            "Risk maximum age must be a nonnegative integer number of days"
        )
    reference_time = _time(as_of) if as_of is not None else datetime.now(timezone.utc)
    associations, complete = _associations(observations, offset)
    desired = set(associations)
    kev, previous_kev, kev_metadata = _select(
        root, "kev", kev_file, previous_kev_file, desired, reference_time, max_age_days
    )
    epss, previous_epss, epss_metadata = _select(
        root,
        "epss",
        epss_file,
        previous_epss_file,
        desired,
        reference_time,
        max_age_days,
    )
    records = []
    for identifier, links in sorted(associations.items()):
        kev_row = kev.records.get(identifier) if kev else None
        epss_row = epss.records.get(identifier) if epss else None
        kev_state: dict[str, Any] = {
            "status": "listed"
            if kev_row
            else "not_listed_in_snapshot"
            if kev
            else "unavailable",
            **(kev_row or {}),
        }
        epss_state: dict[str, Any] = {
            "status": "scored"
            if epss_row
            else "no_row_in_snapshot"
            if epss
            else "unavailable",
            **(epss_row or {}),
        }
        if kev and previous_kev:
            earlier = previous_kev.records.get(identifier)
            forward = (
                kev.data_time is not None
                and previous_kev.data_time is not None
                and kev.data_time > previous_kev.data_time
            )
            change = (
                "added_to_snapshot"
                if kev_row and not earlier
                else "removed_from_snapshot"
                if earlier and not kev_row
                else "record_changed"
                if kev_row
                and earlier
                and kev_row["record_sha256"] != earlier["record_sha256"]
                else "unchanged"
            )
            kev_state["comparison"] = {
                "change": change if forward else "unverified-order",
                "membership_difference": change,
                "chronology": "forward" if forward else "unverified",
                "withdrawal_or_fix": "not-established",
            }
        if epss and previous_epss:
            earlier = previous_epss.records.get(identifier)
            epss_state["previous_status"] = (
                "scored" if earlier else "no_row_in_snapshot"
            )
            epss_state["changed_from_previous"] = (epss_row or {}).get(
                "record_sha256"
            ) != (earlier or {}).get("record_sha256")
        records.append(
            {
                "cve": identifier,
                "associations": links,
                "kev": kev_state,
                "epss": epss_state,
            }
        )
    return {
        "schema": "depcheck.cve-risk.v1",
        "read_only": True,
        "as_of": reference_time.isoformat(),
        "max_age_days": max_age_days,
        "feeds": {"kev": kev_metadata, "epss": epss_metadata},
        "records": records,
        "associations_complete": complete,
        "association_status": "incomplete"
        if not complete
        else "reported"
        if records
        else "not-applicable",
        "association_scope": "current observation page; OSV id/aliases only",
        "finding_effect": "none",
        "exploitation_status": "not-evaluated",
        "coverage": "supplied snapshots; upstream population completeness unverified",
    }
