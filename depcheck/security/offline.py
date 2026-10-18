"""Reevaluate explicitly supplied inventories against explicitly supplied OSV data."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import re
from typing import Any

from semver import Version as SemVersion

from depcheck.sbom import inspect_sbom
from depcheck.snapshots import read_evidence_json, parse_evidence_json
from .osv_client import OSVClient, match_affected_version, _timestamp


def inventory_identities(
    root: Path, path: str
) -> tuple[list[dict[str, Any]], str, list[dict[str, Any]]]:
    data, digest = read_evidence_json(root, path)
    if data.get("bomFormat") == "CycloneDX":
        sbom = inspect_sbom(root, path, limit=20000)
        identities = []
        ambiguous = {
            note.get("bom_ref")
            for note in sbom["diagnostics"]
            if note.get("code")
            in {
                "sbom.identity-ambiguous",
                "sbom.identity-unknown",
                "sbom.purl-type-unsupported",
                "sbom.version-ambiguous",
            }
        }
        for item in sbom["components"]:
            if item["kind"] == "dependency-group":
                continue
            identity = dict(item["identity"])
            reference = (
                item["bom_ref"]
                or "unreferenced:" + item["source_pointer"].rsplit("/", 1)[-1]
            )
            if reference in ambiguous:
                identity["identity_status"] = "ambiguous"
            if item.get("purl"):
                identity["assertion_kind"] = "external-sbom-unqualified-purl"
            origins = [
                prop["value"]
                for prop in item["properties"]
                if prop["name"] == "depcheck:source:origin"
            ]
            if len(origins) == 1:
                identity["origin"] = parse_evidence_json(origins[0].encode())
            elif origins:
                identity["origin"] = {"public": None, "kind": "ambiguous-sbom-origin"}
            identities.append(identity)
        return identities, digest, sbom["diagnostics"]
    if data.get("schema") != "depcheck.scan.v1":
        raise ValueError(
            "Inventory must be a canonical depcheck scan or CycloneDX JSON"
        )
    inventory = data.get("inventory")
    if not isinstance(inventory, dict):
        raise ValueError("Scan inventory must be an object")
    records = inventory.get("resolved_dependencies", [])
    if not isinstance(records, list) or len(records) > 20000:
        raise ValueError("Resolved inventory exceeds its entry budget")
    identities = []
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("identity"), dict):
            raise ValueError("Resolved inventory needs explicit identity objects")
        identity = dict(record["identity"])
        identity.pop("assertion_kind", None)
        # Keep origin as a separate dimension. A private homonym is not public.
        metadata = record.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Resolved inventory metadata must be an object")
        identity["origin"] = record.get("origin", metadata.get("origin"))
        identities.append(identity)
    return identities, digest, []


def reevaluate_vulnerabilities(
    root: Path, inventory_file: str, advisory_file: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Pagination requires positive limit and non-negative offset")
    identities, inventory_digest, diagnostics = inventory_identities(
        root, inventory_file
    )
    database, database_digest = read_evidence_json(root, advisory_file)
    if database.get("schema") == "depcheck.osv-database.v1":
        records = database.get("records")
    elif database.get("id") and database.get("modified"):
        records = [database]
    else:
        raise ValueError("Expected an OSV record or depcheck.osv-database.v1 bundle")
    if not isinstance(records, list) or len(records) > 10000:
        raise ValueError("OSV records must be a bounded array")
    details: dict[str, dict[str, Any]] = {}
    by_package: dict[tuple[str, str], list[dict[str, Any]]] = {}
    associations = 0
    unmapped_affected_entries = 0
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("id"), str)
            or len(record["id"]) > 256
            or re.fullmatch(r"[a-zA-Z0-9:_.-]+", record["id"]) is None
        ):
            raise ValueError("OSV record requires a bounded valid id")
        schema = record.get("schema_version", "1.0.0")
        if (
            not isinstance(schema, str)
            or len(schema) > 64
            or SemVersion.parse(schema).major != 1
        ):
            raise ValueError("Only OSV schema 1.x records are supported")
        identifier = record["id"]
        if identifier in details:
            raise ValueError(
                "OSV record IDs must be unique; select a revision explicitly"
            )
        _timestamp(record.get("modified"))
        if "withdrawn" in record:
            _timestamp(record["withdrawn"])
        aliases = record.get("aliases", [])
        if (
            not isinstance(aliases, list)
            or len(aliases) > 4096
            or not all(
                isinstance(alias, str)
                and len(alias) <= 256
                and re.fullmatch(r"[a-zA-Z0-9:_.-]+", alias)
                for alias in aliases
            )
        ):
            raise ValueError("OSV aliases must be bounded valid identifiers")
        severity = record.get("severity", [])
        if not isinstance(severity, list) or not all(
            isinstance(item, dict) for item in severity
        ):
            raise ValueError("OSV severity must be an array of objects")
        details[identifier] = record
        affected = record.get("affected", [])
        if not isinstance(affected, list):
            raise ValueError("OSV affected must be an array")
        associations += len(affected)
        if associations > 20000:
            raise ValueError("OSV package association budget exhausted")
        for entry in affected:
            if not isinstance(entry, dict):
                raise ValueError("OSV affected entries must be objects")
            if entry.get("package") is None:
                # Package-less Git assertions are valid OSV data. They cannot
                # supply a public package/version match and remain uncovered.
                unmapped_affected_entries += 1
                continue
            if not isinstance(entry["package"], dict):
                raise ValueError("OSV package coordinate must be an object")
            coordinate = entry["package"]
            ecosystem, name = coordinate.get("ecosystem"), coordinate.get("name")
            if not isinstance(ecosystem, str) or not isinstance(name, str):
                raise ValueError("OSV package requires ecosystem and name")
            key = (ecosystem.lower(), OSVClient._normalize_package(name, ecosystem))
            if record not in by_package.setdefault(key, []):
                by_package[key].append(record)
    client = OSVClient()
    observations: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    observation = (
        now.replace(microsecond=0),
        Decimal(f"0.{now.microsecond:06d}"),
    )
    work = 0
    for identity in identities:
        ecosystem, package, version = (
            identity.get(field) for field in ("ecosystem", "package", "version")
        )
        query_ecosystem = (
            "crates.io"
            if isinstance(ecosystem, str) and ecosystem.lower() == "cargo"
            else ecosystem
        )
        origin = identity.get("origin")
        source_eligible = (
            origin.get("public") is True
            if isinstance(origin, dict)
            else origin is None
            and identity.get("assertion_kind") == "external-sbom-unqualified-purl"
        )
        if (
            not all(
                isinstance(value, str) and value
                for value in (ecosystem, package, version)
            )
            or not source_eligible
            or identity.get("qualifiers")
            or identity.get("subpath")
            or identity.get("identity_status") == "ambiguous"
            or str(query_ecosystem).lower()
            not in {"pypi", "npm", "maven", "go", "crates.io"}
        ):
            observations.append(
                {
                    "identity": identity,
                    "status": "unknown",
                    "reason": "Exact public package coordinate is unavailable",
                    "vulnerabilities": [],
                }
            )
            continue
        assert isinstance(package, str) and isinstance(ecosystem, str)
        assert isinstance(version, str) and isinstance(query_ecosystem, str)
        normalized = OSVClient._normalize_package(package, ecosystem)
        issues = []
        uncertain = False
        advisory_checks: list[dict[str, Any]] = []
        for record in by_package.get((query_ecosystem.lower(), normalized), []):
            work += 1
            if work > 100000:
                raise ValueError("Offline advisory comparison budget exhausted")
            if record.get("withdrawn"):
                if _timestamp(record["withdrawn"]) <= observation:
                    continue
            try:
                status, reason = match_affected_version(
                    record, normalized, query_ecosystem, version
                )
                advisory_checks.append(
                    {
                        "id": record["id"],
                        "modified": record["modified"],
                        "status": status,
                        "reason": reason,
                    }
                )
                uncertain |= status == "unknown"
                if status == "affected":
                    issue, notes = client._parse_detail(
                        record, normalized, query_ecosystem, version
                    )
                    issues.append(issue)
                    diagnostics.extend(
                        {
                            "code": note.code,
                            "message": note.message,
                            "severity": note.severity,
                        }
                        for note in notes
                    )
            except (ValueError, TypeError, KeyError) as exc:
                uncertain = True
                advisory_checks.append(
                    {
                        "id": record["id"],
                        "modified": record["modified"],
                        "status": "unknown",
                        "reason": str(exc),
                    }
                )
                diagnostics.append(
                    {
                        "code": "offline.invalid-advisory",
                        "severity": "error",
                        "message": f"{record['id']}: {exc}",
                    }
                )
        if issues:
            issues, notes = client._group_aliases(
                issues,
                {key: (value, None) for key, value in details.items()},
                normalized,
                query_ecosystem,
                version,
            )
            diagnostics.extend(
                {"code": note.code, "message": note.message, "severity": note.severity}
                for note in notes
            )
        observations.append(
            {
                "identity": identity,
                "identity_basis": "external-coordinate-assertion"
                if identity.get("assertion_kind")
                else "public-origin-assertion",
                "status": "matched"
                if issues
                else "unknown"
                if uncertain
                else "not-matched-in-supplied-records",
                "matching_complete": not uncertain,
                "advisory_checks": advisory_checks,
                "vulnerabilities": issues,
            }
        )
    total = len(observations)
    return {
        "schema": "depcheck.offline-security.v1",
        "read_only": True,
        "inventory": {"path": inventory_file, "sha256": inventory_digest},
        "database": {
            "path": advisory_file,
            "sha256": database_digest,
            "generated_at": database.get("generated_at"),
            "record_count": len(records),
            "freshness": "unverified",
            "scope": "supplied-records-only",
            "matching_profile": "public-package-coordinates; Git-commit matching unsupported",
            "unmapped_affected_entries": unmapped_affected_entries,
        },
        "observations": observations[offset : offset + limit],
        "total": total,
        "offset": offset,
        "next_offset": offset + limit if total > offset + limit else None,
        "diagnostics": diagnostics,
        "evaluated_at": now.isoformat(),
        "global_vulnerability_coverage": "unknown",
        "reachability": "not-evaluated",
    }
