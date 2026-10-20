"""Read-only SQLite projections; connection lifetime remains owned by IndexStore."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from packaging.utils import canonicalize_name


def findings(
    connection: sqlite3.Connection, *, package: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    if limit < 1:
        raise ValueError("limit must be positive")
    sql = (
        "SELECT code, package, severity, message, locations_json, details_json "
        "FROM findings"
    )
    parameters: list[Any] = []
    if package is not None:
        sql += " WHERE package = ?"
        parameters.append(package)
    sql += " ORDER BY code, package, message LIMIT ?"
    parameters.append(limit)
    rows = connection.execute(sql, parameters)
    return [
        {
            "code": str(row["code"]),
            "package": str(row["package"]),
            "severity": str(row["severity"]),
            "message": str(row["message"]),
            "locations": json.loads(str(row["locations_json"])),
            "details": json.loads(str(row["details_json"])),
        }
        for row in rows
    ]


def projects(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    capabilities: dict[str, dict[str, dict[str, Any]]] = {}
    for row in connection.execute(
        """
        SELECT project_id, name, complete, reason
        FROM capabilities
        ORDER BY project_id, name
        """
    ):
        capabilities.setdefault(str(row["project_id"]), {})[str(row["name"])] = {
            "complete": bool(row["complete"]),
            "reason": row["reason"],
        }
    source_files: dict[str, list[str]] = {}
    for row in connection.execute(
        """
        SELECT project_id, source_path
        FROM normalized_source_files
        ORDER BY project_id, source_path
        """
    ):
        source_files.setdefault(str(row["project_id"]), []).append(
            str(row["source_path"])
        )
    rows = connection.execute(
        """
        SELECT project_id, project_root, language, ecosystem, manager
        FROM projects
        ORDER BY project_id
        """
    )
    return [
        {
            "project_id": str(row["project_id"]),
            "root": str(row["project_root"]),
            "language": str(row["language"]),
            "ecosystem": str(row["ecosystem"]),
            "manager": str(row["manager"]),
            "capabilities": capabilities.get(str(row["project_id"]), {}),
            "source_file_count": len(source_files.get(str(row["project_id"]), [])),
            "source_files": source_files.get(str(row["project_id"]), []),
        }
        for row in rows
    ]


def ecosystem_summary(connection: sqlite3.Connection) -> dict[str, dict[str, int]]:
    rows = connection.execute(
        """
        SELECT p.ecosystem,
               COUNT(*) AS project_count,
               SUM(COALESCE(d.total, 0)) AS declaration_count,
               SUM(COALESCE(u.total, 0)) AS usage_count,
               SUM(COALESCE(s.total, 0)) AS source_file_count
        FROM projects AS p
        LEFT JOIN (
            SELECT project_id, COUNT(*) AS total
            FROM normalized_declarations GROUP BY project_id
        ) AS d
          ON d.project_id = p.project_id
        LEFT JOIN (
            SELECT project_id, COUNT(*) AS total
            FROM usages GROUP BY project_id
        ) AS u
          ON u.project_id = p.project_id
        LEFT JOIN (
            SELECT project_id, COUNT(*) AS total
            FROM normalized_source_files GROUP BY project_id
        ) AS s
          ON s.project_id = p.project_id
        GROUP BY p.ecosystem
        ORDER BY lower(p.ecosystem)
        """
    )
    return {
        str(row["ecosystem"]): {
            "project_count": int(row["project_count"]),
            "declaration_count": int(row["declaration_count"]),
            "usage_count": int(row["usage_count"]),
            "source_file_count": int(row["source_file_count"]),
        }
        for row in rows
    }


def dependency_graph(connection: sqlite3.Connection, project_id: str) -> dict[str, Any]:
    nodes = [
        dict(row)
        for row in connection.execute(
            "SELECT ecosystem, package, version, instance_id, direct "
            "FROM resolved_dependencies WHERE project_id=? "
            "ORDER BY ecosystem, package, version, instance_id LIMIT 20001",
            (project_id,),
        )
    ]
    edges = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM dependency_edges WHERE project_id=? "
            "ORDER BY parent_ecosystem, parent_package, parent_version, parent_instance_id, "
            "child_ecosystem, child_package, child_version, child_instance_id LIMIT 100001",
            (project_id,),
        )
    ]
    declarations = [
        dict(row)
        for row in connection.execute(
            "SELECT ecosystem, package, source_path, line, column_number "
            "FROM normalized_declarations WHERE project_id=? AND declaration_kind='direct' "
            "ORDER BY ecosystem, package, source_path, line LIMIT 20001",
            (project_id,),
        )
    ]
    resolution = connection.execute(
        "SELECT complete FROM capabilities WHERE project_id=? AND name='resolution'",
        (project_id,),
    ).fetchone()
    return {
        "nodes": nodes[:20000],
        "edges": edges[:100000],
        "declarations": declarations[:20000],
        "resolution_complete": bool(resolution and resolution[0]),
        "truncated": len(nodes) > 20000
        or len(edges) > 100000
        or len(declarations) > 20000,
    }


def dependency_inventory(
    connection: sqlite3.Connection,
    *,
    search: str | None,
    package: str | None,
    ecosystem: str | None,
    project_id: str | None,
    limit: int,
    offset: int,
) -> list[dict[str, Any]]:
    projects = {
        str(row["project_id"]): row
        for row in connection.execute(
            "SELECT project_id, ecosystem, manager FROM projects"
        )
        if project_id is None or str(row["project_id"]) == project_id
    }
    coverage: dict[str, dict[str, bool]] = {}
    error_projects = {
        str(row["project_id"])
        for row in connection.execute(
            "SELECT DISTINCT project_id FROM normalized_diagnostics WHERE severity='error'"
        )
    }
    for row in connection.execute(
        "SELECT project_id, name, complete FROM capabilities"
    ):
        coverage.setdefault(str(row["project_id"]), {})[str(row["name"])] = bool(
            row["complete"]
        )
    records: dict[tuple[str, str, str], dict[str, Any]] = {}

    def record_for(
        row: sqlite3.Row,
        *,
        ecosystem_key: str = "ecosystem",
        package_key: str = "package",
        display_key: str = "display_name",
        purl_key: str = "purl",
    ) -> dict[str, Any] | None:
        row_project_id = str(row["project_id"])
        project = projects.get(row_project_id)
        if project is None:
            return None
        row_ecosystem = str(row[ecosystem_key])
        if ecosystem is not None and row_ecosystem.lower() != ecosystem.lower():
            return None
        row_package = str(row[package_key])
        if package is not None:
            normalize = (
                canonicalize_name
                if row_ecosystem.lower() == "pypi"
                else str.casefold
                if row_ecosystem.lower() == "cmake"
                else str
            )
            if normalize(row_package) != normalize(package):
                return None
        key = (row_project_id, row_ecosystem.lower(), row_package)
        states = coverage.get(row_project_id, {})
        return records.setdefault(
            key,
            {
                "project_id": row_project_id,
                "ecosystem": row_ecosystem,
                "manager": str(project["manager"]),
                "package": row_package,
                "display_name": str(row[display_key]),
                "purl": row[purl_key],
                "declared": False,
                "imported": False,
                "resolved_version": None,
                "resolved_versions": [],
                "declarations": [],
                "usages": [],
                "imports": [],
                "findings": [],
                "evidence_complete": bool(states)
                and all(states.values())
                and row_project_id not in error_projects,
                "usage_complete": all(
                    states.get(name, False) for name in ("usage", "mapping")
                ),
            },
        )

    declaration_rows = connection.execute(
        """
        SELECT project_id, ecosystem, package, display_name, purl,
               constraint_raw, constraint_scheme, constraint_normalized,
               source_path, line, column_number, scope, declaration_kind,
               marker, metadata_json
        FROM normalized_declarations
        ORDER BY project_id, ecosystem, package, source_path, line
        """
    )
    for row in declaration_rows:
        record = record_for(row)
        if record is None:
            continue
        record["declarations"].append(
            {
                "constraint": {
                    "raw": str(row["constraint_raw"]),
                    "scheme": str(row["constraint_scheme"]),
                    "normalized": row["constraint_normalized"],
                },
                "scope": str(row["scope"]),
                "kind": str(row["declaration_kind"]),
                "marker": row["marker"],
                "metadata": json.loads(str(row["metadata_json"])),
                "location": _row_location(row, "source_path"),
            }
        )

    resolved_rows = connection.execute(
        """
        SELECT project_id, ecosystem, package, display_name, purl, version,
               source_path, line, column_number, direct, integrity, instance_id, origin_json
        FROM resolved_dependencies
        ORDER BY project_id, ecosystem, package, version
        """
    )
    for row in resolved_rows:
        record = record_for(row)
        if record is not None:
            record["resolved_versions"].append(str(row["version"]))
            origin = json.loads(row["origin_json"])
            record.setdefault("resolutions", []).append(
                {
                    "version": row["version"],
                    "instance": row["instance_id"],
                    "purl": row["purl"],
                    "origin": origin,
                    "location": _row_location(row, "source_path"),
                }
            )
            if origin.get("public") is False:
                record["purl"] = None

    usage_rows = connection.execute(
        """
        SELECT project_id, language, reference, source_path, line,
               column_number, scope, usage_kind, mapped_ecosystem,
               mapped_package, mapped_display_name, mapped_purl,
               mapping_confidence, mapping_reason
        FROM usages
        WHERE mapped_package IS NOT NULL
        ORDER BY project_id, mapped_ecosystem, mapped_package, source_path, line
        """
    )
    for row in usage_rows:
        record = record_for(
            row,
            ecosystem_key="mapped_ecosystem",
            package_key="mapped_package",
            display_key="mapped_display_name",
            purl_key="mapped_purl",
        )
        if record is None:
            continue
        usage = {
            "language": str(row["language"]),
            "reference": str(row["reference"]),
            "scope": str(row["scope"]),
            "kind": str(row["usage_kind"]),
            "mapping_confidence": str(row["mapping_confidence"]),
            "mapping_reason": row["mapping_reason"],
            "location": _row_location(row, "source_path"),
        }
        record["usages"].append(usage)
        if usage["kind"] not in {"tool", "command", "configuration"}:
            record["imports"].append(usage)

    findings_by_identity: dict[
        tuple[str, str, str],
        list[dict[str, Any]],
    ] = {}
    legacy_python_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in findings(connection, limit=10000):
        details = finding.get("details", {})
        finding_project = details.get("project_id")
        finding_ecosystem = details.get("ecosystem")
        package = str(finding["package"])
        if finding_project and finding_ecosystem:
            key = (
                str(finding_project),
                str(finding_ecosystem).lower(),
                package,
            )
            findings_by_identity.setdefault(key, []).append(finding)
        else:
            legacy_python_findings.setdefault(package, []).append(finding)

    needle = (search or "").strip().lower()
    results: list[dict[str, Any]] = []
    for key in sorted(records):
        record = records[key]
        versions = sorted(set(record["resolved_versions"]))
        record["resolved_versions"] = versions
        record["resolved_version"] = versions[0] if len(versions) == 1 else None
        record["declared"] = bool(record["declarations"])
        record["imported"] = bool(record["imports"])
        record["findings"] = findings_by_identity.get(key, [])
        if not record["findings"] and record["ecosystem"].lower() == "pypi":
            record["findings"] = legacy_python_findings.get(
                record["package"],
                [],
            )
        if needle and not _normalized_record_matches(record, needle):
            continue
        if offset:
            offset -= 1
            continue
        results.append(record)
        if len(results) == limit:
            break
    return results


def _normalized_record_matches(record: Mapping[str, Any], needle: str) -> bool:
    searchable = [
        record.get("package"),
        record.get("display_name"),
        record.get("purl"),
        *(
            usage.get("reference")
            for usage in record.get("usages", [])
            if isinstance(usage, Mapping)
        ),
    ]
    for declaration in record.get("declarations", []):
        metadata = declaration.get("metadata", {})
        if metadata.get("yarn_kind") == "lock-record":
            searchable.extend(
                metadata.get(key) for key in ("installation_name", "descriptor")
            )
        if metadata.get("gradle_kind") == "catalog-library":
            searchable.extend(
                metadata.get(key)
                for key in ("gradle_catalog_alias", "accessor_path", "catalog_file")
            )
            searchable.extend(
                bundle.get("alias") for bundle in metadata.get("bundles", [])
            )
    return any(needle in str(value).lower() for value in searchable if value)


def _row_location(row: sqlite3.Row, path_key: str) -> dict[str, Any]:
    location: dict[str, Any] = {"path": str(row[path_key])}
    if row["line"] is not None:
        location["line"] = int(row["line"])
    if row["column_number"] is not None:
        location["column"] = int(row["column_number"])
    return location
