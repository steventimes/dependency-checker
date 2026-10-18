"""Import supplied call, runtime, artifact and compatibility evidence as data.

Native govulncheck streams are supported directly. Other engines use explicit
versioned interchange records; a tool name alone never upgrades an assertion's
authority, and absence of a path never suppresses a package vulnerability.
"""

from __future__ import annotations

from collections import deque
import hashlib
import json
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from depcheck.bounded_io import read_bytes
from depcheck.path_policy import require_within_project
from depcheck.security.evidence import objects, text
from depcheck.snapshots import read_evidence_json, _unique_object, _invalid_constant

KINDS = (
    "callgraph",
    "govulncheck",
    "runtime",
    "component-matches",
    "behavior",
    "abi",
    "deps-dev",
    "scorecard",
)


def inspect_external_evidence(
    root: Path, path: str, kind: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Invalid external evidence pagination")
    if kind == "govulncheck":
        tables, metadata, digest = _govulncheck(root, path)
    else:
        data, digest = read_evidence_json(root, path)
        if kind == "callgraph":
            tables, metadata = _callgraph(data)
        elif kind in {"deps-dev", "scorecard"}:
            tables, metadata = _metadata(data, kind)
        elif kind in KINDS:
            tables, metadata = _records(data, kind)
        else:
            raise ValueError(f"Unsupported external evidence kind: {kind}")
    return {
        "schema": "depcheck.external-evidence.v1",
        "kind": kind,
        "read_only": True,
        "source": {"path": path, "sha256": digest, "authority": "external-assertion"},
        "metadata": metadata,
        "tables": {
            name: rows[offset : offset + limit] for name, rows in tables.items()
        },
        "counts": {name: len(rows) for name, rows in tables.items()},
        "offset": offset,
        "next_offset": offset + limit
        if any(len(rows) > offset + limit for rows in tables.values())
        else None,
        "source_authenticity": "unverified",
        "freshness": "unverified",
        "finding_effect": "none",
        "exploitation_status": "not-evaluated",
    }


def _callgraph(
    data: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    if data.get("schema") != "depcheck.call-graph.v1":
        raise ValueError("Expected depcheck.call-graph.v1")
    tool = _tool(data)
    nodes: dict[str, dict[str, Any]] = {}
    for record in objects(data.get("nodes"), "Call graph nodes"):
        identifier = text(record.get("id"), "Call node ID")
        text(record.get("symbol"), "Call node symbol")
        if identifier in nodes:
            raise ValueError("Call node IDs must be unique")
        if record.get("package_purl"):
            purl = PackageURL.from_string(record["package_purl"])
            if not purl.version:
                raise ValueError(
                    "External call nodes require versioned package coordinates"
                )
        nodes[identifier] = record
    adjacency: dict[str, list[str]] = {}
    edges = objects(data.get("edges"), "Call graph edges", maximum=100000)
    for edge in edges:
        source, target = edge.get("source"), edge.get("target")
        if source not in nodes or target not in nodes:
            raise ValueError("Call graph edges must reference retained nodes")
        if edge.get("kind") not in {"direct", "inferred", "dynamic", "observed"}:
            raise ValueError("Call graph edge kind must preserve dispatch provenance")
        adjacency.setdefault(source, []).append(target)
    entries = data.get("entries")
    if (
        not isinstance(entries, list)
        or len(entries) > 20000
        or not all(isinstance(item, str) and item in nodes for item in entries)
    ):
        raise ValueError("Explicit graph entries must reference retained nodes")
    predecessors: dict[str, str | None] = {entry: None for entry in entries}
    queue = deque(entries)
    while queue:
        source = queue.popleft()
        for target in adjacency.get(source, []):
            if target not in predecessors:
                predecessors[target] = source
                queue.append(target)
    assessments = []
    path_work = 0
    for record in objects(
        data.get("vulnerability_symbols", []), "Vulnerability symbol mappings"
    ):
        advisory = text(record.get("advisory_id"), "Vulnerability ID")
        target = record.get("node_id")
        if target not in nodes:
            raise ValueError("Vulnerability symbols must reference exact node IDs")
        path = []
        cursor = target
        while cursor in predecessors:
            path.append(cursor)
            path_work += 1
            if path_work > 100000:
                raise ValueError("Call path output budget exhausted")
            parent = predecessors[cursor]
            if parent is None:
                break
            cursor = parent
        assessments.append(
            {
                "advisory_id": advisory,
                "node_id": target,
                "package_purl": nodes[target].get("package_purl"),
                "status": "path-in-supplied-graph"
                if target in predecessors
                else "not-observed-in-supplied-graph",
                "path": list(reversed(path)),
                "vulnerability_binding": record,
                "not_affected_established": False,
            }
        )
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "assessments": assessments,
    }, {
        "tool": tool,
        "mode": data.get("mode"),
        "entries": entries,
        "environment": data.get("environment"),
        "source_hashes": data.get("source_hashes"),
        "coverage": data.get("coverage", {"state": "unknown"}),
        "node_identity_basis": "exact-input-node-id; package/symbol assertions not independently verified",
        "negative_path_semantics": "absence of observed path is not proof of non-reachability",
    }


def _tool(data: dict[str, Any]) -> dict[str, Any]:
    tool = data.get("tool")
    if not isinstance(tool, dict):
        raise ValueError("External evidence requires tool metadata")
    text(tool.get("name"), "Tool name")
    text(tool.get("version"), "Tool version")
    return tool


def _metadata(
    data: dict[str, Any], kind: str
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    if kind == "deps-dev":
        key = data.get("versionKey")
        if not isinstance(key, dict) or key.get("system") not in {
            "GO",
            "RUBYGEMS",
            "NPM",
            "CARGO",
            "MAVEN",
            "PYPI",
            "NUGET",
        }:
            raise ValueError(
                "deps.dev v3 GetVersion response requires versionKey.system"
            )
        text(key.get("name"), "deps.dev package name")
        text(key.get("version"), "deps.dev package version")
        licenses = data.get("licenses", [])
        if (
            not isinstance(licenses, list)
            or len(licenses) > 2048
            or not all(isinstance(value, str) for value in licenses)
        ):
            raise ValueError("deps.dev licenses must be a bounded string array")
        tables = {
            field: objects(data.get(field, []), f"deps.dev {field}")
            for field in (
                "advisoryKeys",
                "links",
                "relatedProjects",
                "slsaProvenances",
                "attestations",
            )
        }
        tables["versions"] = [
            {
                "version_key": key,
                "licenses": licenses,
                "published_at": data.get("publishedAt"),
                "is_deprecated": data.get("isDeprecated"),
                "deprecated_reason": data.get("deprecatedReason"),
                "registries": data.get("registries", []),
            }
        ]
        return tables, {
            "format": "deps.dev-v3-GetVersion",
            "coordinate": key,
            "assertion": data,
            "license_relationship": "unspecified-between-entries",
            "attestation_verification": "provider-assertion-only; not-verified-by-depcheck",
            "dependency_advisories": "not-included-in-GetVersion",
            "source_links": "unverified; not-followed",
        }
    repository = data.get("repo")
    tool = data.get("scorecard")
    if not isinstance(repository, dict) or not isinstance(tool, dict):
        raise ValueError("Scorecard JSON requires repo and scorecard metadata")
    text(repository.get("name"), "Scorecard repository")
    text(tool.get("version"), "Scorecard version")
    checks = objects(data.get("checks"), "Scorecard checks", maximum=256)
    for check in checks:
        text(check.get("name"), "Scorecard check name")
        score = check.get("score")
        if type(score) is not int or score < -1 or score > 10:
            raise ValueError(
                "Scorecard check score must be -1 (inconclusive) or 0 through 10"
            )
    return {"checks": checks}, {
        "format": "OpenSSF-Scorecard-JSON",
        "repository": repository,
        "tool": tool,
        "date": data.get("date"),
        "reported_score": data.get("score"),
        "interpretation": "repository-hygiene-assertions; not package safety or vulnerability reachability",
        "version_profile": "required-field-projection; not-full-schema",
    }


def _records(
    data: dict[str, Any], kind: str
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    expected = {
        "runtime": "depcheck.runtime-trace.v1",
        "component-matches": "depcheck.component-matches.v1",
        "behavior": "depcheck.behavior-evidence.v1",
        "abi": "depcheck.abi-evidence.v1",
    }[kind]
    if data.get("schema") != expected:
        raise ValueError(
            f"Expected {expected}; native engine reports require an explicit conversion"
        )
    tool = _tool(data)
    rows = []
    for index, record in enumerate(objects(data.get("records"), "External records")):
        if kind == "runtime":
            text(record.get("symbol"), "Runtime symbol")
            text(record.get("event"), "Runtime event")
            if (
                "sequence" not in record
                or type(record["sequence"]) is not int
                or record["sequence"] < 0
            ):
                raise ValueError(
                    "Runtime records require non-negative sequence assertions"
                )
            interpretation = (
                "reported-runtime-observation; unobserved symbols remain unknown"
            )
        elif kind == "component-matches":
            text(record.get("method"), "Component match method")
            text(record.get("artifact"), "Component match artifact")
            text(record.get("matched_component"), "Matched component identity")
            if record.get("package_purl"):
                PackageURL.from_string(record["package_purl"])
            interpretation = (
                "reported-artifact-match; no inferred public registry identity or CVE"
            )
        elif kind == "behavior":
            text(record.get("capability"), "Behavior capability")
            if record.get("evidence_type") not in {
                "static",
                "configuration",
                "runtime",
            }:
                raise ValueError(
                    "Behavior evidence requires static/configuration/runtime provenance"
                )
            interpretation = "capability-assertion; maliciousness not established"
        else:
            text(record.get("before"), "ABI before identity")
            text(record.get("after"), "ABI after identity")
            if record.get("status") not in {"compatible", "incompatible", "unknown"}:
                raise ValueError(
                    "ABI status must be compatible, incompatible or unknown"
                )
            text(record.get("scope"), "ABI analysis scope")
            interpretation = (
                "external-ABI-assertion; source API and other platforms remain unknown"
            )
        rows.append(
            {
                "record_index": index,
                "assertion": record,
                "interpretation": interpretation,
            }
        )
    return {"records": rows}, {
        "tool": tool,
        "environment": data.get("environment"),
        "scope": data.get("scope"),
        "inputs": data.get("inputs"),
        "coverage": data.get("coverage", {"state": "unknown"}),
        "sampling": data.get("sampling"),
        "execution_status": "externally-reported; not-executed-by-depcheck",
    }


def _govulncheck(
    root: Path, relative: str
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], str]:
    path = Path(relative)
    if path.is_absolute():
        raise ValueError("govulncheck stream path must be relative")
    candidate = root / path
    require_within_project(root, candidate, operation="read govulncheck stream")
    raw = read_bytes(candidate)
    source = raw.decode("utf-8")
    decoder = json.JSONDecoder(
        object_pairs_hook=_unique_object, parse_constant=_invalid_constant
    )
    position = 0
    messages = []
    while position < len(source):
        while position < len(source) and source[position].isspace():
            position += 1
        if position == len(source):
            break
        try:
            message, position = decoder.raw_decode(source, position)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"Invalid govulncheck JSON stream: {exc}") from exc
        if not isinstance(message, dict) or len(message) != 1:
            raise ValueError("govulncheck messages require exactly one field")
        messages.append(message)
        if len(messages) > 20000:
            raise ValueError("govulncheck message budget exhausted")
    if not messages or not isinstance(messages[0].get("config"), dict):
        raise ValueError("govulncheck stream must begin with a config message")
    config = messages[0]["config"]
    if config.get("protocol_version") != "v1.0.0":
        raise ValueError("Only govulncheck protocol v1.0.0 is supported")
    level = config.get("scan_level", "unknown")
    mode = config.get("scan_mode", "unknown")
    findings = []
    advisories = []
    inventories = []
    for message in messages[1:]:
        field, value = next(iter(message.items()))
        if not isinstance(value, dict):
            raise ValueError("govulncheck message payloads must be objects")
        if field == "finding":
            identifier = text(value.get("osv"), "govulncheck finding OSV ID")
            trace = objects(value.get("trace", []), "govulncheck frames", maximum=1000)
            if not trace:
                raise ValueError("govulncheck findings require a trace")
            first = trace[0]
            granularity = (
                "symbol"
                if first.get("function")
                else "package"
                if first.get("package")
                else "module"
            )
            if granularity == "symbol" and level != "symbol":
                raise ValueError(
                    "govulncheck symbol finding conflicts with its scan level"
                )
            for frame in trace:
                text(frame.get("module"), "govulncheck frame module")
            findings.append(
                {
                    "advisory_id": identifier,
                    "granularity": granularity,
                    "mode": mode,
                    "scan_level": level,
                    "trace": trace,
                    "trace_order": "vulnerable-symbol-to-entry",
                    "fixed_version_assertion": value.get("fixed_version"),
                    "reachability": "reported-symbol-evidence"
                    if granularity == "symbol"
                    else "not-established",
                    "not_affected_established": False,
                }
            )
        elif field == "osv":
            advisories.append(value)
        elif field == "SBOM":
            inventories.append(value)
        elif field != "progress":
            raise ValueError(f"Unsupported govulncheck stream message: {field}")
    return (
        {"findings": findings, "advisories": advisories, "inventories": inventories},
        {
            "format": "govulncheck-json-stream",
            "config": config,
            "message_count": len(messages),
            "producer_exit_status": "not-provided",
            "completion_status": "unknown; JSON EOF does not establish successful producer completion",
        },
        hashlib.sha256(raw).hexdigest(),
    )
