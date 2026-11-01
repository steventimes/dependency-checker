"""Import supplied call, runtime, artifact and compatibility evidence as data.

Native govulncheck streams are supported directly. Other engines use explicit
versioned interchange records; a tool name alone never upgrades an assertion's
authority, and absence of a path never suppresses a package vulnerability.
"""

from __future__ import annotations

import hashlib
from collections import deque
from pathlib import Path
from typing import Any

from packageurl import PackageURL
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.evidence.input import (
    evidence_json_decoder,
    objects,
    read_evidence_json,
    text,
)
from depcheck.evidence.origins import redact_source
from depcheck.filesystem import read_bytes, require_within_project

KINDS = (
    "callgraph",
    "govulncheck",
    "runtime",
    "component-matches",
    "behavior",
    "abi",
    "deps-dev",
    "scorecard",
    "pip-inspect",
    "pip-install-report",
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
            tables, metadata = project_call_graph(data)
        elif kind in {"pip-inspect", "pip-install-report"}:
            tables, metadata = _pip_report(data, kind)
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


def _pip_field_keys(value: dict[str, Any]) -> None:
    """Do not echo credential-bearing URL keys from malformed extensions."""
    for key in value:
        text(key, "pip report field name")
        if redact_source(key) != key:
            raise ValueError("Unsupported credential-bearing pip report field name")


def _pip_report(
    data: dict[str, Any],
    kind: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    installing = kind == "pip-install-report"
    records_key = "install" if installing else "installed"
    if data.get("version") != "1":
        raise ValueError("Unsupported pip report version; expected '1'")
    producer = text(data.get("pip_version"), "pip version")
    environment = data.get("environment")
    if not isinstance(environment, dict) or len(environment) > 128:
        raise ValueError("pip report environment must be a bounded object")
    _pip_field_keys(environment)
    for key, value in environment.items():
        text(key, "Environment key")
        if not isinstance(value, str) or len(value) > 16384:
            raise ValueError("Environment values must be bounded strings")
    rows = []
    for index, record in enumerate(
        objects(data.get(records_key), "Distribution report records")
    ):
        metadata = record.get("metadata")
        if not isinstance(metadata, dict) or len(metadata) > 256:
            raise ValueError("Installed metadata must be a bounded object")
        _pip_field_keys(metadata)
        name = text(metadata.get("name"), "Distribution name")
        try:
            canonical = str(canonicalize_name(name, validate=True))
        except InvalidName:
            raise ValueError("Invalid pip inspect distribution name") from None
        version = text(metadata.get("version"), "Distribution version")
        selected: dict[str, Any] = {"name": name, "version": version}
        for field in ("metadata_version", "requires_python"):
            if field in metadata:
                selected[field] = text(metadata[field], field)
        for field in ("requires_dist", "provides_extra"):
            if field in metadata:
                values = metadata[field]
                if not isinstance(values, list) or len(values) > 4096:
                    raise ValueError(f"{field} must be a bounded string array")
                selected[field] = [text(value, field) for value in values]
        try:
            Version(version)
            version_status = "valid-pep440"
        except InvalidVersion:
            version_status = "invalid-pep440"
        row: dict[str, Any] = {
            "instance_id": f"{kind}:{index}",
            "source_pointer": f"/{records_key}/{index}",
            "name": canonical,
            "version": version,
            "version_status": version_status,
            "metadata": redact_source(selected),
            "omitted_metadata_fields": sorted(set(metadata) - set(selected)),
            "public_identity_status": "unverified",
            "installation_status": (
                "not-established; report-may-be-dry-run"
                if installing
                else "reported-in-supplied-environment"
            ),
        }
        if not installing:
            row["metadata_location"] = redact_source(
                text(record.get("metadata_location"), "Metadata location")
            )
        elif not isinstance(record.get("requested"), bool) or not isinstance(
            record.get("is_direct"), bool
        ):
            raise ValueError(
                "Installation report requires requested and is_direct booleans"
            )
        if "requested" in record:
            if not isinstance(record["requested"], bool):
                raise ValueError("requested must be a boolean when provided")
            row["requested"] = record["requested"]
        if not installing and "installer" in record:
            row["installer"] = text(record["installer"], "Installer")
        if installing:
            row["is_direct"] = record["is_direct"]
            if "is_yanked" in record:
                if not isinstance(record["is_yanked"], bool):
                    raise ValueError("is_yanked must be a boolean when provided")
                row["is_yanked"] = record["is_yanked"]
            if "requested_extras" in record:
                extras = record["requested_extras"]
                if (
                    record["requested"] is not True
                    or not isinstance(extras, list)
                    or len(extras) > 4096
                ):
                    raise ValueError(
                        "requested_extras requires requested=true and a bounded string array"
                    )
                row["requested_extras"] = [
                    text(value, "Requested extra") for value in extras
                ]
            if "download_info" not in record:
                raise ValueError("Installation report requires download_info")
        direct_key = "download_info" if installing else "direct_url"
        if direct_key in record:
            direct = record[direct_key]
            if not isinstance(direct, dict) or len(direct) > 32:
                raise ValueError("direct_url must be a bounded object")
            _pip_field_keys(direct)
            text(direct.get("url"), "Direct URL")
            for field in ("dir_info", "vcs_info", "archive_info"):
                if field in direct and not isinstance(direct[field], dict):
                    raise ValueError(f"direct_url.{field} must be an object")
            # Native direct-URL records have only shallow scalar properties and
            # an optional archive hash map. Reject recursive/oversized extensions
            # before the shared recursive redactor is called.
            for value in direct.values():
                if isinstance(value, dict):
                    if len(value) > 64:
                        raise ValueError("Direct URL properties exceed their limit")
                    _pip_field_keys(value)
                    for nested in value.values():
                        values = (
                            nested.values() if isinstance(nested, dict) else [nested]
                        )
                        if isinstance(nested, dict) and len(nested) > 64:
                            raise ValueError("Direct URL hashes exceed their limit")
                        if isinstance(nested, dict):
                            _pip_field_keys(nested)
                        for scalar in values:
                            if (
                                not isinstance(scalar, (str, bool))
                                or isinstance(scalar, str)
                                and len(scalar) > 16384
                            ):
                                raise ValueError(
                                    "Direct URL properties must be bounded scalars"
                                )
                elif (
                    not isinstance(value, (str, bool))
                    or isinstance(value, str)
                    and len(value) > 16384
                ):
                    raise ValueError("Direct URL properties must be bounded scalars")
            row[direct_key] = redact_source(direct)
        rows.append(row)
    metadata = {
        "format": f"{kind}-v1",
        "tool": {"name": "pip", "version": producer},
        "environment": redact_source(environment),
        "environment_binding": "unverified; not compared with the host or project",
        "current_project_installation": "not-established",
        "public_origin": "not-established; installer and absent direct_url do not identify an index",
        "metadata_locations": "opaque assertions; never opened",
        "requires_dist": "reported constraints; activation and satisfaction not evaluated",
    }
    if installing:
        metadata.pop("metadata_locations")
        metadata["report_execution"] = (
            "unknown; may describe a dry-run or installation attempt"
        )
        metadata["public_origin"] = (
            "not-established; download URL and is_direct do not identify a public index"
        )
    return {"distributions": rows}, metadata


def project_call_graph(
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
    decoder = evidence_json_decoder()
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
