"""Versioned external security assertions, separate from scanner findings.

No URLs, product paths, subject names, commands or signature key IDs from an
input document are opened or executed. Import completeness is not authenticity.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree as ET

from packageurl import PackageURL

from depcheck.bounded_io import read_bytes
from depcheck.evidence_input import (
    objects as objects,
)
from depcheck.evidence_input import (
    parse_evidence_json,
    read_evidence_json,
)
from depcheck.evidence_input import (
    text as text,
)
from depcheck.path_policy import require_within_project


def timestamp(value: Any) -> str:
    value = text(value, "timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include its time zone")
    return value


def inspect_security_evidence(
    root: Path,
    path: str,
    kind: str,
    *,
    limit: int,
    offset: int = 0,
    artifact_file: str | None = None,
) -> dict[str, Any]:
    if offset < 0 or limit < 1:
        raise ValueError("Invalid evidence pagination")
    if kind == "cwe":
        try:
            rows, metadata, digest = _cwe(root, path)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid CWE XML: {exc}") from exc
    else:
        data, digest = read_evidence_json(root, path)
        if kind == "cve":
            rows, metadata = _cve(data)
        elif kind == "vex":
            rows, metadata = _vex(data)
        elif kind == "attestation":
            rows, metadata = _attestation(root, data, artifact_file)
        else:
            raise ValueError(
                "Security evidence kind must be cve, cwe, vex or attestation"
            )
    total = len(rows)
    return {
        "schema": "depcheck.security-evidence.v1",
        "read_only": True,
        "kind": kind,
        "source": {"path": path, "sha256": digest, "authority": "external-assertion"},
        "metadata": metadata,
        "records": rows[offset : offset + limit],
        "total": total,
        "offset": offset,
        "next_offset": offset + limit if total > offset + limit else None,
        "signature_status": "unverified",
        "source_authenticity": "unverified",
        "finding_effect": "none",
        "exploitation_status": "not-evaluated",
    }


def _cve(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    version = data.get("dataVersion")
    if data.get("dataType") != "CVE_RECORD" or version not in {"5.0", "5.1", "5.1.1"}:
        raise ValueError("Supported CVE JSON record versions: 5.0, 5.1, 5.1.1")
    metadata = data.get("cveMetadata")
    if not isinstance(metadata, dict) or not re.fullmatch(
        r"CVE-[0-9]{4}-[0-9]{4,}", str(metadata.get("cveId", ""))
    ):
        raise ValueError("CVE metadata requires an explicit CVE ID")
    if metadata.get("state") not in {"PUBLISHED", "REJECTED"}:
        raise ValueError("Only published or rejected CVE records are supported")
    containers = data.get("containers")
    if not isinstance(containers, dict) or not isinstance(containers.get("cna"), dict):
        raise ValueError("CVE record requires a CNA container")
    entries = [
        ("cna", containers["cna"]),
        *(
            (f"adp:{index}", entry)
            for index, entry in enumerate(
                objects(containers.get("adp", []), "ADP containers", maximum=256)
            )
        ),
    ]
    rows = []
    budget = 0
    for source, entry in entries:
        provider = entry.get("providerMetadata")
        if not isinstance(provider, dict):
            raise ValueError("CVE container requires providerMetadata")
        affected = objects(entry.get("affected", []), "CVE affected")
        problems = objects(entry.get("problemTypes", []), "CVE problemTypes")
        references = objects(entry.get("references", []), "CVE references")
        weaknesses = []
        for problem in problems:
            for description in objects(
                problem.get("descriptions", []), "CVE problem descriptions"
            ):
                cwe_id = description.get("cweId")
                if cwe_id is not None and not re.fullmatch(
                    r"CWE-[1-9][0-9]*", str(cwe_id)
                ):
                    raise ValueError("Invalid CVE weakness identifier")
                weaknesses.append(dict(description))
        budget += len(affected) + len(weaknesses) + len(references)
        if budget > 20000:
            raise ValueError("CVE container projection budget exhausted")
        rows.append(
            {
                "cve_id": metadata["cveId"],
                "source_container": source,
                "provider": provider,
                "affected": affected,
                "weaknesses": weaknesses,
                "references": references,
                "descriptions": objects(
                    entry.get("descriptions", []), "CVE descriptions"
                ),
                "rejected_reasons": objects(
                    entry.get("rejectedReasons", []), "CVE rejection reasons"
                ),
                "metrics": objects(entry.get("metrics", []), "CVE metrics"),
                "assertion": entry,
            }
        )
    return rows, {
        "format": "CVE-JSON",
        "version": version,
        **metadata,
        "package_matching": "not-performed",
        "version_ordering": "provider-assertion-only",
        "schema_validation": "supported-projection; not-full-schema",
    }


def _cwe(root: Path, relative: str) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    path = Path(relative)
    if path.is_absolute():
        raise ValueError("CWE catalog path must be repository-relative")
    target = root / path
    require_within_project(root, target, operation="read CWE catalog")
    raw = read_bytes(target)
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper() or b"\x00" in raw:
        raise ValueError(
            "CWE XML must not contain DTD/entity declarations or UTF-16/32"
        )
    parser = ET.XMLPullParser(events=("start", "end"))
    nodes, depth = 0, 0
    catalog: ET.Element | None = None
    for begin in range(0, len(raw), 8192):
        parser.feed(raw[begin : begin + 8192])
        for event, element in cast(
            Iterator[tuple[str, ET.Element]], parser.read_events()
        ):
            if event == "start":
                nodes += 1
                depth += 1
                if catalog is None:
                    catalog = element
                if nodes > 100000 or depth > 64:
                    raise ValueError("CWE XML node/depth budget exhausted")
            else:
                depth -= 1
    parser.close()
    if (
        catalog is None
        or catalog.tag != "{http://cwe.mitre.org/cwe-7}Weakness_Catalog"
        or not catalog.get("Version")
    ):
        raise ValueError(
            "Expected a versioned CWE 4.x catalog using the cwe-7 namespace"
        )
    if not catalog.get("Version", "").startswith("4."):
        raise ValueError("Only CWE catalog 4.x is supported")
    rows = []
    identifiers = set()
    for weakness in catalog.findall("{*}Weaknesses/{*}Weakness"):
        identifier = "CWE-" + str(weakness.get("ID", ""))
        if (
            not re.fullmatch(r"CWE-[1-9][0-9]*", identifier)
            or identifier in identifiers
        ):
            raise ValueError("CWE weakness IDs must be unique positive integers")
        identifiers.add(identifier)
        rows.append(
            {
                "id": identifier,
                "name": weakness.get("Name"),
                "abstraction": weakness.get("Abstraction"),
                "status": weakness.get("Status"),
                "description": "".join(weakness.findtext("{*}Description", default="")),
                "relationships": [
                    dict(child.attrib)
                    for child in weakness.findall(
                        "{*}Related_Weaknesses/{*}Related_Weakness"
                    )
                ],
            }
        )
    return (
        rows,
        {
            "format": "CWE-XML",
            "version": catalog.get("Version"),
            "catalog": catalog.get("Name"),
            "date": catalog.get("Date"),
            "vulnerability_matching": "not-applicable",
            "omitted_sections": [
                "categories",
                "views",
                "external-references",
                "examples",
                "mitigations",
            ],
            "schema_validation": "supported-projection; not-full-schema",
        },
        hashlib.sha256(raw).hexdigest(),
    )


def _vex(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if data.get("@context") != "https://openvex.dev/ns/v0.2.0":
        raise ValueError("Only OpenVEX 0.2.0 documents are supported")
    document_id = text(data.get("@id"), "VEX document ID")
    author = text(data.get("author"), "VEX author")
    issued = timestamp(data.get("timestamp"))
    if type(data.get("version")) is not int or data["version"] < 1:
        raise ValueError("VEX document version must be a positive integer")
    rows = []
    justifications = {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
    total_products = 0
    for index, statement in enumerate(
        objects(data.get("statements"), "VEX statements")
    ):
        vulnerability = statement.get("vulnerability")
        if not isinstance(vulnerability, dict):
            raise ValueError("VEX vulnerability must be an object")
        identifier = text(vulnerability.get("name"), "VEX vulnerability name")
        status = statement.get("status")
        if status not in {"affected", "not_affected", "fixed", "under_investigation"}:
            raise ValueError("Unknown VEX status")
        justification = statement.get("justification")
        if justification is not None and justification not in justifications:
            raise ValueError("Unknown OpenVEX justification")
        if status == "not_affected" and not justification:
            text(statement.get("impact_statement"), "VEX not_affected impact statement")
        if status == "affected":
            text(statement.get("action_statement"), "VEX affected action statement")
        products = objects(statement.get("products"), "VEX products")
        if not products:
            raise ValueError("Standalone VEX statements require explicit products")
        total_products += len(products)
        if total_products > 20000:
            raise ValueError("VEX product projection budget exhausted")
        for product in products:
            identifiers = product.get("identifiers", {})
            if not isinstance(identifiers, dict):
                raise ValueError("VEX product identifiers must be an object")
            product_id = product.get("@id") or identifiers.get("purl")
            if not product_id and not product.get("hashes"):
                raise ValueError("VEX product requires an identity or digest assertion")
            purl = identifiers.get("purl") or (
                product_id
                if isinstance(product_id, str) and product_id.startswith("pkg:")
                else None
            )
            canonical = PackageURL.from_string(purl).to_string() if purl else None
            rows.append(
                {
                    "statement_index": index,
                    "vulnerability": identifier,
                    "vulnerability_assertion": vulnerability,
                    "product": product,
                    "canonical_purl": canonical,
                    "status": status,
                    "timestamp": timestamp(statement.get("timestamp", issued)),
                    "justification": justification,
                    "impact_statement": statement.get("impact_statement"),
                    "action_statement": statement.get("action_statement"),
                    "status_notes": statement.get("status_notes"),
                    "decision": "external-assertion-only",
                    "suppresses_findings": False,
                }
            )
    return rows, {
        "format": "OpenVEX",
        "version": "0.2.0",
        "document_id": document_id,
        "document_version": data["version"],
        "author": author,
        "timestamp": issued,
        "trust_policy": "not-evaluated",
        "statement_precedence": "not-applied; all source statements retained",
    }


def _attestation(
    root: Path, data: dict[str, Any], artifact_file: str | None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    signatures = []
    envelope = "statement"
    if "payload" in data:
        if data.get("payloadType") != "application/vnd.in-toto+json":
            raise ValueError("Unsupported DSSE payload type")
        payload = data.get("payload")
        if (
            not isinstance(payload, str)
            or not payload
            or len(payload) > 8 * 1024 * 1024
        ):
            raise ValueError("DSSE payload exceeds its byte budget")
        signatures = objects(data.get("signatures"), "DSSE signatures", maximum=256)
        for signature in signatures:
            base64.b64decode(
                text(signature.get("sig"), "DSSE signature"), validate=True
            )
        data = parse_evidence_json(base64.b64decode(payload, validate=True))
        envelope = "DSSE"
    if data.get("_type") not in {
        "https://in-toto.io/Statement/v1",
        "https://in-toto.io/Statement/v0.1",
    }:
        raise ValueError("Unsupported in-toto Statement type")
    predicate_type = text(data.get("predicateType"), "Attestation predicate type")
    if not isinstance(data.get("predicate"), dict):
        raise ValueError("Attestation predicate must be an object")
    artifact_digest = None
    if artifact_file is not None:
        relative = Path(artifact_file)
        if relative.is_absolute():
            raise ValueError("Artifact path must be repository-relative")
        artifact = root / relative
        require_within_project(
            root, artifact, operation="hash supplied attestation artifact"
        )
        artifact_digest = hashlib.sha256(read_bytes(artifact)).hexdigest()
    rows = []
    for subject in objects(data.get("subject"), "Attestation subjects"):
        name = text(subject.get("name"), "Attestation subject name")
        digests = subject.get("digest")
        if (
            not isinstance(digests, dict)
            or not digests
            or not all(
                isinstance(k, str) and isinstance(v, str) and v
                for k, v in digests.items()
            )
        ):
            raise ValueError("Attestation subject requires digest assertions")
        sha256 = digests.get("sha256")
        if sha256 is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
            raise ValueError("Invalid attestation SHA-256 digest")
        rows.append(
            {
                "name": name,
                "digests": digests,
                "selected_artifact": artifact_file,
                "selected_artifact_sha256": artifact_digest,
                "digest_match": artifact_digest == sha256.lower()
                if sha256 and artifact_digest
                else None,
                "identity_verified": False,
            }
        )
    return rows, {
        "format": "in-toto",
        "envelope": envelope,
        "statement_type": data["_type"],
        "predicate_type": predicate_type,
        "predicate": data["predicate"],
        "reported_signatures": signatures,
        "verification_status": "not-performed",
        "commands_executed": False,
    }
