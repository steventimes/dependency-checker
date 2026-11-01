"""Evaluate pinned inventory and advisory corpora against independent truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

import yaml
from packaging.utils import canonicalize_name
from packaging.markers import Marker

from depcheck.agent.service import DependencyAgentService
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.model import ProjectUnit, ResolvedDependency, ScanResult
from depcheck.output import build_cyclonedx
from depcheck.security.advisories import match_affected_version, parse_advisory


def _evaluate_inventory() -> dict:
    fixtures = Path(__file__).resolve().parents[1] / "test/fixtures/pnpm"
    truth = json.loads((fixtures / "truth.json").read_text())
    provenance = json.loads((fixtures / "provenance.json").read_text())
    digests = {item["path"]: item["sha256"] for item in provenance["retained_fixtures"]}
    results = []
    for case in truth["cases"]:
        content = (fixtures / case["fixture"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != digests[case["fixture"]]:
            raise ValueError(f"Corpus digest mismatch: {case['fixture']}")
        document = yaml.safe_load(content)
        with tempfile.TemporaryDirectory(prefix="depcheck-corpus-") as directory:
            root = Path(directory)
            (root / "pnpm-lock.yaml").write_bytes(content)
            (root / "pnpm-workspace.yaml").write_text('packages: ["**"]\n')
            for importer, entry in document["importers"].items():
                member = root / importer
                member.mkdir(parents=True, exist_ok=True)
                manifest = {
                    section: {
                        name: value["specifier"] for name, value in values.items()
                    }
                    for section, values in entry.items()
                }
                (member / "package.json").write_text(json.dumps(manifest))
            scan = RepositoryScanner().scan(
                root, RepositoryScanOptions(security=False, compatibility=False)
            )
            observed = {
                (bundle.project.root.as_posix(), item.package.name, item.version)
                for bundle in scan.bundles
                for item in bundle.resolved
            }
            expected = {
                (member, name, version)
                for member, packages in case["expected"].items()
                for name, version in packages
            }
            codes = {item.code for item in scan.diagnostics}
            missing_diagnostics = sorted(set(case["required_diagnostics"]) - codes)
            results.append(
                {
                    "fixture": case["fixture"],
                    "true_positive": len(observed & expected),
                    "false_positive": sorted(observed - expected),
                    "false_negative": sorted(expected - observed),
                    "missing_diagnostics": missing_diagnostics,
                    "diagnostics": sorted(codes),
                    "capabilities": [
                        item.to_dict()
                        for bundle in scan.bundles
                        for item in bundle.capabilities
                    ],
                }
            )
    return {
        "schema": "depcheck.corpus-result.v1",
        "scope": truth["scope"],
        "upstream_commit": provenance["commit"],
        "truth_sha256": hashlib.sha256(
            (fixtures / "truth.json").read_bytes()
        ).hexdigest(),
        "passed": all(
            not item["false_positive"]
            and not item["false_negative"]
            and not item["missing_diagnostics"]
            for item in results
        ),
        "cases": results,
    }


def evaluate_security(fixtures: Path) -> dict:
    truth_bytes = (fixtures / "truth.json").read_bytes()
    truth = json.loads(truth_bytes)
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    records = []
    for item in provenance["retained_fixtures"]:
        content = (fixtures / item["path"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError(f"Corpus digest mismatch: {item['path']}")
        if item["path"].endswith(".json"):
            records.append(json.loads(content))
    cases = truth["cases"]
    if not records or not cases or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Security corpus needs records and unique, nonempty cases")
    severity_truth = truth.get("advisory_severity")
    if not isinstance(severity_truth, dict) or set(severity_truth) != {
        record["id"] for record in records
    }:
        raise ValueError("Security corpus needs severity labels for every advisory")
    results = []
    with tempfile.TemporaryDirectory(prefix="depcheck-security-corpus-") as directory:
        root = Path(directory)
        inventory = {
            "schema": "depcheck.scan.v1",
            "inventory": {
                "resolved_dependencies": [
                    {
                        "identity": {
                            "project_id": "security-corpus",
                            "ecosystem": case["ecosystem"],
                            "package": case["package"],
                            "version": case["version"],
                            "instance": case["id"],
                        },
                        "origin": case.get("origin", {"public": True}),
                    }
                    for case in cases
                ]
            },
        }
        (root / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        (root / "advisories.json").write_text(
            json.dumps({"schema": "depcheck.osv-database.v1", "records": records}),
            encoding="utf-8",
        )
        service = DependencyAgentService(root)
        observations = []
        for offset in range(0, len(cases), 20):
            page = service.reevaluate_vulnerabilities(
                "inventory.json", "advisories.json", limit=20, offset=offset
            )
            expected_next = offset + 20 if offset + 20 < len(cases) else None
            if page["next_offset"] != expected_next:
                raise ValueError(
                    "Security corpus pagination changed or did not advance"
                )
            observations.extend(page["observations"])
        if len(observations) != len(cases):
            raise ValueError("Security corpus lost inventory observations")
        for case, row in zip(cases, observations, strict=True):
            if row["identity"]["instance"] != case["id"]:
                raise ValueError("Security corpus changed instance correspondence")
            issues = row["vulnerabilities"]
            labelled_issue = next(
                (
                    issue
                    for issue in issues
                    if case["advisory"] in {issue["id"], *issue.get("aliases", [])}
                ),
                None,
            )
            actual = {
                "status": row["status"],
                "advisory_ids": sorted(issue["id"] for issue in issues),
                "cve_ids": sorted(
                    {cve for issue in issues for cve in issue["cve_ids"]}
                ),
                "fix_version": labelled_issue["fix_version"]
                if labelled_issue
                else None,
                "fix_status": labelled_issue["fix_version_status"]
                if labelled_issue
                else None,
            }
            expected = {
                "status": case["expected_status"],
                "advisory_ids": [case["advisory"]]
                if case["expected_status"] == "matched"
                else [],
                "cve_ids": case["expected_cve_ids"],
                "fix_version": case["expected_fix_version"],
                "fix_status": case["expected_fix_status"],
            }
            if case["expected_status"] == "matched":
                label = severity_truth[case["advisory"]]
                actual.update(
                    severity=labelled_issue.get("severity") if labelled_issue else None,
                    severity_status=labelled_issue.get("severity_status")
                    if labelled_issue
                    else None,
                    assertion_fields=[
                        assertion["field"]
                        for assertion in labelled_issue.get("severity_assertions", [])
                        if assertion.get("advisory_id") == case["advisory"]
                        and assertion.get("applicability") == "affected"
                    ]
                    if labelled_issue
                    else [],
                )
                expected.update(label)
            results.append(
                {
                    "case": case["id"],
                    "known_affected": case["known_affected"],
                    "expected": expected,
                    "actual": actual,
                    "mismatched_fields": [
                        key for key in expected if expected[key] != actual[key]
                    ],
                    "advisory_checks": row.get("advisory_checks", []),
                }
            )
    affected = {case["id"] for case in cases if case["known_affected"] is True}
    unaffected = {case["id"] for case in cases if case["known_affected"] is False}
    matched = {row["case"] for row in results if row["actual"]["status"] == "matched"}
    return {
        "scope": truth["scope"],
        "upstream_commit": provenance["commit"],
        "truth_sha256": hashlib.sha256(truth_bytes).hexdigest(),
        "passed": all(not row["mismatched_fields"] for row in results),
        "true_positive": sorted(affected & matched),
        "false_positive": sorted(unaffected & matched),
        # Known unsupported cases stay visible here even when their expected
        # unknown status satisfies the regression contract.
        "false_negative": sorted(affected - matched),
        "true_negative": sorted(
            row["case"]
            for row in results
            if row["case"] in unaffected
            and row["actual"]["status"] == "not-matched-in-supplied-records"
        ),
        "unknown": sorted(
            row["case"] for row in results if row["actual"]["status"] == "unknown"
        ),
        "cases": results,
    }


def evaluate_scoped_severity(fixtures: Path) -> dict:
    """Check real source scores separately from public inventory eligibility."""
    truth_bytes = (fixtures / "truth.json").read_bytes()
    truth = json.loads(truth_bytes)
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    records = {}
    for item in provenance["retained_fixtures"]:
        content = (fixtures / item["path"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError(f"Corpus digest mismatch: {item['path']}")
        if item["path"].endswith(".json"):
            record = json.loads(content)
            records[record["id"]] = record
    cases = truth["cases"]
    if (
        not cases
        or len({case["id"] for case in cases}) != len(cases)
        or set(records) != set(truth["labels"])
        or set(records) != {case["record"] for case in cases}
    ):
        raise ValueError("Scoped severity corpus needs records and unique cases")
    results = []
    for case in cases:
        record = records[case["record"]]
        args = (record, case["package"], case["ecosystem"], case["version"])
        issue, diagnostics = parse_advisory(*args)
        assertions = [
            {
                **label,
                "field": f"/affected/{index}/severity",
                "applicability": state,
            }
            for index, (label, state) in enumerate(
                zip(
                    truth["labels"][case["record"]],
                    case["assertion_states"],
                    strict=True,
                )
            )
        ]
        expected = {
            "membership": case["membership"],
            "severity": [
                score
                for assertion in assertions
                if assertion["applicability"] == "affected"
                for score in assertion["severity"]
            ],
            "severity_status": case["severity_status"],
            "assertions": assertions,
            "fix_versions": case["fix_versions"],
            "fix_version": case["fix_version"],
            "fix_status": "candidate" if case["fix_version"] else "unknown",
        }
        actual = {
            "membership": match_affected_version(*args)[0],
            "severity": issue["severity"],
            "severity_status": issue["severity_status"],
            "assertions": [
                {key: assertion[key] for key in assertions[0]}
                for assertion in issue["severity_assertions"]
            ],
            "fix_versions": sorted(issue["fix_versions"]),
            "fix_version": issue["fix_version"],
            "fix_status": issue["fix_version_status"],
        }
        results.append(
            {
                "case": case["id"],
                "expected": expected,
                "actual": actual,
                "diagnostics": [note.code for note in diagnostics],
                "mismatched_fields": [
                    key for key in expected if expected[key] != actual[key]
                ],
            }
        )
    return {
        "scope": truth["scope"],
        "truth_sha256": hashlib.sha256(truth_bytes).hexdigest(),
        "passed": all(not case["mismatched_fields"] for case in results),
        "cases": results,
    }


def _project_observations(
    service: DependencyAgentService, inventory: str
) -> list[dict]:
    observations: list[dict] = []
    offset = 0
    signature = None
    seen = set()
    while True:
        page = service.reevaluate_vulnerabilities(
            inventory, ".tmp/advisories.json", limit=50, offset=offset
        )
        current = (
            page["total"],
            page["inventory"]["sha256"],
            page["database"]["sha256"],
        )
        if signature is None:
            signature = current
        if current != signature or not 0 <= page["total"] <= 20000:
            raise ValueError("Project corpus pagination changed inventory or total")
        rows = page["observations"]
        if page["offset"] != offset or len(rows) != min(50, page["total"] - offset):
            raise ValueError("Project corpus pagination lost observations")
        for row in rows:
            key = _project_identity(row["identity"])
            if key in seen:
                raise ValueError("Project corpus repeated an inventory identity")
            seen.add(key)
        observations.extend(rows)
        expected_next = offset + 50 if offset + 50 < page["total"] else None
        if page["next_offset"] != expected_next:
            raise ValueError("Project corpus pagination changed or did not advance")
        if expected_next is None:
            break
        offset = expected_next
    if len(observations) != signature[0]:
        raise ValueError("Project corpus lost inventory observations")
    return observations


def _project_identity(identity: dict) -> tuple:
    return tuple(
        identity.get(field)
        for field in ("project_id", "ecosystem", "package", "version", "instance")
    )


def _project_corpus_inputs(fixtures: Path, security_fixtures: Path) -> tuple:
    """Reject empty/duplicate truth and verify retained bytes before scanning."""
    truth_bytes = (fixtures / "truth.json").read_bytes()
    truth = json.loads(truth_bytes)
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    cases = truth.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Project corpus needs nonempty cases")
    case_ids = set()
    required_files = set()
    for case in cases:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("id"), str)
            or not case["id"]
        ):
            raise ValueError("Project corpus needs nonempty case IDs")
        if case["id"] in case_ids:
            raise ValueError("Project corpus case IDs must be unique")
        case_ids.add(case["id"])
        directory = case.get("directory")
        if (
            not isinstance(directory, str)
            or not directory
            or Path(directory).is_absolute()
            or ".." in Path(directory).parts
        ):
            raise ValueError("Project corpus case directory must stay within fixtures")
        required_files.update(
            f"{directory}/{name}"
            for name in ("package.json", "package-lock.json", "LICENSE.txt")
        )
        if (
            type(case.get("expected_inventory_count")) is not int
            or case["expected_inventory_count"] < 1
        ):
            raise ValueError("Project corpus needs a nonempty inventory count")
        digest = case.get("expected_inventory_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("Project corpus needs an inventory SHA256")
        labels = case.get("security_labels")
        context_labels = case.get("resolution_context_labels")
        if not isinstance(context_labels, list) or not context_labels:
            raise ValueError("Project corpus needs independent context labels")
        if not isinstance(labels, list) or not labels:
            raise ValueError("Project corpus needs nonempty security labels")
        seen_labels = set()
        for label in labels:
            if not isinstance(label, dict) or not all(
                isinstance(label.get(field), str) and label[field]
                for field in ("instance", "package", "version", "advisory")
            ):
                raise ValueError(
                    "Project corpus labels need exact instance/package/version/advisory"
                )
            key = (label["instance"], label["advisory"])
            if key in seen_labels:
                raise ValueError("Project corpus security labels must be unique")
            seen_labels.add(key)
            cves = label.get("expected_cve_ids")
            if type(label.get("known_affected")) is not bool or label.get(
                "expected_status"
            ) not in {"matched", "not-matched-in-supplied-records", "unknown"}:
                raise ValueError(
                    "Project corpus labels need explicit affected truth and status"
                )
            if (
                not isinstance(cves, list)
                or not all(isinstance(cve, str) and cve for cve in cves)
                or len(set(cves)) != len(cves)
            ):
                raise ValueError("Project corpus labels need unique CVE IDs")
            if "expected_fix_version" not in label or (
                label["expected_fix_version"] is not None
                and not isinstance(label["expected_fix_version"], str)
            ):
                raise ValueError(
                    "Project corpus labels need an explicit fix version or null"
                )
        for field, columns in (
            ("required_edges", ("parent", "required", "target", "version")),
            ("forbidden_edges", ("parent", "target")),
        ):
            edges = case.get(field)
            if not isinstance(edges, list) or not all(
                isinstance(edge, dict)
                and all(
                    isinstance(edge.get(column), str) and edge[column]
                    for column in columns
                )
                for edge in edges
            ):
                raise ValueError(
                    "Project corpus edges need explicit physical instances"
                )
    variants = truth.get("variants", [])
    if not isinstance(variants, list):
        raise ValueError("Project corpus variants must be an array")
    all_ids = set(case_ids)
    for variant in variants:
        if not isinstance(variant, dict) or not all(
            isinstance(variant.get(field), str) and variant[field]
            for field in ("id", "base", "kind", "npmrc")
        ):
            raise ValueError("Project corpus variants need an ID, base, kind and npmrc")
        if variant["id"] in all_ids or variant["base"] not in case_ids:
            raise ValueError(
                "Project corpus variants need unique IDs and an existing base"
            )
        if (
            variant.get("expected_status") != "unknown"
            or variant.get("known_affected", "missing") is not None
        ):
            raise ValueError(
                "Project corpus private variants require unknown security truth"
            )
        all_ids.add(variant["id"])
    retained = provenance.get("retained_fixtures", [])
    if not isinstance(retained, list) or not retained:
        raise ValueError("Project corpus needs retained fixture provenance")
    verified_files = set()
    for item in retained:
        relative = item.get("path") if isinstance(item, dict) else None
        if not isinstance(relative, str) or not relative or relative in verified_files:
            raise ValueError(
                "Project corpus provenance paths must be unique and nonempty"
            )
        path = fixtures / relative
        if Path(relative).is_absolute() or not path.resolve().is_relative_to(
            fixtures.resolve()
        ):
            raise ValueError("Project corpus provenance path leaves fixtures")
        verified_files.add(relative)
        content = path.read_bytes()
        git_blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content,
            usedforsecurity=False,
        ).hexdigest()
        if (
            hashlib.sha256(content).hexdigest() != item["sha256"]
            or git_blob != item["git_blob_sha1"]
            or len(content) != item["bytes"]
        ):
            raise ValueError(f"Corpus digest mismatch: {item['path']}")
    if not required_files.issubset(verified_files):
        raise ValueError("Project corpus provenance omits original inputs")
    advisory_name = "GHSA-35jh-r3h4-6jhm.json"
    advisory = (security_fixtures / advisory_name).read_bytes()
    security_provenance = json.loads(
        (security_fixtures / "provenance.json").read_bytes()
    )
    expected_advisories = [
        item["sha256"]
        for item in security_provenance["retained_fixtures"]
        if item["path"] == advisory_name
    ]
    if (
        len(expected_advisories) != 1
        or hashlib.sha256(advisory).hexdigest() != expected_advisories[0]
    ):
        raise ValueError(f"Corpus digest mismatch: {advisory_name}")
    return truth_bytes, truth, json.loads(advisory)


def _project_edge_mismatches(
    records: list[ResolvedDependency], case: dict
) -> list[str]:
    by_instance = {item.instance_id: item for item in records}
    mismatches = []
    for edge in case["required_edges"]:
        parent = by_instance.get(edge["parent"])
        if parent is None or not any(
            link.package.name == edge["required"]
            and link.instance_id == edge["target"]
            and link.version == edge["version"]
            for link in parent.dependency_links
        ):
            mismatches.append("missing-required-edge:" + edge["parent"])
    for edge in case["forbidden_edges"]:
        parent = by_instance.get(edge["parent"])
        if parent is not None and any(
            link.instance_id == edge["target"] for link in parent.dependency_links
        ):
            mismatches.append("invented-nested-edge:" + edge["target"])
    for label in case["resolution_context_labels"]:
        record = by_instance.get(label["instance"])
        metadata = getattr(record, "metadata", {})
        context = metadata.get("context", {})
        if (
            metadata.get("npm_kind") != "lock-record"
            or metadata.get("lock_format") != label["lock_format"]
            or metadata.get("activation") != "unknown"
            or not isinstance(context, dict)
            or any(
                context.get(key) != value for key, value in label["assertions"].items()
            )
        ):
            mismatches.append("missing-or-changed-lock-context:" + label["instance"])
    return mismatches


def _project_transport_mismatches(
    scan: ScanResult, canonical: list[dict], sbom: list[dict]
) -> tuple[list[str], int]:
    records = [item for bundle in scan.bundles for item in bundle.resolved]
    expected = Counter(_project_identity(item.identity.to_dict()) for item in records)
    locked_sbom = [row for row in sbom if row["identity"].get("instance") is not None]
    mismatches = []
    for rows in (canonical, locked_sbom):
        if Counter(_project_identity(row["identity"]) for row in rows) != expected:
            mismatches.append("transport-inventory-identities")
    origins = {
        _project_identity(item.identity.to_dict()): dict(item.origin) or None
        for item in records
    }
    metadata = {
        _project_identity(item.identity.to_dict()): dict(getattr(item, "metadata", {}))
        for item in records
    }
    canonical_by_identity = {
        _project_identity(row["identity"]): row for row in canonical
    }
    for row in canonical:
        if row["identity"].get("origin") != origins.get(
            _project_identity(row["identity"])
        ):
            mismatches.append("canonical-origin")
        if row.get("metadata", {}) != metadata.get(
            _project_identity(row["identity"]), {}
        ):
            mismatches.append("canonical-resolution-metadata")
    for row in locked_sbom:
        original = canonical_by_identity.get(_project_identity(row["identity"]))
        if (
            original is None
            or any(
                row.get(field) != original.get(field)
                for field in (
                    "status",
                    "vulnerabilities",
                    "advisory_checks",
                    "metadata",
                )
            )
            or row["identity"].get("origin") != original["identity"].get("origin")
        ):
            mismatches.append("sbom-security-or-origin")
    # Export can add declared-only components, never additional resolved facts.
    manifest_origins = {}
    for bundle in scan.bundles:
        for item in bundle.declarations:
            if item.kind not in {"constraint", "hint"}:
                key = (
                    item.project_id,
                    item.package.ecosystem,
                    item.package.name,
                    None,
                    None,
                )
                assertions = manifest_origins.setdefault(key, [])
                origin = item.metadata.get("origin")
                if isinstance(origin, Mapping):
                    assertions.append(dict(origin))
    for key, assertions in manifest_origins.items():
        manifest_origins[key] = (
            assertions[0]
            if assertions and all(value == assertions[0] for value in assertions)
            else {"kind": "ambiguous", "public": False, "assertions": assertions}
            if assertions
            else None
        )
    extra_sbom = [row for row in sbom if row["identity"].get("instance") is None]
    for row in extra_sbom:
        identity = row["identity"]
        key = _project_identity(identity)
        if (
            row["status"] != "unknown"
            or identity.get("version") is not None
            or key not in manifest_origins
        ):
            mismatches.append("unexpected-sbom-manifest-component")
        elif identity.get("origin") != manifest_origins[key]:
            mismatches.append("sbom-manifest-origin")
    return mismatches, len(extra_sbom)


def _project_security_labels(
    case: dict, variant: dict | None, canonical: list[dict]
) -> tuple[list[dict], list[dict]]:
    by_instance: dict[str, list[dict]] = {}
    for row in canonical:
        by_instance.setdefault(row["identity"].get("instance"), []).append(row)
    labelled = []
    for label in case["security_labels"]:
        rows = by_instance.get(label["instance"], [])
        row = rows[0] if len(rows) == 1 else None
        issues = []
        checks = []
        if row is not None:
            issues = [
                issue
                for issue in row["vulnerabilities"]
                if label["advisory"] in {issue["id"], *issue.get("aliases", [])}
            ]
            checks = [
                check
                for check in row.get("advisory_checks", [])
                if check["id"] == label["advisory"]
            ]
        # A different advisory on the same instance is outside this label's scope.
        status = "missing-or-repeated"
        if row is not None:
            status = "unknown"
            if issues:
                status = "matched"
            elif checks and all(check["status"] == "not-affected" for check in checks):
                status = "not-matched-in-supplied-records"
        selected = next(
            (issue for issue in issues if issue["id"] == label["advisory"]), None
        )
        if selected is None and len(issues) == 1:
            selected = next(iter(issues))
        observed = {
            "status": status,
            "advisory_ids": sorted(issue["id"] for issue in issues),
            "cve_ids": sorted({cve for issue in issues for cve in issue["cve_ids"]}),
            "fix_version": selected["fix_version"] if selected else None,
            "fix_status": selected["fix_version_status"] if selected else None,
        }
        expected_status = (
            variant["expected_status"] if variant else label["expected_status"]
        )
        expected = {
            "status": expected_status,
            "advisory_ids": [label["advisory"]] if expected_status == "matched" else [],
            "cve_ids": [] if variant else label["expected_cve_ids"],
            "fix_version": None if variant else label["expected_fix_version"],
            "fix_status": "candidate" if expected_status == "matched" else None,
        }
        fields = [name for name in expected if observed[name] != expected[name]]
        if row is not None:
            identity = row["identity"]
            if (
                identity.get("package") != label["package"]
                or identity.get("version") != label["version"]
                or identity.get("ecosystem") != "npm"
            ):
                fields.append("label-identity")
            origin = identity.get("origin")
            if not isinstance(origin, dict) or origin.get("public") is not (
                variant is None
            ):
                fields.append("source-qualification")
            if issues and row["status"] != "matched":
                fields.append("observation-status")
            if expected_status == "not-matched-in-supplied-records" and not any(
                check["status"] == "not-affected" for check in checks
            ):
                fields.append("missing-negative-advisory-check")
        labelled.append(
            {
                "instance": label["instance"],
                "advisory": label["advisory"],
                "known_affected": None if variant else label["known_affected"],
                "expected": expected,
                "actual": observed,
                "mismatched_fields": fields,
            }
        )
    labels_by_instance: dict[str, set[str]] = {}
    for label in case["security_labels"]:
        labels_by_instance.setdefault(label["instance"], set()).add(label["advisory"])
    unjudged = []
    for row in canonical:
        labels = labels_by_instance.get(row["identity"].get("instance"), set())
        issues = [
            issue["id"]
            for issue in row["vulnerabilities"]
            if labels.isdisjoint({issue["id"], *issue.get("aliases", [])})
        ]
        if issues:
            unjudged.append(
                {"identity": row["identity"], "advisory_ids": sorted(issues)}
            )
    return labelled, unjudged


def _project_label_metrics(results: list[dict], *, synthetic: bool) -> dict:
    # Unknown affected observations remain false negatives, as in the original
    # security corpus, and also stay visible in unknown. These lists overlap.
    metrics: dict[str, list[dict]] = {
        key: []
        for key in (
            "true_positive",
            "true_negative",
            "false_positive",
            "false_negative",
            "unknown",
        )
    }
    for result in results:
        if result["synthetic"] is not synthetic:
            continue
        for label in result["security_labels"]:
            item = {
                "case": result["case"],
                "instance": label["instance"],
                "advisory": label["advisory"],
            }
            affected = label["known_affected"]
            status = label["actual"]["status"]
            if status in {"unknown", "missing-or-repeated"}:
                metrics["unknown"].append(item)
            if affected is True:
                metrics[
                    "true_positive" if status == "matched" else "false_negative"
                ].append(item)
            elif affected is False and status == "matched":
                metrics["false_positive"].append(item)
            elif affected is False and status == "not-matched-in-supplied-records":
                metrics["true_negative"].append(item)
    return metrics


def evaluate_projects(fixtures: Path, security_fixtures: Path) -> dict:
    """Evaluate actual locked projects; score only independently labelled cases."""
    truth_bytes, truth, advisory = _project_corpus_inputs(fixtures, security_fixtures)
    cases = {case["id"]: case for case in truth["cases"]}
    jobs = [(case, None) for case in cases.values()]
    jobs.extend(
        (cases[variant["base"]], variant) for variant in truth.get("variants", [])
    )
    results = []
    for case, variant in jobs:
        with tempfile.TemporaryDirectory(
            prefix="depcheck-project-corpus-"
        ) as directory:
            root = Path(directory)
            for name in ("package.json", "package-lock.json"):
                (root / name).write_bytes(
                    (fixtures / case["directory"] / name).read_bytes()
                )
            if variant:
                (root / ".npmrc").write_text(variant["npmrc"], encoding="utf-8")
            inputs = {
                name: (path.read_bytes(), path.stat().st_mtime_ns)
                for name in ("package.json", "package-lock.json", ".npmrc")
                if (path := root / name).is_file()
            }
            scan = RepositoryScanner().scan(
                root, RepositoryScanOptions(security=False, compatibility=False)
            )
            records = [item for bundle in scan.bundles for item in bundle.resolved]
            inventory_rows = sorted(
                [item.instance_id, item.package.name, item.version] for item in records
            )
            inventory_digest = hashlib.sha256(
                json.dumps(
                    inventory_rows, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            mismatches = []
            if (
                len(records) != case["expected_inventory_count"]
                or inventory_digest != case["expected_inventory_sha256"]
            ):
                mismatches.append("locked-inventory")
            mismatches.extend(_project_edge_mismatches(records, case))
            derived = root / ".tmp"
            derived.mkdir()
            (derived / "inventory.json").write_text(
                json.dumps(scan.to_dict()), encoding="utf-8"
            )
            (derived / "sbom.json").write_text(
                json.dumps(build_cyclonedx(scan)), encoding="utf-8"
            )
            (derived / "advisories.json").write_text(
                json.dumps(
                    {"schema": "depcheck.osv-database.v1", "records": [advisory]}
                ),
                encoding="utf-8",
            )
            service = DependencyAgentService(root)
            canonical = _project_observations(service, ".tmp/inventory.json")
            sbom = _project_observations(service, ".tmp/sbom.json")
            transport_mismatches, extra_sbom_count = _project_transport_mismatches(
                scan, canonical, sbom
            )
            mismatches.extend(transport_mismatches)
            labelled, unjudged = _project_security_labels(case, variant, canonical)
            if any(fields["mismatched_fields"] for fields in labelled):
                mismatches.append("labelled-security")
            input_unchanged = all(
                (root / name).read_bytes() == value[0]
                and (root / name).stat().st_mtime_ns == value[1]
                for name, value in inputs.items()
            )
            if not input_unchanged or (root / ".depcheck").exists():
                mismatches.append("read-only-inputs")
            labels = {label["instance"] for label in case["security_labels"]}
            results.append(
                {
                    "case": variant["id"] if variant else case["id"],
                    "synthetic": variant is not None,
                    "kind": variant["kind"]
                    if variant
                    else "original upstream manifest and lock",
                    "inventory_count": len(records),
                    "inventory_sha256": inventory_digest,
                    "unlabelled_instances": sum(
                        item.instance_id not in labels for item in records
                    ),
                    "unjudged_findings": unjudged,
                    "extra_sbom_unknown_components": extra_sbom_count,
                    "readonly": input_unchanged,
                    "diagnostics": sorted({item.code for item in scan.diagnostics}),
                    "capabilities": [
                        item.to_dict()
                        for bundle in scan.bundles
                        for item in bundle.capabilities
                    ],
                    "mismatches": mismatches,
                    "security_labels": labelled,
                    "passed": not mismatches,
                }
            )
    return {
        "scope": truth["scope"],
        "annotation_method": truth["annotation_method"],
        "truth_sha256": hashlib.sha256(truth_bytes).hexdigest(),
        "labelled_security": {
            "real_upstream": _project_label_metrics(results, synthetic=False),
            "synthetic_variants": _project_label_metrics(results, synthetic=True),
        },
        "passed": all(case["passed"] for case in results),
        "cases": results,
    }


def _multilingual_inputs(fixtures: Path) -> tuple[dict, list[dict]]:
    truth = json.loads((fixtures / "truth.json").read_bytes())
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    verified = set()
    for entry in provenance["retained_fixtures"]:
        relative = entry["path"]
        path = fixtures / relative
        if (
            relative in verified
            or Path(relative).is_absolute()
            or not path.resolve().is_relative_to(fixtures.resolve())
        ):
            raise ValueError("Multilingual corpus has unsafe or repeated provenance")
        raw = path.read_bytes()
        if (
            len(raw) != entry["bytes"]
            or hashlib.sha256(raw).hexdigest() != entry["sha256"]
            or hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw,
                usedforsecurity=False,
            ).hexdigest()
            != entry["git_blob_sha1"]
        ):
            raise ValueError(f"Corpus digest mismatch: {relative}")
        verified.add(relative)
    cases = truth["cases"]
    if not cases or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Multilingual corpus needs nonempty unique cases")
    for case in cases:
        directory = fixtures / case["directory"]
        if not directory.resolve().is_relative_to(fixtures.resolve()):
            raise ValueError("Multilingual corpus case leaves fixtures")
        copied = list(directory.rglob("*"))
        actual_files = {
            p.relative_to(fixtures).as_posix() for p in copied if p.is_file()
        }
        original_files = {
            path for path in verified if path.startswith(case["directory"] + "/")
        }
        if actual_files != original_files or any(p.is_symlink() for p in copied):
            raise ValueError(
                "Multilingual corpus provenance omits or adds copied files"
            )
        entries = case["expected_lock_entries"]
        digest = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        required = {
            case["directory"] + "/" + path
            for path in [
                case["lock_path"],
                *case["manifest_paths"],
                *case["license_paths"],
            ]
        }
        if (
            not entries
            or len(entries) != case["expected_lock_entry_count"]
            or [row["row_index"] for row in entries] != list(range(len(entries)))
            or digest != case["expected_lock_entries_sha256"]
            or not required.issubset(verified)
            or not case["security_labels"]
        ):
            raise ValueError("Multilingual corpus has incomplete independent truth")
        labels = [label["id"] for label in case["security_labels"]]
        if len(set(labels)) != len(labels):
            raise ValueError("Multilingual corpus has duplicate security labels")
        bindings = case.get("python_directness_labels")
        if bindings is not None and (
            case["ecosystem"] != "python"
            or not bindings
            or any(
                label["lock_entry"] != entries[label["lock_entry"]["row_index"]]
                for label in bindings
            )
        ):
            raise ValueError("Multilingual corpus has incomplete Python binding truth")
        overrides = case.get("cargo_override_labels")
        if overrides is not None and (
            case["ecosystem"] != "cargo"
            or not overrides.get("root_entries")
            or not overrides.get("lock_projection_labels")
            or not overrides.get("declaration_projection_labels")
            or overrides.get("project_manifest_paths") != case["primary_manifest_paths"]
            or any(
                label["lock_entry"] != entries[label["lock_entry"]["row_index"]]
                for label in overrides["lock_projection_labels"]
            )
        ):
            raise ValueError("Multilingual corpus has incomplete Cargo override truth")
    if not {a["path"] for a in truth["advisories"]}.issubset(verified):
        raise ValueError("Multilingual corpus lacks original advisory provenance")
    records = [
        json.loads((fixtures / advisory["path"]).read_bytes())
        for advisory in truth["advisories"]
    ]
    return truth, records


def _multilingual_override_mismatches(scan: ScanResult, case: dict) -> list[str]:
    labels = case.get("cargo_override_labels")
    if labels is None:
        return []
    mismatches = []
    bundles = {bundle.project.project_id: bundle for bundle in scan.bundles}
    diagnostic = labels["required_diagnostic"]
    expected_diagnostics = Counter(
        (
            diagnostic["code"],
            diagnostic["severity"],
            json.dumps(entry["location"], sort_keys=True),
        )
        for entry in labels["root_entries"]
    )

    def diagnostic_keys(notes):
        return Counter(
            (
                note.code,
                note.severity,
                json.dumps(note.source.to_dict(scan.root), sort_keys=True),
            )
            for note in notes
            if note.code == diagnostic["code"] and note.source is not None
        )

    if not expected_diagnostics.keys() <= diagnostic_keys(scan.diagnostics).keys():
        mismatches.append("missing-cargo-aggregate-override-diagnostics")
    for manifest in labels["project_manifest_paths"]:
        project_id = ProjectUnit.stable_id(Path(manifest).parent, "Cargo", "cargo")
        bundle = bundles.get(project_id)
        if bundle is None:
            mismatches.append("missing-cargo-override-view:" + project_id)
            continue
        if diagnostic_keys(bundle.diagnostics) != expected_diagnostics:
            mismatches.append("missing-cargo-root-override-diagnostics:" + project_id)
        for label in labels["lock_projection_labels"]:
            records = [
                item
                for item in bundle.resolved
                if item.metadata.get("package_index")
                == label["lock_entry"]["row_index"]
            ]
            if len(records) != 1 or any(
                item.direct is not label["direct"]
                or item.origin.get("public") is not label["public"]
                or item.package.purl != label["purl"]
                or any(
                    item.metadata.get(key) != value
                    for key, value in label["metadata"].items()
                )
                for item in records
            ):
                mismatches.append(
                    "changed-cargo-override-lock-projection:" + project_id
                )
    for label in labels["declaration_projection_labels"]:
        project_id = ProjectUnit.stable_id(
            Path(label["project_manifest_path"]).parent, "Cargo", "cargo"
        )
        bundle = bundles.get(project_id)
        declarations = (
            []
            if bundle is None
            else [
                item
                for item in bundle.declarations
                if item.source.to_dict(scan.root) == label["location"]
                and item.package.name == label["package"]
                and item.metadata.get("installation_name") == label["installation_name"]
                and item.constraint.raw == label["constraint_raw"]
            ]
        )
        if len(declarations) != 1 or any(
            any(
                item.metadata.get(key) != value
                for key, value in label["metadata"].items()
            )
            for item in declarations
        ):
            mismatches.append("changed-cargo-override-declaration:" + project_id)
        if bundle is not None and any(
            note.code in label["forbidden_diagnostic_codes"]
            and note.source is not None
            and note.source.to_dict(scan.root) == label["location"]
            for note in bundle.diagnostics
        ):
            mismatches.append("misdiagnosed-cargo-override-source:" + project_id)
    return sorted(set(mismatches))


def _multilingual_inventory(
    scan: ScanResult, case: dict, *, private: bool = False
) -> list[str]:
    expected = {row["row_index"]: row for row in case["expected_lock_entries"]}
    python = case["ecosystem"] == "python"
    selected = {
        ProjectUnit.stable_id(
            Path(manifest).parent,
            "PyPI" if python else "Cargo",
            "python" if python else "cargo",
        ): Path(manifest).parent
        for manifest in case["primary_manifest_paths"]
    }
    project_counts = Counter(bundle.project.project_id for bundle in scan.bundles)
    lock_rows_by_project = {project_id: set() for project_id in selected}
    observed = {}
    project_occurrences = set()
    mismatches = []
    if project_counts != Counter({project_id: 1 for project_id in selected}):
        mismatches.append("selected-project-views")
    for bundle in scan.bundles:
        for item in bundle.resolved:
            meta = item.metadata
            source_path = item.source.path.relative_to(scan.root).as_posix()
            if source_path != case["lock_path"]:
                if (
                    source_path not in case.get("manifest_paths", [])
                    or meta.get("python_kind") == "lock-record"
                    or meta.get("cargo_kind") == "lock-record"
                ):
                    mismatches.append("unexpected-resolution-source")
                continue
            index = meta.get("package_index")
            if (
                type(index) is not int
                or index not in expected
                or meta.get("python_kind" if python else "cargo_kind") != "lock-record"
            ):
                mismatches.append("missing-or-invalid-lock-occurrence")
                continue
            if bundle.project.project_id in lock_rows_by_project:
                lock_rows_by_project[bundle.project.project_id].add(index)
            row = expected[index]
            occurrence = (bundle.project.project_id, index)
            if occurrence in project_occurrences:
                mismatches.append(f"repeated-project-lock-occurrence:{index}")
            project_occurrences.add(occurrence)
            name = row["name"]
            if case["ecosystem"] == "python":
                name = str(canonicalize_name(name))
                source = meta.get("context", {}).get("package", {}).get("source")
                source_matches = source == row["source_raw"]
                source_public = not private and (
                    source is None
                    or isinstance(source, dict)
                    and source == {"registry": "https://pypi.org/simple"}
                )
            else:
                raw_source = row["source_raw"]
                source_matches = meta.get("source_sha256") == (
                    hashlib.sha256(raw_source.encode()).hexdigest()
                    if raw_source is not None
                    else None
                )
                source_public = raw_source in {
                    "registry+https://github.com/rust-lang/crates.io-index",
                    "sparse+https://index.crates.io/",
                    "registry+https://index.crates.io/",
                }
            if item.origin.get("public") is not source_public:
                mismatches.append(f"changed-source-qualification:{index}")
            identity = (item.package.name, item.version, item.instance_id)
            if (
                item.package.name != name
                or item.version != row["version"]
                or not item.instance_id
                or not source_matches
                or meta.get("activation") != "unknown"
                or item.source.path.relative_to(scan.root).as_posix()
                != case["lock_path"]
            ):
                mismatches.append(f"changed-lock-occurrence:{index}")
            if index in observed and observed[index] != identity:
                mismatches.append(f"inconsistent-shared-lock-instance:{index}")
            observed[index] = identity
    if set(observed) != set(expected):
        mismatches.append("missing-lock-occurrences")
    for project_id, directory in selected.items():
        # Cargo members expose a qualified shared-lock superset. Python members
        # without their own lock do not establish shared-lock availability.
        if (not python or directory == Path(case["lock_path"]).parent) and (
            lock_rows_by_project[project_id] != set(expected)
        ):
            mismatches.append("missing-project-lock-occurrences:" + project_id)
    if len({row[2] for row in observed.values()}) != len(observed):
        mismatches.append("merged-lock-occurrences")
    for edge in case["required_edges"]:
        parent_index, target_index = (
            edge["parent"]["row_index"],
            edge["target"]["row_index"],
        )
        parents = [
            item
            for bundle in scan.bundles
            for item in bundle.resolved
            if item.metadata.get("package_index") == parent_index
        ]
        target = observed.get(target_index)
        if (
            not parents
            or target is None
            or any(
                not any(
                    link.instance_id == target[2] for link in parent.dependency_links
                )
                for parent in parents
            )
        ):
            mismatches.append(f"missing-qualified-edge:{parent_index}:{target_index}")
    for label in case["metadata_labels"]:
        if label["kind"] == "manifest-value":
            declarations = [
                declaration
                for bundle in scan.bundles
                for declaration in bundle.declarations
                if declaration.source.path.relative_to(scan.root).as_posix()
                == label["path"]
            ]
            if case["ecosystem"] == "python":
                matches = [
                    d
                    for d in declarations
                    if d.metadata.get("raw_requirement") == label["contains"]
                ]
                group = label["key_path"]
                if len(group) > 2 and group[1] == "optional-dependencies":
                    matches = [
                        d
                        for d in matches
                        if d.metadata.get("group") == "optional:" + group[2]
                    ]
            else:
                alias = label["key_path"][1]
                matches = [
                    d
                    for d in declarations
                    if d.metadata.get("installation_name") == alias
                ]
                matches = [
                    d
                    for d in matches
                    if (
                        d.package.name
                        if label["key_path"][-1] == "package"
                        else d.constraint.raw
                    )
                    == label["equals"]
                ]
            if not matches:
                mismatches.append("missing-manifest-assertion:" + label["path"])
            continue
        if label["kind"] == "lock-entry-variants":
            selector = label["selector"]
            variants = {}
            for bundle in scan.bundles:
                for item in bundle.resolved:
                    if (item.package.name, item.version) != (
                        selector["name"],
                        selector["version"],
                    ):
                        continue
                    context = item.metadata.get("context", {}).get("package", {})
                    variants[item.metadata["package_index"]] = {
                        key: context[key]
                        for key in label["variant_fields"]
                        if key in context
                    }

            def serialize(value):
                return json.dumps(value, sort_keys=True)

            if sorted(map(serialize, variants.values())) != sorted(
                map(serialize, label["expected_variants"])
            ):
                mismatches.append("lost-lock-variants:" + selector["name"])
            continue
        if label["kind"] != "lock-entry-fields":
            continue
        selector = label["selector"]
        for bundle in scan.bundles:
            for item in bundle.resolved:
                if type(item.metadata.get("package_index")) is not int:
                    continue
                if (item.package.name, item.version) != (
                    selector["name"],
                    selector["version"],
                ):
                    continue
                context = item.metadata.get("context", {})
                context = (
                    context.get("package", {})
                    if case["ecosystem"] == "python"
                    else context
                )
                for key, value in label["fields"].items():
                    if context.get(key) != value:
                        mismatches.append("changed-lock-context:" + item.package.name)
    for label in case.get("python_directness_labels", []):
        project_id = ProjectUnit.stable_id(
            Path(label["project_manifest_path"]).parent, "PyPI", "python"
        )
        records = [
            item
            for bundle in scan.bundles
            if bundle.project.project_id == project_id
            for item in bundle.resolved
            if item.metadata.get("package_index") == label["lock_entry"]["row_index"]
        ]
        prefix = "private_" if private else ""
        if len(records) != 1 or any(
            item.direct is not label[prefix + "direct"]
            or item.metadata.get("directness_status") != label[prefix + "status"]
            for item in records
        ):
            mismatches.append(
                "changed-python-direct-binding:" + str(label["lock_entry"]["row_index"])
            )
    mismatches.extend(_multilingual_override_mismatches(scan, case))
    return sorted(set(mismatches))


def _multilingual_security(
    case: dict, rows: list[dict], *, private: bool
) -> list[dict]:
    root_id = ProjectUnit.stable_id(
        Path("."),
        "PyPI" if case["ecosystem"] == "python" else "Cargo",
        "python" if case["ecosystem"] == "python" else "cargo",
    )
    labelled = []
    # These are source-record boundary candidates, not publisher upgrade advice.
    fixes = {
        "GHSA-9wx4-h78v-vm56": "2.32.0",
        "GHSA-34jh-p97f-mpxf": "2.2.2",
        "GHSA-9hjg-9r4m-mvj7": "2.32.4",
        "RUSTSEC-2022-0013": "1.5.5",
        "RUSTSEC-2020-0071": "0.2.0",
        "RUSTSEC-2023-0001": "1.23.1",
        "RUSTSEC-2024-0003": "0.3.24",
    }
    for label in case["security_labels"]:
        indices = {entry["row_index"] for entry in label["lock_entries"]}
        selected = [
            row
            for row in rows
            if row["identity"]["project_id"] == root_id
            and row.get("metadata", {}).get("package_index") in indices
        ]
        status = (
            "unknown"
            if private
            else "matched"
            if label["known_affected"]
            else "not-matched-in-supplied-records"
        )
        mismatches = []
        actual = []
        for row in selected:
            issues = [
                issue
                for issue in row["vulnerabilities"]
                if label["advisory"] in {issue["id"], *issue.get("aliases", [])}
            ]
            checks = [
                check
                for check in row.get("advisory_checks", [])
                if check["id"] == label["advisory"]
            ]
            observed = (
                "matched"
                if issues
                else "not-matched-in-supplied-records"
                if checks and all(check["status"] == "not-affected" for check in checks)
                else "unknown"
            )
            if observed != status:
                mismatches.append("status")
            if issues and row["status"] != "matched":
                mismatches.append("observation-status")
            if row["identity"].get("origin", {}).get("public") is not (not private):
                mismatches.append("public-origin")
            if issues and (
                sorted({cve for issue in issues for cve in issue["cve_ids"]})
                != label["expected_cve_ids_if_matched"]
                or issues[0]["fix_version"] != fixes[label["advisory"]]
                or issues[0]["fix_version_status"] != "candidate"
            ):
                mismatches.append("cve-or-fix")
            actual.append(observed)
        if len(selected) != len(indices):
            mismatches.append("missing-or-repeated-observation")
        labelled.append(
            {
                "label": label["id"],
                "instance": str(sorted(indices)),
                "advisory": label["advisory"],
                "known_affected": None if private else label["known_affected"],
                "expected_status": status,
                "actual": {
                    "status": actual[0] if len(actual) == 1 else "missing-or-repeated"
                },
                "mismatched_fields": sorted(set(mismatches)),
            }
        )
    return labelled


def evaluate_multilingual_projects(fixtures: Path) -> dict:
    """Round-trip selected root/member views of seven original locked projects."""
    import shutil

    truth, advisories = _multilingual_inputs(fixtures)
    results = []
    for case in truth["cases"]:
        for private in [False, True] if case["id"] == "poetry-1.8.3" else [False]:
            with tempfile.TemporaryDirectory(
                prefix="depcheck-multilingual-"
            ) as directory:
                root = Path(directory)
                shutil.copytree(fixtures / case["directory"], root, dirs_exist_ok=True)
                if private:
                    with (root / "pyproject.toml").open(
                        "a", encoding="utf-8"
                    ) as target:
                        target.write(
                            '\n[[tool.poetry.source]]\nname="private"\nurl="https://private.invalid/simple"\npriority="primary"\n'
                        )
                inputs = {
                    p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
                    for p in root.rglob("*")
                    if p.is_file()
                }
                project_ids = tuple(
                    sorted(
                        {
                            ProjectUnit.stable_id(
                                Path(manifest).parent,
                                "PyPI" if case["ecosystem"] == "python" else "Cargo",
                                "python" if case["ecosystem"] == "python" else "cargo",
                            )
                            for manifest in case["primary_manifest_paths"]
                        }
                    )
                )
                scan = RepositoryScanner().scan(
                    root,
                    RepositoryScanOptions(
                        security=False,
                        compatibility=False,
                        enabled_ecosystems=(
                            case["osv_ecosystem"]
                            if case["ecosystem"] == "python"
                            else "Cargo",
                        ),
                        project_ids=project_ids,
                    ),
                )
                mismatches = _multilingual_inventory(scan, case, private=private)
                derived = root / ".tmp"
                derived.mkdir()
                (derived / "inventory.json").write_text(
                    json.dumps(scan.to_dict()), encoding="utf-8"
                )
                (derived / "sbom.json").write_text(
                    json.dumps(build_cyclonedx(scan)), encoding="utf-8"
                )
                (derived / "advisories.json").write_text(
                    json.dumps(
                        {"schema": "depcheck.osv-database.v1", "records": advisories}
                    ),
                    encoding="utf-8",
                )
                service = DependencyAgentService(root)
                canonical = _project_observations(service, ".tmp/inventory.json")
                sbom = _project_observations(service, ".tmp/sbom.json")
                transport, extra = _project_transport_mismatches(scan, canonical, sbom)
                mismatches.extend(transport)
                labelled = _multilingual_security(case, canonical, private=private)
                if any(label["mismatched_fields"] for label in labelled):
                    mismatches.append("labelled-security")
                RepositoryIndexer().refresh(
                    root,
                    ecosystems=(
                        case["osv_ecosystem"]
                        if case["ecosystem"] == "python"
                        else "Cargo",
                    ),
                    project_ids=project_ids,
                )
                cache = root / ".depcheck/index.sqlite3"
                cache_before = cache.read_bytes(), cache.stat().st_mtime_ns
                indexed = RepositoryIndex(root).dependencies(limit=20000)
                actual_index = {
                    (
                        row["project_id"],
                        row["ecosystem"],
                        row["package"],
                        item["version"],
                        item["instance"],
                    ): (item["origin"], item["metadata"])
                    for row in indexed
                    for item in row.get("resolutions", [])
                }
                expected_index = {
                    _project_identity(item.identity.to_dict()): (
                        dict(item.origin),
                        dict(item.metadata),
                    )
                    for bundle in scan.bundles
                    for item in bundle.resolved
                }
                if actual_index != expected_index:
                    mismatches.append("indexed-identities-or-context")
                first = service.query_dependencies(
                    search=case["security_labels"][0]["package"],
                    project_id=project_ids[0],
                    limit=20,
                )
                if not first["dependencies"]:
                    mismatches.append("service-index-query")
                if (cache.read_bytes(), cache.stat().st_mtime_ns) != cache_before:
                    mismatches.append("index-query-mutated-cache")
                readonly = all(
                    (root / path).read_bytes() == data
                    and (root / path).stat().st_mtime_ns == mtime
                    for path, (data, mtime) in inputs.items()
                )
                if not readonly:
                    mismatches.append("changed-original-inputs")
                lock_kind = (
                    "python_kind" if case["ecosystem"] == "python" else "cargo_kind"
                )
                lock_view_rows = sum(
                    item.source.path.relative_to(root).as_posix() == case["lock_path"]
                    and item.metadata.get(lock_kind) == "lock-record"
                    and type(item.metadata.get("package_index")) is int
                    for bundle in scan.bundles
                    for item in bundle.resolved
                )
                manifest_resolutions = sum(
                    item.source.path.relative_to(root).as_posix()
                    in case["manifest_paths"]
                    and item.metadata.get("python_kind") != "lock-record"
                    and item.metadata.get("cargo_kind") != "lock-record"
                    for bundle in scan.bundles
                    for item in bundle.resolved
                )
                root_id = ProjectUnit.stable_id(
                    Path("."),
                    "PyPI" if case["ecosystem"] == "python" else "Cargo",
                    "python" if case["ecosystem"] == "python" else "cargo",
                )
                labelled_indices = {
                    entry["row_index"]
                    for label in case["security_labels"]
                    for entry in label["lock_entries"]
                }
                labelled_view_rows = sum(
                    row["identity"]["project_id"] == root_id
                    and row.get("metadata", {}).get(lock_kind) == "lock-record"
                    and row.get("metadata", {}).get("package_index") in labelled_indices
                    for row in canonical
                )
                override_labels = case.get("cargo_override_labels", {})
                results.append(
                    {
                        "case": case["id"] + ("-private-source" if private else ""),
                        "synthetic": private,
                        "selected_projects": list(project_ids),
                        "raw_lock_entries": case["expected_lock_entry_count"],
                        "project_view_rows": len(canonical),
                        "lock_project_view_rows": lock_view_rows,
                        "manifest_resolution_assertions": manifest_resolutions,
                        "labelled_python_direct_bindings": len(
                            case.get("python_directness_labels", [])
                        ),
                        "labelled_cargo_override_project_rows": len(
                            override_labels.get("lock_projection_labels", [])
                        )
                        * len(override_labels.get("project_manifest_paths", [])),
                        "labelled_cargo_override_declarations": len(
                            override_labels.get("declaration_projection_labels", [])
                        ),
                        "labelled_advisory_pairs": sum(
                            len(label["lock_entries"])
                            for label in case["security_labels"]
                        ),
                        "labelled_project_view_rows": labelled_view_rows,
                        "unlabelled_project_view_rows": len(canonical)
                        - labelled_view_rows,
                        "extra_sbom_unknown_components": extra,
                        "security_labels": labelled,
                        "readonly": readonly,
                        "diagnostics": sorted({d.code for d in scan.diagnostics}),
                        "mismatches": sorted(set(mismatches)),
                        "passed": not mismatches,
                    }
                )
    return {
        "scope": truth["scope"],
        "passed": all(case["passed"] for case in results),
        "labelled_security": {
            "real_upstream": _project_label_metrics(results, synthetic=False),
            "synthetic_variants": _project_label_metrics(results, synthetic=True),
        },
        "cases": results,
    }


def _pipenv_inputs(fixtures: Path) -> dict:
    truth = json.loads((fixtures / "truth.json").read_bytes())
    provenance = json.loads((fixtures / "provenance.json").read_bytes())
    verified = set()
    for entry in provenance["retained_fixtures"]:
        relative = entry["path"]
        path = fixtures / relative
        if (
            relative in verified
            or Path(relative).is_absolute()
            or not path.resolve().is_relative_to(fixtures.resolve())
            or path.is_symlink()
        ):
            raise ValueError("Pipenv corpus has unsafe or repeated provenance")
        raw = path.read_bytes()
        if (
            len(raw) != entry["bytes"]
            or hashlib.sha256(raw).hexdigest() != entry["sha256"]
            or hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw,
                usedforsecurity=False,
            ).hexdigest()
            != entry["git_blob_sha1"]
        ):
            raise ValueError(f"Corpus digest mismatch: {relative}")
        verified.add(relative)
    actual = {
        path.relative_to(fixtures).as_posix()
        for path in fixtures.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    entries = truth["entries"]
    if (
        actual != verified | {"truth.json", "provenance.json"}
        or not {"Pipfile", "Pipfile.lock", "LICENSE.txt", "category-test-source.txt"}
        <= verified
        or not entries
        or len(entries) != truth["expected_entry_count"]
        or dict(Counter(row["category"] for row in entries))
        != truth["expected_category_counts"]
        or [row["row_index"] for row in entries] != list(range(len(entries)))
        or len({(row["category"], row["name"]) for row in entries}) != len(entries)
        or hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != truth["entries_sha256"]
        or len(truth.get("manifest_entries", []))
        != truth.get("expected_manifest_entry_count")
        or hashlib.sha256(
            json.dumps(
                truth.get("manifest_entries", []), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        != truth.get("manifest_entries_sha256")
    ):
        raise ValueError("Pipenv corpus has incomplete independent truth")
    return truth


def _pipenv_inventory(
    scan: ScanResult,
    entries: list[dict],
    source_assertions: list[dict],
    *,
    private: bool,
) -> list[str]:
    expected = {row["row_index"]: row for row in entries}
    project_id = ProjectUnit.stable_id(Path("."), "PyPI", "python")
    mismatches = []
    observed = {}
    if Counter(bundle.project.project_id for bundle in scan.bundles) != Counter(
        {project_id: 1}
    ):
        mismatches.append("pipenv-project-view")
    for bundle in scan.bundles:
        for item in bundle.resolved:
            meta = item.metadata
            index = meta.get("package_index")
            if type(index) is not int or index not in expected:
                mismatches.append("pipenv-missing-lock-occurrence")
                continue
            if index in observed:
                mismatches.append("pipenv-repeated-lock-occurrence")
            observed[index] = item.instance_id
            row = expected[index]
            kind = (
                row["category"]
                if row["category"] in {"default", "develop"}
                else "custom"
            )
            context = meta.get("context", {})
            package = context.get("package", {})
            if (
                item.project_id != project_id
                or item.package.ecosystem != "PyPI"
                or item.source.path.relative_to(scan.root).as_posix() != "Pipfile.lock"
                or item.package.name != canonicalize_name(row["name"])
                or item.version != row["version_raw"].removeprefix("==")
                or not item.instance_id
                or meta.get("python_kind") != "lock-record"
                or meta.get("lock_format") != "pipfile"
                or meta.get("pipenv_category") != row["category"]
                or meta.get("category_kind") != kind
                or meta.get("source_pointer") != row["source_pointer"]
            ):
                mismatches.append("pipenv-changed-lock-identity")
            if (
                {key: value for key, value in package.items() if key != "hashes"}
                != row["context"]
                or context.get("root", {}).get("_meta", {}).get("sources")
                != source_assertions
                or meta.get("conditional") is not True
                or meta.get("activation") != "unknown"
                or meta.get("details_omitted")
            ):
                mismatches.append("pipenv-changed-lock-context")
            if (
                item.origin.get("public") is not (not private)
                or private
                and item.package.purl is not None
            ):
                mismatches.append("pipenv-source-qualification")
            if (
                meta.get("dependency_status") != "uncollected"
                or item.dependencies
                or item.dependency_links
            ):
                mismatches.append("pipenv-invented-dependency-graph")
    if set(observed) != set(expected):
        mismatches.append("pipenv-missing-lock-occurrences")
    if len(set(observed.values())) != len(observed):
        mismatches.append("pipenv-merged-category-occurrences")
    return sorted(set(mismatches))


def evaluate_pipenv_projects(fixtures: Path) -> dict:
    """Evaluate an original lock inventory and explicitly synthetic variants."""
    truth = _pipenv_inputs(fixtures)
    results = []
    for variant in ("original", "private-source", "custom-category"):
        with tempfile.TemporaryDirectory(prefix="depcheck-pipenv-corpus-") as directory:
            root = Path(directory)
            manifest_bytes = (fixtures / "Pipfile").read_bytes()
            manifest = manifest_bytes.decode("utf-8")
            lock = json.loads((fixtures / "Pipfile.lock").read_bytes())
            entries = json.loads(json.dumps(truth["entries"]))
            private = variant == "private-source"
            if private:
                manifest = manifest.replace(
                    "https://pypi.org/simple", "https://private.invalid/simple"
                )
                for source in lock["_meta"]["sources"]:
                    source["url"] = "https://private.invalid/simple"
            elif variant == "custom-category":
                manifest += (
                    '\n[docs]\nrequests = {version="==2.34.2", extras=["socks"], '
                    "markers=\"python_version >= '3.10'\"}\n"
                )
                package = {
                    "version": "==2.34.2",
                    "index": "pypi",
                    "extras": ["socks"],
                    "markers": "python_version >= '3.10'",
                }
                lock["docs"] = {"requests": package}
                entries.append(
                    {
                        "row_index": len(entries),
                        "category": "docs",
                        "name": "requests",
                        "version_raw": "==2.34.2",
                        "source_pointer": "/docs/requests",
                        "context": package,
                    }
                )
            (root / "Pipfile").write_bytes(
                manifest_bytes if variant == "original" else manifest.encode("utf-8")
            )
            if variant == "original":
                (root / "Pipfile.lock").write_bytes(
                    (fixtures / "Pipfile.lock").read_bytes()
                )
            else:
                (root / "Pipfile.lock").write_text(json.dumps(lock), encoding="utf-8")
            inputs = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in (root / "Pipfile", root / "Pipfile.lock")
            }
            scan = RepositoryScanner().scan(
                root,
                RepositoryScanOptions(
                    security=False, compatibility=False, enabled_ecosystems=("PyPI",)
                ),
            )
            mismatches = _pipenv_inventory(
                scan, entries, lock["_meta"]["sources"], private=private
            )
            manifest_declarations = [
                declaration
                for bundle in scan.bundles
                for declaration in bundle.declarations
                if declaration.source.path == root / "Pipfile"
                and declaration.metadata.get("category_kind") != "custom"
            ]
            if len(manifest_declarations) != truth["expected_manifest_entry_count"]:
                mismatches.append("pipenv-missing-manifest-declarations")
            by_name_and_group = {
                (
                    declaration.package.name,
                    declaration.metadata.get("group"),
                ): declaration
                for declaration in manifest_declarations
            }
            for expected in truth["manifest_entries"]:
                group = "runtime" if expected["section"] == "packages" else "dev"
                declaration = by_name_and_group.get((expected["name"], group))
                terms = [
                    value if key == "markers" else key + " " + value
                    for key, value in expected["marker_terms"].items()
                ]
                expected_marker = (
                    str(Marker(" and ".join("(" + term + ")" for term in terms)))
                    if terms
                    else None
                )
                if (
                    declaration is None
                    or declaration.constraint.raw != expected["constraint"]
                    or declaration.marker != expected_marker
                    or declaration.metadata.get("extras") != expected["extras"]
                    or declaration.metadata.get("python_kind") != "pipenv-declaration"
                ):
                    mismatches.append(
                        "pipenv-changed-manifest-condition:" + expected["name"]
                    )
            if variant == "custom-category":
                custom = [
                    declaration
                    for bundle in scan.bundles
                    for declaration in bundle.declarations
                    if declaration.metadata.get("pipenv_category") == "docs"
                    and declaration.package.name == "requests"
                    and declaration.source.path == root / "Pipfile"
                ]
                if len(custom) != 1 or any(
                    declaration.scope != "unknown"
                    or declaration.kind != "conditional"
                    or declaration.metadata.get("category_kind") != "custom"
                    or declaration.metadata.get("python_kind") != "pipenv-declaration"
                    or declaration.metadata.get("activation") != "unknown"
                    or declaration.metadata.get("extras") != ["socks"]
                    for declaration in custom
                ):
                    mismatches.append("pipenv-custom-scope-promotion")
            derived = root / ".tmp"
            derived.mkdir()
            (derived / "inventory.json").write_text(
                json.dumps(scan.to_dict()), encoding="utf-8"
            )
            (derived / "sbom.json").write_text(
                json.dumps(build_cyclonedx(scan)), encoding="utf-8"
            )
            (derived / "advisories.json").write_text(
                json.dumps({"schema": "depcheck.osv-database.v1", "records": []}),
                encoding="utf-8",
            )
            service = DependencyAgentService(root)
            canonical = _project_observations(service, ".tmp/inventory.json")
            sbom = _project_observations(service, ".tmp/sbom.json")
            transport, extra = _project_transport_mismatches(scan, canonical, sbom)
            mismatches.extend(transport)
            expected_status = (
                "unknown" if private else "not-matched-in-supplied-records"
            )
            if any(
                row["status"] != expected_status or row["vulnerabilities"]
                for row in canonical
            ):
                mismatches.append("pipenv-offline-coordinate-qualification")
            if (root / ".depcheck").exists():
                mismatches.append("pipenv-offline-query-created-cache")
            indexer = RepositoryIndexer()
            indexer.refresh(root)
            indexer.refresh(root)
            cache = root / ".depcheck/index.sqlite3"
            before = cache.read_bytes(), cache.stat().st_mtime_ns
            indexed = RepositoryIndex(root).dependencies(limit=20000)
            indexed_resolutions = [
                (row, item) for row in indexed for item in row.get("resolutions", [])
            ]
            actual_index = {
                (
                    row["project_id"],
                    row["ecosystem"],
                    row["package"],
                    item["version"],
                    item["instance"],
                ): (item["origin"], item["metadata"])
                for row, item in indexed_resolutions
            }
            expected_index = {
                _project_identity(item.identity.to_dict()): (
                    dict(item.origin),
                    dict(item.metadata),
                )
                for bundle in scan.bundles
                for item in bundle.resolved
            }
            if (
                len(indexed_resolutions) != len(expected_index)
                or actual_index != expected_index
            ):
                mismatches.append("pipenv-indexed-identities-or-context")
            page = service.query_dependencies(search="setuptools", limit=20)
            categories = Counter(
                resolution["metadata"].get("pipenv_category")
                for dependency in page["dependencies"]
                for resolution in dependency.get("resolutions", [])
            )
            if categories != Counter({"default": 1, "develop": 1}):
                mismatches.append("pipenv-service-lost-categories")
            if (cache.read_bytes(), cache.stat().st_mtime_ns) != before:
                mismatches.append("pipenv-index-query-mutated-cache")
            readonly = all(
                path.read_bytes() == data and path.stat().st_mtime_ns == mtime
                for path, (data, mtime) in inputs.items()
            )
            if not readonly:
                mismatches.append("pipenv-changed-inputs")
            results.append(
                {
                    "case": "pipenv-root-" + variant,
                    "synthetic": variant != "original",
                    "manifest_declaration_rows": len(manifest_declarations),
                    "manifest_condition_labels": truth["expected_manifest_entry_count"],
                    "raw_lock_entries": len(entries),
                    "category_counts": dict(
                        Counter(row["category"] for row in entries)
                    ),
                    "cross_category_duplicate_names": len(
                        [
                            count
                            for count in Counter(
                                row["name"] for row in entries
                            ).values()
                            if count > 1
                        ]
                    ),
                    "project_view_rows": len(canonical),
                    "unjudged_project_view_rows": len(canonical),
                    "extra_sbom_unknown_components": extra,
                    "database_records": 0,
                    "activation": "unknown",
                    "dependency_status": "uncollected",
                    "readonly": readonly,
                    "diagnostics": sorted({note.code for note in scan.diagnostics}),
                    "mismatches": sorted(set(mismatches)),
                    "passed": not mismatches,
                }
            )
    return {
        "scope": truth["scope"],
        "source_commit": truth["commit"],
        "truth_sha256": hashlib.sha256(
            (fixtures / "truth.json").read_bytes()
        ).hexdigest(),
        "provenance_sha256": hashlib.sha256(
            (fixtures / "provenance.json").read_bytes()
        ).hexdigest(),
        "advisory_scope": "Empty supplied database tests coordinate qualification only; every row is unjudged for CVE accuracy.",
        "passed": all(case["passed"] for case in results),
        "cases": results,
    }


def evaluate() -> dict:
    inventory = _evaluate_inventory()
    security = evaluate_security(
        Path(__file__).resolve().parents[1] / "test/fixtures/security"
    )
    projects = evaluate_projects(
        Path(__file__).resolve().parents[1] / "test/fixtures/projects",
        Path(__file__).resolve().parents[1] / "test/fixtures/security",
    )
    scoped_severity = evaluate_scoped_severity(
        Path(__file__).resolve().parents[1] / "test/fixtures/security/scoped"
    )
    multilingual = evaluate_multilingual_projects(
        Path(__file__).resolve().parents[1] / "test/fixtures/projects/multilingual"
    )
    pipenv = evaluate_pipenv_projects(
        Path(__file__).resolve().parents[1] / "test/fixtures/projects/pipenv"
    )
    return {
        **inventory,
        "security": security,
        "projects": projects,
        "scoped_severity": scoped_severity,
        "multilingual_projects": multilingual,
        "pipenv_projects": pipenv,
        "passed": all(
            result["passed"]
            for result in (
                inventory,
                security,
                projects,
                scoped_severity,
                multilingual,
                pipenv,
            )
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = evaluate()
    text = json.dumps(result, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
