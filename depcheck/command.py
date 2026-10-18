from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import replace
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from depcheck._version import __version__
from depcheck.agent import DependencyAgentService
from depcheck.config import load_project_config
from depcheck.policy_codes import normalize_fail_on
from depcheck.profiling import capture_profile, profile_payload
from depcheck.engine import RepositoryScanOptions, RepositoryScanner
from depcheck.output import (
    build_cyclonedx,
    build_sarif,
    evaluate_policy,
    load_policy,
    render_json,
    render_text,
)


_FORMATS = ("text", "json", "sarif", "cyclonedx-json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="depcheck",
        description="Static multi-ecosystem dependency evidence scanner.",
    )
    parser.add_argument(
        "--version", action="version", version=f"depcheck {__version__}"
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Write local inclusive phase measurements to stderr",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Scan a repository")
    _root_argument(scan)
    scan.add_argument(
        "--security",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable OSV security queries",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="Disable security and compatibility network queries",
    )
    scan.add_argument(
        "--compatibility",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Resolve Python compatibility using PyPI metadata",
    )
    scan.add_argument("--python-version")
    scan.add_argument(
        "--dependency-group",
        action="append",
        default=[],
        help="Explicit Python compatibility group, e.g. dev:test or optional:docs",
    )
    scan.add_argument("--ecosystem", action="append", default=[])
    scan.add_argument("--project", action="append", default=[])
    scan.add_argument("--ignore", action="append", default=[])
    scan.add_argument("--map", action="append", default=[], dest="mappings")
    scan.add_argument("--format", choices=_FORMATS, default="text")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--fail-on", action="append", default=[])

    index = commands.add_parser("index", help="Refresh the local evidence index")
    _root_argument(index)
    index.add_argument("--ecosystem", action="append", default=[])
    index.add_argument("--project", action="append", default=[])

    context = commands.add_parser("context", help="Show index freshness and scope")
    _root_argument(context)

    query = commands.add_parser("query", help="Query indexed dependencies")
    _root_argument(query)
    query.add_argument("package", nargs="?")
    _identity_options(query)
    query.add_argument("--evidence-limit", type=int, default=20)
    query.add_argument("--evidence-offset", type=int, default=0)
    query.add_argument("--limit", type=int, default=20)
    query.add_argument("--offset", type=int, default=0)

    explain = commands.add_parser("explain", help="Explain one indexed dependency")
    _root_argument(explain)
    explain.add_argument("package")
    _identity_options(explain)
    explain.add_argument("--evidence-limit", type=int, default=20)
    explain.add_argument("--evidence-offset", type=int, default=0)
    explain.add_argument("--origin-limit", type=int, default=20)
    explain.add_argument("--origin-depth", type=int, default=32)

    impact = commands.add_parser("impact", help="Show dependency usage impact")
    _root_argument(impact)
    impact.add_argument("package")
    _identity_options(impact)
    impact.add_argument("--evidence-limit", type=int, default=20)
    impact.add_argument("--evidence-offset", type=int, default=0)
    impact.add_argument("--origin-limit", type=int, default=20)
    impact.add_argument("--origin-depth", type=int, default=32)

    update = commands.add_parser(
        "update",
        help="Preview Python dependency updates without writing",
    )
    _root_argument(update)
    update.add_argument(
        "updates",
        nargs="+",
        metavar="PACKAGE=SPECIFIER",
    )
    update.add_argument("--add-missing", action="store_true")
    update.add_argument("--file", dest="target_file")
    update.add_argument("--group")
    _identity_options(update)

    doctor = commands.add_parser("doctor", help="Inspect local integration state")
    _root_argument(doctor)
    compare = commands.add_parser(
        "compare", help="Compare two canonical scan snapshots without writing"
    )
    _root_argument(compare)
    compare.add_argument("before_file")
    compare.add_argument("after_file")
    compare.add_argument("--limit", type=int, default=20)
    compare.add_argument("--offset", type=int, default=0)
    sbom = commands.add_parser(
        "sbom", help="Inspect an external CycloneDX JSON inventory"
    )
    _root_argument(sbom)
    sbom.add_argument("sbom_file")
    sbom.add_argument("--limit", type=int, default=20)
    sbom.add_argument("--offset", type=int, default=0)
    cmake = commands.add_parser(
        "cmake-model", help="Inspect a supplied CMake File API reply"
    )
    _root_argument(cmake)
    cmake.add_argument("index_file")
    cmake.add_argument("--configuration")
    cmake.add_argument(
        "--target", help="Exact target id within the selected configuration"
    )
    cmake.add_argument("--limit", type=int, default=20)
    cmake.add_argument("--offset", type=int, default=0)
    evidence = commands.add_parser(
        "evidence", help="Inspect supplied security, call, runtime or artifact evidence"
    )
    _root_argument(evidence)
    evidence.add_argument(
        "kind",
        choices=(
            "cve",
            "cwe",
            "vex",
            "attestation",
            "callgraph",
            "govulncheck",
            "runtime",
            "component-matches",
            "behavior",
            "abi",
            "deps-dev",
            "scorecard",
        ),
    )
    evidence.add_argument("evidence_file")
    evidence.add_argument("--artifact-file")
    evidence.add_argument("--limit", type=int, default=20)
    evidence.add_argument("--offset", type=int, default=0)
    reevaluate = commands.add_parser(
        "reevaluate",
        help="Match supplied inventory against supplied offline OSV records",
    )
    _root_argument(reevaluate)
    reevaluate.add_argument("inventory_file")
    reevaluate.add_argument("advisory_file")
    reevaluate.add_argument("--limit", type=int, default=20)
    reevaluate.add_argument("--offset", type=int, default=0)
    calls = commands.add_parser(
        "python-calls", help="Analyze selected Python sources and explicit call entries"
    )
    _root_argument(calls)
    calls.add_argument("analysis_file")
    calls.add_argument("--limit", type=int, default=20)
    calls.add_argument("--offset", type=int, default=0)
    export = commands.add_parser(
        "export-evidence",
        help="Export unsigned provenance or policy input from a saved scan",
    )
    _root_argument(export)
    export.add_argument("kind", choices=("provenance", "policy"))
    export.add_argument("snapshot_file")
    export.add_argument("--input-file", action="append", default=[])
    export.add_argument("--configuration-file")
    inventory_compare = commands.add_parser(
        "compare-inventories",
        help="Compare saved scan/CycloneDX inventories across producers",
    )
    _root_argument(inventory_compare)
    inventory_compare.add_argument("before_file")
    inventory_compare.add_argument("after_file")
    inventory_compare.add_argument("--limit", type=int, default=20)
    inventory_compare.add_argument("--offset", type=int, default=0)
    behavior = commands.add_parser(
        "package-behavior",
        help="Compare supplied npm package metadata and script capabilities",
    )
    _root_argument(behavior)
    behavior.add_argument("before_file")
    behavior.add_argument("after_file")
    behavior.add_argument("--limit", type=int, default=20)
    behavior.add_argument("--offset", type=int, default=0)
    names = commands.add_parser(
        "package-names", help="Compare a package with explicit reference names"
    )
    _root_argument(names)
    names.add_argument("ecosystem", choices=("PyPI", "npm"))
    names.add_argument("package")
    names.add_argument("references", nargs="+")
    registry = commands.add_parser(
        "registry", help="Explicit public registry existence check; no installation"
    )
    _root_argument(registry)
    registry.add_argument("ecosystem", choices=("PyPI", "npm"))
    registry.add_argument("package")
    registry.add_argument("--package-version")
    registry.add_argument("--allow-network", action="store_true")
    return parser


def _root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("root", nargs="?", default=".", type=Path)


def _identity_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ecosystem")
    parser.add_argument("--project", dest="project_id")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    root = arguments.root.resolve()
    if not root.is_dir():
        print(f"depcheck: repository is not a directory: {root}", file=sys.stderr)
        return 2
    try:
        with capture_profile(enabled=arguments.profile) as measurements:
            if arguments.command == "scan":
                status = _scan(root, arguments)
                if arguments.profile:
                    print(
                        json.dumps(profile_payload(measurements), sort_keys=True),
                        file=sys.stderr,
                    )
                return status
            service = DependencyAgentService(root)
            payload = _service_command(service, arguments)
        if arguments.profile:
            print(
                json.dumps(profile_payload(measurements), sort_keys=True),
                file=sys.stderr,
            )
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        sqlite3.Error,
    ) as exc:
        print(f"depcheck {arguments.command}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return (
        2
        if "error" in payload
        or any(
            item.get("severity") == "error" for item in payload.get("diagnostics", [])
        )
        else 0
    )


def _scan(root: Path, arguments: argparse.Namespace) -> int:
    config = load_project_config(root)
    policy = load_policy(arguments.policy) if arguments.policy else {}
    fail_on = normalize_fail_on(policy.get("fail_on", ()))
    policy = {
        **policy,
        "fail_on": normalize_fail_on((*config.fail_on, *fail_on, *arguments.fail_on)),
    }
    security = False if arguments.offline else arguments.security
    result = RepositoryScanner().scan(
        root,
        RepositoryScanOptions(
            security=security,
            compatibility=False if arguments.offline else arguments.compatibility,
            enabled_ecosystems=(
                tuple(arguments.ecosystem) if arguments.ecosystem else None
            ),
            project_ids=tuple(arguments.project),
            ignored_packages=tuple(arguments.ignore),
            import_mapping=_parse_updates(arguments.mappings, option="--map"),
            python_version=arguments.python_version,
            dependency_groups=tuple(arguments.dependency_group),
        ),
    )
    evaluation = evaluate_policy(result, policy)
    result = replace(
        result, metadata={**result.metadata, "policy": evaluation.to_dict()}
    )
    if arguments.format == "text":
        rendered = render_text(result)
    elif arguments.format == "json":
        rendered = render_json(result)
    elif arguments.format == "sarif":
        rendered = json.dumps(
            build_sarif(result),
            indent=2,
            sort_keys=True,
        )
    else:
        rendered = json.dumps(
            build_cyclonedx(result),
            indent=2,
            sort_keys=True,
        )

    if arguments.output is None:
        print(rendered)
    else:
        arguments.output.write_text(rendered + "\n", encoding="utf-8")

    return 1 if evaluation.should_fail() else 0


def _service_command(
    service: DependencyAgentService,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    command = arguments.command
    if command == "compare-inventories":
        return service.compare_inventories(
            arguments.before_file,
            arguments.after_file,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "package-behavior":
        return service.compare_package_behavior(
            arguments.before_file,
            arguments.after_file,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "package-names":
        return service.compare_package_names(
            arguments.package, arguments.references, arguments.ecosystem
        )
    if command == "registry":
        return service.verify_registry_package(
            arguments.ecosystem,
            arguments.package,
            version=arguments.package_version,
            allow_network=arguments.allow_network,
        )
    if command == "python-calls":
        return service.analyze_python_calls(
            arguments.analysis_file, limit=arguments.limit, offset=arguments.offset
        )
    if command == "export-evidence":
        return service.export_evidence(
            arguments.snapshot_file,
            arguments.kind,
            input_files=tuple(arguments.input_file),
            configuration_file=arguments.configuration_file,
        )
    if command == "evidence":
        return service.inspect_evidence(
            arguments.evidence_file,
            arguments.kind,
            artifact_file=arguments.artifact_file,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "reevaluate":
        return service.reevaluate_vulnerabilities(
            arguments.inventory_file,
            arguments.advisory_file,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "compare":
        return service.compare_dependency_snapshots(
            arguments.before_file,
            arguments.after_file,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "sbom":
        return service.inspect_dependency_sbom(
            arguments.sbom_file, limit=arguments.limit, offset=arguments.offset
        )
    if command == "cmake-model":
        return service.inspect_cmake_model(
            arguments.index_file,
            configuration=arguments.configuration,
            target=arguments.target,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "index":
        return service.index_repository(
            ecosystems=tuple(arguments.ecosystem),
            project_ids=tuple(arguments.project),
        )
    if command == "context":
        return service.repository_context()
    if command == "query":
        return service.query_dependencies(
            arguments.package,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
            evidence_limit=arguments.evidence_limit,
            evidence_offset=arguments.evidence_offset,
            limit=arguments.limit,
            offset=arguments.offset,
        )
    if command == "explain":
        return service.explain_dependency(
            arguments.package,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
            evidence_limit=arguments.evidence_limit,
            evidence_offset=arguments.evidence_offset,
            origin_limit=arguments.origin_limit,
            origin_depth=arguments.origin_depth,
        )
    if command == "impact":
        return service.dependency_impact(
            arguments.package,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
            evidence_limit=arguments.evidence_limit,
            evidence_offset=arguments.evidence_offset,
            origin_limit=arguments.origin_limit,
            origin_depth=arguments.origin_depth,
        )
    if command == "update":
        return service.plan_dependency_updates(
            _parse_updates(arguments.updates, option="update"),
            add_missing=arguments.add_missing,
            target_file=arguments.target_file,
            group=arguments.group,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
        )
    if command == "doctor":
        return {
            "schema": "depcheck.doctor.v1",
            "version": __version__,
            "root": service.project_root.as_posix(),
            "dependency_index": service.repository_context(),
            "mcp": {
                "installed": find_spec("mcp") is not None,
            },
        }
    raise ValueError(f"unknown command: {command}")


def _parse_updates(
    values: list[str],
    *,
    option: str,
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        name, separator, specifier = value.partition("=")
        if not separator or not name.strip() or not specifier.strip():
            raise ValueError(f"{option} values must use PACKAGE=SPECIFIER")
        if (
            option == "update"
            and specifier.startswith("=")
            and not specifier.startswith("==")
        ):
            specifier = "=" + specifier
        parsed[name.strip()] = specifier.strip()
    return parsed


def cli() -> None:
    raise SystemExit(main())
