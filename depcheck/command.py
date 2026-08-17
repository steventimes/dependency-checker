from __future__ import annotations

import argparse
import json
import sys
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from depcheck.agent import DependencyAgentService
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
    parser.add_argument("--version", action="version", version="depcheck 0.4.0")
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
        help="Disable network-backed security queries",
    )
    scan.add_argument(
        "--compatibility",
        action="store_true",
        help="Resolve Python compatibility using PyPI metadata",
    )
    scan.add_argument("--python-version")
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
    query.add_argument("--limit", type=int, default=20)

    explain = commands.add_parser("explain", help="Explain one indexed dependency")
    _root_argument(explain)
    explain.add_argument("package")
    _identity_options(explain)

    impact = commands.add_parser("impact", help="Show dependency usage impact")
    _root_argument(impact)
    impact.add_argument("package")
    _identity_options(impact)

    update = commands.add_parser(
        "update",
        help="Preview Python requirements updates without writing",
    )
    _root_argument(update)
    update.add_argument(
        "updates",
        nargs="+",
        metavar="PACKAGE=SPECIFIER",
    )
    update.add_argument("--add-missing", action="store_true")
    _identity_options(update)

    doctor = commands.add_parser("doctor", help="Inspect local integration state")
    _root_argument(doctor)
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
        if arguments.command == "scan":
            return _scan(root, arguments)
        service = DependencyAgentService(root)
        payload = _service_command(service, arguments)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"depcheck {arguments.command}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


def _scan(root: Path, arguments: argparse.Namespace) -> int:
    security = False if arguments.offline else arguments.security
    result = RepositoryScanner().scan(
        root,
        RepositoryScanOptions(
            security=security,
            compatibility=arguments.compatibility,
            enabled_ecosystems=(
                tuple(arguments.ecosystem) if arguments.ecosystem else None
            ),
            project_ids=tuple(arguments.project),
            ignored_packages=tuple(arguments.ignore),
            import_mapping=_parse_updates(arguments.mappings, option="--map"),
            python_version=arguments.python_version,
        ),
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

    policy = load_policy(arguments.policy) if arguments.policy else {}
    evaluation = evaluate_policy(
        result,
        {
            **policy,
            "fail_on": [
                *(policy.get("fail_on", ()) or ()),
                *arguments.fail_on,
            ],
        },
    )
    return 1 if evaluation.should_fail() else 0


def _service_command(
    service: DependencyAgentService,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    command = arguments.command
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
            limit=arguments.limit,
        )
    if command == "explain":
        return service.explain_dependency(
            arguments.package,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
        )
    if command == "impact":
        return service.dependency_impact(
            arguments.package,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
        )
    if command == "update":
        return service.plan_dependency_updates(
            _parse_updates(arguments.updates, option="update"),
            add_missing=arguments.add_missing,
            ecosystem=arguments.ecosystem,
            project_id=arguments.project_id,
        )
    if command == "doctor":
        return {
            "schema": "depcheck.doctor.v1",
            "version": "0.4.0",
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
        parsed[name.strip()] = specifier.strip()
    return parsed


def cli() -> None:
    raise SystemExit(main())
