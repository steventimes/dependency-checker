from __future__ import annotations
import argparse
import json
import sys
import logging
import concurrent.futures
from pathlib import Path

from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.security.osv_checker import OSV_Check
from depcheck.reporter.formatter import ReportFormatter
from depcheck.reporter.dependency_reporter import DependencyReporter
from depcheck.reporter.scan_summary import build_scan_summary, should_fail
from depcheck.reporter.policy import evaluate_policy, load_policy, should_fail_policy
from depcheck.reporter.sarif_reporter import SarifReporter
from depcheck.cli.util import normalize_imports, load_ignore_file
from depcheck.compatibility import CompatibilityChecker
from depcheck.compatibility.requirements_updater import RequirementsUpdater

# logging configure
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="depcheck",
        description="Dependency Bloat and Vulnerability Checker"
    )
    
    parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Project directory to be scanned (default: current directory)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON"
    )

    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write a SARIF 2.1.0 report for GitHub code scanning and enterprise security tools"
    )
    
    parser.add_argument(
        "--graph",
        metavar="FILE",
        help="Generate a dependency graph .dot file (e.g. --graph graph.dot)"
    )
    
    parser.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="Exit with error code 1 if vulnerabilities are found (legacy CI/CD mode)"
    )

    parser.add_argument(
        "--fail-on",
        action="append",
        choices=["any", "missing", "unused", "vuln", "compat"],
        default=[],
        help=(
            "Exit with error code 1 for selected risk classes. "
            "May be repeated. Choices: any, missing, unused, vuln, compat."
        ),
    )
    
    parser.add_argument(
        "--policy",
        metavar="FILE",
        help="Read depcheck policy JSON with fail_on rules and time-bound exemptions"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of threads for vulnerability checks (default: 5)"
    )

    parser.add_argument(
        "--compat",
        action="store_true",
        help="Check dependency compatibility using PyPI metadata"
    )

    parser.add_argument(
        "--fix-compat",
        action="store_true",
        help="Auto-fix compatibility issues by updating requirements*.txt"
    )

    parser.add_argument(
        "--auto-update",
        action="store_true",
        help="Update requirements*.txt to latest compatible versions"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        
    project_root = Path(args.project_path).resolve()
    
    if not project_root.is_dir():
        logger.error(f"Path is not a directory: {project_root}")
        sys.exit(1)
    
    logger.info(f"Scanning project: {project_root}")
    
    ignored_packages = load_ignore_file(project_root)
    if ignored_packages:
        logger.info(f"Ignored packages from config: {len(ignored_packages)}")

    scanner = ImportScanner()
    
    # new feature of generating graph
    if args.graph:
        graph_path = Path(args.graph)
        logger.info(f"Generating dependency graph at {graph_path}")
        scanner.generate_dot(project_root, graph_path)

    raw_imports = scanner.scan_directory(project_root)
    imported_pkg = normalize_imports(raw_imports)
    logger.info(f"Found {len(imported_pkg)} imported packages")
    
    # Parse declared dependencies
    dep_reporter = DependencyReporter(project_root)
    declared_deps = dep_reporter.parse_all()
    logger.info(f"Found {len(declared_deps)} declared dependencies")
    

    active_declared = {
        k: v for k, v in declared_deps.items() 
        if k.lower() not in ignored_packages
    }

    osv = OSV_Check()
    vulns = {}
    
    if active_declared:
        logger.info("Checking for vulnerabilities...")

        check_list = {pkg: ver for pkg, ver in active_declared.items() if ver}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_pkg = {
                executor.submit(osv.check, pkg, version): pkg 
                for pkg, version in check_list.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_pkg):
                pkg = future_to_pkg[future]
                try:
                    issues = future.result()
                    if issues:
                        vulns[pkg] = issues
                        logger.warning(f"Found {len(issues)} vulnerabilities in {pkg}")
                except Exception as exc:
                    logger.error(f"{pkg} check generated an exception: {exc}")
    
    compat_report = None
    if args.compat or args.fix_compat or args.auto_update:
        checker = CompatibilityChecker()
        logger.info("Checking dependency compatibility via PyPI metadata...")
        compat_report = checker.check(active_declared)

        if args.fix_compat:
            updater = RequirementsUpdater()
            fixes = compat_report.suggestions
            _apply_requirements_updates(dep_reporter, updater, fixes)

        if args.auto_update:
            updater = RequirementsUpdater()
            updates = checker.suggest_updates(active_declared)
            _apply_requirements_updates(dep_reporter, updater, updates)

    summary = build_scan_summary(imported_pkg, active_declared, vulns, compat_report)

    policy_evaluation = None
    if args.policy:
        policy_path = Path(args.policy)
        policy = load_policy(policy_path)
        policy_evaluation = evaluate_policy(summary, policy)
        logger.info("Loaded policy file: %s", policy_path)

    if args.sarif:
        sarif_path = Path(args.sarif)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_doc = SarifReporter().build(
            summary=summary,
            project_root=project_root,
            dependency_files=dep_reporter.last_dependency_files,
            vulnerabilities=vulns,
            compatibility=compat_report,
        )
        sarif_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        logger.info("Wrote SARIF report: %s", sarif_path)

    fail_policies = list(args.fail_on)
    if args.fail_on_vuln:
        fail_policies.append("vuln")

    # Output results
    if args.json:
        output = {
            "imported": sorted(imported_pkg),
            "declared_dependencies": active_declared,
            "vulnerabilities": vulns,
            "summary": summary.to_dict(),
            "fail_policies": fail_policies,
        }
        if policy_evaluation is not None:
            output["policy"] = policy_evaluation.to_dict()
        if compat_report is not None:
            output["compatibility"] = _compatibility_json(compat_report)
        print(json.dumps(output, indent=2))
    else:
        formatter = ReportFormatter()
        print("\n" + "="*30)
        print("       SCAN REPORT       ")
        print("="*30)
        print(formatter.format(imported_pkg, active_declared, vulns, compat_report, policy_evaluation))

    if policy_evaluation is not None and should_fail_policy(policy_evaluation, fail_policies):
        logger.error(
            "Build failed by policy governance: %s effective risks.",
            policy_evaluation.effective_risk_count,
        )
        sys.exit(1)

    if should_fail(summary, fail_policies):
        logger.error(
            "Build failed by policy %s: %s total risks.",
            ",".join(fail_policies),
            summary.risk_count,
        )
        sys.exit(1)

    sys.exit(0)

def _compatibility_json(report):
    return {
        "conflicts": [
            {
                "package": conflict.package,
                "declared": conflict.declared,
                "required": conflict.required,
                "required_by": conflict.required_by,
            }
            for conflict in report.conflicts
        ],
        "unconstrained": [
            {
                "package": gap.package,
                "required": gap.required,
                "required_by": gap.required_by,
            }
            for gap in report.unconstrained
        ],
        "missing": [
            {
                "package": gap.package,
                "required": gap.required,
                "required_by": gap.required_by,
            }
            for gap in report.missing
        ],
        "suggestions": report.suggestions,
    }


def _apply_requirements_updates(dep_reporter, updater, updates):
    if not updates:
        logger.info("No compatibility updates to apply.")
        return

    requirements_files = [
        path
        for path in dep_reporter.find_dependency_file()
        if path.name.startswith("requirements") and path.suffix == ".txt"
    ]
    if not requirements_files:
        logger.warning("No requirements*.txt files found for auto-fix.")
        return

    for req_file in requirements_files:
        result = updater.apply(req_file, updates)
        changed = len(result.updated) + len(result.added)
        logger.info(f"Updated {changed} dependencies in {req_file}")


if __name__ == "__main__":
    main()
