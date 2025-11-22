from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.security.osv_checker import OSV_Check
from depcheck.reporter.formatter import ReportFormatter
from depcheck.reporter.dependency_reporter import DependencyReporter

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="depcheck",
        description="Dependency Bload and Vulnerability Checker"
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
        help="Output result as json"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    project_root = Path(args.project_path).resolve()
    
    if not project_root.exists():
        print(f"Error! Path does not exist: {project_root}", file=sys.stderr)
        sys.exit(1)
        
    
    scanner = ImportScanner()
    imported_pkg = scanner.scan_directory(project_root)
    dep_reporter = DependencyReporter(project_root)
    declared_deps = dep_reporter.parse_all()
    
    osv = OSV_Check()
    vulns = {}
    for pkg, version in declared_deps.items():
        if version:
            issues = osv.check(pkg, version)
            if issues:
                vulns[pkg] = issues
    
    if args.json:
        output = {
            "imported": sorted(imported_pkg),
            "declared_dependencies": declared_deps,
            "vulnerabilities": vulns,
        }
        print(json.dumps(output, indent=2))
        return
    
    formatter = ReportFormatter()
    print(formatter.format(imported_pkg, declared_deps, vulns))

if __name__ == "__main__":
    main()