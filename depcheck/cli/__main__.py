from __future__ import annotations
import argparse
import json
import sys
import logging
from pathlib import Path

from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.security.osv_checker import OSV_Check
from depcheck.reporter.formatter import ReportFormatter
from depcheck.reporter.dependency_reporter import DependencyReporter
from depcheck.cli.util import normalize_imports

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
        help="Output result as json"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.json:
        logging.getLogger().setLevel(logging.WARNING)
    
    project_root = Path(args.project_path).resolve()
    
    if not project_root.exists():
        logger.error(f"Path does not exist: {project_root}")
        sys.exit(1)
    
    if not project_root.is_dir():
        logger.error(f"Path is not a directory: {project_root}")
        sys.exit(1)
    
    logger.info(f"Scanning project: {project_root}")
    
    # Scan for imports
    scanner = ImportScanner()
    raw_imports = scanner.scan_directory(project_root)
    imported_pkg = normalize_imports(raw_imports)
    logger.info(f"Found {len(imported_pkg)} imported packages")
    
    # Parse declared dependencies
    dep_reporter = DependencyReporter(project_root)
    declared_deps = dep_reporter.parse_all()
    logger.info(f"Found {len(declared_deps)} declared dependencies")
    
    # Check for vulnerabilities
    osv = OSV_Check()
    vulns = {}
    
    if declared_deps:
        logger.info("Checking for vulnerabilities...")
        for pkg, version in declared_deps.items():
            if version:
                issues = osv.check(pkg, version)
                if issues:
                    vulns[pkg] = issues
                    logger.warning(f"Found {len(issues)} vulnerabilities in {pkg}")
    
    # Output results
    if args.json:
        output = {
            "imported": sorted(imported_pkg),
            "declared_dependencies": declared_deps,
            "vulnerabilities": vulns,
        }
        print(json.dumps(output, indent=2))
    else:
        formatter = ReportFormatter()
        print(formatter.format(imported_pkg, declared_deps, vulns))


if __name__ == "__main__":
    main()