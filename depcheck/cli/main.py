import argparse
from depcheck.analyzer.import_scanner import ImportScanner
from depcheck.analyzer.requirement_parser import requirementParse
from depcheck.security.osv_checker import OSV_Check
from depcheck.reporter.formatter import ReportFormatter

def main():
    parser = argparse.ArgumentParser(description="Dependency Bload and Vulnerability Checker")
    parser.add_argument("directory", help="Path of project directory")
    args = parser.parse_args()
    
    scanner = ImportScanner()
    parser_req = requirementParse()
    osv = OSV_Check()
    formatter = ReportFormatter()
    
    imports = scanner.scan_directory(args.directory)
    declared = parser_req.parse_file()
    
    vulns = {}
    for pkg, version in declared.items():
        if version:
            issues = osv.check(pkg, version)
            if issues:
                vulns[pkg] = issues
    
    print(formatter.format(imports, declared, vulns))

if __name__ == "__main__":
    main()