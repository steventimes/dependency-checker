import logging

logger = logging.getLogger(__name__)


class ReportFormatter:
    
    def format(self, imports, declared, vulns):
        report = []
        
        # unused dependencies
        unused = [pkg for pkg in declared.keys() if pkg not in imports]
        
        report.append("Unused Dependencies: ")
        if unused:
            for u in unused:
                report.append(f" - {u}")
        else:
            report.append(" None")
            
        # missing dependencies
        missing = [pkg for pkg in imports if pkg not in declared]
        
        report.append("\nMissing Dependencies: ")
        if missing:
            for m in missing:
                report.append(f" - {m}")
        else:
            report.append(" None")
            
        # vulnerabilities
        report.append("\nVulnerabilities:")
        if vulns:
            for pkg, issues in vulns.items():
                report.append(f"Package: {pkg}")
                for issue in issues:
                    report.append(f" - {issue['id']}: {issue['summary']}")
                    if issue.get('fix_version'):
                        report.append(f"    FIX: Upgrade to version {issue['fix_version']}")
        else:
            report.append(" None")
            
        return "\n".join(report)