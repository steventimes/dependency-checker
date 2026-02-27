import logging

logger = logging.getLogger(__name__)


class ReportFormatter:

    def format(self, imports, declared, vulns, compatibility=None):
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

        if compatibility is not None:
            report.append("\nCompatibility:")
            if compatibility.conflicts:
                report.append(" Conflicts:")
                for conflict in compatibility.conflicts:
                    report.append(
                        f" - {conflict.package} ({conflict.declared}) "
                        f"not compatible with {conflict.required_by} "
                        f"requires {conflict.required}"
                    )
            else:
                report.append(" Conflicts: None")

            if compatibility.unconstrained:
                report.append(" Unconstrained:")
                for gap in compatibility.unconstrained:
                    report.append(
                        f" - {gap.package} declared without version; "
                        f"{gap.required_by} requires {gap.required}"
                    )
            else:
                report.append(" Unconstrained: None")

            if compatibility.missing:
                report.append(" Missing:")
                for gap in compatibility.missing:
                    report.append(
                        f" - {gap.package} required by {gap.required_by} "
                        f"({gap.required})"
                    )
            else:
                report.append(" Missing: None")

            if compatibility.suggestions:
                report.append(" Suggested fixes:")
                for name, spec in sorted(compatibility.suggestions.items()):
                    report.append(f" - {name}{spec}")
            else:
                report.append(" Suggested fixes: None")

        return "\n".join(report)
