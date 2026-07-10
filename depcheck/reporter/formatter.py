import logging

from .scan_summary import build_scan_summary

logger = logging.getLogger(__name__)


class ReportFormatter:

    def format(self, imports, declared, vulns, compatibility=None, policy_evaluation=None):
        report = []
        summary = build_scan_summary(imports, declared, vulns, compatibility)

        report.append("Summary:")
        report.append(f" Status: {summary.status.upper()}")
        report.append(f" Imported packages: {summary.imported_count}")
        report.append(f" Declared dependencies: {summary.declared_count}")
        report.append(f" Total risks: {summary.risk_count}")

        # unused dependencies
        unused = summary.unused
        
        report.append("Unused Dependencies: ")
        if unused:
            for u in unused:
                report.append(f" - {u}")
        else:
            report.append(" None")
            
        # missing dependencies
        missing = summary.missing
        
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

        if policy_evaluation is not None:
            policy = policy_evaluation.to_dict()
            report.append("\nPolicy governance:")
            report.append(f" Status: {policy['status'].upper()}")
            report.append(f" Effective risks: {policy['effective_risk_count']}")
            report.append(f" Active exemptions: {len(policy['active_exemptions'])}")
            report.append(f" Expired exemptions: {len(policy['expired_exemptions'])}")
            report.append(f" Invalid exemptions: {len(policy['invalid_exemptions'])}")
            report.append(f" Unmatched exemptions: {len(policy['unmatched_exemptions'])}")

        return "\n".join(report)
