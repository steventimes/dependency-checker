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
            report.append(f" None")
            
        # missing dependencies
        missing = [pkg for pkg in imports.keys() if pkg not in declared]
        
        report.append("\nMissing Dependencies: ")
        if missing:
            for m in missing:
                report.append(f" - {m}")
        else:
            report.append(f" None")
            
        # vulnerbilities
        report.append("\nVunerabilities")
        if vulns:
            for pkg, issues in vulns.items():
                report.append(f"Package: {pkg}")
                for issue in issues:
                    report.append(f" - {issue['id']}: {issue['summary']}")
        else:
            report.append(" None")
            
        return "\n".join(report)