import requests

class OSV_Check:
    
    OSV_URL = "https://api.osv.dev/v1/query"
    
    def check(self, pkg, version):
        payload = {
            "package":{"name": pkg, "ecosystem":"PyPI"},
            "version": version
        }
        
        try:
            response = requests.post(self.OSV_URL, json=payload)
            data = response.json()
        except Exception:
            return []
        
        vulns = data.get("vulns", [])
        results = []
        
        for v in vulns:
            fix_version = None
            for affected in v.get('affected', []):
                for range_ in affected.get('ranges', []):
                    if range_.get('type') == 'ECOSYSTEM':
                        for event in range_.get('events', []):
                            if 'fixed' in event:
                                fix_version = event['fixed']
                                break

            results.append({
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity", []),
                "fix_version": fix_version
            })

        return results
        