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
        
        results = [
            {
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity", [])
            }
            for v in vulns
        ]

        return results
        