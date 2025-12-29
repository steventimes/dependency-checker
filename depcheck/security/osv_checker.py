import requests
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class OSV_Check:
    
    OSV_URL = "https://api.osv.dev/v1/query"
    TIMEOUT = 10 
    
    def check(self, pkg: str, version: str) -> List[Dict[str, Any]]:
        version_clean = version.lstrip('=<>!~') if version else version
        
        if not version_clean:
            return []
        
        payload = {
            "package": {"name": pkg, "ecosystem": "PyPI"},
            "version": version_clean
        }
        
        try:
            response = requests.post(
                self.OSV_URL, 
                json=payload, 
                timeout=self.TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"OSV check failed for {pkg}@{version_clean}: {e}")
            return []
        
        return self._parse_response(data)

    def _parse_response(self, data: dict) -> List[Dict[str, Any]]:
        """Parses the raw OSV response and extracts key vulnerability info."""
        vulns = data.get("vulns", [])
        results = []
        
        for v in vulns:
            results.append({
                "id": v.get("id"),
                "summary": v.get("summary", "No summary available"),
                "severity": v.get("severity", []),
                "fix_version": self._find_fix_version(v)
            })

        return results

    def _find_fix_version(self, vuln_data: dict) -> Optional[str]:
        """Extracts the first fixed version from the vulnerability data."""
        for affected in vuln_data.get('affected', []):
            for range_ in affected.get('ranges', []):
                if range_.get('type') == 'ECOSYSTEM':
                    for event in range_.get('events', []):
                        if 'fixed' in event:
                            return event['fixed']
        return None