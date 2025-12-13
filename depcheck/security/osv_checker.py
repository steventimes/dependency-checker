import requests
import logging

logger = logging.getLogger(__name__)


class OSV_Check:
    
    OSV_URL = "https://api.osv.dev/v1/query"
    TIMEOUT = 10  # seconds
    
    def check(self, pkg: str, version: str) -> list:
        version_clean = version.lstrip('=<>!~') if version else version
        
        if not version_clean:
            logger.warning(f"No version specified for package {pkg}, skipping OSV check")
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
        except requests.exceptions.Timeout:
            logger.error(f"Timeout checking {pkg}@{version_clean} against OSV API")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error checking {pkg}@{version_clean}: {e}")
            return []
        except ValueError as e:
            logger.error(f"Invalid JSON response for {pkg}@{version_clean}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error checking {pkg}@{version_clean}: {e}")
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
                        if fix_version:
                            break
                if fix_version:
                    break

            results.append({
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": v.get("severity", []),
                "fix_version": fix_version
            })

        return results