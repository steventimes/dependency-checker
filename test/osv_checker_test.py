import unittest
from unittest.mock import patch
from depcheck.security.osv_checker import OSV_Check

class TestOSVChecker(unittest.TestCase):
    
    def setUp(self):
        self.checker = OSV_Check()

    @patch("requests.post")
    def test_check_vulnerable_package(self, mock_post):
        """Test parsing a real-looking OSV response."""
        
        # Mock API Response
        mock_response = {
            "vulns": [{
                "id": "GHSA-1234",
                "summary": "Bad vulnerability",
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.3"}
                        ]
                    }]
                }]
            }]
        }
        
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = mock_response
        
        results = self.checker.check("bad-lib", "1.0.0")
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['id'], "GHSA-1234")
        self.assertEqual(results[0]['fix_version'], "1.2.3")

    @patch("requests.post")
    def test_check_safe_package(self, mock_post):
        """Test an empty response (safe package)."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {} # No vulns
        
        results = self.checker.check("safe-lib", "1.0.0")
        self.assertEqual(results, [])