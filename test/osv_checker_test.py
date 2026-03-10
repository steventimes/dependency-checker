import unittest
from unittest.mock import patch

import requests

from depcheck.security.osv_checker import OSV_Check


class TestOSVCheckUnitAndIntegration(unittest.TestCase):
    def setUp(self):
        self.checker = OSV_Check()

    @patch("depcheck.security.osv_checker.requests.post")
    def test_parses_vulnerabilities(self, mock_post):
        mock_post.return_value.json.return_value = {
            "vulns": [
                {
                    "id": "OSV-1",
                    "summary": "issue",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "affected": [
                        {
                            "ranges": [
                                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}
                            ]
                        }
                    ],
                }
            ]
        }

        results = self.checker.check("demo", "==1.0.0")

        self.assertEqual(results[0]["id"], "OSV-1")
        self.assertEqual(results[0]["fix_version"], "2.0.0")
        self.assertEqual(mock_post.call_args.kwargs["json"]["version"], "1.0.0")

    @patch("depcheck.security.osv_checker.requests.post")
    def test_returns_empty_on_http_error(self, mock_post):
        mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("boom")
        self.assertEqual(self.checker.check("demo", "1.0.0"), [])

    @patch("depcheck.security.osv_checker.requests.post")
    def test_skips_request_when_version_normalizes_empty(self, mock_post):
        self.assertEqual(self.checker.check("demo", "=="), [])
        mock_post.assert_not_called()


try:
    from hypothesis import given
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except Exception:
    HAS_HYPOTHESIS = False


if HAS_HYPOTHESIS:

    class TestOSVPropertyBased(unittest.TestCase):
        @given(
            prefix=st.sampled_from(["", "=", "==", ">", ">=", "<", "<=", "!=", "~"]),
            major=st.integers(min_value=0, max_value=100),
            minor=st.integers(min_value=0, max_value=100),
            patch=st.integers(min_value=0, max_value=100),
        )
        @patch("depcheck.security.osv_checker.requests.post")
        def test_check_normalizes_version_prefixes(self, mock_post, prefix, major, minor, patch):
            checker = OSV_Check()
            mock_post.return_value.json.return_value = {}

            checker.check("pkg", f"{prefix}{major}.{minor}.{patch}")

            self.assertEqual(
                mock_post.call_args.kwargs["json"]["version"],
                f"{major}.{minor}.{patch}",
            )

else:

    @unittest.skip("property-based tests require hypothesis")
    class TestOSVPropertyBased(unittest.TestCase):
        def test_property_tests_require_hypothesis(self):
            pass
