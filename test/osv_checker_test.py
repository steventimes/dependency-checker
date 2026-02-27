import importlib.util
import unittest
from unittest.mock import patch

import requests

from depcheck.security.osv_checker import OSV_Check

HAS_HYPOTHESIS = importlib.util.find_spec("hypothesis") is not None
if HAS_HYPOTHESIS:
    from hypothesis import given
    from hypothesis import strategies as st


class TestOSVCheckBehavior(unittest.TestCase):
    """Deterministic contract tests for OSV_Check.check."""

    def setUp(self):
        self.checker = OSV_Check()

    @staticmethod
    def _vuln_payload(*, vuln_id="GHSA-1234", summary="Bad vulnerability", fix_version="1.2.3"):
        return {
            "vulns": [
                {
                    "id": vuln_id,
                    "summary": summary,
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": fix_version}],
                                }
                            ]
                        }
                    ],
                }
            ]
        }

    @patch("depcheck.security.osv_checker.requests.post")
    def test_returns_normalized_vulnerability_details_for_affected_package(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = self._vuln_payload()

        results = self.checker.check("bad-lib", "==1.0.0")

        self.assertEqual(
            results,
            [
                {
                    "id": "GHSA-1234",
                    "summary": "Bad vulnerability",
                    "severity": [],
                    "fix_version": "1.2.3",
                }
            ],
        )

    @patch("depcheck.security.osv_checker.requests.post")
    def test_sends_expected_osv_query_contract(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {}

        self.checker.check("bad-lib", "==1.0.0")

        mock_post.assert_called_once_with(
            OSV_Check.OSV_URL,
            json={
                "package": {"name": "bad-lib", "ecosystem": "PyPI"},
                "version": "1.0.0",
            },
            timeout=OSV_Check.TIMEOUT,
        )

    @patch("depcheck.security.osv_checker.requests.post")
    def test_returns_empty_results_when_no_vulnerabilities_exist(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {}

        results = self.checker.check("safe-lib", "1.0.0")

        self.assertEqual(results, [])

    @patch("depcheck.security.osv_checker.requests.post")
    def test_fails_closed_and_returns_empty_results_when_osv_request_errors(self, mock_post):
        mock_post.return_value.raise_for_status.side_effect = requests.HTTPError("500 error")

        results = self.checker.check("broken-lib", "2.0.0")

        self.assertEqual(results, [])

    @patch("depcheck.security.osv_checker.requests.post")
    def test_skips_osv_call_when_version_becomes_empty_after_normalization(self, mock_post):
        results = self.checker.check("pkg", "==")

        self.assertEqual(results, [])
        mock_post.assert_not_called()


class TestOSVFixVersionExtraction(unittest.TestCase):
    """Focused tests for internal fix-version extraction rules."""

    def setUp(self):
        self.checker = OSV_Check()

    def test_prefers_first_fixed_event_in_ecosystem_ranges(self):
        vuln = {
            "affected": [
                {
                    "ranges": [
                        {"type": "SEMVER", "events": [{"fixed": "999.999.999"}]},
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.2.3"},
                                {"fixed": "1.2.4"},
                            ],
                        },
                    ]
                }
            ]
        }

        self.assertEqual(self.checker._find_fix_version(vuln), "1.2.3")

    def test_returns_none_when_ecosystem_ranges_do_not_include_fixed_event(self):
        vuln = {
            "affected": [
                {
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]},
                        {"type": "SEMVER", "events": [{"fixed": "9.9.9"}]},
                    ]
                }
            ]
        }

        self.assertIsNone(self.checker._find_fix_version(vuln))


if HAS_HYPOTHESIS:

    class TestOSVCheckProperties(unittest.TestCase):
        """Property-based tests that validate invariants over many generated inputs."""

        def setUp(self):
            self.checker = OSV_Check()

        @given(
            prefix=st.sampled_from(["", "=", "==", ">", ">=", "<", "<=", "!=", "~"]),
            major=st.integers(min_value=0, max_value=50),
            minor=st.integers(min_value=0, max_value=50),
            patch_version=st.integers(min_value=0, max_value=50),
        )
        @patch("depcheck.security.osv_checker.requests.post")
        def test_check_always_sends_normalized_version(self, mock_post, prefix, major, minor, patch_version):
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {}
            version = f"{prefix}{major}.{minor}.{patch_version}"

            self.checker.check("generated-lib", version)

            self.assertEqual(mock_post.call_args.kwargs["json"]["version"], f"{major}.{minor}.{patch_version}")

else:

    @unittest.skip("property-based tests require hypothesis")
    class TestOSVCheckProperties(unittest.TestCase):
        def test_property_tests_require_hypothesis(self):
            pass
