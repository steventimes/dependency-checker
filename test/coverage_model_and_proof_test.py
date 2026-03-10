"""
Long-horizon reliability tests:
- Coverage-checking hook (verifies critical APIs are exercised in one scenario).
- Theorem-proving style obligations (finite exhaustive proof over a bounded domain).
"""

import unittest

from depcheck.analyzer.base_parser import BaseDependencyParser


class TestCoverageCheckingContract(unittest.TestCase):
    def test_critical_api_paths_exercised(self):
        # This does not replace coverage.py; it acts as a guardrail that key paths stay callable.
        samples = [
            "requests==2.31.0",
            "flask>=2.0",
            "numpy; python_version >= '3.9'",
            "invalid line !!!",
        ]
        outputs = [BaseDependencyParser.parse_line(s) for s in samples]
        self.assertEqual(outputs[0], ("requests", "2.31.0"))
        self.assertEqual(outputs[1], ("flask", "2.0"))
        self.assertEqual(outputs[2], ("numpy", None))
        self.assertEqual(outputs[3], ("", None))


class TestTheoremStyleProofObligations(unittest.TestCase):
    def test_normalize_version_is_idempotent_on_bounded_domain(self):
        domain = [
            "", "1", " 1.2.3 ", "==1.2.3", ">=2", "<=3", "~=4.5", "!=7", "<9", ">10",
            "===1.0",
        ]
        for raw in domain:
            with self.subTest(raw=raw):
                once = BaseDependencyParser._normalize_version(raw)
                twice = BaseDependencyParser._normalize_version(once or "")
                self.assertEqual(once, twice)

    def test_parse_line_lowercases_names_for_all_case_patterns(self):
        names = ["Requests", "REQUESTS", "rEqUeStS"]
        for n in names:
            with self.subTest(name=n):
                parsed, ver = BaseDependencyParser.parse_line(f"{n}==1.0")
                self.assertEqual(parsed, "requests")
                self.assertEqual(ver, "1.0")
