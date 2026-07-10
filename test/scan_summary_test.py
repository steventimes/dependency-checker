from __future__ import annotations

import unittest
from dataclasses import dataclass

from depcheck.reporter.formatter import ReportFormatter
from depcheck.reporter.policy import evaluate_policy
from depcheck.reporter.scan_summary import build_scan_summary, should_fail


@dataclass(frozen=True)
class FakeCompatibilityReport:
    conflicts: list[object]
    missing: list[object]
    unconstrained: list[object]


class TestScanSummary(unittest.TestCase):
    def test_build_scan_summary_counts_enterprise_risk_classes(self):
        compatibility = FakeCompatibilityReport(
            conflicts=[object()],
            missing=[object(), object()],
            unconstrained=[],
        )
        summary = build_scan_summary(
            imports={"requests", "fastapi", "PyYAML"},
            declared={"requests": "2.32.0", "pytest": "8.0.0", "pyyaml": "6.0.0"},
            vulns={"requests": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]},
            compatibility=compatibility,
        )

        self.assertEqual(summary.imported_count, 3)
        self.assertEqual(summary.declared_count, 3)
        self.assertEqual(summary.missing, ["fastapi"])
        self.assertEqual(summary.unused, ["pytest"])
        self.assertEqual(summary.vulnerable, ["requests"])
        self.assertEqual(summary.vulnerability_count, 2)
        self.assertEqual(summary.compatibility_conflict_count, 1)
        self.assertEqual(summary.compatibility_missing_count, 2)
        self.assertEqual(summary.risk_count, 7)
        self.assertEqual(summary.status, "fail")

    def test_should_fail_obeys_policy_classes(self):
        summary = build_scan_summary(
            imports={"fastapi"},
            declared={"requests": "2.32.0"},
            vulns={},
        )

        self.assertTrue(should_fail(summary, ["missing"]))
        self.assertTrue(should_fail(summary, ["unused"]))
        self.assertTrue(should_fail(summary, ["any"]))
        self.assertFalse(should_fail(summary, ["vuln"]))
        self.assertFalse(should_fail(summary, ["compat"]))

    def test_formatter_includes_summary_before_details(self):
        rendered = ReportFormatter().format(
            imports={"fastapi"},
            declared={"requests": "2.32.0"},
            vulns={},
        )

        self.assertIn("Summary:", rendered)
        self.assertIn("Status: FAIL", rendered)
        self.assertIn("Total risks: 2", rendered)
        self.assertIn(" - fastapi", rendered)
        self.assertIn(" - requests", rendered)

    def test_formatter_includes_policy_governance(self):
        summary = build_scan_summary(
            imports={"fastapi"},
            declared={},
            vulns={},
        )
        policy = evaluate_policy(
            summary,
            {"fail_on": ["missing"], "exemptions": []},
        )

        rendered = ReportFormatter().format(
            imports={"fastapi"},
            declared={},
            vulns={},
            policy_evaluation=policy,
        )

        self.assertIn("Policy governance:", rendered)
        self.assertIn("Effective risks: 1", rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
