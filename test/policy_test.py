from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from depcheck.reporter.policy import evaluate_policy, load_policy, should_fail_policy
from depcheck.reporter.scan_summary import build_scan_summary


class TestPolicyGovernance(unittest.TestCase):
    def test_active_exemption_reduces_effective_risk_without_hiding_audit_record(self):
        summary = build_scan_summary(
            imports={"fastapi"},
            declared={"requests": "2.32.0"},
            vulns={},
        )

        evaluation = evaluate_policy(
            summary,
            {
                "schema": "depcheck.policy.v1",
                "fail_on": ["any"],
                "exemptions": [
                    {
                        "id": "TEMP-MISSING-FASTAPI",
                        "risk": "missing",
                        "package": "fastapi",
                        "reason": "service imports are optional in this plugin fixture",
                        "owner": "platform",
                        "expires_at": "2099-01-01",
                    }
                ],
            },
            today=date(2026, 7, 9),
        )

        self.assertEqual(len(evaluation.active_exemptions), 1)
        self.assertEqual(evaluation.effective["missing"], [])
        self.assertEqual(evaluation.effective["unused"], ["requests"])
        self.assertTrue(should_fail_policy(evaluation))

    def test_expired_and_invalid_exemptions_are_governance_risks(self):
        summary = build_scan_summary(
            imports={"fastapi"},
            declared={},
            vulns={},
        )

        evaluation = evaluate_policy(
            summary,
            {
                "fail_on": ["missing"],
                "exemptions": [
                    {
                        "risk": "missing",
                        "package": "fastapi",
                        "reason": "temporary migration",
                        "owner": "platform",
                        "expires_at": "2026-01-01",
                    },
                    {
                        "risk": "unused",
                        "package": "pytest",
                        "reason": "missing owner",
                        "expires_at": "2099-01-01",
                    },
                ],
            },
            today=date(2026, 7, 9),
        )

        self.assertEqual(len(evaluation.expired_exemptions), 1)
        self.assertEqual(len(evaluation.invalid_exemptions), 1)
        self.assertEqual(evaluation.governance_risk_count, 2)
        self.assertTrue(should_fail_policy(evaluation))

    def test_load_policy_requires_json_object(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_policy(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
