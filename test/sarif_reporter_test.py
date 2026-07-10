from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path

from depcheck.reporter.sarif_reporter import SarifReporter
from depcheck.reporter.scan_summary import build_scan_summary


@dataclass(frozen=True)
class FakeConflict:
    package: str
    declared: str
    required: str
    required_by: str


@dataclass(frozen=True)
class FakeGap:
    package: str
    required: str
    required_by: str


@dataclass(frozen=True)
class FakeCompatibilityReport:
    conflicts: list[FakeConflict]
    missing: list[FakeGap]
    unconstrained: list[FakeGap]


class TestSarifReporter(unittest.TestCase):
    def test_builds_sarif_for_enterprise_security_tools(self):
        project_root = Path("/workspace/project")
        dependency_file = project_root / "requirements.txt"
        vulnerabilities = {
            "requests": [
                {
                    "id": "GHSA-test",
                    "summary": "demo vulnerability",
                    "fix_version": "2.32.0",
                }
            ]
        }
        compatibility = FakeCompatibilityReport(
            conflicts=[FakeConflict("urllib3", "==1.0.0", ">=2", "requests")],
            missing=[FakeGap("certifi", ">=2024.0", "requests")],
            unconstrained=[FakeGap("idna", ">=3", "requests")],
        )
        summary = build_scan_summary(
            imports={"requests", "fastapi"},
            declared={"requests": "2.31.0", "pytest": "8.0.0"},
            vulns=vulnerabilities,
            compatibility=compatibility,
        )

        doc = SarifReporter().build(
            summary=summary,
            project_root=project_root,
            dependency_files=[dependency_file],
            vulnerabilities=vulnerabilities,
            compatibility=compatibility,
        )

        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "depcheck")
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(run["invocations"][0]["properties"]["status"], "fail")
        self.assertEqual(run["invocations"][0]["properties"]["risk_count"], 6)

        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        self.assertIn("DEP-MISSING", rule_ids)
        self.assertIn("DEP-VULNERABILITY", rule_ids)
        self.assertIn("DEP-COMPAT-CONFLICT", rule_ids)

        results = run["results"]
        self.assertEqual(len(results), 6)
        self.assertEqual(
            {result["ruleId"] for result in results},
            {
                "DEP-MISSING",
                "DEP-UNUSED",
                "DEP-VULNERABILITY",
                "DEP-COMPAT-CONFLICT",
                "DEP-COMPAT-MISSING",
                "DEP-COMPAT-UNCONSTRAINED",
            },
        )
        self.assertTrue(
            all(
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
                for result in results
            )
        )
        self.assertTrue(any(result["properties"].get("vulnerabilityId") == "GHSA-test" for result in results))

    def test_pass_summary_marks_invocation_successful(self):
        summary = build_scan_summary(
            imports={"requests"},
            declared={"requests": "2.31.0"},
            vulns={},
        )

        doc = SarifReporter().build(
            summary=summary,
            project_root=Path("/workspace/project"),
            dependency_files=[],
            vulnerabilities={},
        )

        self.assertTrue(doc["runs"][0]["invocations"][0]["executionSuccessful"])
        self.assertEqual(doc["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
