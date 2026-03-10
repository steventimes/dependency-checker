import tempfile
import unittest
from pathlib import Path

from depcheck.reporter.dependency_reporter import DependencyReporter


class TestDependencyReporterIntegration(unittest.TestCase):
    def test_find_parse_and_generate_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (root / "requirements-dev.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
            (root / "Dockerfile").write_text("RUN pip install flask>=2.0\n", encoding="utf-8")

            reporter = DependencyReporter(root)
            files = reporter.find_dependency_file()
            deps = reporter.parse_all()
            report = reporter.generate_report()

        names = {p.name for p in files}
        self.assertIn("requirements.txt", names)
        self.assertIn("requirements-dev.txt", names)
        self.assertIn("Dockerfile", names)

        self.assertEqual(deps["requests"], "2.31.0")
        self.assertEqual(deps["pytest"], "8.0.0")
        self.assertEqual(deps["flask"], "2.0")
        self.assertIn("flask==2.0", report)
        self.assertIn("pytest==8.0.0", report)
