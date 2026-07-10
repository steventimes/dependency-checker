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

    def test_discovers_nested_manifests_and_skips_virtualenv_noise(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "services" / "api").mkdir(parents=True)
            (root / "services" / "api" / "pyproject.toml").write_text(
                "[project]\nname='api'\ndependencies=['fastapi>=0.100']\n",
                encoding="utf-8",
            )
            (root / "workers").mkdir()
            (root / "workers" / "requirements-dev.txt").write_text("rq==1.16.0\n", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "requirements.txt").write_text("should-not-be-read==0.0.1\n", encoding="utf-8")

            reporter = DependencyReporter(root)
            files = reporter.find_dependency_file()
            deps = reporter.parse_all()

        paths = {path.relative_to(root).as_posix() for path in files}
        self.assertIn("services/api/pyproject.toml", paths)
        self.assertIn("workers/requirements-dev.txt", paths)
        self.assertNotIn(".venv/requirements.txt", paths)
        self.assertEqual(deps["fastapi"], "0.100")
        self.assertEqual(deps["rq"], "1.16.0")
