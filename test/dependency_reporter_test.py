import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from depcheck.reporter.dependency_reporter import DependencyReporter


class TestDependencyReporter(unittest.TestCase):
    def test_finds_requirement_variants(self):
        with TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "requirements.txt").write_text("requests==2.31.0\n")
            (root / "requirements-dev.txt").write_text("pytest==7.4.0\n")

            reporter = DependencyReporter(root)
            found = reporter.find_dependency_file()

            names = {path.name for path in found}
            self.assertIn("requirements.txt", names)
            self.assertIn("requirements-dev.txt", names)
