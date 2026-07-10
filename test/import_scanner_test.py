import tempfile
import unittest
from pathlib import Path

from depcheck.analyzer.import_scanner import ImportScanner


class TestImportScannerIntegration(unittest.TestCase):
    def setUp(self):
        self.scanner = ImportScanner()

    def test_scan_directory_filters_stdlib_and_local_modules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pkg").mkdir()
            (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "pkg" / "mod.py").write_text(
                "import requests\nimport os\nfrom pkg import x\nfrom numpy import array\n",
                encoding="utf-8",
            )
            (root / "utils.py").write_text("", encoding="utf-8")

            deps = self.scanner.scan_directory(root)

            self.assertIn("requests", deps)
            self.assertIn("numpy", deps)
            self.assertNotIn("os", deps)
            self.assertNotIn("pkg", deps)
            self.assertNotIn("utils", deps)

    def test_generate_dot_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("import requests\n", encoding="utf-8")
            out = root / "deps.dot"
            self.scanner.generate_dot(root, out)
            self.assertTrue(out.exists())
            self.assertIn("digraph DepGraph", out.read_text(encoding="utf-8"))

    def test_scan_directory_skips_virtualenvs_and_nested_local_packages(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "services" / "api" / "localpkg").mkdir(parents=True)
            (root / "services" / "api" / "localpkg" / "__init__.py").write_text("", encoding="utf-8")
            (root / "services" / "api" / "main.py").write_text(
                "import requests\nfrom localpkg import helpers\n",
                encoding="utf-8",
            )
            (root / ".venv").mkdir()
            (root / ".venv" / "leak.py").write_text("import should_not_appear\n", encoding="utf-8")

            deps = self.scanner.scan_directory(root)

        self.assertIn("requests", deps)
        self.assertNotIn("localpkg", deps)
        self.assertNotIn("should_not_appear", deps)
