import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import depcheck.cli.util
from depcheck.cli.util import load_ignore_file, normalize_imports


class TestUtilFunctions(unittest.TestCase):
    def test_normalize_imports_prefers_installed_mapping_then_static_then_lowercase(self):
        with patch.object(
            depcheck.cli.util,
            "packages_distributions",
            return_value={"yaml": ["PyYAML"], "jwt": ["PyJWT"]},
        ):
            normalized = normalize_imports({"yaml", "jwt", "bs4", "CustomLib"})

        self.assertIn("PyYAML", normalized)
        self.assertIn("PyJWT", normalized)
        self.assertIn("beautifulsoup4", normalized)
        self.assertIn("customlib", normalized)

    def test_load_ignore_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".depcheckignore").write_text(
                "# comment\npytest\nBLACK\n\n",
                encoding="utf-8",
            )
            ignored = load_ignore_file(root)

        self.assertEqual(ignored, {"pytest", "black"})
