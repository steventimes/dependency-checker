import unittest
from pathlib import Path
from unittest.mock import patch

from depcheck.analyzer.pip_install_parser import PipInstallParser


class TestPipInstallParser(unittest.TestCase):
    def test_parse_pip_install_commands(self):
        content = """\
RUN pip install requests==2.31.0 flask>=2.0
RUN python -m pip install numpy==1.26.0 \\
    pandas==2.0.0
RUN pip install -r requirements.txt
"""
        parser = PipInstallParser(Path("Dockerfile"))
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "read_text", return_value=content):
                deps = parser.parse()

        self.assertEqual(deps["requests"], "2.31.0")
        self.assertEqual(deps["flask"], "2.0")
        self.assertEqual(deps["numpy"], "1.26.0")
        self.assertEqual(deps["pandas"], "2.0.0")
        self.assertNotIn("requirements.txt", deps)

    def test_ignores_editable_and_extras(self):
        content = "pip install -e . requests[socks]==2.28.0\n"
        parser = PipInstallParser(Path("Makefile"))
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "read_text", return_value=content):
                deps = parser.parse()

        self.assertEqual(deps["requests"], "2.28.0")
        self.assertNotIn(".", deps)
