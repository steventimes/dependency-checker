import random
import string
import unittest
from pathlib import Path

from packaging.requirements import Requirement

from depcheck.analyzer.base_parser import BaseDependencyParser
from depcheck.analyzer.requirement_parser import RequirementParser


class TestSmokeBaseParser(unittest.TestCase):
    """Sanity checks / smoke tests."""

    def test_parse_line_runs(self):
        name, version = BaseDependencyParser.parse_line("requests==2.31.0")
        self.assertEqual((name, version), ("requests", "2.31.0"))


class TestUnitBaseParser(unittest.TestCase):
    """Unit tests over representative input partitions."""

    def test_parse_line_partitions(self):
        cases = [
            ("numpy==1.2.0", ("numpy", "1.2.0")),
            ("requests>=2.0", ("requests", "2.0")),
            (" pandas ", ("pandas", None)),
            ("scipy; python_version < '3.8'", ("scipy", None)),
            ("FLASK==2.0", ("flask", "2.0")),
            ("requests[socks]==2.31.0", ("requests", "2.31.0")),
            ("", ("", None)),
            ("not a dependency line", ("", None)),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(BaseDependencyParser.parse_line(raw), expected)

    def test_environment_marker_stripping(self):
        self.assertEqual(
            BaseDependencyParser.parse_line("black==22.3.0; platform_system == 'Windows'"),
            ("black", "22.3.0"),
        )


class TestFuzzBaseParser(unittest.TestCase):
    """Fuzzing for crash detection on random-ish strings."""

    def test_parse_line_fuzz_no_crash(self):
        alphabet = string.ascii_letters + string.digits + "=<>!~;[]_'\".-/ @"
        rnd = random.Random(1337)

        for _ in range(2000):
            raw = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 64)))
            name, version = BaseDependencyParser.parse_line(raw)
            self.assertIsInstance(name, str)
            self.assertTrue(version is None or isinstance(version, str))


class TestModelCheckingBaseParser(unittest.TestCase):
    """Bounded exhaustive checks over a finite state space (model-checking style)."""

    def test_bounded_exhaustive_against_packaging_requirement(self):
        names = ["requests", "Flask", "mypkg"]
        extras = ["", "[socks]"]
        specs = ["", "==1.2.3", ">=1.0", "<=2.0", "~=3.4"]
        markers = ["", "; python_version < '3.11'", "; platform_system == 'Linux'"]

        for n in names:
            for e in extras:
                for s in specs:
                    for m in markers:
                        raw = f"{n}{e}{s}{m}"
                        with self.subTest(raw=raw):
                            parsed = Requirement(raw)
                            expected_name = parsed.name.lower()
                            expected_version = (
                                BaseDependencyParser._normalize_version(str(parsed.specifier))
                                if str(parsed.specifier)
                                else None
                            )
                            self.assertEqual(
                                BaseDependencyParser.parse_line(raw),
                                (expected_name, expected_version),
                            )


class TestRequirementParserIntegration(unittest.TestCase):
    """Integration testing for file parsing behavior."""

    def test_skips_option_lines(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            requirements_path = Path(temp_dir) / "requirements.txt"
            requirements_path.write_text(
                "\n".join(
                    [
                        "-r base.txt",
                        "--constraint constraints.txt",
                        "-e git+https://example.com/repo.git#egg=demo",
                        "requests==2.31.0",
                        "numpy; python_version >= '3.9'",
                    ]
                ),
                encoding="utf-8",
            )

            parser = RequirementParser(requirements_path)
            deps = parser.parse()

            self.assertEqual(deps, {"requests": "2.31.0", "numpy": None})
