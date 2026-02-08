import unittest
import tempfile
from pathlib import Path
from depcheck.analyzer.base_parser import BaseDependencyParser
from depcheck.analyzer.requirement_parser import RequirementParser

class TestBaseParser(unittest.TestCase):
    
    def test_parse_line_logic(self):
        """Test the shared version splitting logic."""
        
        self.assertEqual(BaseDependencyParser.parse_line("numpy==1.2.0"), ("numpy", "1.2.0"))
        self.assertEqual(BaseDependencyParser.parse_line("requests>=2.0"), ("requests", "2.0"))
        self.assertEqual(BaseDependencyParser.parse_line(" pandas "), ("pandas", None))
        name, ver = BaseDependencyParser.parse_line("scipy; python_version < '3.8'")
        self.assertEqual(name, "scipy")
        self.assertEqual(BaseDependencyParser.parse_line("FLASK==2.0"), ("flask", "2.0"))
        self.assertEqual(BaseDependencyParser.parse_line("requests[socks]==2.31.0"), ("requests", "2.31.0"))

    def test_environment_marker_stripping(self):
        """Ensure markers like '; sys_platform' are handled safely."""
        name, ver = BaseDependencyParser.parse_line("black==22.3.0; platform_system == 'Windows'")
        self.assertEqual(name, "black")
        self.assertEqual(ver, "22.3.0")


class TestRequirementParser(unittest.TestCase):

    def test_skips_option_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            requirements_path = Path(temp_dir) / "requirements.txt"
            requirements_path.write_text(
                "\n".join(
                    [
                        "-r base.txt",
                        "--constraint constraints.txt",
                        "-e git+https://example.com/repo.git#egg=demo",
                        "requests==2.31.0",
                    ]
                ),
                encoding="utf-8",
            )

            parser = RequirementParser(requirements_path)
            deps = parser.parse()

            self.assertEqual(deps, {"requests": "2.31.0"})
