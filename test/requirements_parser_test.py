import unittest
from pathlib import Path
from depcheck.analyzer.base_parser import BaseDependencyParser

class TestBaseParser(unittest.TestCase):
    
    def test_parse_line_logic(self):
        """Test the shared version splitting logic."""
        
        self.assertEqual(BaseDependencyParser.parse_line("numpy==1.2.0"), ("numpy", "1.2.0"))
        self.assertEqual(BaseDependencyParser.parse_line("requests>=2.0"), ("requests", "2.0"))
        self.assertEqual(BaseDependencyParser.parse_line(" pandas "), ("pandas", None))
        name, ver = BaseDependencyParser.parse_line("scipy; python_version < '3.8'")
        self.assertEqual(name, "scipy")
        self.assertEqual(BaseDependencyParser.parse_line("FLASK==2.0"), ("flask", "2.0"))

    def test_environment_marker_stripping(self):
        """Ensure markers like '; sys_platform' are handled safely."""
        name, ver = BaseDependencyParser.parse_line("black==22.3.0; platform_system == 'Windows'")
        self.assertEqual(name, "black")
        self.assertEqual(ver, "22.3.0")