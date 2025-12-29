import unittest
from unittest.mock import patch, mock_open
from depcheck.cli.util import normalize_imports, load_ignore_file
from pathlib import Path

class TestUtil(unittest.TestCase):
    
    @patch("depcheck.util.packages_distributions")
    def test_normalize_dynamic_mapping(self, mock_dist):
        """Test that installed packages are detected via importlib."""
        mock_dist.return_value = {"yaml": ["PyYAML"]}
        
        raw = {"yaml", "requests"}
        normalized = normalize_imports(raw)
        
        self.assertIn("PyYAML", normalized)
        self.assertIn("requests", normalized)

    def test_normalize_static_fallback(self):
        """Test hardcoded fallback for known packages."""
        raw = {"bs4", "cv2"}
        normalized = normalize_imports(raw)
        
        self.assertIn("beautifulsoup4", normalized)
        self.assertIn("opencv-python", normalized)

    @patch("builtins.open", new_callable=mock_open, read_data="# comment\npytest\nblack")
    def test_load_ignore_file(self, mock_file):
        """Test reading .depcheckignore."""

        with patch.object(Path, 'exists', return_value=True):
            ignored = load_ignore_file(Path("."))
            
        self.assertIn("pytest", ignored)
        self.assertIn("black", ignored)
        self.assertEqual(len(ignored), 2)