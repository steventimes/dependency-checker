import unittest
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path
from depcheck.analyzer.import_scanner import ImportScanner

class TestImportScanner(unittest.TestCase):
    
    def setUp(self):
        self.scanner = ImportScanner()

    @patch("depcheck.analyzer.import_scanner.Path.rglob")
    @patch("depcheck.analyzer.import_scanner.open", new_callable=mock_open)
    def test_scan_directory_ignores_locals(self, mock_file, mock_rglob):
        """Test that local modules (like 'utils.py') are NOT reported as 3rd party."""

        mock_main = MagicMock(spec=Path)
        mock_main.parts = ("main.py",)
        mock_main.name = "main.py"
        
        mock_utils = MagicMock(spec=Path)
        mock_utils.parts = ("utils.py",)
        mock_utils.name = "utils.py"
        mock_utils.stem = "utils"
        
        mock_rglob.return_value = [mock_main, mock_utils]

        file_content_map = {
            "main.py": "import requests\nimport utils",
            "utils.py": "import sys" 
        }
        
        def side_effect(path, *args, **kwargs):
            content = file_content_map.get(path.name, "")
            return mock_open(read_data=content).return_value

        mock_file.side_effect = side_effect

        with patch.object(self.scanner, '_get_local_modules', return_value={'utils'}):
            results = self.scanner.scan_directory(Path("."))

        self.assertIn("requests", results)
        self.assertNotIn("utils", results)

    @patch("depcheck.analyzer.import_scanner.open", new_callable=mock_open)
    def test_generate_dot_graph(self, mock_file):
        """Test if Graphviz DOT file is generated correctly."""
        
        fake_map = {"main.py": {"requests", "utils"}}
        
        with patch.object(self.scanner, '_scan_for_graph', return_value=fake_map):
            with patch.object(self.scanner, '_get_local_modules', return_value={'utils'}):
                self.scanner.generate_dot(Path("."), Path("graph.dot"))
        
        mock_file.assert_called_with(Path("graph.dot"), "w", encoding="utf-8")
        
        handle = mock_file()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)
        
        self.assertIn("digraph DepGraph", written_content)
        self.assertIn('"file_main_py" -> "pkg_requests"', written_content)
        self.assertIn('[style=dashed', written_content)