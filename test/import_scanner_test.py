from depcheck.analyzer.import_scanner import ImportScanner
import tempfile

def test_import_scanner_basic():
    code = "import os\nimport numpy as np"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name

    scanner = ImportScanner()
    result = scanner.scan_file_(path)
    assert "os" in result
    assert "numpy" in result
