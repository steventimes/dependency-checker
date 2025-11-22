from depcheck.analyzer.requirement_parser import RequirementParser
import tempfile
import os
from pathlib import Path

def test_requirements_parser():
    content = "numpy==1.21.0\nrequests\n"

    # Create a temp requirements.txt file
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(content)
        path = Path(f.name).resolve()

    try:
        parser = RequirementParser(path)
        result = parser.parse()

        assert "numpy" in result
        assert result["numpy"] == "1.21.0"
        assert "requests" in result
        assert result["requests"] is None  # no version specified

    finally:
        os.remove(path)
