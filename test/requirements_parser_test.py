from depcheck.analyzer.requirement_parser import requirementParse
import tempfile

def test_requirements_parser():
    content = "numpy==1.21.0\nrequests\n"
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(content)
        path = f.name

    parser = requirementParse()
    result = parser.parse_file(path)

    assert "numpy" in result
    assert result["numpy"] == "1.21.0"
    assert "requests" in result
