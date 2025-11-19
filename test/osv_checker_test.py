from depcheck.security.osv_checker import OSV_Check

def test_osv_checker_no_crash():
    checker = OSV_Check()
    result = checker.check("nonexistent-package-xyz", "1.0.0")
    assert isinstance(result, list)
