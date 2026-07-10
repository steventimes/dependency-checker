# Description

`depcheck` is a dependency risk scanner for Python repositories and monorepos. It detects:

1. Unused declared dependencies
2. Missing dependencies imported by source code
3. Package security issues using OSV
4. Compatibility conflicts from PyPI dependency metadata

The CLI is designed for local audits and CI policy gates, with text, JSON, and SARIF output for automation.

## How to Run

To run from source code: `python main.py <path>`

To run as a module: `python -m depcheck {folder to scan}`

## Options

- `--json` returns machine-readable JSON including a `summary` object.
- `--sarif depcheck.sarif` writes SARIF 2.1.0 for GitHub code scanning and enterprise security tools.
- `--graph graph.dot` writes a Graphviz dependency graph.
- `--fail-on missing|unused|vuln|compat|any` exits with status 1 for selected risk classes. Repeat the flag to combine policies.
- `--fail-on-vuln` keeps backward-compatible vulnerability-only CI behavior.
- `--policy depcheck-policy.json` reads enterprise policy rules and time-bound exemptions.
- `--compat` checks dependency compatibility against PyPI metadata.
- `--fix-compat` auto-fixes compatibility issues by updating `requirements*.txt`.
- `--auto-update` updates `requirements*.txt` to latest compatible versions.


## CI examples

Fail a build on missing imports or known vulnerabilities:

```bash
python -m depcheck . --json --fail-on missing --fail-on vuln
```

Fail on any dependency hygiene, security, or compatibility risk:

```bash
python -m depcheck . --compat --fail-on any
```

Write a SARIF artifact while preserving normal CLI output:

```bash
python -m depcheck . --compat --sarif depcheck.sarif
```

GitHub Actions can upload the generated SARIF with `github/codeql-action/upload-sarif`, which lets dependency hygiene, OSV vulnerabilities, and compatibility risks appear in code scanning dashboards.

Example JSON output includes a stable summary for dashboards and policy engines:

```json
{
  "summary": {
    "status": "fail",
    "risk_count": 2,
    "missing_count": 1,
    "unused_count": 1,
    "vulnerability_count": 0
  }
}
```


## Policy governance

Enterprise CI can use a JSON policy file to keep exceptions explicit, owned, and time-bound:

```json
{
  "schema": "depcheck.policy.v1",
  "fail_on": ["missing", "vuln", "compat"],
  "exemptions": [
    {
      "id": "TEMP-MISSING-FASTAPI",
      "risk": "missing",
      "package": "fastapi",
      "reason": "Optional plugin dependency until service split is complete",
      "owner": "platform-team",
      "expires_at": "2026-12-31"
    }
  ]
}
```

Run with:

```bash
python -m depcheck . --json --compat --policy depcheck-policy.json
```

Active exemptions reduce the effective risk count but remain visible in the JSON output. Expired or invalid exemptions are governance risks and fail the run even if the underlying package risk is otherwise exempted. Supported exemption risk types are `missing`, `unused`, and `vuln`.

## Workflow of the program

The program will scan through all python files to find used imports, and then compare to *requirements*.txt and other supported dependency sources. It also inspects Dockerfile/Makefile/CMakeLists.txt for `pip install` commands as additional dependency hints. For all imports, it will send to OSV API to check for vulnerabilities.

### Future of this little project

1. try on auto fixing unused imports
2. recommand a list of packages with their version to fix the vulnerability (ADDED)
3. write documentations
