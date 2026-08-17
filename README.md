# depcheck

`depcheck` is a static dependency-evidence scanner for repositories and coding
agents. It correlates declarations, exact resolutions, source usage, security
results, and policy findings without importing project code or running package
managers.

## Capabilities

- One qualified identity for every component:
  `(project_id, ecosystem, package, version, instance)`.
- Missing, unused, unpinned, conflicting, and scope-mismatched dependency
  findings, gated by evidence confidence.
- Exact-version OSV queries for PyPI, npm, Go, and Maven.
- Python compatibility analysis backed by PyPI metadata when explicitly enabled.
- Text, `depcheck.scan.v1` JSON, SARIF 2.1.0, and CycloneDX 1.7 output.
- A rebuildable `depcheck.index.v3` SQLite evidence index.
- Qualified inventory queries, dependency explanations, impact analysis, and
  read-only Python requirements update previews.
- CLI and MCP interfaces over the same scanner, model, index, and service layer.

A scan distinguishes findings from incomplete analysis. A skipped, unsupported,
or failed capability never becomes a clean result.

## Ecosystem coverage

| Ecosystem | Evidence |
| --- | --- |
| Python / PyPI | `pyproject.toml`, requirements files, setup metadata, Pipfile, supported locks, Docker/Make install hints, Python and notebook imports |
| JavaScript / npm | `package.json`, npm lockfiles, literal ESM/CommonJS/dynamic imports, resolved instance edges |
| Go modules | `go.mod`, `go.sum`, replacements, exclusions, direct/indirect requirements, literal imports |
| Java/Kotlin / Maven or Gradle | effective local POM evidence, properties and dependency management, literal Gradle declarations, lock evidence, imports |
| C/C++ / Conan or vcpkg | supported manifests and JSON locks, includes, CMake `find_package` evidence |

Dynamic or ambiguous syntax is reported as incomplete evidence. Conan and vcpkg
currently emit a `security.ecosystem-unsupported` diagnostic and keep security incomplete because depcheck cannot produce safe
OSV coordinates for them.

## Install

Python 3.11 or 3.12 is required.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[agent,test]'
.venv/bin/depcheck --version
```

The plugin launchers use the checked-in `uv.lock` with uv 0.12.4.

## CLI

Scan offline and emit canonical JSON:

```bash
depcheck scan . --offline --format json
```

Run security and Python compatibility analysis:

```bash
depcheck scan . --security --compatibility --python-version 3.12
```

Generate integration formats:

```bash
depcheck scan . --offline --format sarif --output depcheck.sarif
depcheck scan . --offline --format cyclonedx-json --output bom.json
```

Build and query the local index:

```bash
depcheck index .
depcheck context .
depcheck query . requests --ecosystem PyPI --project pypi:python:.
depcheck explain . requests --ecosystem PyPI --project pypi:python:.
depcheck impact . requests --ecosystem PyPI --project pypi:python:.
```

Preview an update without changing the manifest:

```bash
depcheck update . "requests===2.32.4" \
  --ecosystem PyPI --project pypi:python:.
```

Use `depcheck doctor .` to inspect the installed version, index, and optional
MCP runtime.

### Exit policy

`--fail-on` accepts `any`, `incomplete`, `missing`, `unused`,
`unpinned`, `scope`, `duplicate`, `vuln`, or `compat`. Options may be
repeated.

A JSON policy file can add expiring, qualified exemptions:

```json
{
  "fail_on": ["missing", "vuln", "incomplete"],
  "exemptions": [
    {
      "id": "temporary-requests-exemption",
      "risk": "vuln",
      "package": "requests",
      "project_id": "pypi:python:.",
      "ecosystem": "PyPI",
      "reason": "Upgrade is scheduled",
      "owner": "platform",
      "expires_at": "2026-09-01"
    }
  ]
}
```

Pass it with `--policy policy.json`. Invalid, expired, or unmatched exemptions
remain observable; invalid and expired exemptions fail governance evaluation.

## Configuration

Use `.depcheck.toml` at the repository root:

```toml
security = false
compatibility = false
python-version = "3.12"
enabled-ecosystems = ["PyPI", "npm", "Go", "Maven", "Conan", "vcpkg"]
excluded-directories = ["generated"]
ignore-packages = ["internal-placeholder"]
fail-on = ["missing", "incomplete"]

[mappings.PyPI."pypi:python:."]
PIL = "pillow"

[mappings.npm."npm:npm:apps/web"]
"@internal/ui" = "@company/ui"
```

Mappings are scoped by ecosystem and stable project ID. Excluded directories
must be relative paths inside the repository.

## Result model

`depcheck.scan.v1` contains:

- `summary`: status, completeness, counts, risks, and diagnostics.
- `capabilities`: explicit `complete`, `incomplete`, `skipped`, or
  `unsupported` states.
- `findings` and `diagnostics`: separate policy risks and analysis failures.
- `inventory`: sources, manifests, declarations, resolved identities, and
  dependency edges.
- `projects` and `ecosystems`: per-project capability and evidence summaries.
- `vulnerabilities`: issues keyed by full package identity.
- `metadata`: structured optional-stage results such as compatibility.

An incompatible SQLite cache is discarded and rebuilt at its configured cache
path. Source files and manifests are never changed by scanning or indexing.

## MCP and agent integration

The stdio server exports seven tools:

- `index_repository`
- `scan_repository`
- `repository_context`
- `query_dependencies`
- `explain_dependency`
- `dependency_impact`
- `plan_dependency_updates`

The server authorizes only roots supplied by the MCP client or explicit
`--root` arguments. Query tools accept `ecosystem` and `project_id`
qualifiers; ambiguous unqualified names return structured choices. Update
planning is read-only. `scan_repository` runs offline and therefore reports
security as skipped.

Plugin descriptors are provided in `plugin.json`, `.codex-plugin/plugin.json`,
`mcp.json`, and `.mcp.json`. The coding-agent workflow is in
`skills/check-dependencies/SKILL.md`.

## Safety boundary

Repository files are parsed as data. depcheck does not evaluate `setup.py`,
load target modules, or invoke pip, npm, pnpm, yarn, Go, Maven, Gradle, Conan,
vcpkg, or build scripts. Symlink and parent-directory escapes are rejected.

OSV is the only default network path and receives an ecosystem, package name,
and exact version. Python compatibility analysis additionally accesses PyPI
only when `--compatibility` is requested. Use `--offline` to disable OSV.

## Development

The suite is intentionally consolidated into five test files.

```bash
.venv/bin/pytest test -q
.venv/bin/ruff check depcheck test
.venv/bin/mypy
.venv/bin/python -m compileall -q depcheck test
.venv/bin/python -m build
.venv/bin/python -m pip check
.venv/bin/uv lock --check
```

A repository benchmark fixture can be generated with
`scripts/benchmark_monorepo.py`.
