# depcheck

`depcheck` scans dependency declarations, resolved versions, and source imports.
It reports how packages are used, dependency issues, and optional security
results through a CLI and MCP tools. It reads repository files without importing
project code or running package managers.

## Capabilities

- Components are identified by
  `(project_id, ecosystem, package, version, instance)`.
- Reports missing, unused, unpinned, conflicting, and scope-mismatched dependencies
  when the collected evidence supports those findings.
- Exact-version OSV queries for PyPI, npm, Go, and Maven.
- Python compatibility analysis backed by PyPI metadata when explicitly enabled.
- Text, `depcheck.scan.v1` JSON, SARIF 2.1.0, and CycloneDX 1.7 output.
- A rebuildable `depcheck.index.v3` SQLite evidence index.
- Qualified inventory queries, dependency explanations, impact analysis, and
  read-only Python requirements update previews.
- CLI and MCP interfaces over the same scanner, model, index, and service layer.

Scan results separate dependency findings from analysis failures. Skipped,
unsupported, and failed stages keep the overall result incomplete.

## Ecosystem coverage

| Ecosystem | Evidence |
| --- | --- |
| Python / PyPI | `pyproject.toml`, requirements files, setup metadata, Pipfile, supported locks, Docker/Make install hints, Python and notebook imports |
| JavaScript / npm | `package.json`, npm lockfiles, literal ESM/CommonJS/dynamic imports, resolved instance edges |
| Go modules | `go.mod`, `go.sum`, replacements, exclusions, direct/indirect requirements, literal imports |
| Java/Kotlin / Maven or Gradle | effective local POM evidence, properties and dependency management, literal Gradle declarations, lock evidence, imports |
| C/C++ / Conan or vcpkg | supported manifests and JSON locks, includes, CMake `find_package` evidence |

Dynamic or ambiguous syntax produces incomplete evidence. Security scanning for
Conan and vcpkg returns `security.ecosystem-unsupported`: depcheck cannot map
these packages to OSV coordinates, so their security results remain incomplete.

## Install

Python 3.11 or newer is required. CI tests Python 3.11 and 3.12.

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

Queries reject stale indexes. Run `depcheck index .` again after changing source,
manifests, or configuration. A corrupt SQLite cache produces a command error;
move `.depcheck/index.sqlite3` aside and rebuild it with `depcheck index .`.

Inventory queries return pages. When `truncated` is true, pass `next_offset` as
`--offset` with the same query and filters to continue. `count` is the number of
items in the current page, not the total inventory size.

Preview an update without changing the manifest:

```bash
depcheck update . "requests===2.32.4" \
  --ecosystem PyPI --project pypi:python:.
```

Use `depcheck doctor .` to inspect the installed version, index, and optional
MCP runtime.

### Exit policy

`--fail-on` accepts `any`, `incomplete`, `hygiene-incomplete`, `missing`, `unused`,
`unpinned`, `scope`, `duplicate`, `vuln`, or `compat`. Options may be
repeated. `incomplete` includes skipped stages; `hygiene-incomplete` checks
only dependency evidence, so the offline pre-commit hook can pass without an
OSV query. Command errors, including unsupported update targets, exit with code 2.
Policy failures exit with code 1.

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

Index refresh discards and rebuilds incompatible SQLite caches. Queries open the
cache read-only and report when a rebuild is needed. Source files and manifests
are never changed by scanning or indexing.

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
`--allow-root` arguments. Query tools accept `ecosystem` and `project_id`
qualifiers; ambiguous unqualified names return structured choices. Update
planning is read-only. `scan_repository` runs offline and therefore reports
security as skipped.

MCP tool annotations distinguish read-only queries/previews from operations
that replace the local `.depcheck` cache. All seven tools operate locally.

Plugin descriptors are provided in `plugin.json`, `.codex-plugin/plugin.json`,
`mcp.json`, and `.mcp.json`. The coding-agent workflow is in
`skills/check-dependencies/SKILL.md`.

## Safety boundary

Repository files are parsed as data. depcheck does not evaluate `setup.py`,
load target modules, or invoke pip, npm, pnpm, yarn, Go, Maven, Gradle, Conan,
vcpkg, or build scripts. Symlink and parent-directory escapes are rejected.

OSV is the only default network path and receives an ecosystem, package name,
and exact version. Python compatibility analysis additionally accesses PyPI
when enabled by `--compatibility` or configuration. Use `--offline` to disable
both OSV and PyPI queries.

## Analysis limits

Python import names without a configured or built-in distribution mapping remain
`inferred`; they do not establish a missing dependency. Add a scoped mapping when
you know the distribution name.

Non-literal Python module loads produce `usage.dynamic` diagnostics and suppress
unused-dependency conclusions. Literal `importlib` calls, including imported
aliases, retain usage evidence. Local-module detection uses top-level names in
the repository and its `src` directory; arbitrary Python path changes are not
resolved.

Unresolved npm `#` imports retain unknown usage evidence. Configure a scoped
mapping when the alias points to a known dependency. Malformed dependency fields
or lockfile structures make evidence incomplete. Security still checks known
versions, but reports `security.collection-incomplete` if manifest or resolution
coverage is incomplete.

Compatibility analysis checks a selected candidate graph without full version
backtracking. Conflicts involving unpinned candidates carry an incomplete
diagnostic because other versions may work. Non-Python indexing rescans the
selected evidence rather than reusing individual parsed files.

Use `repository_context.runtime_capabilities` or a project's
`supported_capabilities` to check which operations its ecosystem pack supports.
The project's `capabilities` report the state of indexed evidence. Update previews
support version entries in `requirements*.txt`; other targets return diagnostics.

## Development

Tests are grouped in five files under `test/`.

```bash
.venv/bin/pytest test -q
.venv/bin/ruff check depcheck test
.venv/bin/ruff format --check depcheck test scripts/smoke_installed.py
.venv/bin/mypy
.venv/bin/python -m compileall -q depcheck test
.venv/bin/python -m build
.venv/bin/python -m pip check
.venv/bin/uv lock --check
```

CI also installs the built wheel without extras into a separate environment and
runs `scripts/smoke_installed.py` to check the base CLI away from source imports.

`skills/check-dependencies/evals/run_live.py` exercises the skill's MCP contracts
offline using temporary repositories. Pass `--output /tmp/depcheck-live.json` to
record actual calls. CI runs it alongside the tests. The hand-authored
`traces.example.json` checks the scorer's format and rules; it is not evidence
that an agent followed the skill. Evaluate agent behavior separately with real
tasks and recorded calls.

A repository benchmark fixture can be generated with
`scripts/benchmark_monorepo.py`.
