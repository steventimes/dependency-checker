---
name: check-dependencies
description: Audit repository dependencies using depcheck static evidence across Python, JavaScript/TypeScript, Go, Java/Kotlin, and C/C++. Use for dependency health, unused or missing packages, dependency upgrade previews, vulnerability checks, and SBOMs. Do not activate for unrelated code edits or symbol renames that leave dependencies unchanged.
---

# Check Dependencies

Use depcheck as a source of static dependency evidence. Discover the available
MCP tools first; do not assume installing this skill also installed its server.
If the tools are absent or the transport fails, use an installed `depcheck` CLI
as described below. If neither is available, report that limitation. Do not
silently install tools or repeatedly retry a stalled transport.

An MCP allowlist can exclude another repository the user explicitly asked you
to inspect. Use the CLI when direct filesystem access to that requested root is
authorized; keep the server allowlist intact. CLI scans are read-only, while
indexing writes a cache. For read-only trials, scan the original and use an
isolated source snapshot for indexed queries, stating the snapshot's coverage.

MCP queries and update previews are read-only. `index_repository` and
`scan_repository` create or replace the local `.depcheck` cache; they do not
change source or manifests. The tool annotations describe these side effects.

## Workflow

1. Call `repository_context` with the target `project_root`. If `indexed` is
   false or `stale` is true, refresh once: use `scan_repository` for a hygiene
   audit, or `index_repository` for inventory/explanation only. Reuse the scan's
   returned `context`. After indexing alone, call context again if you need the
   discovered identities or coverage; the index response contains counters, not
   project details. A fresh index can remain incomplete; inspect the reasons
   instead of refreshing again without a relevant file or configuration change.
   An incompatible-schema error needs `index_repository` to rebuild the cache;
   querying it will not migrate or discard it.
2. Check `projects`, `ecosystems`, and `scope` against the requested coverage.
   A filtered index has `incomplete_reasons: ["index-selection"]`; it can answer
   within that selection but cannot describe the whole repository. Refresh
   without filters if the task needs broader coverage. Index refresh counters
   describe work performed, not total inventory: zero `parsed_manifest_files`
   does not mean there are no npm/Go/Maven/C++ dependencies.
3. Read each project's `supported_capabilities` for supported operations and
   `capabilities` for evidence status. Keep freshness, hygiene, security, and
   policy results separate. An offline scan can have `summary.complete: false`,
   `capabilities.security.state: "skipped"`, and complete dependency hygiene.
   Context `status` reflects indexed findings/evidence errors, while scan
   `metadata.policy.status` reflects configured failure rules; they can differ.
   Missing locks, unsupported syntax, and skipped security do not improve by
   repeating the same scan. Report their effect on the requested conclusion.
4. Use `query_dependencies` for inventory and `explain_dependency` for a known
   package. Pass `ecosystem` and `project_id` when known. Queries return a page:
   follow `next_offset` with the same filters until it is null when full coverage
   is needed. `count` is the page count. If a budget stops traversal, say how
   much was inspected; do not call a truncated page the complete inventory.
5. Inspect payload `error` and `diagnostics` even when the MCP call itself
   succeeds. For `dependency.ambiguous`, present the returned identities and
   qualify a follow-up using the user's scope. Ask only if that scope cannot
   choose between them. Preserve `resolved_versions: []` as unknown resolution;
   a fresh, complete index does not guarantee exact versions for security work.
6. Use `dependency_impact` before recommending removal or upgrade, and read
   `explain_dependency` for usage locations and mapping confidence. No observed
   imports is a removal candidate, not proof of non-use: entry points, plugins,
   dynamic imports, and deployment configuration may need inspection.
   Check `usage_complete` and `evidence_complete` in query, explain, and impact
   results. Zero observed usages with incomplete coverage means unknown impact.
   These flags describe the collected static evidence; even `true` does not
   establish coverage of every command, entry point, or plugin.
   Read `usages` as well as `imports`: a `kind: "tool"` entry with
   `mapping_confidence: "configured"` records a scoped user declaration in
   `.depcheck.toml`. Preserve its reason and location when explaining use;
   do not describe it as an observed import or command execution. Impact counts
   both source and tool usages. Use existing policy exemptions for temporary
   finding exceptions; `ignore-packages` removes dependency evidence from
   inventory, security checks, and SBOMs.
7. `plan_dependency_updates` defaults to Python `requirements*.txt` version
   entries. For static PEP 621 dependencies, specify `target_file` and determine
   `group` first: `project` or `optional:NAME`. Omit group only when each requested
   package has one group. Report `update.ambiguous-target` rather than guessing.
   Unsupported targets return `update.unsupported-target`; invalid targets
   return `update.invalid-target`. Read both plans and diagnostics for partial
   results. Empty plans without diagnostics means no changes were needed.
   Previews never edit manifests/locks, apply upgrades, or establish compatibility.

## CLI fallback

Use the installed executable and quote paths and specifiers. All examples use
`<root>` as a placeholder for the target repository. Context, index, query,
explain, impact, and update print JSON without a format flag.

| MCP operation | CLI equivalent |
| --- | --- |
| `repository_context` | `depcheck context "<root>"` |
| `index_repository` | `depcheck index "<root>"` |
| `scan_repository` | `depcheck scan "<root>" --offline --format json`, then `depcheck index "<root>"` if indexed queries are needed |
| `query_dependencies` | `depcheck query "<root>" --limit 20 --offset 0` |
| `explain_dependency` | `depcheck explain "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `dependency_impact` | `depcheck impact "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `plan_dependency_updates` | `depcheck update "<root>" 'requests=2.32.4' --ecosystem PyPI --project 'pypi:python:.'` |

For an explicit pyproject preview, use
`depcheck update "<root>" 'requests==2.32.4' --file pyproject.toml --group project`;
optional groups use
`--group optional:NAME`. Without `--file`, keep the default requirements route.

CLI query text is an optional positional argument, not a `--package` flag.
It uses substring matching, not glob patterns: to list `package-*`, use
`depcheck query "<root>" package- --limit 20 --offset 0` and follow pagination.

CLI `scan` does not refresh the index. Add `--ecosystem`/`--project` to queries
when the identity is known; filter index/scan only when the task asks for that
scope. Respect configured exclusions. CLI exit 1 is a policy failure, exit 2 an
operation error; exit 0 alone does not establish complete coverage.

Before acting on findings, compare collected files with the project's manifests,
ignored/generated directories, package scripts, and build/test configuration.
Discovery excludes installed `site-packages`/`dist-packages` trees but does not
interpret `.gitignore`. Use existing configured exclusions or an explicitly
scoped snapshot to keep unrelated artifacts out; do not edit the audited
project's configuration just to improve a trial result.

Compare raw dependency-bearing manifests with the registered packs. Cargo/Rust
and browser/CDN dependencies are not covered by the current scanners, even when
`scope.repository_complete` is true. Python manifests currently share a
repository-level project ID; inspect declaration locations before treating
repetition across independent Python components as duplication. For component
decisions, scan the component root separately and retain that narrower scope.

For a requested tool-usage configuration, use a scoped entry with a reason
supported by the project's build, test, or deployment files:

```toml
[[tool-usage]]
ecosystem = "PyPI"
project-id = "pypi:python:."
package = "ruff"
scope = "test"
reason = "Runs as the lint command in CI"
```

Confirm the exact project ID and direct declaration first. This records a user
configuration claim, not command execution; do not add it solely to silence a
warning or change the audited project's configuration during a read-only trial.

## Static and network boundary

The normal scan is data-only: it must not execute repository code, import the
target project, or invoke package managers such as npm, pnpm, yarn, Go, Maven,
Gradle, Conan, or vcpkg. Do not add an execution step implicitly.

MCP `scan_repository` always skips network security and compatibility checks.
For an authorized vulnerability check with network access allowed, use
`depcheck scan "<root>" --security --no-compatibility --format json` and inspect
`capabilities.security` and its diagnostics. If only MCP is available, report
that security has not run; do not invent a security tool or parameter.

OSV is the optional network path in that security scan and receives
qualified package/version coordinates, not source text. Respect offline status
and never describe a skipped or incomplete security capability as safe.
PyPI, npm, Go, and Maven have OSV coordinate support. Conan and vcpkg currently
return an explicit unsupported-security diagnostic.

Treat yarn locks, unsupported pnpm resolutions, dynamic Gradle or Conan
expressions, and unknown Java/C++ namespace ownership as incomplete or
low-confidence evidence. Do not
turn those limitations into confident removal, upgrade, or safety claims.

Maven versions inherited from unavailable parents/BOMs remain unresolved;
absence of a literal version is not proof that an installed dependency is
unpinned. Local reactor SNAPSHOT references also need build-context review.
Astro, Vue, and Svelte components produce `usage.unsupported-source`; stylesheet
and command-only uses may also be absent from import evidence. Check frontend
scripts and test/build configuration before suggesting removal or scope moves.

Compiled `requirements*.lock` and `*-requirements.lock` files provide exact
Python version evidence, including multiline hash options and markers. These
locks are read-only evidence sources; update previews still target supported
requirements text entries or explicit static PEP 621 groups.

Exact `package.json` imports string keys can map to bare npm package targets,
explicit safely discovered local files, or bare Node builtins such as `"fs"`
and `"fs/promises"`. An imports target of `"node:fs"` is invalid; direct source
imports using that specifier are valid. Package targets have
exact confidence and retain their package.json reason; local/builtin aliases
are not external dependencies. Conditions, arrays, nulls, wildcard patterns,
alias chains, missing/unsafe local files and unsupported targets produce
`mapping.alias-unsupported` and leave usage incomplete. Scoped configured
mappings take precedence. TypeScript paths and full Node resolution are not implemented.

pnpm v9 locks provide registry versions and instance edges per workspace importer,
including optional dependencies and peer instances. Other lock versions and
local, file, Git, or URL resolutions leave resolution incomplete. Check lock
diagnostics before claiming full coverage. npm installation aliases retain
their local import names but use the real registry identity for inventory,
OSV, and SBOMs; do not suggest installing the alias name as a separate package.

Non-literal Python module loads and unresolved npm `#` imports also leave
usage incomplete. Use a scoped npm mapping only when the alias's dependency
target is known; a `#` alias may point to a local file. Malformed manifests or
locks leave security incomplete even when the known versions have no findings.

All MCP update tools are read-only. Never claim `plan_dependency_updates`
changed a manifest. Make edits only within the user's authorized scope; a
preview-only request does not authorize applying the preview.

## Code graph boundary

Inspect `repository_context.code_index` before relying on GitNexus. Require
`available`, `indexed`, and `head_aligned` to be true and `stale` to be false.
Continue with depcheck's dependency evidence when GitNexus is unavailable. Do
not install or run `npx` implicitly.

## Reporting

Report task completion separately from individual capability results. If the
user asks whether dependencies are safe and security was skipped, the overall
answer is incomplete even when hygiene and policy pass. An inventory-only task
can be complete without a security scan.

- Preserve the stable identity `(project_id, ecosystem, package)` and PURL when
  present.
- Distinguish direct declarations, resolved dependencies, usage evidence,
  diagnostics, and inferred findings.
- Preserve file and line locations and mapping-confidence reasons.
- State when output is truncated, stale, incomplete, offline, ambiguous, or
  limited by a missing capability.
- Tie conclusions to the detected projects, manifests, and resolved versions.
  Empty findings with no collected dependencies do not establish an audit.
  depcheck does not measure upstream maintenance, publisher access, or install
  script risk; a broader supply-chain request needs separate evidence for those.
- If scan findings are truncated, use CLI JSON for the full scan output or
  query/explain selected dependencies; inventory pagination is a separate limit.
- Prefer `depcheck.scan.v1`, SARIF, or CycloneDX output when the result will feed
  another tool.
