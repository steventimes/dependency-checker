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

## Workflow

1. Call `repository_context` with the target `project_root`. If `indexed` is
   false or `stale` is true, refresh once: use `scan_repository` for a hygiene
   audit, or `index_repository` for inventory/explanation only. Reuse the scan's
   returned `context`. After indexing alone, call context again if you need the
   discovered identities or coverage; the index response contains counters, not
   project details. A fresh index can remain incomplete; inspect the reasons
   instead of refreshing again without a relevant file or configuration change.
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
7. `plan_dependency_updates` previews Python `requirements*.txt` version entries
   only. The `update_preview` capability does not promise support for every
   Python manifest. `capability.unsupported` or `update.unsupported-target`
   means that target was not planned; report partial success per target. Empty
   `plans` with no diagnostics means no changes were needed. Previews neither
   edit files nor verify that an upgrade is compatible.

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

CLI `scan` does not refresh the index. Add `--ecosystem`/`--project` to queries
when the identity is known; filter index/scan only when the task asks for that
scope. Respect configured exclusions. CLI exit 1 is a policy failure, exit 2 an
operation error; exit 0 alone does not establish complete coverage.

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

Treat yarn/pnpm locks, dynamic Gradle or Conan expressions, and unknown
Java/C++ namespace ownership as incomplete or low-confidence evidence. Do not
turn those limitations into confident removal, upgrade, or safety claims.

All MCP update tools are read-only. Never claim `plan_dependency_updates`
changed a manifest. Make edits only within the user's authorized scope; a
preview-only request does not authorize applying the preview.

## Code graph boundary

Inspect `repository_context.code_index` before relying on GitNexus. Require
`available`, `indexed`, and `head_aligned` to be true and `stale` to be false.
Continue with depcheck's dependency evidence when GitNexus is unavailable. Do
not install or run `npx` implicitly.

## Reporting

- Preserve the stable identity `(project_id, ecosystem, package)` and PURL when
  present.
- Distinguish direct declarations, resolved dependencies, usage evidence,
  diagnostics, and inferred findings.
- Preserve file and line locations and mapping-confidence reasons.
- State when output is truncated, stale, incomplete, offline, ambiguous, or
  limited by a missing capability.
- If scan findings are truncated, use CLI JSON for the full scan output or
  query/explain selected dependencies; inventory pagination is a separate limit.
- Prefer `depcheck.scan.v1`, SARIF, or CycloneDX output when the result will feed
  another tool.
