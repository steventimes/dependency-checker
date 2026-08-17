---
name: check-dependencies
description: Index and audit static multi-ecosystem dependency evidence, explain qualified package identities and impact, inspect security findings, and preview supported manifest updates. Use when reviewing dependency health, investigating unused or missing packages, preparing upgrades, generating SBOM context, or giving a coding agent compact repository dependency evidence.
---

# Check Dependencies

Use the depcheck MCP tools as the repository's static dependency evidence
source. Built-in packs cover Python/PyPI, JavaScript/TypeScript/npm, Go modules,
Java/Kotlin with Maven or Gradle, and C/C++ with Conan or vcpkg.

## Workflow

1. Call `repository_context` for the target root. If `indexed` is false, call
   `index_repository`.
2. Treat `stale: true`, `complete: false`, or a non-empty
   `incomplete_reasons` list as a reason to refresh with `scan_repository`
   before drawing dependency-hygiene conclusions. `scan_repository` refreshes
   an offline index and explicitly leaves security skipped; it is not a full
   vulnerability scan.
3. Inspect `projects`, `ecosystems`, and project `capabilities`. Never present an
   unsupported capability as an empty successful result.
4. Use `query_dependencies` for inventory search. Pass `ecosystem` and
   `project_id` whenever the user or repository context identifies them.
5. Use `explain_dependency` for declarations, usages, resolutions, and findings.
   If it returns `dependency.ambiguous`, show the exact choices and qualify the
   follow-up call rather than selecting one silently.
6. Use `dependency_impact` before recommending a removal or upgrade. Distinguish
   exact/configured usage mappings from inferred or unknown evidence.
7. Use `plan_dependency_updates` only for a preview and only when the selected
   project advertises `update_preview`. `capability.unsupported` is a real
   result, not evidence that no update is needed.

## Static and network boundary

The normal scan is data-only: it must not execute repository code, import the
target project, or invoke package managers such as npm, pnpm, yarn, Go, Maven,
Gradle, Conan, or vcpkg. Do not add an execution step implicitly.

OSV is the only optional network path in a default security scan and receives
qualified package/version coordinates, not source text. Respect offline status
and never describe a skipped or incomplete security capability as safe.
PyPI, npm, Go, and Maven have OSV coordinate support. Conan and vcpkg currently
return an explicit unsupported-security diagnostic.

Treat yarn/pnpm locks, dynamic Gradle or Conan expressions, and unknown
Java/C++ namespace ownership as incomplete or low-confidence evidence. Do not
turn those limitations into confident removal, upgrade, or safety claims.

All MCP update tools are read-only. Never claim `plan_dependency_updates`
changed a manifest. Request explicit authorization before making source or
manifest edits outside these tools.

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
- Prefer `depcheck.scan.v1`, SARIF, or CycloneDX output when the result will feed
  another tool.
