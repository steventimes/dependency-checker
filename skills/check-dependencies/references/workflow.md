# Backend workflow

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
   Read scan `metadata.coverage` and context `coverage` for recognized uncovered
   paths and reasons. A repository selection does not establish coverage of
   every format; an empty gap list only concerns the recognized formats.
   A filtered index has `incomplete_reasons: ["index-selection"]`; it can answer
   within that selection but cannot describe the whole repository. Refresh
   without filters if the task needs broader coverage. Index refresh counters
   describe work performed, not total inventory: zero `parsed_manifest_files`
   does not mean there are no npm/Go/Maven/C++ dependencies.

   Before acting on findings, compare collected files with the project's manifests,
   ignored/generated directories, package scripts, and build/test configuration.
   Discovery excludes installed `site-packages`/`dist-packages` trees but does not
   interpret `.gitignore`. Use existing configured exclusions or an explicitly
   scoped snapshot to keep unrelated artifacts out; do not edit the audited
   project's configuration just to improve a trial result.

   Compare raw dependency-bearing manifests with the registered packs. Browser/CDN
   dependencies are not covered by the current scanners, even when
   `scope.repository_complete` is true.
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
   Nested declarations, resolutions, usages/imports, findings and impact files
   have their own `evidence_page.counts` and `next_offset`. Continue with a
   qualified explanation and `evidence_offset`/`evidence_limit` (1–100, default 20).
   In CLI use `--evidence-offset`/`--evidence-limit`. Main `next_offset` traverses
   dependencies; `inventory_truncated` and `evidence_truncated` distinguish them.
   Overall `truncated` can be true with a null main `next_offset`.
   The returned effective evidence limit may shrink to fit the 256 KiB response
   budget. A `response.budget-exceeded` error omits an oversized tool result;
   a scan/index may already have refreshed its cache. Inspect context and use a
   CLI scan exported to `.tmp/` when a full local report is needed.
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
   Read `origins` for paths from owning direct declarations to resolved versions
   and instances. `origin_limit` (1–100) and `origin_depth` (1–64) bound traversal.
   Missing/ambiguous edges, unrooted instances and truncation remain incomplete;
   an origin path does not establish installed activation, usage or security.
   For tool/command/configuration usage or policy exceptions, read
   [Usage and policy evidence](usage-and-policy.md) before interpreting those records.

7. `plan_dependency_updates` defaults to Python `requirements*.txt` version
   entries. For static PEP 621 dependencies, specify `target_file` and determine
   `group` first: `project` or `optional:NAME`. Omit group only when each requested
   package has one group. Report `update.ambiguous-target` rather than guessing.
   Unsupported targets return `update.unsupported-target`; invalid targets
   return `update.invalid-target`. Read both plans and diagnostics for partial
   results. Empty plans without diagnostics means no changes were needed.
   Previews never edit manifests/locks, apply upgrades, or establish compatibility.
   Select the owning Python project when multiple components exist. Read
   `handoff.status`, blockers, baseline coverage and source digests. `ready`
   permits a maintenance handoff; its validation checks still say `not-run`.
   Requested-together groups do not establish dependency coupling.

Treat Yarn application resolution, unsupported pnpm resolutions, dynamic Gradle or Conan
expressions, and unknown Java/C++ namespace ownership as incomplete or
low-confidence evidence. Do not
turn those limitations into confident removal, upgrade, or safety claims.

Non-literal Python module loads and unresolved npm `#` imports also leave
usage incomplete. Use a scoped npm mapping only when the alias's dependency
target is known; a `#` alias may point to a local file. Malformed manifests or
locks leave security incomplete even when the known versions have no findings.

All MCP update tools are read-only. Never claim `plan_dependency_updates`
changed a manifest. Make edits only within the user's authorized scope; a
preview-only request does not authorize applying the preview.
