# Dependency Checker maintenance

Read applicable parent AGENTS.md instructions and [README.md](README.md). Preserve
existing work. Keep reports, caches, benchmark output and raw trial material in
`.tmp/`; exclude them from commits and release bundles. Commit, push and publish
only within the user's requested scope.

## Current baseline

The project is an Agent Skill with an MCP server and CLI backend. The published
release is [0.5.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.5.0),
selected on 2026-10-18. Source and plugin metadata use 0.5.0, analysis revision 57
and index schema v4. Do not bump the package version before another release is
selected. The source checkout includes changes since that release. See
[Unreleased](CHANGELOG.md#unreleased) for changes awaiting the next release.

Historical implementation and verification records remain under `.tmp/`.
`.tmp/implementation-report-20261018.md` is archived. Continue the active record
in `.tmp/implementation-report-20261019.md`; do not create parallel progress or
design documents. Historical test counts and CI results do not verify current
source. Report local checks, remote CI and published artifacts separately.

## Implementation boundaries

- Parse target repositories as bounded data. Do not import target code, evaluate
  setup/build files or execute package managers to improve static evidence.
- Preserve incomplete, skipped, unsupported and ambiguous states. Missing
  coverage, unknown versions and zero observed usages need qualified reporting.
- Keep queries and update previews read-only. Index/scan MCP tools can replace
  the derived cache; their annotations and the Skill must state that side effect.
- Resolve helper executables outside the audited repository. Keep metadata
  subprocesses non-interactive with `stdin=subprocess.DEVNULL`.
- Evidence semantics changes require an `analysis_revision` update in
  `depcheck/model.py`. Table changes require an index schema/rebuild decision in
  `depcheck/indexing/models.py` and `store.py`. Pure internal refactors retain
  the current revision and schema when their evidence is unchanged.
- Keep backend version markers consistent in `pyproject.toml`,
  `depcheck/_version.py`, both plugin descriptors and the lockfile at release.
- Keep repeated declarations, physical lock instances, origin assertions and
  source locations distinct. Retain file-only locations when spans are unknown.
- Public registry queries require supported, verified public coordinates.
  Private, local, ambiguous or unknown sources must not become public identities.
- External SBOM, security, call, runtime and build records remain supplied
  assertions. Input hashes do not authenticate producers, establish source
  freshness, installation, exploitation or ABI/API compatibility.
- CMake File API inspection reads an explicitly selected existing codemodel v2
  reply without configuring or building. Preserve configuration/target identities,
  relationship kinds, assertions and JSON-pointer provenance. Build execution
  stays unknown, package mapping unsupported and security skipped.

## Module responsibilities

Use the [architecture map](README.md#architecture) when changing shared code.

- `engine.py` coordinates discovery, collection and optional stages. Security
  and compatibility scan projections live in their respective `scanning.py`
  modules. Clients are selected by the scanner and passed into those stages.
- `agent/service.py` is the common CLI/MCP application interface. Keep root
  authorization, result limits and public method parameters there. Update
  preview discovery and maintenance handoffs live in `update_planning.py`.
- `indexing/store.py` owns connections, staging, transactions and publication.
  `indexing/queries.py` reads from an existing connection and does not open or
  commit databases. Keep input freshness and transaction checks in the indexer.
- `output.py` retains text/JSON rendering and compatible public imports. SARIF,
  CycloneDX and exemption policy have separate modules. Report projections must
  preserve captured evidence and must not reopen source paths.
- `evidence_input.py` owns shared bounded input mechanics. Format inspectors
  depend on it; it must not depend on individual formats or transport modules.
- Keep pure OSV advisory interpretation independent of HTTP. Keep parsers
  independent of CLI/MCP transport. Prefer existing modules over new forwarding
  layers, dynamic dispatch frameworks or duplicated validation rules.

## Remaining analysis priorities

Address one coherent scope at a time and preserve qualified limitations.

1. Improve remaining legacy manifest and lock positions without merging repeats
   or inventing spans. Preserve inherited origin and component identities.
2. Extend Python installation evidence and uv member ownership conservatively.
   Shared lock activation and cross-member availability remain unknown.
3. Extend bounded build/plugin/command evidence where ownership is known.
   Separate configuration, source imports and execution. Maven effective merges,
   lifecycle/profile activation and runtime use remain uncollected.
4. Expose unsupported manifests and source formats. Keep Rust compiler binding,
   framework template/implicit imports, SCSS/Sass and browser/CDN dependencies
   qualified. Preserve environment and variant conditions in lock evidence.
5. Measure discovery, hashing, parsing, storage and queries before optimizing
   cache reuse. Use `scripts/benchmark_monorepo.py` with recorded parameters and
   runtime. Compare inventory, diagnostics and completeness with timings. Keep
   baselines in `.tmp/`; do not change CI thresholds without evidence.

Current coverage and format-specific limitations are documented in the README
and `skills/check-dependencies/references/`. Treat those as the current feature
map rather than the older dated iteration notes.

## Verification

Start with `git status --short --branch` and inspect the affected interfaces.
Finish the complete agreed implementation scope before concentrated verification.
Prefer realistic upstream fixtures, cross-module scenarios and consequential
boundaries over mechanical field tests. Reuse the five existing modules under
`test/`; consolidate setup without weakening independent assertions.

Run the README Development commands for runtime changes, including the offline
MCP contract runner. Changes to stdio, roots, metadata subprocesses or packaging
need Ubuntu/macOS/Windows build checks. Local Linux results do not replace
native platform or remote CI checks.

For documentation changes, verify local links and run changed command examples
against temporary fixtures. Do not add tests that compare documentation text
with itself. Keep the full Skill tree in bundles and validate its relative links.

The Skill entry is `skills/check-dependencies/SKILL.md`. Keep shared constraints
and reference routing there. Update the applicable reference when a tool contract
or coverage rule changes. The evaluation directory separates live MCP checks,
recorded agent trials and synthetic scorer fixtures. Synthetic traces do not
establish observed agent behavior, and public product material does not establish
vendor accuracy or internal behavior.

## Reference records

The user reference catalog and per-entry status are in [REFERENCES.md](REFERENCES.md).
The 2026-10-18 review read 26 supplied papers in full and reviewed the remaining
public entries. The following round read nine more scoped papers, recorded in
`.tmp/implementation-20261019/papers/`. Preserve the reading ledgers and archived
reports when deleting reproducible environments or caches.

Dependency-Track and Xerj were initially list-only references, then reviewed as
public overviews on 2026-10-18. Those reviews did not deploy either project or
upload data. Any later machine-wide installation has its own authorization and
verification; it does not change this repository's recorded review scope.
