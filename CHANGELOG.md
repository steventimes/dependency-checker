# Changelog

## Unreleased

- Separate shared evidence input, OSV advisory interpretation, Python metadata
  resolution, index preparation and ecosystem parsers into focused modules.
  Offline advisory reevaluation no longer constructs an HTTP session. CLI and
  MCP contracts, analysis revision 57 and index schema v4 are unchanged.

- Publish standalone JSON Schemas for scan, policy-input and provenance output
  through `depcheck schema`. Validate exported scan semantics before deriving
  policy or provenance evidence.
- Add page-local derivation references to explanations, qualified refresh plans
  to repository context and local read-work counters. These do not establish
  minimal proofs, active installations or source authenticity.
- Extend reproducible benchmark records and generated regression cases. Add
  paired benign/adversarial README consumer trials with separate task utility,
  observed exposure and side-effect results.
- Separate optional scan stages, update planning, SQLite query projections,
  report formats and policy evaluation. Keep CLI/MCP contracts and existing
  `depcheck.output` imports compatible. Group live MCP scenarios and consolidate
  scorer setup while retaining distinct regression assertions.
- Update architecture and test documentation. Clarify which features belong
  to the unreleased source checkout.

## 0.5.0 — 2026-10-18

[Release](https://github.com/steventimes/dependency-checker/releases/tag/v0.5.0) ·
[Changes since 0.4.0](https://github.com/steventimes/dependency-checker/compare/v0.4.0...v0.5.0)

This release expands the Agent Skill, CLI, and MCP backend with additional static
ecosystem evidence, bounded Python metadata resolution and explicit external
evidence operations. Analysis revision 57 and index schema v4 require rebuilding
older caches with `depcheck index .`. Python 3.11 or newer and uv 0.12.4 remain
the supported backend setup.

- Preserve base dependency constraints when resolving Python extras, including
  conflicts and backtracking across extra selections. Report unavailable marker
  contexts and unsupported comparisons as incomplete evidence; retain affected
  root declarations and avoid public metadata queries for unknown root selection.

- Separate offline OSV version matching from fix selection. Retain supported
  positive evidence, normalized versions and per-source reasons; qualify missing
  ranges and reject unsupported schema majors. Accept package-less Git assertions
  without promoting them to package identities. Preserve submicrosecond withdrawal
  ordering and keep unrelated packages out of matching completeness.

- Add bounded Python metadata backtracking with explicit resolution outcomes,
  extras/interpreter constraints and explicit development/optional group selection.
- Keep PEP 723 script requirements in independent source and index scopes.
- Add explicit offline OSV reevaluation and supplied security/call/runtime/artifact
  evidence inspection, including native govulncheck streams, CVE/CWE, OpenVEX,
  in-toto, deps.dev and Scorecard records.
- Add Python callable propagation over selected source/module maps, package-script
  and inventory comparisons, explicit registry checks and unsigned provenance and
  policy exports. Preserve incomplete evidence and separate external assertions.
- Retain raw SBOM component assertions with field completeness profiles; add
  opt-in local inclusive work measurements without telemetry.

### Evidence and diagnostics

- Close SQLite fixture connections explicitly after their transactions so native
  Windows filesystem checks do not fail on handles retained by the tests.
- Inspect explicitly selected CMake File API codemodel v2 replies through the
  CLI and read-only MCP tool. Retain configuration/target identities, abstract
  and imported flags, separate relationship kinds, source assertions, input
  hashes and paginated tables. Qualify invalid details, version disagreements
  and budgets without executing commands, reading source paths or changing
  the index. Source freshness and build execution remain unknown; package
  mapping and security remain unsupported/skipped. This additive external
  projection does not change the source index tables or package version.
- Collect bounded literal Rust crate references with Cargo alias candidates,
  Unicode positions and explicit conditional/unknown scope. Skip comments and
  literals; preserve unknown owners for known shadows and conflicting origins.
  Keep module/target selection, macros, generated code and compiler bindings
  unknown, with no missing/unused/scope advice from inferred references.
  Validate exact Cargo lock versions using Rust SemVer rules while preserving
  legal prereleases and build metadata. Analysis revision 54 invalidates older
  cached evidence; existing index tables and package version are unchanged.
- Normalize Python import and dynamic-load columns from AST UTF-8 byte offsets
  to Unicode code points, including decoded notebooks and coding-cookie sources.
  Preserve universal line boundaries and readable neighbors of invalid Unicode
  cells. Declare SARIF column/newline units; keep notebook virtual coordinates
  as qualified properties alongside file-only physical locations. Analysis
  revision 53 refreshes cached positions without changing index tables.
- Preserve SARIF diagnostic locations and symbolic source-root bases. Keep
  explicit outside-root files distinct; use only a matching project's manifest
  as a fallback, and qualify unavailable locations without fabricating `.`.
  Share the existing scan summary directly so SARIF projection does not resolve
  source paths or serialize unrelated inventory. Analyzer evidence is unchanged.
- Collect Yarn Modern format 8/10 lock assertions in independent physical
  inventory scopes. Preserve descriptor multiplicity, aliases, record positions,
  locator/version assertions and conditional context through queries and SBOM.
  Keep application/workspace ownership, registry selection, PnP, peer instances,
  installation, and source usage unknown. Add no public advisory coordinates or
  application edges; qualify unsupported formats, malformed records and budgets.
- Validate exact npm/pnpm lock versions with the existing `semver` parser and
  node-semver's text/numeric bounds. Keep malformed versions out of public
  advisory queries without losing readable neighbors, valid prereleases or
  build metadata.
- Preserve npm and pnpm registry/source assertions and bounded repository
  `.npmrc` evidence. Exclude known non-public or unknown instances from public
  vulnerability queries and prevent same-version public findings from spreading
  to private instances. Keep origins through indexing and exports, omit
  authentication settings from new metadata and invalidate changed configuration.
- Preserve CVE identifiers and provider-reported CWE classifications with
  official lookup links and per-source provenance in JSON, SARIF and text.
  Qualify absent, malformed and bounded metadata without dropping matched
  vulnerabilities or adding network requests. Keep alias-group source evidence.
- Group active OSV aliases within each exact dependency identity to avoid
  counting provider IDs as separate vulnerabilities. Preserve member IDs,
  source metadata, severity assertions and policy matching. Compare fix
  candidates against all usable sources; keep unavailable, unconfirmed and
  over-budget results qualified. Related/upstream records remain separate.
- Refresh OSV details against querybatch revision timestamps without truncating
  nanoseconds. Do not reuse stale details after a failed refresh or use missing
  revision hints to authorize cross-call reuse. Exclude effective withdrawals
  with an audit diagnostic; keep future withdrawals and active alias records.
- Select OSV fix candidates relative to each queried version and all matching
  affected ranges, instead of choosing the lowest fixed version across branches.
  Support SemVer ranges with `semver`, retain raw fixed boundaries and qualify
  unsupported or unknown fixes. Keep batch matches when malformed detail data
  cannot supply a fix; preserve diagnostics and readable neighboring advisories.
- Retain bounded uv lock environment, fork and dependency/extra/group assertions
  in indexed source origins and CycloneDX properties. Keep physical lock entries
  distinct, qualify selection and avoid treating alternative versions as one
  installed-environment conflict or seeding flat compatibility suggestions.
  Public version advisory matches retain their lock context and unknown activation.
- Preserve parsed PURL qualifiers and subpaths in external SBOM identities, with
  explicit incomplete states for dimensions beyond the local package/version
  profile. Use `packageurl-python` without folding npm/Go casing or silently
  discarding duplicate qualifiers, invalid namespace shapes or dot subpaths.
  Unsupported types retain their parsed assertions without ecosystem mapping.
- Collect legacy Cargo development/build dependency sections with positions and
  raw section provenance. Apply literal edition and canonical-table precedence,
  including inherited editions and the `[project]` package alias. Keep ignored or
  rejected requests as configuration inventory without direct lock associations;
  unknown editions retain a manifest gap. Active target/feature selection remains
  unknown; literal Rust crate-reference candidates are collected separately.
- Match unordered evaluator expectations against distinct recorded calls using
  both arguments and results. Reverse-order explanations for different projects
  and overlapping expectations no longer fail through greedy result pairing.
- Add bounded literal Bzlmod `bazel_dep` inventory in separate MODULE.bazel scopes,
  retaining version requests, aliases, development conditions and source positions.
  Keep extensions, overrides, includes and unknown arguments qualified; expose
  uncollected Bazel locks, WORKSPACE, BUILD and `.bzl` paths. Do not infer selected
  versions, source ownership, activation, application edges or security coordinates.
- Collect literal CMake `find_dependency` assertions and `*.cmake.in` inputs in
  their lexical project/script scopes. Preserve positions, repeats, raw dynamic
  arguments and template provenance. Retain explicit gaps for substitutions and
  injected/generated code without executing CMake or inferring installation.
  Template additions, changes and removals invalidate cached evidence.
- Collect legacy `tool.uv.dev-dependencies` as positioned development declarations
  alongside the standard `dev` group. Append them after standard include expansion,
  preserving uv's non-inheritance behavior, markers, extras and source assertions.
  Invalid tables/entries retain diagnostics and readable siblings; shared group
  budgets apply without inferring installation or enabling update previews.
- Check Python development-group constraints within their declared group and
  retain group-local conflict details. Keep incompatible cross-group/runtime
  requests incomplete while installer selection is unknown. Preserve analysis
  diagnostics through indexing and include project errors in query completeness.
- Match PEP 735 dependency-group names after normalization, reject ambiguous
  names and non-exact include tables, and preserve ordered repeated includes
  through collection and indexing. Distinguish repeated expansion from duplicate
  physical declarations. Bound expansion entries, context and diagnostics;
  cycles and missing/invalid targets retain explicit gaps.
- Collect positioned Gradle TOML catalog library definitions in separate
  configuration scopes. Preserve aliases, local version references, rich
  constraints and repeated bundle memberships without build binding, selected
  versions or source-usage claims. Search aliases before evidence pagination;
  unsupported shapes, ambiguous references and bounded expansion retain gaps.
- Ignore C/C++ include examples inside comments and quoted/raw strings. Preserve
  physical positions across standard line splices and retain conditional includes
  with unknown activation. Macro operands, compiler-dependent translation and
  malformed/budget-limited input leave gaps rather than confident hygiene advice.
- Collect bounded positioned Gradle Groovy/Kotlin configuration calls, including
  multiline and versionless notation, wrappers, classifiers and lexical contexts.
  Ignore comments/documentation strings and keep source versions as requests.
  Preserve configuration-qualified repeated project/buildscript lock instances
  without choosing an active build or installed graph. Inventory both DSL build
  files; expose settings/helper/catalog gaps and exclude Gradle Kotlin scripts
  from application imports. Unknown syntax and lexer/context budgets stay qualified.
- Collect literal Go `tool` directives as positioned build configuration usages.
  Preserve repeated directives, indirect requirement ownership and unknown owners
  without execution or installation claims. Required modules nested under the
  main module path and local replacement modules without domain names retain
  configured ownership. Bound configuration evidence and preselect namespace
  candidates once per collection.
- Preserve Go minimum requirements and replacement/exclusion origins with literal
  token positions. Retain repeated archive/module-file checksum assertions and
  CycloneDX properties without selected versions, verified integrity or direct
  application edges. Keep MVS/workspace/vendor selection and security incomplete;
  version-specific replacements do not select a target from a minimum. Qualify
  uncollected directives and bound metadata expansion.
- Compare declaration metadata in scan snapshots, including checksum-only
  changes, while preserving read-only and unverified-remediation semantics.
- Collect Maven build/reporting plugin definitions, management and plugin
  dependencies as conditional build configuration with positions, declaring
  property context, inheritance and execution/profile assertions. Keep effective
  plugin selection and execution unknown; plugin classpath does not establish
  application dependencies. Bound XML nodes before DOM allocation and qualify
  uncollected extensions/profile dependencies and metadata expansion.
- Resolve bounded Maven directory parent paths and both separator forms. Keep
  implicit lifecycle/build resolution unknown, and let evaluation cases opt out
  of arbitrary call ordering without losing required-call/result checks.
- Collect vcpkg feature dependency lists as conditional inventory with positions,
  default/support assertions and host/self-feature context. Keep activation,
  installation and removal conclusions unknown; preserve repeated groups in
  queries and CycloneDX without adding direct application edges. Invalid scopes
  and bounded context expansion leave explicit gaps.
- Retain Conan/vcpkg declaration and supported JSON inventory locations, Conan
  lock contexts and repeated instances. Preserve recipe revision assertions and
  keep version ranges unresolved.
- Qualify C/C++ build selection and installation. Distinguish native vcpkg
  registry locks from supplied dependency inventory; preserve root dependency
  conditions, feature assertions, minimum versions and override origins.
- Report ambiguous vcpkg overrides.
  Incomplete manifests no longer support unused-dependency findings. Bound JSON
  location traversal, discard replaced subtrees and keep budget-limited spans file-only.
- Recognize GoogleTest-style C/C++ `*_unittest` filenames as test scope,
  avoiding runtime scope mismatches for test-only dependencies. Build-target
  membership remains unknown.
- Preserve declaration positions in TOML, npm JSON, and Maven XML through
  indexing and explanations. Group includes and inherited Maven dependencies
  retain their original source locations.
- Locate invalid requirements and JSON entries, JavaScript lexical uncertainty
  and dynamic loads, and unresolved namespaces. Diagnostics retain project
  context and bounded examples without upgrading uncertain evidence.
- Separate named independent Python components and their sources, locks and
  command evidence. Keep anonymous/shared-workspace scopes qualified and preserve
  component-root scans.
- Collect bounded literal package scripts and GitHub Actions commands with
  configuration provenance, separately from imports and configured tool usage.
- Report unparsed stylesheet formats and recognized unsupported manifests in
  coverage metadata; include their changes in index freshness checks.
- Add Cargo manifests and v3/v4 lock inventory with workspace inheritance,
  source-qualified instances, conditional metadata, safe links, OSV coordinates
  and CycloneDX components. Compiler-resolved Rust usage and active lock selection
  remain unknown.
- Retain rejected symlink diagnostic locations without following outside files.
- Reject default-cache aliases and hard-linked databases before opening SQLite,
  preventing refresh from modifying other files inside the selected root.
- Bound legacy Python, configuration, preview, and hashing reads to complete
  regular-file snapshots. Pin directory handles across content operations and
  isolate default SQLite work from repository journal/sidecar paths.
- Preserve Python source encodings, CRLF previews, in-root manifest aliases,
  stable repository-root aliases, and search-only ancestor access on platforms
  that expose search-only directory handles.
- Collect literal Astro frontmatter/script/style imports and CSS `@import`
  targets with npm alias mapping and source positions. Keep template expressions,
  browser imports, external URLs, and unsupported CSS syntax incomplete.
- Keep default SQLite snapshots and temporary storage in memory, preventing
  temporary-directory replacement from redirecting queries or refreshes.
- Classify CSS imports as build usage when the owning project declares a
  supported build tool and has its configuration file. Otherwise preserve
  unknown scope without a runtime scope-mismatch finding.
- Preserve ambiguous npm/pnpm/Yarn lock selection as incomplete resolution;
  apply npm's shrinkwrap precedence when only npm lock formats are present.
- Collect literal TypeScript JSONC and pytest plugin configuration evidence with
  source locations and uncertainty diagnostics.
- Check workspace membership and closer pnpm boundaries before inheriting locks.
- Add read-only scan comparisons and external CycloneDX JSON inspection through
  CLI and MCP, with pagination, source digests and qualified completeness.
- Attach component-scoped maintenance handoffs to update previews, preserving
  blockers and checks that have not run. Reject aliased service preview targets.
- Reject orphaned legacy Python configuration scopes after component splitting,
  with the owning project IDs in the error. Preserve caches on failed refreshes.
- Reject malformed or duplicate SBOM application references before building edges.
- Preserve external SBOM component types, CycloneDX scopes, repeated source
  properties and license assertions. Distinguish Trivy dependency groups from
  packages without inferring direct ownership from group membership.
- Add bounded origin paths through qualified lock instances in explanations and
  impact queries, with direct declaration locations and incomplete graph states.
- Add advisory ID/alias and exact-version policy exemption selectors, retaining
  raw findings and inventory and rejecting invalid selectors.
- Support explicit repository IDs for snapshot comparison across checkouts.
- Add explicit anonymous Python component scopes and separate uv member source
  ownership while keeping shared environment activation unknown.
- Collect literal Vue/Svelte script/style imports while retaining template,
  implicit framework and compilation gaps.
- Preserve Python source assertions through parsing, index reuse and SBOMs;
  skip public registry security/compatibility checks for unverified sources.
- Page nested evidence independently, preserving full impact counts and explicit
  truncation. Bound MCP responses to 256 KiB and report oversized results.
- Validate observed Agent pagination and qualified explanations, and classify
  known forbidden command forms from execution events.
- Map GoogleTest and GoogleMock headers to Conan/vcpkg `gtest` and recognize
  C/C++ `*_test` source files as test scope.
- Collect CMake FetchContent/find-package configuration inventory with source
  positions, raw options, repeated declarations and unknown activation. Keep
  availability requests separate from execution and package-manager coordinates.
- Ignore commented CMake package hints and support multiline calls in C++ packs.
- Inventory standalone `.cmake` script trees under distinct identities without
  duplicating nested project inputs. Track all owned configuration files and
  retain unknown entry points, execution order and activation.
- Match CMake package names case-insensitively and expose uncollected CPM
  dependency calls as positioned coverage gaps.
- Add a qualified CMake consumer evaluation and classify known CMake configure/build
  attempts alongside package-manager actions in the recorded command checks.
- Preserve structural declaration positions in Pipfile, Python locks, setup.cfg
  and literal setup.py sequences; qualify unmatched/interpolated locations.
- Preserve Pipenv private and ambiguous index identities, report invalid INI
  interpolation and reject duplicate Pipfile.lock keys.
- Invalidate old cached evidence with analysis revision 57 and schema v4.
  Queries remain read-only; indexing rebuilds incompatible derived caches.

### Performance

- Reuse scan evidence for index publication after checking read digests and
  topology controls. Explanations validate index freshness once per operation.

- Avoid selected-evidence reparsing during unchanged queries, checking file
  contents, topology and ownership controls before reusing the indexed result.
  Changed controls/topology fall back to a full selected scan.

- Reduce path-component work during file discovery and index freshness checks,
  preserving symbolic-link resolution and repository containment.

### Documentation

- Distinguish the published 0.4.0 bundle from current source capabilities and
  correct outdated coverage limits, cache revisions and maintenance records.
- Split the Skill's backend, transport and ecosystem details into linked references.
  Keep shared boundaries and reporting rules in the entrypoint so focused tasks
  can load the relevant guidance. Include references in copied or bundled Skills.
- Describe the Agent Skill workflow and backend setup in the README.
- Document completeness fields, compiled requirements locks, component scope,
  unsupported usage, and Maven inventory limits.
- Add repository maintenance guidance and priorities for the next updates.
- Connect static audit evidence to separately authorized package-manager updates,
  with baseline, lockfile, migration and verification handoff requirements.

## 0.4.0 — 2026-10-07

[Release](https://github.com/steventimes/dependency-checker/releases/tag/v0.4.0) ·
[Changes since 0.2.0](https://github.com/steventimes/dependency-checker/compare/v0.2.0...v0.4.0)

### Added

- The `check-dependencies` Agent Skill and plugin/MCP descriptors, backed by a
  shared CLI and scanner.
- Static dependency evidence for Python/PyPI, JavaScript/TypeScript/npm, Go,
  Java/Kotlin/Maven or Gradle, and C/C++/Conan or vcpkg.
- Seven MCP tools for context, indexing, offline hygiene scans, inventory,
  explanations, impact, and update previews.
- A SQLite evidence index, qualified package identities, pagination, and
  explicit evidence and usage completeness.
- JSON, SARIF, and CycloneDX output, optional OSV checks for supported ecosystems,
  and scoped policies and tool-usage declarations.
- Read-only version previews for requirements text and static PEP 621 groups.

### Fixed

- Installed Python directories no longer pollute source and manifest discovery.
  Sibling modules in `if __package__` script fallbacks retain local ownership.
- Compiled requirements locks retain exact versions and requirement markers from
  hashed entries. Docker pip hints stop at shell separators.
- Frontend test/build files retain their scope. Unsupported Astro, Vue, and
  Svelte components leave usage evidence incomplete.
- Literal Maven child declarations survive a mismatched local parent. Unknown
  inherited versions remain unresolved instead of producing unpinned findings.
- Independent Python components no longer produce cross-component duplicates;
  their shared analysis scope is reported as ambiguous.
- Lock/component changes invalidate indexes, and analysis changes reparse cached
  Python usage.
- Git/GitNexus metadata queries use an empty input stream, fixing the Windows
  MCP request stall caused by inherited protocol input.

### Compatibility and validation

- Python 3.11 or newer is required. Bundled MCP launchers use uv 0.12.4.
- The CLI uses subcommands. Update scripts that use the 0.2 flags or removed
  Python module paths, and rebuild incompatible derived indexes.
- The release baseline passed 301 tests on Python 3.11 and 3.12, plus all six
  [CI jobs](https://github.com/steventimes/dependency-checker/actions/runs/37683267157),
  including MCP and installed-wheel checks on Ubuntu, macOS, and Windows.

## Earlier releases

- [0.2.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.2.0)
- [0.1.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.1.0)
