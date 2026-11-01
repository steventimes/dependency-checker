# Changelog

## Unreleased

No changes recorded after the 0.6.0 release line.

## 0.6.0 — 2026-11-01

This release uses analysis revision 88, index schema v8 and nineteen MCP tools.
Rebuild older indexes with the matching backend. The entries below retain their
implementation-time revision history; those historical 0.5.0 references describe
unreleased source work, not separate published packages.

- Reorganize ecosystem tests and Cargo workspace, override and lock collection
  without changing evidence semantics. Merge duplicate Go invalid-manifest
  setup while retaining all nine cases.
- Separate representative daily CI from explicitly selected full compatibility
  qualification, retaining native OS, installed-wheel and Skill bundle checks.
- Include the two repository guidance resources referenced by AGENTS, and keep
  the original Ambient build-crate manifest in the source distribution.

- Add opt-in `depcheck compare --fail-on-changes` for script exit status based
  on all observed changes, including those outside the current page.

- Add `depcheck compare --format text` for paged terminal summaries of saved
  scan comparisons. JSON remains the default; both retain comparability and
  incomplete-evidence diagnostics.

- Preserve each project's capability state and reason in index context, while
  retaining the existing `complete` boolean. Analysis revision is 88 and index
  schema is v8; rebuild older indexes before querying them.

- Collect `setup.cfg` setup/test requirements with build and development scopes,
  preserving literal positions, duplicates, markers and extras. Share the fixed
  field/group mapping with the existing static `setup.py` reader and keep one
  interpolation budget across runtime, build, test and extras. Unsupported
  directives remain diagnosed without execution. Analysis revision advances to
  87; package 0.5.0 and index schema v7 stay unchanged.

- Accept relative requirements includes through parent directories when the
  normalized target remains inside the selected repository root. Preserve root
  and symlink escape refusal, absolute-path policy, include limits, source
  positions and direct/constraint roles. Analysis revision advances to 86;
  package 0.5.0 and index schema v7 stay unchanged.

- Capture explicit Maven profile library and management declarations as
  conditional inventory, retaining repeated rows, profile conditions, declaring
  positions and raw requests. Keep profile properties and effective merging
  unevaluated; conditional management does not resolve unconditional versions,
  satisfy Java imports or enable public advisory queries. Analysis revision
  advances to 85; package 0.5.0 and index schema v7 stay unchanged.

- Collect explicit Maven build extensions as conditional build evidence with
  declaring-POM ownership, source positions, version requests and raw
  scope/type/classifier fields. Keep activation, inheritance, installation and
  public origin unknown; do not merge parent extension configuration or infer
  application dependencies. Analysis revision advances to 84; package 0.5.0
  and index schema v7 stay unchanged.

- Capture explicit Maven compiler `annotationProcessorPaths` as conditional build
  evidence with processor classpath, owner plugin, source positions and inherited
  context. Keep processors separate from application dependencies, installed
  versions and public advisory coordinates. Arbitrary plugin configuration and
  lifecycle/profile execution remain uncollected. Analysis revision advances to
  83; package 0.5.0 and index schema v7 stay unchanged.

- Retain repeated Maven dependency and management declarations from the nearest
  declaring local POM, including their physical source positions. Keep explicit
  dependency versions ahead of management defaults and preserve unknown external
  parent/BOM versions. Repeated declarations do not establish extra installations.
  Analysis revision advances to 82; package 0.5.0 and index schema v7 stay unchanged.

- Mark uncollected `setup(**kwargs)` keyword expansions as incomplete instead
  of reporting an empty, complete manifest. Retain explicit literal arguments
  and diagnostic positions without executing target code. Add a pinned original
  scikit-learn setup fixture with its license. Analysis revision advances to 81;
  package 0.5.0 remains unchanged. Index schema v7 separates source and manifest
  file digests so setup.py can occupy both roles without an indexing collision.
  Existing read-only queries reject older caches; indexing rebuilds them.

- Preserve independently locked Python records when a same-name direct
  declaration is excluded by the requested Python version. A transitive
  dependency can still reference that lock record. Continue evaluating each
  record's own marker; lock presence does not establish installation or active
  selection. Analysis revision advances to 80; package 0.5.0 and index v6 remain
  unchanged.

- Reuse bounded TOML source-position parsing within a scan, while rereading and
  validating every input. Limit reuse to four captured path/text entries and
  discard it at scan exit. Larger inputs are still fully parsed. Preserve
  member evidence, diagnostics and freshness; package, analysis revision and
  index schema stay unchanged.

- Preserve TOML boolean syntax items and dotted-key parent positions, including
  Cargo workspace declarations previously located only to a file. Keep explicit
  headers, repeated occurrences and inherited root provenance distinct. Use an
  iterative syntax walk and retain file-only fallback when positions are
  unavailable. Analysis revision advances to 79; package 0.5.0, index v6 and
  19 tools remain unchanged.

- Match explicitly supplied RubyGems inventories and CycloneDX `pkg:gem`
  coordinates against OSV records using bounded native Gem::Version ordering,
  normalized equality and forward fix candidates. Preserve unknown private,
  qualified and incomparable inputs. Retain pinned original ordering tests and
  MIT attribution. Correct the existing lodash-rails advisory corpus miss;
  Gemfile collection and online RubyGems scanning remain uncollected. Analysis
  revision advances to 78; package 0.5.0, index v6 and 19 tools stay unchanged.

- Read bounded native PEP 751 v1.0 pylock inventories with Packaging's structural
  validator. Preserve physical occurrences, unknown source-tree versions,
  artifact/condition assertions and informational record selectors without
  choosing an environment or creating required installation edges. Add original
  pip fixtures with license and provenance. Raise the Packaging minimum to the
  already locked 26.3; all locked package versions remain unchanged. Analysis
  revision advances to 77; package 0.5.0, index v6 and 19 tools stay unchanged.
  Discover default and named files, including lock-only Python components and
  selected scans. Track additions, changes and removals in index freshness;
  unsupported format versions retain explicit coverage diagnostics.

- Read supplied native pip installation reports through the existing evidence
  interface. Keep selected records, download information, extras and yanked flags
  separate from installed state and public package identity; reports may describe
  dry-runs. Reuse the bounded pip report reader and validate real installation
  reports during wheel smoke checks. Reject credential-bearing field names in
  either native report without echoing them. Analysis revision advances to 75.

- Keep malformed, colliding and over-budget uv source tables unverified instead
  of falling back to public PyPI. Share bounded source interpretation between
  root and workspace declarations, retain conditional alternatives without host
  selection, and omit unsupported details with content fingerprints. Preserve
  declared origins separately. Analysis revision advances to 74; package 0.5.0,
  index schema v6 and 19 tools remain unchanged.
- Capture bounded uv project index configuration, including legacy index URLs
  and uv.toml precedence. Start workspace lookup at the root, preserve config
  locations and unknown selection, and keep uv pip settings separate. Private,
  invalid and over-budget configuration cannot establish public PyPI identity.
  Selected member caches track config changes. Analysis revision advances to 73;
  package 0.5.0, index schema v6 and 19 tools remain unchanged.
- Inherit uv workspace root source and index assertions in member declarations.
  Respect whole-entry member source overrides, including conditional ones, and
  retain source positions and relative path bases. Ambiguous membership, invalid
  tables and exhausted budgets stay unverified without public PyPI queries.
  Keep lock-only registry fields in uv source tables unverified; actual lock
  registry assertions retain their classification. Shared lock activation remains
  unknown. Analysis revision advances to 72;
  package 0.5.0, index schema v6 and 19 tools remain unchanged.
- Add opt-in offline KEV JSON and EPSS CSV/gzip context to vulnerability
  reevaluation. Validate complete supplied snapshots, retain explicit stale
  fallback, dates, model, source hashes and missing states, and associate only
  existing CVE IDs or OSV aliases. Probability and percentile remain separate;
  these assertions do not alter matches, severity or exploitation conclusions.
  Analysis revision advances to 71; package 0.5.0, schema v6 and 19 tools remain.
- Bind Python direct declarations to unique compatible public lock occurrences
  using version constraints and captured Pipenv categories. Preserve ambiguous,
  private and over-budget bindings as unknown without merging occurrences or
  changing advisory coordinates. Retain binding metadata in caches and exports.
  Analysis revision advances to 70; index schema v6 and package 0.5.0 remain.
- Retain workspace-root Cargo patch/replace assertions in member views. Keep
  potentially affected source bindings and directness unknown, preserve explicit
  version contradictions, and report ignored member-local overrides. Bound and
  redact override details without changing raw lock instances or public source
  eligibility. Analysis revision advances to 69; index schema v6 and package
  version 0.5.0 remain unchanged.
- Support Python 3.15 in the test matrix and Ubuntu/macOS/Windows build checks.
  Require Pydantic 2.14 or newer for agent/test extras on 3.15 and retain lazy
  import references without executing them. The Python 3.11 minimum remains.
- Preserve Pipenv custom categories, repeated lock occurrences and bounded
  marker, extra and source context through scans, caches and exports. Flat
  Pipenv locks do not establish dependency edges or active category selection.
  Preserve conditional lock metadata in compatibility scans. Analysis revision
  advances to 68; index schema v6 and package version 0.5.0 remain unchanged.

- Keep repeated Poetry and PDM lock rows, groups and extras as separate source
  assertions. Preserve uv lock origins alongside declaration overrides, and bind
  only unconditional, uniquely identified Python lock dependency edges. Qualified
  omissions and conditional selection remain incomplete.
- Apply captured private index policy to default-source transitive Python lock
  rows. Conditional lock inventories cannot seed a flat compatibility graph;
  source-qualified known versions remain eligible for advisory matching.
- Retain Cargo lock source qualification across canonical reports, index queries
  and CycloneDX. Match Git dependency references without their target's precise
  commit fragment while preserving query/revision distinctions and ambiguity.
  Redact credentials in lock identities and declaration output.
- Add seven pinned Python/Cargo project corpora with original inputs, licenses,
  independent inventory labels and selected advisory boundaries. Analysis
  revision advances to 67 and index schema v6 preserves Python requirement
  metadata across incremental refreshes. Queries reject older caches without
  changing them; explicit indexing rebuilds the derived data. Package version
  0.5.0 remains.

- Add five unmodified Bitnami and Hackage advisories with licenses and independent
  package-level severity labels. Corpus checks retain unsupported version states
  and distinguish source scores from public registry eligibility.

- Preserve package-level OSV severity with source pointers, package coordinates
  and version applicability. Keep uncertain or conflicting scopes qualified,
  retain raw assertions and bound score projections without erasing CVE matches.
  Alias groups preserve each source's scope and incomplete metadata. These
  assertions do not change vulnerability policy levels or calculate CVSS scores.

- Match supplied Go module versions against OSV `ECOSYSTEM` ranges. Normalize
  Go's optional leading `v` consistently in version lists and fix comparisons,
  while keeping `SEMVER` boundaries strict. Add a fifth pinned upstream advisory
  and independent Go boundary labels to the existing offline corpus gate.
- Keep fix candidates unknown when same-package affected entries lack version
  evidence, including alias groups. Preserve supported vulnerability matches
  and raw fixed boundaries instead of presenting an unconfirmed fix.

- Retain npm lock context separately from identity, origin and required edges:
  optional and peer requests, platform restrictions, and dependency-tree flags
  remain supplied assertions with unknown activation. Respect optional overrides
  without letting shadowed requests change the effective identity or origin.
- Preserve resolution metadata in scan JSON, index queries, CycloneDX and offline
  observations. Snapshot and inventory comparisons expose context-only changes.
  Index schema v5 adds resolution metadata; rebuild older caches explicitly.
- Keep legacy origin qualification consistent across canonical and CycloneDX
  inventories. Private or null legacy origins stay unknown unless an explicit
  origin assertion takes precedence.

- Resolve legacy npm dependency edges from `requires` assertions, including
  hoisted instances. Keep physical nesting separate from dependency edges;
  missing assertions and conflicting explicit aliases leave qualified gaps.
- Evaluate two pinned historical npm projects from their original manifests
  and locks through inventory, offline advisory matching and CycloneDX
  round trips. Keep selected CVE labels and a synthetic registry variant
  separate from unlabelled inventory and general accuracy claims.
- Preserve captured manifest origins in CycloneDX components without locked
  versions. Conflicting origin assertions remain ambiguous and retain their
  evidence without a public PURL.

- Reject exponent overflow and lone Unicode surrogates in shared JSON inputs
  and OSV responses, including successive-object evidence streams. Preserve
  supported byte encodings, valid non-BMP text and manifest duplicate-key rules.
- Stop npm parent lookups at a fixed point, reject noncanonical instance
  paths and bound ancestor candidate work per modern lock. Preserve valid
  neighbors and source-qualified unknown edges when lock
  nodes are malformed or unsupported. CycloneDX retains unresolved assertions
  instead of binding them to a different instance or public origin.

- Keep index freshness checks and result projection in one read-only database
  view. A cache replacement during a query cannot switch its results to another
  generation. Reuse that query's connection while retaining checks on every call
  and page; trusted explicit SQLite paths use a read transaction.

- Extend opt-in work accounting to index snapshots, refreshes, query freshness
  and OSV transfers. The offline benchmark now checks fixture and full evidence
  digests, measures pagination and supports runs without profiling. Normalize
  macOS peak memory to KiB; report its whole-worker scope.

- Preserve the last published default index when a refresh context fails. Roll
  back failed commits and release database/directory resources on interrupted
  setup. Keep the current analysis revision and index schema.
- Serialize default-cache publication between cooperating writers, check initial
  absence as well as the captured digest, and reject replaced parent directories.
  Add injected write failures and real process-interruption/recovery cases to
  the existing engineering tests. Queries do not acquire a publication lock.

- Support bounded ASCII Maven `ECOSYSTEM` ranges and normalized version equality
  using Apache Maven's `ComparableVersion` ordering. Use that profile for forward
  fix candidates while preserving unsupported ranges and literal assertions.
- Retain Apache attribution in `NOTICE` and include it in wheels, source archives
  and Skill bundles. Extend the fixed advisory corpus with Log4j branch gaps,
  prerelease boundaries and equivalent explicit versions, plus upstream ordering
  assertions without adding a Java runtime dependency.

- Interpret npm and crates.io OSV `ECOSYSTEM` ranges with strict SemVer
  precedence for membership and forward fix candidates. Preserve unknown
  results for nonstandard versions and unsupported ecosystem ordering.
- Extend the existing offline corpus gate with four pinned, attributed upstream
  advisories and independent version/fix labels. Report known affected cases
  that remain unknown without treating expected limitations as detected CVEs.

- Group collectors and Python parsers by ecosystem, with separate packages for
  filesystem access, supplied evidence and report projections. Merge related
  registration, identity, Gradle, configuration and metadata helpers. Retain
  the top-level Python API, CLI/MCP entry points and `depcheck.output` imports.
- Group Skill ecosystem references under `references/ecosystems/` and update
  their links. Internal module paths change without changing evidence revisions
  or the index schema.

- Inspect supplied native `pip inspect` v1 reports through the existing evidence
  CLI/MCP operation. Preserve duplicate instances, optional fields and environment
  assertions without opening metadata locations or inferring public provenance.
- Collect literal Hatch environment requirements and Hatch/Poe commands from
  pyproject files. Keep separate environments outside application hygiene and
  resolution; qualify inheritance, formatting and separate configuration files.
- Mark Python entry-point discovery as incomplete usage evidence, preventing
  conclusions that a plugin is unused based only on imports. Extend the existing pure-module
  architecture checks to cover indirect imports.
- Skip TOML source-position indexing when pytest configuration is absent and
  reuse one position index for its required plugins. Preserve scan evidence.

- Reorganize README and Skill guidance around backend identity, public-coordinate
  eligibility, cache recovery and bounded network reads. Clarify release/source
  differences, corpus scope, local candidate builds and platform-check status.

- Preserve requirements source options across includes and collector deduplication.
  Require caller-qualified public Maven coordinates before OSV lookups. Redact
  Python URL credentials from retained assertions, requirements and diagnostics.
- Reject executable or mismatched SQLite cache schemas and bound VM work.
  Bound shared setup.cfg/Maven expansion, Python call traversal and workspace
  glob matching; remove JavaScript regex-context prefix rescans. Escape terminal
  controls in human-readable output.
- Bound streamed OSV responses, pagination and request work; disable redirects
  and environment inheritance. Raise the MCP extra minimum to 1.30 and update
  the lockfile without changing the stdio transport.
- Add backend identity through `depcheck runtime` and MCP `backend_info`, a pinned
  inventory corpus evaluator, deterministic Skill bundles and native CI gates.
  Add security reporting and contribution guidance.
- Include the Skill, development scripts and bundle metadata in source archives
  so their checks can run from an extracted source distribution.
- Current evidence uses analysis revision 67, index schema v6 and tool contract
  revision 2. Refresh older indexes; package version 0.5.0 remains unchanged.

- Separate shared evidence input, OSV advisory interpretation, Python metadata
  resolution, index preparation and ecosystem parsers into focused modules.
  Offline advisory reevaluation no longer constructs an HTTP session. CLI and
  MCP contracts, analysis revision 57 and index schema v4 were unchanged by
  that internal refactor.

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
