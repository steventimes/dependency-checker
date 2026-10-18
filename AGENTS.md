# Dependency Checker maintenance

Read applicable parent AGENTS.md instructions and [README.md](README.md). Preserve
existing work. Keep reports, caches, benchmark output, and raw trial material in
`.tmp/`; do not put them into commits or release bundles. Commit, push, and
publish only within the user's requested scope.

## Published baseline

The project is an Agent Skill with an MCP server and CLI backend.
[v0.4.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.4.0)
was published on 2026-10-07 from `c23742c0e3961390beacb78d94fb68b39c57a944`.
The package and plugin metadata use 0.4.0. Next-update preparation does not
change that version until a new release is selected.

The published baseline passed 301 tests on Python 3.11 and 3.12 and all six
[CI jobs](https://github.com/steventimes/dependency-checker/actions/runs/37683267157).
Those are release results. Check current source, CI, and test collection before
reporting counts or verification for later changes.

## Implementation boundaries

- Parse target repositories as bounded data. Do not import target code, evaluate
  setup/build files, or execute package managers to improve static evidence.
- Preserve incomplete, skipped, unsupported, and ambiguous states. Missing
  coverage, unknown versions, and zero observed usages need qualified reporting.
- Keep queries and update previews read-only. Index/scan MCP tools can replace
  the derived cache; their annotations and the Skill must state that side effect.
- Resolve helper executables outside the audited repository and keep metadata
  subprocesses non-interactive with `stdin=subprocess.DEVNULL`.
- Evidence semantics changes require an `analysis_revision` update in
  `depcheck/model.py` (currently 57, re-exported by the indexer). Table changes require an index
  schema/rebuild decision in `depcheck/indexing/models.py` and `store.py`.
- Keep backend version markers consistent in `pyproject.toml`,
  `depcheck/_version.py`, both plugin descriptors, and the lockfile at release.

## Next updates

The first local iteration implements TOML/npm JSON/Maven XML declaration
positions, source-focused uncertainty diagnostics, and a path-check optimization.
Its experiments and local verification live in `.tmp/optimization-20261008/`.
These changes are unreleased. Native platform CI remains a release check.

The second iteration adds conservative Python ownership, structured coverage,
static package-script/workflow command evidence, and Cargo manifest/lock
inventory. Its local verification is in `.tmp/implementation-20261011/`.
Cargo usage and lock activation remain unknown; command evidence describes
configuration rather than execution. The package version is still 0.4.0.

The third iteration adds bounded, anchored content I/O and private default-cache
SQLite snapshots, followed by literal Astro/CSS imports. Frontend experiments
live in `.tmp/frontend-20261011/`. Astro expressions and subsequent template
regions, browser/CDN references, and CSS preprocessors remain incomplete.
Native Windows/macOS filesystem checks remain release requirements.

The fourth iteration collects bounded TypeScript/pytest configuration evidence,
separates named independent Python components, and qualifies inherited pnpm
workspace locks. It adds read-only scan comparisons, maintenance handoff metadata
and external CycloneDX JSON inspection. Local verification is in
`.tmp/implementation-20261014/`. Analysis revision 21 invalidates pre-split caches;
schema v3 tables already support qualified project identities. Shared uv workspace
ownership remains conservative. External SBOM assertions do not establish source
usage, execution, or a completed vulnerability check.

The interface/migration review in `.tmp/new-skill-review-20261015/` rejects orphaned
legacy Python configuration scopes and invalid or duplicate application SBOM
references. Migrate scoped configuration before rebuilding; a failed refresh
preserves the previous cache. Version 0.4.0 and schema v3 are unchanged.

The Trivy interoperability iteration retains external SBOM component types,
CycloneDX scopes, license assertions and repeated source properties. It identifies
unambiguous Trivy dependency groups without turning group membership into direct
package ownership. Its experiments and local verification are in
`.tmp/trivy-implementation-20261015/`. That iteration used analysis revision 22; the
package remains 0.4.0 and the index schema remains v3.

The roadmap iteration adds bounded dependency origin paths, advisory/version
exemptions, explicit portable repository identity, recorded Codex consumer
trials, configured anonymous Python scopes, conservative uv member ownership,
and literal Vue/Svelte script/style evidence. Unchanged selected-index queries
validate content and ownership/topology guards without reparsing; changes fall
back to a selected scan. Evidence is in `.tmp/roadmap-implementation-20261015/`.
That iteration used analysis revision 23, package 0.4.0 and schema v3.

The follow-up fixes preserve Python source assertions and exclude non-public or
unknown identities from public registry checks. Schema v4 adds origin JSON to
the cached requirement/resolution tables; read-only queries reject old schemas,
and indexing rebuilds the derived cache. Evidence pages and MCP byte budgets
qualify omitted output. Scan publication reuses captured evidence after read
digest and topology checks; explanations check freshness once. Agent scoring
validates observed pagination and known forbidden command forms. Evidence is
in `.tmp/followup-fixes-20261015/`. That iteration used analysis revision 24; the package
version remains 0.4.0. Native macOS/Windows remain release checks.

The GoogleTest reference iteration maps `gtest/` and `gmock/` headers to the
shared Conan/vcpkg `gtest` package and recognizes C/C++ `*_test` filenames as
test scope. Literal `find_package(GTest)` remains a build hint; standalone
CMake `FetchContent` inventory was unsupported in that iteration. Evidence is in
`.tmp/googletest-reference-20261015/`. That iteration used analysis revision 25; schema
v4 and package 0.4.0 are unchanged.

The CMake inventory iteration collects bounded literal FetchContent/find-package
assertions and availability requests in lexical CMake directory trees. Repeated
declarations, source options and positions survive indexing. Conditions, include
graphs, first-declaration precedence, providers and overrides remain unevaluated;
activation, installed versions, package-manager coordinates and source/target
usage remain unknown. The shared lexical reader also fixes commented/multiline
Conan/vcpkg CMake hints. Evidence is in `.tmp/cmake-inventory-20261015/`.
That iteration used analysis revision 26; schema v4 and package 0.4.0 are unchanged.

The CMake script iteration gives orphan `.cmake` trees distinct
`cmake:cmake-script:<root>` identities without absorbing nested CMake projects.
Project/script manifest lists contain their owned input files. Entry points,
include execution and activation remain unknown. CMake lookup is case-insensitive;
CPMAddPackage/CPMFindPackage calls expose positioned coverage gaps. Evidence is
in `.tmp/cmake-scripts-20261015/`. That iteration used analysis revision 27; schema v4 and
package 0.4.0 are unchanged.

The legacy Python fidelity iteration adds structural positions for Pipfile,
supported Python locks, setup.cfg and literal setup.py sequences. Interpolated
or unmatched values retain file-only locations; invalid INI interpolation and
duplicate Pipfile.lock keys are qualified. Shared Pipenv source selection retains
private/local/Git assertions and rejects ambiguous or missing named indexes for
public checks. Evidence is in `.tmp/legacy-positions-20261015/`.
That iteration used analysis revision 28; schema v4 and package 0.4.0 are unchanged.

The GoogleTest sample follow-up recognizes C/C++ `*_unittest` filenames alongside
`*_test`, avoiding runtime scope mismatches for test-only dependencies in the
official samples. Filename/path scope remains a heuristic; build-target
membership is not inferred. The selected upstream sample trial and local
verification are in `.tmp/googletest-followup-20261015/`.
That iteration used analysis revision 29; schema v4 and package 0.4.0 are unchanged.

The C/C++ fidelity iteration retains literal Conan requirement and JSON inventory
positions, lock contexts, repeated instances and recipe references. Ranges stay
unresolved, native vcpkg registry locks do not establish package resolution, and
all C/C++ build selection/installation remains unknown. Root vcpkg dependency
conditions, feature assertions, minimum versions and override sources survive
indexing; feature-specific dependency lists expose a coverage gap. Incomplete
manifests suppress unsupported missing/unused conclusions. JSON location walks
have depth/node budgets, follow retained JSON values and discard replaced spans. Evidence
is in `.tmp/cpp-fidelity-20261015/`.
That iteration used analysis revision 30; schema v4 and package 0.4.0 are unchanged.

The vcpkg feature iteration collects conditional dependency lists, feature/default
assertions, support expressions, host/self-feature context and structural
locations. These records do not establish activation, resolved versions, direct
application edges or hygiene advice. Repeated conditions survive queries and
CycloneDX properties. Invalid scopes/default assertions and bounded context
expansion retain explicit gaps. Verification and selected upstream trials live
in `.tmp/vcpkg-features-20261015/`.
That iteration used analysis revision 31; schema v4 and package 0.4.0 are unchanged.

The Maven plugin iteration collects build/reporting plugins, management definitions
and explicit plugin dependencies as conditional build configuration. Positions,
declaring property context, literal inheritance, execution/report sets and profile
assertions survive queries and CycloneDX. Effective merges, profile selection,
lifecycle defaults, configuration bodies and actual execution remain unknown;
plugin dependencies do not satisfy application imports or trigger public queries.
Build extension inventory and profile application dependencies retain explicit
gaps. Local parent directory paths and both separators resolve bounded
`pom.xml` files; outside aliases stay rejected. Implicit lifecycle/build resolution
remains unknown even without declared plugins. Independent evaluation reads can
opt out of ordering while still requiring distinct calls and valid results. XML node counts are bounded before DOM allocation; plugin metadata expansion
is bounded. Experiments and verification are in `.tmp/maven-plugins-20261015/`.
That iteration used analysis revision 32; schema v4 and package 0.4.0 are unchanged.

The Go fidelity iteration preserves positioned minimum requirements, replacement
and exclusion origins, quoted literals and repeated checksum assertions. `go.sum`
module-file and archive hashes are unverified inventory, not selected versions;
Go resolution/security stay incomplete and no exact OSV query is inferred.
Version-specific replacements retain unknown applicability. Uncollected
tool/ignore directives and bounded context expansion leave explicit gaps.
Checksums survive queries/CycloneDX without application edges or installed
versions. Read-only snapshot comparisons preserve metadata-only changes, including
hash assertions, without verifying integrity. Real manifest trials and verification live in `.tmp/go-fidelity-20261015/`.
That iteration used analysis revision 33; schema v4 and package 0.4.0 are unchanged.

The Go tool iteration collects bounded literal `tool` directives as positioned
build configuration usages. Declared module prefixes and scoped mappings retain
ownership and provenance; indirect requirements still declare their providers.
Local/standard tools do not create external dependencies. Explicit required
modules nested under the main module path remain external candidates for imports
and tools. Explicit local replacement modules without domain names retain their
owners. Candidate preselection avoids a full dependency walk per local import;
the fixed helper benchmark is in the iteration directory. Unknown owners and exhausted budgets leave coverage gaps; package
availability, execution, installation and selected versions remain unknown.
Experiments and verification live in `.tmp/go-tools-20261015/`. Analysis revision
34 was used; schema v4 already stores these usages and package 0.4.0 is unchanged.

The Gradle fidelity iteration collects bounded lexical Groovy/Kotlin calls with
positions, contexts, wrappers and requested-version semantics. Both DSL build
files remain distinct; comments and documentation strings do not add dependencies.
Configuration assertions remain conditional and constraints stay separate.
Project/buildscript lock inventory retains repeated configuration-qualified
instances and origins; source requests never supply exact OSV versions.
Settings/helper scripts/catalogs expose coverage/freshness gaps, and Gradle Kotlin
scripts do not become application imports. Execution, evaluated ownership and
active selection remain unknown. Experiments live in `.tmp/gradle-fidelity-20261015/`.
That iteration used analysis revision 35; schema v4 and package 0.4.0 are unchanged.

The C/C++ source follow-up ignores comment/string examples, preserves physical
include locations across standard line splices and retains preprocessing
conditions as inferred usages with unknown activation. Macro operands,
unsupported directives, compiler-dependent translation and lexical/depth budgets
leave explicit gaps. No compiler or preprocessor is executed. Experiments and
verification live in `.tmp/cpp-source-20261015/`. That iteration used analysis revision 36;
existing schema v4 stores the qualified usages and package 0.4.0 is unchanged.

The Gradle catalog iteration adds separate TOML library-definition scopes,
per-file named/rich version assertions, aliases, bundle memberships and positions.
Catalog binding, programmatic overrides and build/source usage remain unknown;
definitions do not provide selected security versions or direct application
edges. Plugin IDs and arbitrary/imported catalog names remain uncollected.
Alias queries search all declarations before evidence pagination. Entry/context
budgets and unsupported inputs retain gaps. Experiments and verification are in
`.tmp/gradle-catalog-20261015/`. That iteration used analysis revision 37; schema v4 already
stores these scopes and metadata and package 0.4.0 is unchanged.

The Python group iteration normalizes PEP 735 include targets, preserves ordered
repetitions and rejects ambiguous/invalid names and non-exact include tables.
Collection retains each parser result's multiplicity without duplicating the same
physical requirements through overlapping entry files. Repeated expansion is not
another source declaration. Entry/context/diagnostic budgets qualify omitted
evidence; installed group selection stays unknown. Experiments and verification
live in `.tmp/python-groups-20261015/`. That iteration used analysis revision 38; existing
schema v4 stores repeated rows and package 0.4.0 is unchanged.

The Python group-context iteration checks development-group intersections within
each declared group, including expanded includes. Incompatible cross-group or
runtime/development requests retain unknown co-selection rather than a definite
active-environment conflict. Native installer/uv group policies remain unevaluated.
Analysis diagnostics are retained in normalized project evidence; analysis errors
keep dependency-query completeness false independently of source usage. Evidence
is in `.tmp/python-group-context-20261015/`. That iteration used analysis revision 39; schema
v4 already stores these diagnostics and package 0.4.0 is unchanged.

The uv legacy iteration collects `tool.uv.dev-dependencies` after standard group
expansion, matching uv's non-inheritance behavior. Legacy and standard `dev`
declarations share a group while retaining locations, markers, extras and source
assertions. Invalid tables/entries preserve diagnostics and readable siblings;
group budgets apply. Installed selection and development-group update previews
remain unsupported. Trials and verification live in `.tmp/uv-legacy-20261015/`.
That iteration used analysis revision 40; schema v4 and package 0.4.0 are unchanged.

The GoogleTest recheck uses six pinned upstream configuration/sample files in a
synthetic Conan consumer. Header/test scope and conditional CMake assertions
retain their qualifications; read-only queries preserve cache bytes and mtime.
The trial in `.tmp/googletest-recheck-20261015/` is not a whole-upstream audit.
At revision 40, package-config templates (`*.cmake.in`) and `find_dependency`
were uncollected; README and Skill named that boundary explicitly.

The CMake package-config iteration collects literal `find_dependency` assertions
and `*.cmake.in` templates within existing lexical project/script scopes. Positions,
repeats, raw dynamic arguments and template provenance survive queries. Every
template retains a substitution/injected-code gap; only standalone `@PACKAGE_INIT@`
is skipped, without expansion. Generated code, exported installation contents and
active selection remain unknown. Template changes and topology invalidate caches.
Trials and verification live in `.tmp/cmake-package-config-20261015/`.
That iteration used analysis revision 41; schema v4 and package 0.4.0 are unchanged.

The Bzlmod iteration collects literal top-level `bazel_dep` calls in independent
physical MODULE.bazel scopes. Requested versions, aliases, development conditions,
nodep assertions and positions remain conditional configuration inventory. The
Python syntax reader does not execute Starlark; escaped/prefixed/concatenated
strings and dynamic/ambiguous arguments stay unknown. Budgets bound tokens,
nodes, declarations, context and diagnostics. Includes, extensions, overrides,
registry/root selection, locks and build/source usage remain uncollected; Bazel
WORKSPACE/BUILD/lock/`.bzl` paths expose coverage gaps. No public security versions
or application edges are inferred. Evidence is in `.tmp/bzlmod-20261015/`.
That iteration used analysis revision 42; schema v4 and package 0.4.0 are unchanged.

The Skill routing iteration moves transport, evidence and ecosystem details into
linked `references/` files. The entry retains shared data/network boundaries and
reporting rules; runtime evidence semantics, analysis revision 42, schema v4 and
package 0.4.0 are unchanged. The before/after source, resource-link and bundle
checks, plus selected recorded consumer trials live in `.tmp/skill-routing-20261015/`.
Treat prior runtime checks separately from current instruction-behavior evidence.
The new nested pnpm consumer distinguishes static completeness from an observed
installed version. Its reverse-order explanations exposed an evaluator defect:
unordered calls now require one-to-one argument/result matches, including
overlapping expectations. Ordered matching retains its previous behavior.

The Cargo legacy iteration retains positioned `dev_dependencies` and
`build_dependencies` assertions, including target tables, and recognizes the
pre-2024 `[project]` package alias. Literal editions and bounded workspace edition
inheritance distinguish accepted, shadowed, rejected and unknown sections.
Canonical tables take precedence even when empty. Non-accepted legacy sections
remain configuration inventory without direct lock association or implicit path
membership. Installation, active feature/target selection and Rust usage remain
unknown; legacy `default_features` fields are still retained but uninterpreted.
Trials and verification live in `.tmp/cargo-legacy-20261015/`. Analysis revision
43 was used; existing schema v4 stores the metadata and package 0.4.0 is unchanged.

The PURL interoperability iteration uses `packageurl-python` to retain decoded
coordinate fields, qualifiers and subpaths in external SBOM inventory. Additional
identity dimensions remain qualified/incomplete; malformed encodings, duplicate
qualifier keys and unsupported namespace shapes are rejected. npm/Go casing and
raw PURLs survive inspection. Unknown PURL types keep assertions without a
supported ecosystem mapping. That iteration used analysis revision 44; external inventory
does not enter the index, so schema v4 is unchanged. Package 0.4.0 is unchanged.
Verification lives in `.tmp/reference-purl-20261017/`.

The uv lock-context iteration retains bounded environment/fork/dependency and
extra/group assertions in `origin.lock`, with independent physical instances.
Conditions and omitted context keep active selection unknown through indexing,
queries, advisory findings and CycloneDX. Conditional locks do not seed a flat
compatibility graph or an installed-version conflict. Native selection, package
installation and shared-workspace activation remain unknown. Analysis revision
45 was used; existing schema v4 stores origin context and package 0.4.0 is
unchanged. Verification lives in `.tmp/uv-lock-context-20261017/`.

The OSV fix-context iteration compares fixed boundaries with each queried
version and all matching affected ranges or explicit affected versions. PyPI
ECOSYSTEM ranges use PEP 440; SEMVER ranges use the `semver` library. Raw fix
assertions survive unsupported ordering, while unavailable or unconfirmed fixes
stay unknown. Candidates do not prove availability, compatibility, lock activation
or safety against other advisories. Invalid/oversized detail metadata preserves
matched IDs, diagnostics and readable siblings. Analysis revision 46 was used;
schema v4 and package 0.4.0 are unchanged. Verification lives in
`.tmp/osv-fix-context-20261017/`.

The OSV lifecycle iteration refreshes cached details using querybatch revisions,
preserving nanosecond precision. Unversioned hints cannot authorize cross-call
reuse; stale or failed refreshes retain matched IDs and errors. Effective
withdrawals are excluded per record with an audit diagnostic, while future
withdrawals and active alias records remain active. Alias-based record merging
was unimplemented at analysis revision 47; schema v4 and package
0.4.0 are unchanged. Verification lives in `.tmp/osv-lifecycle-20261017/`.

The OSV alias iteration groups active alias-linked records within each exact
dependency identity. Actual member IDs and parsed source metadata survive in
`advisory_ids`/`advisories`, including source severity, fix assertions and dates.
Group candidates must satisfy every comparable source; unavailable or
unconfirmed evidence remains unknown, and aggregate budgets retain errors.
Related/upstream records and different projects, versions or instances do not
merge. Source withdrawal is still record-scoped. That iteration used analysis
revision 48; schema v4 and package 0.4.0 are unchanged. Verification lives in
`.tmp/osv-aliases-20261017/`.

The CVE/CWE metadata iteration retains canonical CVE identifiers and provider CWE
assertions, official lookup links and per-source field provenance. Alias groups
preserve source classifications and bound their flattened reference projection.
Missing, malformed, over-budget or unavailable classifications stay qualified;
optional classification warnings do not discard vulnerability matches or fix
evidence. Current CVE/CWE records, taxonomy relationships, existence and status
are not fetched or validated, and no new network path is added. Experiments and
verification live in `.tmp/cve-cwe-20261017/`. That iteration used analysis
revision 49; schema v4 and package 0.4.0 are unchanged.

The npm origin iteration collects bounded repository `.npmrc` registry assertions
and retains declaration/lock sources across npm and pnpm evidence. Known
non-public and unknown instances do not supply public PURLs or OSV coordinates;
same-name/version public matches do not spread to private instances. Cache guards
cover registry configuration changes. Authentication settings are omitted and
new origin URL fields remove credentials, queries and fragments. Public defaults
remain static assertions; package visibility, user/global/environment/CLI settings,
workspace precedence and active installation remain unverified. Experiments and
verification live in `.tmp/npm-origins-20261017/`. That iteration used analysis
revision 50; schema v4 and package 0.4.0 are unchanged.

The npm version iteration replaces the permissive lock-version regex with the
existing SemVer parser plus node-semver's text and release-component bounds.
Invalid prerelease identifiers, oversized strings and out-of-range components
do not supply public advisory coordinates. Raw npm inventory and valid build
metadata remain intact; invalid pnpm nodes retain gaps and readable neighbors.
Requests, tags, publication and installation are not resolved. Development-only
Node comparisons do not introduce a backend Node dependency. Verification lives
in `.tmp/npm-semver-20261017/`. That iteration used analysis revision 51;
schema v4 and package 0.4.0 are unchanged.

The Yarn inventory iteration collects Modern format 8/10 lock records in independent
physical `npm:yarn-lock:<root>` scopes, including standalone files. Grouped/repeated
descriptors, alias names, positions and locator/version/context assertions survive
indexing and CycloneDX without selected versions, public advisory coordinates or
application edges. Registry selection, workspace/application ownership, peer
virtualization, PnP, installation and source usage remain unknown. Classic/other
formats, invalid records and entry/context/diagnostic budgets retain gaps. Official
source/data trials and verification live in `.tmp/yarn-inventory-20261017/`.
That iteration used analysis revision 52; schema v4 and package 0.4.0 are unchanged.

The SARIF location iteration preserves diagnostic positions and symbolic
`%SRCROOT%` bases whose mapping omits the checkout directory. Diagnostic messages
retain provider text and may contain paths. Explicit outside-root
files keep distinct file URIs; absent finding locations use only their project's
known manifest or retain an unavailable qualification. The shared scan summary
avoids source-path resolution and unrelated inventory serialization during SARIF
projection. Official schema/SDK source and data checks live in
`.tmp/sarif-locations-20261017/`. This changes output projection only: analysis
revision 52, schema v4 and package 0.4.0 are unchanged. GitHub line fingerprints,
native SDK validation and hosted ingestion remain separate, unverified concerns.

The Unicode position iteration converts Python import/dynamic-load AST byte
offsets to one-based Unicode code-point columns through the shared position
reader. Raw AST text and notebook cells preserve universal line boundaries.
Static Python/Conan/Bzlmod AST parsing avoids CPython's implicit error-context
file reopen. Evidence retains the actual file independently of the parser name.
Unparseable Unicode cells leave diagnostics while readable cells survive.
Notebook JSON coordinates remain virtual across cells. SARIF preserves them in
qualified properties with file-only physical locations and declares column/newline
units. Cell-to-JSON mapping and notebook execution remain unsupported. Evidence
lives in `.tmp/unicode-columns-20261017/` (started October 17, completed October 18).
Analysis revision 53 invalidates old position evidence; schema v4 and package
0.4.0 remain unchanged.

The Rust source iteration collects bounded literal crate-reference candidates
from owned `.rs` files. Cargo aliases retain inferred owners, unknown scope and
conditional confidence; known shadows and conflicting origins retain unknown
owners. Comments and literals are skipped. Module/target/cfg selection, macros,
generated code, custom crate names and compiler binding remain unknown. Virtual
workspaces do not acquire application ownership, and no missing/unused/scope
advice follows from these candidates. Exact Cargo lock validation follows Rust
SemVer rules and retains valid prereleases/build metadata. Evidence lives in
`.tmp/cargo-source-20261018/`. Analysis revision 54 invalidates old evidence;
existing schema v4 tables and package 0.4.0 are unchanged.

Address one bounded change at a time. The remaining priorities are:

1. Extend position fidelity to remaining legacy manifests and locks. Keep
   repeated declarations and inherited origin distinct, and retain a file-only
   location when a supported value cannot be matched to a reliable span.
2. Extend Python installation evidence beyond configured anonymous scopes and
   separate uv member source ownership. Shared uv lock activation and cross-member
   availability remain unknown. Preserve the
   repository-relative IDs of named components and component-root scans.
3. Collect bounded build/plugin/command evidence where ownership is known.
   Preserve provenance and confidence separately from source imports, configured
   `tool-usage`, and actual execution. Command/configuration uses of CLI, test,
   and doc plugins beyond the bounded command/configuration set remain absent.
   Maven plugin inventory is configuration-only; effective plugin merging,
   lifecycle/profile activation and runtime use remain uncollected.
4. Expose uncovered manifests and source formats alongside index-selection
   coverage. Cargo inventory and conditional literal Rust crate references are
   supported; compiler-resolved Rust usage and browser/CDN dependencies remain
   uncovered. Astro frontmatter and bounded script/style
   regions plus CSS imports and literal Vue/Svelte script/style regions are collected.
   Framework template expressions/implicit imports, SCSS, and Sass remain unparsed. Extend conservative framework coverage
   before widening snapshot conclusions and npm update previews.
   Preserve lock environment/variant conditions when expanding resolution data.
5. Measure discovery, hashing, parsing, storage, and query work before optimizing
   cache reuse. Non-Python refresh still rescans selected evidence; unchanged
   selected queries have a content-checked fast path. Reuse
   `scripts/benchmark_monorepo.py` on Linux/macOS. Record its fixed parameters
   and runtime, and compare inventory, diagnostics, and completeness with timing.
   Keep local baselines in `.tmp/` and leave CI thresholds unchanged without
   evidence.

## Verification

Implement each bounded change before concentrated verification. Prefer realistic
upstream fixtures, cross-module scenarios and consequential boundary cases over
mechanical tests for individual fields. Reuse and consolidate existing coverage.

Start with `git status --short --branch` and inspect the affected interface.
Reuse the five existing test modules under `test/` for regression cases.
Run the commands in the README's Development section for runtime changes,
including the offline MCP contract runner. Changes to stdio, roots, metadata
subprocesses, or packaging need the Ubuntu/macOS/Windows build checks.

For documentation changes, verify local links and run changed command examples
against temporary fixtures. Do not add tests that compare documentation text
with itself. Report collected tests, local passes, remote CI, and published
artifacts as separate evidence.

The Skill entry is `skills/check-dependencies/SKILL.md`. Keep shared constraints
and reference routing there; update the applicable `references/` file when a tool
contract or coverage rule changes. Include the whole Skill tree in bundles and
validate its relative links. Its evaluation directory separates live MCP
contract checks, recorded agent trials, and synthetic scorer-format fixtures;
do not describe synthetic traces as observed agent behavior.

## Reference review and external build models

The 2026-10-18 reference review reads all 26 supplied papers in full and reviews
the remaining repository/documentation entries plus earlier user-shared links.
The implementation report, source snapshots, per-entry reading scope and
verification artifacts stay in `.tmp/`; do not include them in commits or bundles.
Public product material does not establish vendor accuracy or internal behavior.

The CMake File API inspector reads an explicitly selected existing index and
codemodel v2 replies without configuring or building. Preserve build-order versus
link/compile/object relationships, configuration/target identities, abstract and
imported flags, source assertions and JSON-pointer provenance. Input hashes do not
authenticate the producer or establish source freshness. Build execution remains
unknown, package mapping unsupported and security skipped. This separate external
projection does not change cached analyzer evidence or schema v4. Package 0.4.0
remains unchanged. Local verification is recorded in
`.tmp/cmake-file-api-20261018/`; native macOS/Windows and remote CI remain separate.

## 待参考项目

完整的用户参考清单及逐项状态见 [REFERENCES.md](REFERENCES.md)。

2026-10-17 登记时仅加入清单，2026-10-18 按后续要求阅读公开资料。实际范围如下。

| 项目 | 链接 | 状态 |
| --- | --- | --- |
| DependencyTrack/dependency-track | https://github.com/DependencyTrack/dependency-track | 2026-10-18 已阅读公开概览；未部署或上传数据 |
| xerj-org/xerj | https://github.com/xerj-org/xerj | 2026-10-18 已阅读公开概览；未安装、运行或发送反馈 |

## Full reference implementation batch (2026-10-18, revision 55 checkpoint)

The user requires completion of all implementation directions in the ignored
report before concentrated testing. The exact 101 reference decisions and 15
workstream mappings are retained in `.tmp/all-implementation-20261018/requirements.json`.
Revision 55 adds bounded resolvelib metadata backtracking, independent PEP 723
script ownership and separately scoped external evidence operations. Schema v4
and package 0.4.0 remain unchanged. External claims, static call candidates,
registry existence and unsigned hashes never establish exploitation, source
trust, installation or ABI/API compatibility. Default scans do not acquire new
network behavior. The batch completed implementation, integration, and review
before concentrated verification. Keep its results separate from later revisions.

The revision 55 checkpoint passed 1006 tests with one skip on Python 3.11 and
3.12 and all 16 local workflow steps; these are historical results, not evidence
for subsequent changes. The offline OSV follow-up separates version membership
from fix selection, preserves per-source matching reasons and counts package-less
Git assertions without public identity inference. Analysis revision 56 changes
the evidence contract; existing schema v4 tables and version 0.4.0 are unchanged.
Its current-source verification belongs in `.tmp/osv-matching-20261018/`.

The final solver review retains base dependencies when extras are requested and
qualifies unavailable marker contexts without dropping root declarations or
querying public metadata for unknown root selection. Analysis revision 57
invalidates older evidence; schema v4 and package 0.4.0 remain unchanged.
The user's 2026-10-18 closing instruction ends the ongoing optimization goal after
code review, documentation and concentrated local verification. The progress
record is `.tmp/implementation-report-20261018.md`; the local closing checks are
in `.tmp/solver-final-20261018/`.

The subsequent Windows CI fixture fix was pushed as `6a6e98a` (`test fix`). All
six jobs in [run 39090540656](https://github.com/steventimes/dependency-checker/actions/runs/39090540656)
passed, including Ubuntu/macOS/Windows build, native filesystem and installed-wheel
checks. Full pytest runs remain on Linux with Python 3.11 and 3.12; the platform
jobs run selected boundary checks. The task cleanup removed temporary environments,
source copies, raw logs and unpublished check bundles. Retained JSON summaries
record historical verification; recreate environments from the lockfile and CI
commands when rerunning checks. Reports and trial material remain outside commits.
