# Dependency Checker

Dependency Checker provides the `check-dependencies` Agent Skill for repository
dependency audits. Its MCP tools and `depcheck` CLI share a scanner that collects
declarations, locked versions, and source usage. An agent can inspect a package,
explain its impact, and preview a supported update from that evidence.

Repository files are parsed as data. Scans do not import target project code or
run its package managers.

[Agent Skill setup](#use-with-a-coding-agent) · [CLI](#cli) ·
[Coverage](#ecosystem-coverage) · [Changelog](CHANGELOG.md) ·
[Reference backlog](REFERENCES.md)

The published version is
[v0.5.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.5.0).
The release includes the Agent Skill bundle and its SHA-256 checksum.

See the [changelog](CHANGELOG.md) for changes since 0.4.0. Use the
[development setup](#development) to work from a source checkout.

## Use with a coding agent

Download the
[v0.5.0 bundle](https://github.com/steventimes/dependency-checker/releases/download/v0.5.0/dependency-checker-0.5.0.zip)
and check it against
[SHA256SUMS](https://github.com/steventimes/dependency-checker/releases/download/v0.5.0/SHA256SUMS).
Extract it and use your agent host's skill or plugin loader. The published
0.5.0 bundle contains:

| Entry | Purpose |
| --- | --- |
| `skills/check-dependencies/SKILL.md` | Dependency audit workflow and reporting rules |
| `skills/check-dependencies/references/` | Backend, transport, and ecosystem guidance loaded for the requested task |
| `skills/check-dependencies/agents/openai.yaml` | Skill display metadata |
| `.codex-plugin/plugin.json`, `plugin.json` | Plugin descriptors |
| `.mcp.json`, `mcp.json` | MCP server launch configuration |
| `depcheck/`, `pyproject.toml`, `uv.lock` | Scanner, CLI, and locked backend environment |

The Skill needs an available MCP server or an installed `depcheck` CLI. A copied
Skill directory provides instructions; set up its backend before requesting an
audit. The bundled launchers use uv 0.12.4 and Python 3.11 or newer.

From the extracted bundle directory, install the agent backend:

```bash
uv sync --frozen --extra agent
uv run --frozen --extra agent depcheck --version
```

For a client that needs an explicit server command, use absolute paths for the
backend and the repository being audited:

```bash
uv run --project "/absolute/path/to/dependency-checker" --extra agent --frozen depcheck-mcp --allow-root "/absolute/path/to/your-repository"
```

The bundled descriptors use `cwd: "./"`; their working directory must resolve
to the bundle root. MCP clients that supply repository roots can omit
`--allow-root`. See [MCP and agent integration](#mcp-and-agent-integration) for
root precedence and tool side effects.

Request an audit with a concrete repository path, or ask why a package is
present and what an update would affect. The Skill checks coverage and follows
inventory pagination before drawing conclusions. If MCP is unavailable, it can
use the installed CLI.

The Skill entry links to shared workflow and task-specific guidance in
`skills/check-dependencies/references/`. Keep the whole Skill directory when
copying or bundling it. The earlier 0.4.0 Skill predates this split and keeps its
guidance in the entry file. Reference paths are relative to the Skill directory,
even when the audited repository is elsewhere. This follows
[OpenAI's skill guidance](https://learn.chatgpt.com/docs/build-skills) on loading
instructions and supporting resources as needed.

### From audit to dependency maintenance

Use the static evidence to choose a bounded change before starting an update.
The `check-dependencies` Skill provides inventory, usage, coverage and previews.
A dependency-maintenance workflow, such as `dependency-manager`, handles native
resolution, installation and verification after the user authorizes changes.

| Stage | Evidence or action |
| --- | --- |
| Baseline | Inspect Git status, owning manifests and locks, runtime/package-manager pins, CI checks, and existing failures. Keep unknown resolved versions explicit. |
| Select | Use qualified package identities, declarations, impact and advisories to choose one ecosystem or coupled package family. Check migrations for major changes. |
| Apply | Use the project's existing package manager and pinned version. Regenerate generated lockfiles through that manager; depcheck previews do not apply them. |
| Verify | Reinstall in the project's locked mode, compare the resolved graph, run focused and broader checks, then report versions, advisories and failures before and after. |

These maintenance actions are separate from scanner execution. Unsupported Ruby,
PHP or .NET manifests can leave coverage incomplete even when a maintenance
agent can work with their native package managers.

## Capabilities

- Components are identified by
  `(project_id, ecosystem, package, version, instance)`.
- Reports missing, unused, unpinned, conflicting, and scope-mismatched dependencies
  when the collected evidence supports those findings.
- Exact-version OSV queries for PyPI, npm, Maven and verified crates.io records.
- Python compatibility analysis backed by PyPI metadata when explicitly enabled.
- Text, `depcheck.scan.v1` JSON, SARIF 2.1.0, and CycloneDX 1.7 output.
- A rebuildable `depcheck.index.v4` SQLite evidence index.
- Qualified inventory queries, dependency explanations, impact analysis, and
  read-only update previews for Python requirements and static PEP 621 entries.
- CLI and MCP interfaces over the same scanner, model, index, and service layer.

Scan results separate dependency findings from analysis failures. Skipped,
unsupported, and failed stages keep the overall result incomplete.

## Ecosystem coverage

| Ecosystem | Evidence |
| --- | --- |
| Python / PyPI | `pyproject.toml`, requirements text and compiled requirements locks, setup metadata, Pipfile, supported locks, Docker/Make install hints, Python and notebook imports |
| JavaScript / npm | `package.json`, npm and pnpm v9 locks, independent Yarn Modern lock inventory, literal module imports, Astro frontmatter and supported script/style regions, CSS imports, resolved instance edges |
| Go modules | positioned minimum requirements, replacement/exclusion assertions, repeated `go.sum` checksums and literal imports; selected build versions remain unknown |
| Java/Kotlin / Maven or Gradle | local POM properties/management, bounded Gradle configuration calls, configuration-qualified locks, TOML catalog library definitions and imports |
| C/C++ / Conan or vcpkg | supported manifests, Conan v2 lock inventory, supplied vcpkg dependency inventory, includes and CMake `find_package` evidence; active build/installation remains unknown |
| CMake configuration | literal `FetchContent_Declare`, `find_package` and `find_dependency` assertions, bounded package-config templates, source options and positions; active graph and installed versions remain unknown |
| Rust / Cargo | `Cargo.toml`, workspace inheritance, dependency aliases and conditions, Cargo.lock v3/v4 instances and edges; conditional literal Rust crate references with inferred owners |
| Bazel / Bzlmod | literal top-level `bazel_dep` calls in `MODULE.bazel`, requested versions, repository aliases, development conditions and source positions; selected graph and build/source usage remain unknown |

Go `require` directives retain their minimum version with `scheme: go-minimum`.
An all-version module replacement retains a `go-replacement` assertion; a
version-specific replacement does not select a target from the minimum alone.
Repeated `go.sum` lines use `kind: checksum`, with separate module-archive and
`go.mod` hashes, original locations and `integrity_verified: false`. They do not
establish source usage, direct application edges or installed versions. CycloneDX
keeps them as `depcheck:checksum-assertion` properties on unversioned components.
Following the [Go module specification](https://go.dev/ref/mod#go-sum-files),
old checksums and minimum requirements do not establish the MVS build list.
Go resolution and security remain incomplete, and these records do not supply
exact versions to OSV. Workspace/vendor selection is uncollected; `go.work` and
`go.work.sum` expose uncovered manifest paths. Literal quoted
directive values are supported; escaped interpreted strings and uncollected
ignore or future directives leave explicit gaps. Metadata expansion is bounded.
Snapshot comparisons retain declaration metadata, including checksum-only changes;
the comparison does not verify either hash or establish remediation.

Literal Go `tool` directives provide positioned `kind: configuration`, build-scoped
usage. A declared module prefix or explicit mapping identifies the configured
owner; repeated directives remain separate. `// indirect` still marks a `require`
declaration and does not make that owner missing. Main-module and standard-library
tools do not become external dependencies. Declared modules nested under the
main module's path remain external candidates for tools and source imports.
Explicitly required local replacement modules without domain names are not
discarded as standard-library imports.
Unknown owners and exhausted evidence budgets leave explicit gaps. This is
configuration evidence, not proof that a package exists, ran or was installed;
selected versions and security remain unknown. See the
[Go tool directive](https://go.dev/ref/mod#go-mod-file-tool).

For Conan and vcpkg projects, `gtest/` and `gmock/` includes map to the shared
`gtest` package. C/C++ files named `*_test` or `*_unittest` (before the extension),
as in the [GoogleTest quickstart](https://google.github.io/googletest/quickstart-cmake.html)
and [samples](https://github.com/google/googletest/tree/main/googletest/samples),
carry test scope, as do files under `test/` or `tests/`. This is a filename/path
heuristic; it does not establish which build targets use the file. Other source
files retain their runtime scope. CMake `find_package(GTest)` is a build hint when
`gtest` is declared. Commented calls are ignored and multiline calls retain locations.

C/C++ include collection skips comments and quoted/raw-string examples, joins
standard escaped newlines and retains physical source positions. Headers inside
preprocessor conditions have `kind: conditional` and inferred confidence;
activation is unknown, so they do not establish missing packages or scope errors.
Macro operands, unsupported inclusion directives, malformed input and exhausted
lexical budgets leave explicit gaps. Compiler-dependent translation keeps only
its preceding evidence. No compiler or preprocessor is run.

Conan text/literal Python declarations and supported JSON inventory retain source
positions. Conan v2 locks keep repeated instances, recipe revisions and separate
`requires`, `build_requires`, `python_requires` and `config_requires` categories.
Locks can contain unused versions from multiple configurations. Version ranges
remain unresolved; neither a manifest pin nor a lock entry proves installation
or selection for the active build.

vcpkg root and feature dependencies retain platform expressions, minimum versions,
feature assertions, default-feature flags and override locations. Feature lists
use `kind: conditional`, with their feature group, support expressions and default
feature assertions. These declarations do not establish activation, installed
versions, or removal evidence. They produce no unused, unpinned, duplicate or
scope-mismatch advice without an active context. Other root declarations retain
their checks. Repeated groups survive explanations and CycloneDX properties;
conditional-only components add no direct application edge. Invalid feature
scopes and expansion beyond the bounded metadata budget leave explicit gaps.
Native `vcpkg-lock.json` caches registry references, not a resolved port graph.
The previously supported `dependencies` object in a supplied JSON file remains
readable as dependency inventory, with unknown activation. It is not the native
vcpkg lock format. Build triplets, feature selection and installed versions
remain unknown.

Maven build/reporting plugins, `pluginManagement` definitions and explicit plugin
dependencies are separate `kind: conditional`, build-scoped configuration
assertions. Default plugin groups, declaring-POM property assertions, source
positions, executions/report sets and profile conditions are retained. Local
parent assertions retain their source; literal inheritance flags are qualified,
including execution-level overrides. These are not a merged effective plugin
model. Management does not activate a plugin or supply a selected version here.
Local parent `relativePath` values may name a POM or a directory; slash and
backslash forms stay within the audited root after resolving `pom.xml`.
Profile-local properties, default lifecycle bindings and configuration bodies
remain unevaluated. Plugin dependencies belong to the plugin/build-extension
classpath and do not satisfy application dependency declarations. Configuration
adds no installed versions, application edges, public version queries or removal
advice from zero Java imports. Build extension inventory, profile application
dependencies and unsupported activation conditions leave explicit coverage gaps.
Maven build resolution remains incomplete even without declared plugins because
implicit lifecycle defaults and the installed graph are uncollected.

Gradle Groovy/Kotlin build files supply positioned literal configuration calls,
including multiline calls, versionless coordinates, classifiers and supported
`platform`, `enforcedPlatform` and `testFixtures` wrappers. Comments and
documentation strings do not add dependencies. Calls retain their lexical
contexts and `kind: conditional`; constraint blocks stay separate. Their
`gradle-required` versions are requests, not selected pins, following
[Gradle's version semantics](https://docs.gradle.org/current/userguide/dependency_versions.html).
Both build files are inventoried when both DSL filenames exist; no active
script is chosen. Executed ownership, settings, plugins, catalog binding and property
maps remain uncollected. Interpolation and unsupported expressions stay
qualified; ambiguous slash syntax and exhausted lexer/context budgets retain
only a qualified prefix. Triple-quoted dependency arguments remain unsupported.

`gradle.lockfile` and `buildscript-gradle.lockfile` retain repeated module/version
instances, configuration names, positions and lock provenance. A later row does
not overwrite another configuration's version. Only these lock assertions can
supply versions for inventory and OSV; source requests alone cannot. Lock
inventory does not establish the active configuration, dependency edges or
installation, so Gradle resolution/security remain incomplete. See
[Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html).
Settings and other Gradle scripts expose uncovered paths and participate in
freshness checks. Gradle Kotlin scripts are excluded from Java
application imports. Query this evidence with `ecosystem: Maven` and the returned
`maven:gradle:<root>` identity. This collection does not execute Gradle.

`*.versions.toml` files provide separate `maven:gradle-catalog:<directory>`
configuration scopes. Files in one directory share a scope, while version and
bundle references remain local to each file. Library aliases retain literal
coordinates, inline/named/rich version assertions, bundle memberships and source
positions. They use `kind: conditional`, `scope: unknown` and
`scheme: gradle-catalog`; even a literal version does not establish an active
build dependency or selected version. Aliases with repeated coordinates remain
distinct; normalized-name collisions stay ambiguous. Text queries match aliases, accessor paths, files and bundle
names before evidence pagination.

Catalog extension names, settings imports, programmatic overrides and script
usage remain unknown. Plugin IDs stay an explicit gap; no Maven marker coordinate
is invented. Arbitrary TOML filenames and imported/published catalogs are not
discovered. Missing/ambiguous references, unsupported fields, malformed inputs
and entry/context budgets leave gaps. Zero source usages do not justify removing
catalog entries. See [Gradle version catalogs](https://docs.gradle.org/current/userguide/version_catalogs.html).

CMake inventory groups each top-level `CMakeLists.txt` directory tree, including
its nested CMake lists, `.cmake` helpers and `*.cmake.in` templates, under
`cmake:cmake:<root>`. These are lexical configuration scopes. Helpers and templates outside those project trees form
separate `cmake:cmake-script:<root>` scopes, grouped by their topmost script
directory. A parent script scope does not absorb nested project files. Each
scope lists all of its input files; an entry point or execution order is not
inferred. Adding a `CMakeLists.txt` can change that boundary, so rediscover IDs
after refreshing. CMake package-name matching is case-insensitive.
Files are collected without evaluating `include`,
conditions or `add_subdirectory`; an unreferenced helper can still contribute an
assertion. Repeated declarations and raw variable/unsupported options remain
distinct. `FetchContent_MakeAvailable` is a configuration request with inferred
provenance. [CMake's first-declaration rules and dependency providers](https://cmake.org/cmake/help/latest/module/FetchContent.html)
can change what is selected, so activation stays unknown. A Git tag or archive
URL does not establish an installed version or package-manager identity. CMake
source/target usage, `ExternalProject_Add` and update previews remain unsupported;
security reports `security.ecosystem-unsupported`.
Literal `find_dependency` calls retain their package name, requested version,
arguments and source location as configuration assertions. Template declarations
also retain `metadata.template: true`. `@...@` arguments remain dynamic, and the
standard standalone `@PACKAGE_INIT@` placeholder is skipped without expansion.
Every template exposes `manifest.unsupported-cmake-template-expansion`: literal
calls do not establish substituted/generated dependencies, exported installation
contents or active selection. Unknown command substitutions and malformed input
can stop collection after earlier assertions. See [CMakeFindDependencyMacro](https://cmake.org/cmake/help/latest/module/CMakeFindDependencyMacro.html).
`CPMAddPackage` and `CPMFindPackage` currently produce source-positioned coverage
gaps; their shorthand and override semantics are not collected.

```bash
depcheck index . --ecosystem CMake
depcheck query . googletest --ecosystem CMake --project cmake:cmake:.
```

For a repository with scripts at its root and no top-level CMake list, use its
script scope after indexing:

```bash
depcheck query . Catch2 --ecosystem CMake --project cmake:cmake-script:.
```

CMake/Cargo/Bzlmod collection, Astro/CSS imports, static command evidence, and
the coverage fields below were added in 0.5.0. The earlier 0.4.0 ZIP predates them.

Bzlmod inventory uses `ecosystem: Bazel` and `bazel:bzlmod:<root>` project IDs.
Each physical `MODULE.bazel` defines a separate declaration scope; native root
selection and availability across modules are not inferred. `bazel_dep` records
use `kind: conditional` and build or development scope, retaining source versions,
explicit `repo_name`, `dev_dependency` and compatibility arguments in metadata.
`repo_name=None` remains a nodep assertion, not an unconditional graph edge.
Single unescaped quoted strings, booleans and integer literals are supported.
Expressions, string escapes/prefixes/concatenation, ambiguous arguments and
uncollected statements leave `manifest.bazel-uncollected`; unknown fields do not
become guessed versions or activation. Syntax errors and token/node/declaration/
context/diagnostic budgets leave explicit gaps. Nothing is evaluated as Starlark.
Includes, overrides, extensions, registry/root/dev/nodep selection and the native
module graph remain unevaluated. `MODULE.bazel.lock`, legacy WORKSPACE, BUILD and
`.bzl` inputs expose uncovered paths. Requested versions do not supply resolved
versions, package-manager ownership, public OSV coordinates or application edges.
Zero build/source usages cannot establish non-use or justify removal. See
[Bazel module declarations](https://bazel.build/rules/lib/globals/module#bazel_dep).

Cargo preserves manifest constraints separately from locked versions. A bare
`"1.2.3"` requirement is a range; `"=1.2.3"` is exact. Workspace locks are a
superset of member, feature, and target possibilities. Query that inventory
without treating it as the deployed graph. Only verified crates.io coordinates
are sent to OSV; Git, path, alternate-registry, and ambiguous evidence stays
qualified. Exact lock versions follow Rust SemVer rules, including valid alpha,
beta and rc suffixes and build metadata. Malformed or overflowing versions leave
security coverage incomplete and do not supply public query coordinates.
Cargo update previews remain unsupported.

Owned `.rs` files supply literal `extern crate`, simple `use` and crate-path
candidates. Manifest aliases and hyphen-to-underscore names map to inferred
owners; known local shadows or conflicting declarations retain unknown owners.
Comments and string/character literals are skipped. References keep Unicode
source positions, unknown scope and conditional confidence. Module/target/cfg
selection, macros, generated code and custom library names remain unevaluated.
Virtual workspaces do not acquire application source ownership. Rust usage and
mapping coverage stay incomplete, so zero references cannot justify removal.

Legacy Cargo `dev_dependencies` and `build_dependencies` tables retain their
original spelling, scope and positions, including target-specific declarations.
Before edition 2024, a canonical table takes precedence even when empty; the
shadowed legacy declarations remain configuration inventory. Edition 2024 rejects
these aliases. Unknown or unresolved inherited editions retain an explicit gap
instead of supplying direct dependency evidence. The legacy `[project]` package
alias follows the same edition boundary, with `[package]` taking precedence.
These are static manifest rules; they do not establish an installed graph.
See the [Rust edition migration guide](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-table-key-names.html).
Legacy `default_features` fields remain retained but uninterpreted.

Dynamic or ambiguous syntax produces incomplete evidence. Security scanning for
Conan, vcpkg and CMake return `security.ecosystem-unsupported`: depcheck cannot map
these packages to OSV coordinates, so their security results remain incomplete.

For pnpm v9, each project reads its importer from the nearest `pnpm-lock.yaml`
inside the repository. Registry versions, peer instances, and dependency edges
(including optional dependencies) feed inventory, OSV queries, and CycloneDX.
Local workspace links, file/Git/URL resolutions, other lock versions, and
manifest/lock mismatches produce incomplete-resolution diagnostics. Yarn application
resolution remains unsupported. Lockfiles are read as bounded YAML data; aliases, duplicate
keys, and executable tags are rejected.

## CLI installation

Python 3.11 or newer is required. CI tests Python 3.11 and 3.12.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/depcheck --version
```

On Windows, use `.venv\Scripts\python.exe` and `.venv\Scripts\depcheck.exe`.
Install `.[agent]` to add MCP support, or follow the locked setup above. For the
development and test environment, see [Development](#development).

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

SARIF uses percent-encoded repository-relative paths with the symbolic
`%SRCROOT%` base. Consumers map that base to their checkout; this mapping omits
the local checkout directory. Diagnostic messages retain provider text and may
contain paths. Files explicitly outside the repository keep
absolute file URIs and remain distinct from repository files with the same name. Known diagnostic
locations retain file/line/column evidence. An alert without a known location uses
its project's manifest when available; otherwise it retains an empty location list
and `depcheck:location-status: unavailable`, rather than inventing a file.
SARIF projection does not reread or resolve source paths or serialize unrelated
inventory. Coverage and invocation completion retain their existing qualifications.
Columns count Unicode code points, starting at one. Python AST byte offsets are
converted before storing import and dynamic-load evidence; cached positions use
the same units. Static AST readers use captured text without letting CPython
reopen the target filename for error context. SARIF declares
`columnKind: unicodeCodePoints` and CRLF/CR/LF
newline sequences. Refresh indexes created before analysis revision 53.

Notebook JSON evidence retains virtual line coordinates for the concatenated code
cells, with code-point columns within each cell. These are not physical JSON
locations. SARIF retains a file-only physical location and records virtual
coordinates under `depcheck:reported-region`, qualified by
`depcheck:region-status: notebook-virtual`. A cell with invalid Unicode leaves a
syntax diagnostic while readable cells remain available. Cell-to-JSON character
mapping and native notebook execution remain unsupported.

GitHub requires a real source location to display an alert. Its supported
fingerprint is `primaryLocationLineHash`; depcheck does not generate that hash.
Use the upload action's source-based fingerprint generation when needed. Schema
validation and local examples do not establish acceptance by GitHub's ingestion
service. See the [SARIF support guide](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

Build and query the local index:

```bash
depcheck index .
depcheck context .
depcheck query . requests --ecosystem PyPI --project pypi:python:. --limit 20 --offset 0
depcheck explain . requests --ecosystem PyPI --project pypi:python:.
depcheck impact . requests --ecosystem PyPI --project pypi:python:.
```

Queries reject stale indexes. Run `depcheck index .` again after changing source,
manifests, or configuration. A corrupt SQLite cache produces a command error;
move `.depcheck/index.sqlite3` aside and rebuild it with `depcheck index .`.

Inventory queries return pages. Follow non-null `next_offset` with `--offset`
and the same filters. `count` is the dependency count in that page.
Declarations, resolutions, usages, imports, findings and impact files have a
separate `evidence_page`, with full `counts` and its own `next_offset`. Use
`explain` with the qualified identity and `--evidence-limit 20 --evidence-offset 0`
to traverse those lists. Supported evidence limits are 1–100. `impact.usage_count`
and scope totals cover all observed usages, even when its detail page is partial.
`inventory_truncated` and `evidence_truncated` distinguish the two limits;
`truncated` is true when either is partial.

Query/explain/impact responses have a 256 KiB JSON budget and can reduce the
effective evidence page size to fit; follow the returned offsets. All MCP tool
responses use that budget. An oversized indivisible result returns
`response.budget-exceeded` instead of silently dropping evidence. A scan/index
tool may already have refreshed the cache before this output error; inspect
context or export `depcheck scan . --offline --format json --output .tmp/scan.json`
with the selected repository root for a full local report.

CLI `scan` prints a report without refreshing the index. Run `depcheck index .`
before indexed queries when context reports a missing or stale index. MCP
`scan_repository` performs that refresh as part of its operation.
It reuses the scan evidence for indexing. File-read digests and a topology/control
guard reject changes observed during collection before replacing the cache.

Compare two scans from the same repository and scan selection:

```bash
mkdir -p .tmp/snapshots
depcheck scan . --offline --format json --output .tmp/snapshots/before.json
# After the authorized dependency change and its verification:
depcheck scan . --offline --format json --output .tmp/snapshots/after.json
depcheck compare . .tmp/snapshots/before.json .tmp/snapshots/after.json --limit 20
```

Comparison preserves qualified versions, instances, edges, and repeated
declarations. It requires matching analysis revisions, repository identity and
selection settings. Older reports without that metadata return
`snapshot.incompatible`. Repository identity defaults to a hash of the local
absolute path. To compare checkouts or CI artifacts, configure the same explicit
`repository-id = "team/repository"` in each checkout's `.depcheck.toml` before
scanning. This is a user assertion of identity, not authenticated provenance.
Different IDs, revisions or selection settings remain incompatible.
Inventory and security completeness are separate.
Changes describe static observations; `remediation_verified` remains false.
Each change collection uses the same `offset` and `limit`. Follow `next_offset`
until null and retain the total `counts` when reporting a full comparison.

Inspect a CycloneDX JSON inventory without adding it to the source index:

```bash
depcheck scan . --offline --format cyclonedx-json --output .tmp/snapshots/bom.json
depcheck sbom . .tmp/snapshots/bom.json --limit 20 --offset 0
```

The supported import profile reads CycloneDX JSON 1.4–1.7 components, application
edges and dependency references. It retains reported package identities,
depcheck project/instance properties, input SHA-256 and generator names/versions.
Components also retain `component_type`, CycloneDX `scope`, license assertions
and source `properties`. Repeated properties keep their original order. License
IDs, names and expressions are reported values; no license compatibility check
has run.

Package URLs are parsed with `packageurl-python`. Each component preserves the
original `purl` and decoded `package_url` fields, including namespace, qualifiers
and subpath. Qualifiers and subpaths also remain in `identity`; repository URLs,
Maven classifiers and package-internal paths cannot silently disappear into a
package/version key. These additional identity dimensions produce
`sbom.identity-qualified` and leave inventory/resolution incomplete within the
local profile. npm and Go coordinate casing is preserved; PyPI names use Python
distribution-name normalization. Duplicate qualifier keys, invalid percent/UTF-8
encoding, control characters, invalid supported namespace shapes and dot/slash
subpath segments are rejected. Unsupported PURL types retain their parsed fields
with `sbom.purl-type-unsupported`; they do not acquire an ecosystem mapping.
Parsing does not verify that a package exists or that a reported repository is
public or trustworthy. See the [PURL specification](https://github.com/package-url/purl-spec).

Trivy application nodes with one `aquasecurity:trivy:Class=lang-pkgs` property,
one non-empty `aquasecurity:trivy:Type` property and no package URL or depcheck
identity properties are returned as `kind: "dependency-group"`. Other entries
retain `kind: "package"`. All entries remain in component pagination. A group's
name and properties describe its reported manifest or artifact, and packages
list incoming group references in `dependency_groups`. Group edges preserve
context without establishing direct package ownership. Groups have unknown
`direct` status and do not need a package coordinate or version. Other unknown
identities and versions still make evidence incomplete.

Unknown identities or versions, conflicting versions, nested assemblies and
dangling edges produce diagnostics. This is external SBOM evidence with
`identity_provenance: "sbom-asserted"`; usage is unsupported and security is
skipped. It does not inspect the corresponding binary or verify the publisher.
Follow component pagination to inspect the whole inventory. Both new commands
read explicitly named relative files within the repository, reject aliases and
ambiguous JSON keys, enforce the 8 MiB input limit, and leave the index unchanged.

Inspect an existing CMake File API reply without configuring or building:

```bash
depcheck cmake-model . build/.cmake/api/v1/reply/index-selected.json \
  --configuration Debug --limit 20 --offset 0
```

Choose an actual `index-*.json` file explicitly; depcheck does not choose the
newest reply. The index must reference one codemodel version 2 object. Select
`--configuration` when it contains multiple configurations; `--target` accepts
an exact target ID from that configuration, including an abstract target.

The `depcheck.cmake-model.v1` result keeps `targets` and `abstractTargets`
identities, reported target flags, source paths and command fragments. Legacy
`dependencies` describe build ordering, including transitive edges. Codemodel
2.9 adds separate linking, compilation, object and ordering relationships;
their absence in older replies does not prove that a target has no links.
Abstract/imported/interface targets do not establish buildable targets or
package-manager identities. Sources and interface sources retain distinct
collections, generated assertions, indices and JSON-pointer locations.

All result tables share the returned `offset` and effective `limit`; the service
caps pages at 50 by default. Follow `next_offset` until null. `counts` retain
table totals. Target references can
remain present with unavailable or unselected details. Invalid target details,
inconsistent version fields, unresolved IDs and budgets produce diagnostics
while retaining readable neighboring records. `import_complete` concerns this
supported projection; `evidence_complete` remains false. Directory objects,
compile groups, interface include directories, resolved backtrace graphs,
artifact contents and installed packages are outside that projection.

Reply JSON files must stay inside the repository and referenced `jsonFile`
values must be plain filenames. Reads are limited to 8 MiB per file, 16 MiB
total and 1024 file attempts, with bounded arrays, result records and diagnostics.
Reported paths and shell fragments remain inert data; depcheck does not open
the source paths, execute commands or change the index. Input SHA-256 hashes
identify the bytes read, without authenticating their producer or establishing
source freshness. Build execution stays unknown, package mapping unsupported
and security skipped. See the [CMake File API specification](https://cmake.org/cmake/help/latest/manual/cmake-file-api.7.html).

Preview an update without changing the manifest:

```bash
depcheck update . "requests==2.32.4" \
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
      "advisory_ids": ["GHSA-example-reviewed-advisory"],
      "versions": ["2.31.0"],
      "reason": "Upgrade is scheduled",
      "owner": "platform",
      "expires_at": "2027-01-31"
    }
  ]
}
```

Pass it with `--policy policy.json`. Invalid, expired, or unmatched exemptions
remain observable; invalid and expired exemptions fail governance evaluation.
`advisory_ids` matches the finding ID or an alias and requires `risk: "vuln"`.
`versions` matches exact version strings; unknown versions do not match.
Each optional selector accepts 1–100 non-empty strings. When both are supplied,
both must match. Omitting them preserves the existing package-wide exemption.
Raw findings, security evidence and SBOM inventory remain available.

Explicit pyproject previews select static PEP 621 dependency groups:

```bash
depcheck update . "requests==2.32.4" --file pyproject.toml --group project
depcheck update . "requests==2.32.4" --file pyproject.toml --group optional:test
```

Without `--file`, updates continue to preview requirements files. With an
explicit pyproject file, omit `--group` only when each requested package has
one group; repeated packages across groups return `update.ambiguous-target`.
Previews preserve supported single-line string formatting and do not write
manifests or locks, apply upgrades, or establish compatibility. Dynamic
requirements, URL/VCS entries, multiline strings, and other dependency tables
remain unsupported. Invalid input returns `update.invalid-target`.

Previews select the owning Python component. Pass its returned `project_id` or
an explicit file when multiple components exist; unqualified updates return
`update.ambiguous-target`. Aliased update targets are rejected at the service
boundary. The `handoff` object records readiness, blocking reasons, baseline
coverage, source digests and pending verification. A group means the packages
were requested together; coupling stays unknown. `ready` means the preview can
be handed to maintenance. Runtime/package-manager pin checks, locked installation,
graph validation and tests remain `not-run` until that workflow executes them.

## Configuration

Use `.depcheck.toml` at the repository root:

```toml
security = false
compatibility = false
python-version = "3.12"
enabled-ecosystems = ["PyPI", "npm", "Go", "Maven", "Conan", "vcpkg", "Cargo", "CMake", "Bazel"]
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

For anonymous Python components, set `python-roots = ["services/api", "tools"]`
before any TOML table. These explicit installation scopes use repository-relative
project IDs and exclude nested components from their parent's source collection.
Named pyprojects continue to establish component roots automatically. uv members
retain separate source/declaration ownership, while shared lock activation and
cross-member availability remain unknown. Neither configured scopes nor uv
inventory prove which environment was installed.

Declare a dependency's use as a CLI, build tool, or plugin in `.depcheck.toml`
when source imports do not show that use:

```toml
[[tool-usage]]
ecosystem = "PyPI"
project-id = "pypi:python:."
package = "ruff"
scope = "test"
reason = "Runs as the lint command in CI"
```

Each entry requires an ecosystem, exact project ID, package, scope, and reason.
Scopes are `runtime`, `development`, `test`, or `build`. Tool usage is
`configured` evidence: it records your declaration, not an observed command
execution. Query explanations retain its `kind: "tool"`, confidence, reason,
and configuration location in `usages`; `imports` lists source evidence.
Impact includes both forms of usage. Tool declarations preserve dependency
inventory, security coordinates, and SBOM components. Unmatched package entries
produce `config.tool-usage-unmatched` warnings within the selected project.

Use policy exemptions for temporary finding exceptions. An `unused` exemption
changes policy evaluation while retaining raw findings and security evidence.
`ignore-packages` removes the package's evidence, including resolved versions,
so it also removes that package from security checks and SBOM output.

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

The current source uses analysis revision 57 and index schema
`depcheck.index.v4`, with package version 0.5.0. Rebuild older
indexes with `depcheck index .`; queries do not migrate them.

Index refresh discards and rebuilds incompatible SQLite caches. Queries open the
cache read-only and report when a rebuild is needed. Source files and manifests
are never changed by scanning or indexing.

Inventory records, dependency explanations, and impact results also expose
`evidence_complete` and `usage_complete`. They describe the collected project
evidence. A zero usage count still needs review against command, plugin, and
deployment configuration, even when these fields are true. Check scan
`capabilities.security` separately before making a vulnerability claim.

`explain` and `impact` also return `origins`: paths from owning direct declarations
to resolved package instances, with versions and installation locations intact.
Use `--origin-limit 20 --origin-depth 32` (MCP: `origin_limit`, `origin_depth`);
supported ranges are 1–100 paths and 1–64 nodes per path. Missing or ambiguous
edges, unrooted instances and traversal limits leave this section incomplete.
Cycles do not repeat nodes in a path. Origin completeness does not establish
usage, installed activation or security completeness.

Index freshness, evidence coverage, policy status, and security status answer
different questions. A fresh index can contain incomplete evidence. An offline
scan can pass its configured policy while reporting skipped security.

## MCP and agent integration

The 0.5.0 stdio server exports eighteen tools. The earlier 0.4.0 bundle has the
original seven tools, from `index_repository` through `plan_dependency_updates`.
Upgrade the backend and Skill together to use the additional tools.

- `index_repository`
- `scan_repository`
- `repository_context`
- `query_dependencies`
- `explain_dependency`
- `dependency_impact`
- `plan_dependency_updates`
- `compare_dependency_snapshots`
- `inspect_dependency_sbom`
- `inspect_cmake_model`
- `inspect_evidence`
- `reevaluate_vulnerabilities`
- `analyze_python_calls`
- `export_evidence`
- `compare_inventories`
- `compare_package_behavior`
- `compare_package_names`
- `verify_registry_package`

The server uses explicit `--allow-root` arguments first, then
`DEPCHECK_ALLOWED_ROOTS` (separated by the platform's path separator), then
the MCP client's local roots. Requested paths must stay inside those roots.
Query tools accept `ecosystem` and `project_id`
qualifiers; ambiguous unqualified names return structured choices. Update
planning is read-only. `scan_repository` runs offline and therefore reports
security as skipped.

MCP tool annotations distinguish read-only queries/previews from operations
that replace the local `.depcheck` cache.

Plugin descriptors are provided in `plugin.json`, `.codex-plugin/plugin.json`,
`mcp.json`, and `.mcp.json`. The coding-agent workflow is in
`skills/check-dependencies/SKILL.md`.

## Safety boundary

Repository files are parsed as data. depcheck does not evaluate `setup.py`,
load target modules, or invoke pip, npm, pnpm, yarn, Go, Maven, Gradle, Conan,
vcpkg, Cargo, CMake, Bazel, Starlark, or build scripts. Source and shared ecosystem discovery reject
symlinked evidence; legacy Python manifests and configuration can follow links
that resolve within the project. Content reads use pinned directory handles and
regular-file snapshots, rejecting symlinks introduced between validation and
opening. Default caches reject directory/file aliases and hard-linked databases.
Default SQLite caches use an in-memory snapshot and in-memory temporary storage;
`TMPDIR` and `SQLITE_TMPDIR` cannot redirect that work to repository files.
Refresh publishes the completed cache through the pinned parent; queries leave
the existing cache unchanged. This requires SQLite serialization support and a
build that permits in-memory temporary storage; unsupported builds return an
operation error. Explicit library cache paths are a separate capability granted
by the embedding caller.

Content readers, configuration, update previews, and evidence hashing limit
individual files to 8 MiB. The derived SQLite snapshot has a 128 MiB limit.
Oversized evidence is rejected with a diagnostic or operation error; partial
bytes are not treated as a complete file. YAML and commands have additional
limits. There is no total repository size or processing-time budget.

When security is enabled, scans send qualified ecosystem, package name and exact
version coordinates to OSV. Python compatibility analysis accesses PyPI when
enabled by `--compatibility` or configuration. Use `--offline` to disable both
scan stages' network queries. The separate `registry` command requires explicit
`--allow-network`; its request is limited to the selected public PyPI/npm
coordinate. Supplied-evidence inspection does not fetch linked resources.

Context checks can run installed Git and GitNexus executables. depcheck rejects
executables inside the scanned repository and limits their runtime, but these
helpers run with the host user's permissions and are not sandboxed by depcheck.
Their metadata commands use an empty input stream so they cannot consume the
MCP protocol input.

## Analysis limits

Discovery excludes common generated and installed-package directories, including
`.tmp`, `node_modules`, `site-packages`, and `dist-packages`. It does not interpret
`.gitignore`. Use scoped `excluded-directories` settings or a stated source
snapshot when ignored artifacts should be outside the audit.

`scope.repository_complete` describes the index selection within registered
ecosystems. Scan `metadata.coverage` and context `coverage` list recognized
uncovered paths and reasons, independently of that selection. Unregistered
PHP, Ruby, Dart, and .NET manifests prevent a complete repository conclusion.
The list concerns recognized formats; an empty list does not prove support for
every file format. Browser/CDN dependencies remain outside the packs.
SCSS and Sass produce `usage.unsupported-source`. Vue and Svelte support bounded
literal top-level JavaScript/TypeScript script and CSS style regions, including
source positions and npm aliases. Template expressions, implicit framework
imports and compilation stay incomplete (`usage.unsupported-component-template`).
Extraction stops after template expressions can hide subsequent markup;
preprocessors and custom attributes remain qualified. See the
[Vue SFC specification](https://vuejs.org/api/sfc-spec.html) and
[Svelte file structure](https://svelte.dev/docs/svelte/svelte-files).

Astro frontmatter and literal imports in supported script/style regions retain
source locations and npm installation aliases. Template expressions and the
remaining template after the first expression are unparsed, preserving known
frontmatter imports while leaving usage incomplete. Browser scripts, external
URLs, inline styles, and style preprocessors remain qualified. `astro:` virtual
modules do not become npm package names.

CSS supports literal top-level `@import` strings and quoted or bare `url()`
targets. A safely discovered local file takes precedence over a package name.
Only a declared npm installation or scoped mapping establishes a package owner;
unknown names and external URLs remain unknown. Escapes, computed imports,
nested imports, and dependency-bearing preprocessor/plugin directives produce
diagnostics. A declared Vite, Astro, webpack, or Rollup tool and its root
configuration file establish build scope for CSS imports. Otherwise
`usage.unsupported-css-scope` preserves unknown scope and incomplete usage;
CSS imports alone do not require moving devDependencies into dependencies.
Asset `url()` values are not package imports. See the
[Astro script rules](https://docs.astro.build/en/guides/client-side-scripts/) and
[Vite CSS imports](https://vite.dev/guide/features.html#css-import-inlining-and-rebasing)
for the bundler behavior this collection models.

Projects with locks from more than one of npm, pnpm and Yarn produce
`resolution.package-manager-ambiguous`. Resolution remains incomplete, and no
single lock graph supplies exact versions for queries or OSV. A `packageManager`
pin does not resolve conflicting committed graphs. Confirm the intended manager
and lock before making changes; depcheck does not delete or regenerate either.
For npm's two lock formats, `npm-shrinkwrap.json` takes precedence over
`package-lock.json`, following the
[npm lockfile rules](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

npm inventory retains declaration and lock `origin` assertions. Git, local,
download URL, alternate-registry and unknown sources do not supply public npm
PURLs or OSV coordinates. Public advisory matches belong only to eligible
instances, including when a private instance has the same name and version.
Skipped instances keep security incomplete; their inventory and graph evidence
remain available. npm v1/v2/v3 locks and shrinkwrap retain these distinctions.
pnpm registry instances use the same configuration evidence; unsupported pnpm
source forms still leave explicit resolution gaps.

Yarn Modern lock versions 8 and 10 have separate `npm:yarn-lock:<root>` inventory
scopes, including standalone locks. Each descriptor retains its literal request,
the locator/version assertions and the physical record position. Repeated and
grouped requests retain their multiplicity; aliases retain their installation
names. Dependency and peer requests, optional/build metadata, conditions, checksums,
link types and cache keys remain uninterpreted assertions. Unsupported record
fields are omitted with a diagnostic. Invalid records and entry/context limits
retain readable prefixes and explicit coverage gaps.

These scopes do not establish application/workspace ownership, registry selection,
peer virtualization, PnP, installation or source usage. They add no selected
versions, public advisory queries or direct application SBOM edges. Patches, local
and Git locators retain their assertions without becoming public npm identities.
Classic locks and other Modern format versions remain unsupported. See the
[Yarn lock writer](https://github.com/yarnpkg/berry/blob/e4e423a1eb117b5129f20ac626a03eb7a97aedff/packages/yarnpkg-core/sources/Project.ts)
and [descriptor/locator definitions](https://yarnpkg.com/advanced/lexicon).

Exact npm lock coordinates require canonical SemVer text within node-semver's
256-character limit and safe-integer limit of `2**53 - 1` for each release
component. Prereleases such as `1.0.0-alpha.1`, `1.0.0-beta.0` and `1.0.0-rc.1`
remain valid. Numeric prerelease identifiers cannot have leading zeroes; build
metadata may contain them. Git tag prefixes do not establish package versions.
Invalid npm lock versions retain their raw inventory and incomplete source
state without public queries. Invalid pnpm snapshot keys
leave explicit gaps while supported neighbors remain available. Dependency
request ranges and tags are not normalized by this validation. See
[SemVer 2.0.0](https://semver.org/) and
[node-semver limits](https://github.com/npm/node-semver/blob/v7.5.4/internal/constants.js).

The bounded `.npmrc` reader collects only default and scoped registry settings
inside the audited root, with positions. Authentication settings are omitted;
new origin fields remove URL credentials, query strings and fragments. A default
registry URL in an npm lock is interpreted with the repository's registry
assertions, following npm's configured-registry convention. Missing `resolved`
fields can retain a registry assertion for a canonical version. Without a
repository override, the assertion is npm's public default. This describes
static configuration, not verified package visibility or an installed registry.
User/global files, environment expansion and command-line overrides are not read
or evaluated. Indirection, aliased configuration paths, malformed or bounded inputs and conflicting
ancestor/duplicate candidates remain unknown; workspace precedence is unevaluated.
Registry inputs and their creation/removal invalidate cached evidence. See
[npm registry configuration](https://docs.npmjs.com/cli/configuring-npm/npmrc/).

Python pyprojects with a literal PEP 621 or Poetry project name establish
component roots. Each component owns its nearest manifests, locks and sources;
nested components cannot supply each other's local modules or command usage.
IDs are repository-relative, such as `pypi:python:apps/api`. Scanning `apps/api`
as the repository root gives that component `pypi:python:.`. Read the returned
identities rather than carrying an aggregate ID into a split repository.
If the old `pypi:python:.` ID disappears, update matching `[mappings.PyPI]`
tables and `[[tool-usage]]` entries in `.depcheck.toml` to their owning component
IDs. Scans reject that orphaned scope and list the available IDs. Keep a rule
only in components whose configuration supports it. When a root Python project
still exists, `pypi:python:.` applies to that root alone. Component-root scans
continue to use `pypi:python:.` within their selected root.
Anonymous pyprojects without explicit `python-roots` retain conservative aggregate
handling; multiple dependency-bearing roots produce
`analysis.python-component-scope-ambiguous`. uv members keep component IDs and
`resolution.uv-workspace-activation-unknown`; the shared lock inventory does not
establish a member's active graph. See [uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/).
After updating scoped configuration, run `depcheck index .` to rebuild the
derived cache with the current analysis revision. A failed refresh leaves the
previous cache intact; queries reject it while it is stale. Index refresh replaces old
project rows; schema v4 stores Python requirement/resolution origins. Queries
reject older schemas without writing them; indexing rebuilds the derived cache.
Component indexing currently
rescans evidence rather than reusing individual Python parse results.
Unchanged selected-index queries check content digests, file topology and
ownership controls without reparsing evidence. A changed guard falls back to
the full selected scan. Queries keep the cache read-only; freshness is never
inferred from modification times alone.
Compiled `requirements*.lock` and `*-requirements.lock`
files retain exact versions and requirement markers, including multiline hash
options. Locks are evidence sources; update previews target supported text
requirements or explicit static PEP 621 groups.

PEP 735 dependency groups compare names after normalization while retaining their
original spelling in `metadata.group` as `dev:NAME`. Includes preserve list order,
repeated occurrences and the original requirement location. Reaching one physical
assertion through multiple includes does not by itself create a duplicate-source
finding. Separate source declarations and their columns remain distinct.
Colliding/invalid names, non-exact include tables, missing targets, cycles and
entry/context/diagnostic limits leave explicit gaps. Group declarations do not
establish which groups were installed. Update previews still cover requirements
text and supported PEP 621 entries. See the [dependency groups specification](https://packaging.python.org/en/latest/specifications/dependency-groups/).

Legacy `tool.uv.dev-dependencies` strings are collected in the development group,
alongside standard `dependency-groups.dev` declarations. Their original locations,
markers, extras and source assertions are retained. Following uv's behavior,
legacy entries are appended after standard includes are expanded: another group
that includes `dev` does not inherit those legacy entries. Invalid entries retain
diagnostics and valid siblings; the shared group budgets still apply.
Neither form establishes installed selection or supports an update preview.
See [uv's legacy development dependencies](https://docs.astral.sh/uv/concepts/projects/dependencies/#legacy-dev-dependencies).

Constraint intersections are checked within each declared Python development
group, including its expanded includes. A group-local conflict retains that
group in the finding details. Incompatible requests across development groups,
or between those groups and runtime scope, produce
`analysis.python-group-selection-unknown` when no group-local conflict is proven.
This keeps hygiene incomplete without asserting an active-environment conflict.
Installer rules, uv conflict/default-group settings and actual group selection
remain unevaluated; these checks do not validate native lock generation.
Different PEP 508 marker predicates leave their joint applicability unknown;
marker overlap is not solved. A conflict under one shared predicate retains it
in finding details, without establishing that it is active.
Analysis diagnostics survive indexing, and a project with an analysis error
retains `evidence_complete: false` in dependency queries. Source-usage completeness
is reported separately.

Python declarations and lock entries retain static source assertions. Explicit
uv lock sources must identify public PyPI before supplying OSV coordinates;
local/editable paths, Git, private registries and unknown sources keep versions
in inventory without asserting a public package URL. Resolution and security
remain incomplete for those sources, and public PyPI compatibility checks skip
them. Conflicting declared uv sources conservatively block public lock lookup.

uv locks retain bounded environment and fork context in `origin.lock`: format
version/revision, Python constraints, root/package resolution markers,
supported/required environments, conflicts and dependency/extra/group assertions.
Each physical entry has a distinct `lock:uv:` instance, even for repeated
name/version pairs. Conditions are retained as data; the scanner does not use
the agent's OS or an explicit Python version to choose an installed branch.
Conditional inventories keep resolution incomplete and return
`compatibility.uv-lock-selection-unknown` instead of selecting one version,
reporting a flat version conflict or suggesting an upgrade from that graph.
Known public versions may still be checked separately against OSV; affected
candidate findings retain `lock_context` and `activation: "unknown"`.
CycloneDX preserves origin context without adding inferred application edges.
Unsupported field shapes and context/package limits produce explicit gaps.
Refresh indexes older than analysis revision 45. See
[uv's universal resolution](https://docs.astral.sh/uv/concepts/resolution/#universal-resolution).

Source-qualified instances remain distinct in snapshots/SBOMs; CycloneDX also
retains `depcheck:source:origin`. This does not prove installed provenance.
See [uv dependency sources](https://docs.astral.sh/uv/concepts/projects/dependencies/#dependency-sources).
Pipfile and Pipfile.lock use literal named index selectors and their configured
default source. Private, missing or duplicate source names remain unverified;
they do not silently acquire public PyPI coordinates. Local and Git assertions
retain their source fields. See [Pipenv index restrictions](https://pipenv.pypa.io/en/latest/indexes.html).

Maven versions inherited from unavailable parents or BOMs remain unresolved.
Literal child declarations survive a mismatched local parent, while the evidence
stays incomplete. Review local reactor SNAPSHOT versions in their build context.
Declared Maven build/reporting plugins are collected as conditional configuration
inventory. Effective plugin merges, lifecycle/profile activation, execution, and
parts of Java namespace ownership remain unknown.

Declaration locations in `pyproject.toml`, Pipfile, supported Python locks,
`setup.cfg`, literal `setup.py` lists/tuples, `package.json`, and `pom.xml` retain
line and column positions, including repeated declarations, group includes and
inherited Maven evidence. Structural positions refer to the parsed input;
interpolated or unmatched values keep file-only locations. Invalid
setup.cfg interpolation is reported, and duplicate Pipfile.lock object keys are
rejected. Related parse diagnostics use the entry's location where available. JavaScript
uncertainty reports the first unsupported construct and its reason; unresolved
namespace diagnostics identify the project and representative source reference.
Some legacy manifests and lock records still have file-level locations. Some
Python lock formats beyond the retained uv context still have uncollected
variant conditions; inspect the original lock before interpreting multiple
versions as an installed conflict.

Python import names without a configured or built-in distribution mapping remain
`inferred`; they do not establish a missing dependency. Add a scoped mapping when
you know the distribution name.

Literal `package.json` scripts and GitHub Actions `run` fields can provide
`usages.kind: "command"` evidence for a fixed set of declared test/build tools.
It has exact command-to-package mapping, a configuration location and a reason;
it is not an observed import or proof of execution. Workflow working directories
must identify the owning project. Supported prefixes include bounded `uv run`,
`python -m`, and local npm/pnpm/yarn script references. Unknown executables,
shell control flow, dynamic directories, and script cycles leave usage
incomplete. Commands are included in impact counts and excluded from `imports`.
Configured `kind: "tool"` evidence retains its separate user-provided reason.

Literal tsconfig `types`, `extends` and plugin names, plus pytest `addopts -p`
and `required_plugins`, can provide `kind: "configuration"` usage. Explanations
keep configuration locations and reasons; these entries are excluded from
source `imports`. TypeScript JSONC comments and trailing commas are accepted.
Local inheritance stays inside the repository and has file/depth limits.
Package-provided configuration, custom type roots, unsupported values and unknown
pytest plugin mappings leave usage incomplete. The scanner does not load
configuration modules or infer that a configured tool ran.

Inherited pnpm locks require workspace membership evidence. The nearest
`pnpm-workspace.yaml` forms a boundary, even without a lock. Supported literal
workspace patterns include `*`, `?`, `**` and exclusions. Extglobs and other
unsupported forms preserve unknown ownership. npm `workspaces` and stale pnpm
importers alone cannot confirm an inherited active pnpm graph. An unrelated
parent lock is excluded from an independent child's lock selection.

Non-literal Python module loads produce `usage.dynamic` diagnostics and suppress
unused-dependency conclusions. Literal `importlib` calls, including imported
aliases, retain usage evidence. Local-module detection uses top-level names in
the repository and its `src` directory; arbitrary Python path changes are not
resolved.

Exact `package.json` imports string keys support bare npm packages and subpaths,
safely discovered local files, and bare Node builtins such as `"fs/promises"`.
The target `"node:fs"` is invalid in that field, although source imports can use
it directly. Conditions, arrays, nulls, wildcards, alias chains, and unsafe or
absent local targets retain unknown usage with `mapping.alias-unsupported`.
Scoped configured mappings take precedence. TypeScript paths and full Node
resolution are not implemented.

Installation aliases such as `"safe-name": "npm:lodash@4.17.20"` retain their
local names for import matching and use the registry name for inventory,
vulnerability queries, and SBOMs.

Malformed dependency fields
or lockfile structures make evidence incomplete. Security still checks known
versions, but reports `security.collection-incomplete` if manifest or resolution
coverage is incomplete.

Python compatibility uses bounded resolvelib backtracking over public release
metadata. `resolution_status` distinguishes `resolved`, `unsatisfiable` and
`incomplete`; missing metadata or exhausted budgets cannot establish an
unsatisfiable graph. Runtime requirements are selected by default; add
`--dependency-group dev:test` or `--dependency-group optional:docs` to select
additional groups in each selected Python project. Extras add their dependencies
to the base dependencies; their versions and Requires-Python constraints
participate in backtracking. Markers without a supported evaluation context
retain an incomplete result rather than crashing or establishing compatibility.
Non-public homonyms are blocked. A selected graph
does not establish wheel availability, installation or API compatibility.
Non-Python indexing still rescans selected evidence rather than reusing
individual parsed files. `depcheck --profile index ROOT` writes inclusive local
work measurements to stderr; nested durations overlap and must not be summed.

PEP 723 scripts have independent `pypi:pep723:path/to/script.py` identities.
Only actual comment blocks are read; examples inside strings are ignored.
Declarations retain positions, markers, extras and interpreter assertions.
Script source ownership does not absorb adjacent scripts or project requirements.
Runner locks, interpreter selection and imported local helpers remain unknown;
unobserved imports do not justify removing a script dependency.

Supplied CVE/CWE, VEX, attestations, call graphs, govulncheck streams, runtime,
artifact, ABI, deps.dev and Scorecard records have separate read-only inspection
interfaces. Offline OSV reevaluation, static Python callable propagation,
package-script comparisons, inventory comparison and unsigned provenance/policy
exports are described in the Skill's
[external evidence reference](skills/check-dependencies/references/external-evidence.md).
These operations do not suppress existing findings or install target packages.
Public registry existence checks require an explicit network flag and do not
establish publisher trust or package safety.
Offline OSV matching separates affected-version membership from fix availability,
retains per-advisory reasons, and normalizes supported ecosystem version equality.
Unsupported negative evidence stays unknown. Package-less Git assertions remain
unmapped; the tool does not clone repositories to infer package identity.

Use `repository_context.runtime_capabilities` or a project's
`supported_capabilities` to check which operations its ecosystem pack supports.
The project's `capabilities` report the state of indexed evidence. Update previews
support version entries in `requirements*.txt` and explicitly selected static
PEP 621 groups in `pyproject.toml`; other targets return diagnostics.

OSV `fix_versions` retain the matching package's raw fixed boundaries.
`fix_version` is a forward candidate for the queried version, using PEP 440 for
PyPI `ECOSYSTEM` ranges and SemVer precedence for `SEMVER` ranges. A candidate
must fall outside every comparable affected range and explicit affected-version
list in that advisory or its alias group. Reintroduced vulnerabilities and
parallel maintained branches therefore do not turn an earlier fix into a
downgrade suggestion.
`fix_version_status: "unknown"` preserves unsupported ordering, missing fixes
and unconfirmed range applicability. Invalid or over-budget detail data keeps
the matched advisory ID and a diagnostic. A candidate does not establish an
available release, dependency compatibility or safety against other advisories.
See the [OSV range evaluation rules](https://ossf.github.io/osv-schema/#evaluation).

OSV detail reuse follows `querybatch` modification times, including nanosecond
precision. Newer revisions trigger a refresh. Missing or invalid revision hints
cannot authorize reuse across calls; older details and failed refreshes retain
matched advisory IDs with diagnostics. Withdrawals that have taken effect are
excluded from active findings, with `osv.withdrawn-advisory` recording the ID and
withdrawal time. A future withdrawal remains active and carries a warning.
Withdrawal applies to that record alone; it does not withdraw an active alias
record or establish that the package is safe.

Active OSV records connected by `aliases` become one vulnerability for each
project/package/version/instance identity. `advisory_ids` lists the matched
source IDs and `advisories` preserves each source's parsed metadata, including
severity, fix assertions and timestamps. Group-level aliases include all member
IDs for policy matching. `related` and `upstream` do not merge vulnerabilities.

A group's fix candidate must satisfy all comparable source assertions. Missing
details or unconfirmed applicability keep the fix unknown; aggregate metadata
limits retain the sources and an incomplete diagnostic. Modification and future
withdrawal timestamps remain per source rather than describing the whole group.
Grouping follows the sources' alias assertions and does not prove runtime use.

Advisory metadata includes `cve_ids` from canonical CVE IDs in OSV `id` and
`aliases`, and `cwe_ids` from `database_specific.cwe_ids`. CVE identifies a
vulnerability record; CWE classifies a weakness. `identifier_references` gives
each assertion's official lookup URL, source advisory ID and field. These
fields survive JSON and SARIF exports; text reports show the lookup links.
Alias groups combine the IDs while retaining each source's assertions. A
group's reference projection is limited to 4096 entries; an omission count and
diagnostic point to the complete per-source assertions in `advisories`.

`weaknesses_status` is `reported`, `not-provided` or `incomplete`. Malformed or
over-budget CWE metadata retains valid IDs within a 256-entry per-source limit
and emits a warning; vulnerability matching and fix evaluation remain separate.
An absent classification does not establish the absence of weaknesses. IDs and
links are provider assertions: the backend does not fetch or validate the
current CVE/CWE records, their status, weakness names or taxonomy relationships.
See the [CVE List](https://github.com/CVEProject/cvelistV5) and
[CWE API guide](https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md).
Extracting these advisory identifiers adds no network requests. Supplied CVE/CWE
files can be inspected separately through the external evidence interface;
inspection does not fetch or authenticate the current upstream records.

## Development

Tests are grouped in five files under `test/`. Keep local reports, logs, and
scratch fixtures under `.tmp/`; it is ignored by Git and dependency discovery.

```bash
uv sync --frozen --extra test
uv run --frozen --extra test python -m pytest test -q
uv run --frozen --extra test python -m ruff check depcheck test scripts/smoke_installed.py scripts/check_wheel_install.py skills/check-dependencies/evals
uv run --frozen --extra test python -m ruff format --check depcheck test scripts/smoke_installed.py scripts/check_wheel_install.py skills/check-dependencies/evals
uv run --frozen --extra test python -m mypy
uv lock --check --offline
uv run --frozen --extra test python skills/check-dependencies/evals/run_live.py
uv run --frozen --extra test python -m build --outdir .tmp/dist
```

CI also installs the built wheel without extras into a separate environment and
runs `scripts/smoke_installed.py` to check the base CLI away from source imports.
The wheel job covers Ubuntu, macOS, and Windows with Python 3.12. Run the same
installation check locally with `python scripts/check_wheel_install.py --wheel <path-to-wheel>`.

`skills/check-dependencies/evals/run_live.py` exercises the skill's MCP contracts
offline using temporary repositories. Pass `--output .tmp/depcheck-live.json` to
record actual calls. CI runs it alongside the tests. The hand-authored
`traces.example.json` checks the scorer's format and rules; it is not evidence
that an agent followed the skill. Evaluate agent behavior separately with real
tasks and recorded calls. `evals/cases.agent.json` defines independent
CLI tasks. `evals/record_cli.py` runs the installed CLI and records actual
arguments, results, and exit codes. The recorder inserts `--root` as the CLI's
repository argument: use `-- explain requests`, without repeating the path.
Pair those records with the agent's answer
and score them using `evals/score.py --cases evals/cases.agent.json`.
Review the full Skill and relevant reference reads, pagination, qualified identities, uncertainty, and unchanged fixture
files as well as the scorer result. Paths here are relative to
`skills/check-dependencies/`.

Run the opt-in Codex consumer trials with an existing login and installed CLI:

```bash
python skills/check-dependencies/evals/run_agent.py --output-dir .tmp/agent-evals --cli /absolute/path/to/depcheck
```

This invokes a model through [Codex exec](https://learn.chatgpt.com/docs/developer-commands#codex-exec).
It creates disposable offline fixtures, records commands and answers, checks the
original fixture hashes, and scores the selected cases. The Gradle case checks
literal requests and configuration-qualified lock versions without installed-state
or removal claims. The Go tool case checks
configured build use without source imports or execution/installation claims.
The Go checksum case separates
minimum requirements and checksum assertions from selected/installed versions
and verified integrity. The Maven case separates
plugin management and configured execution from installation and actual runtime
use. The vcpkg case checks
conditional feature/default/host assertions without installed-state or removal
claims. The Pipenv case checks a
private source, declaration location and static pin without installed-state or
security clearance claims. The CMake cases check
qualified project/script explanations, independent component ownership and
unknown activation, installed versions and uncollected wrapper calls.
The forbidden-action classifier handles known package-manager commands, selected
CMake configure/build/script forms and curl/wget calls, not arbitrary program behavior. Pagination
scoring validates observed offsets, totals and qualified identities rather than
accepting the answer's count alone. Expected calls are ordered by default;
cases with independent reads can set `ordered_tool_calls: false`. Each required
call and its result assertions still apply. Unordered matching pairs arguments
and results with distinct recorded calls, including overlapping expectations.
Answer terms are format checks;
review the claims in the recorded answer as well. Inspect unknown command forms in the event records
alongside the score; a pass is evidence for those trials, not a general agent
reliability guarantee. It is separate from the offline CI contract runner.

Run the existing deterministic offline benchmark on Linux or macOS before a
performance change. It uses the Unix `resource` module for memory reporting:

```bash
uv run --frozen --extra test python scripts/benchmark_monorepo.py --projects 8 --files-per-project 25 --seed 1729 --depth 8 > .tmp/benchmark-baseline.json
```

OSV request counts are simulated without network access. Keep fixture parameters,
interpreter, dependencies, and output evidence fixed when comparing changes.
A local timing sample is a baseline for an experiment, not a CI performance
guarantee. Current maintenance priorities and verification rules are in
[AGENTS.md](AGENTS.md).
