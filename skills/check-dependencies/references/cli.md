# CLI fallback

Use the installed executable and quote paths and specifiers. The transport table
uses `<root>` for the target repository; later examples use `.` from that
repository. Create `.tmp/` before writing reports there; output commands require
an existing parent directory. Context, index, query,
explain, impact, and update print JSON without a format flag.

| MCP operation | CLI equivalent |
| --- | --- |
| `backend_info` (current source) | `depcheck runtime` (no root argument) |
| `repository_context` | `depcheck context "<root>"` |
| `index_repository` | `depcheck index "<root>"` |
| `scan_repository` | `depcheck scan "<root>" --offline --format json`, then `depcheck index "<root>"` if indexed queries are needed |
| `query_dependencies` | `depcheck query "<root>" --limit 20 --offset 0` |
| `explain_dependency` | `depcheck explain "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `dependency_impact` | `depcheck impact "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `plan_dependency_updates` | `depcheck update "<root>" 'requests=2.32.4' --ecosystem PyPI --project 'pypi:python:.'` |
| `compare_dependency_snapshots` | `depcheck compare "<root>" .tmp/before.json .tmp/after.json --limit 20 --offset 0` |
| `inspect_dependency_sbom` | `depcheck sbom "<root>" .tmp/bom.json --limit 20 --offset 0` |
| `inspect_cmake_model` | `depcheck cmake-model "<root>" build/.cmake/api/v1/reply/index-selected.json --configuration Debug --limit 20 --offset 0` |

For the other tools' CLI equivalents and input formats, read
[External evidence](external-evidence.md). That reference covers evidence
inspection, offline OSV reevaluation, Python calls, comparisons, exports, and
explicit registry checks.

For supplied KEV/EPSS context, `reevaluate` accepts `--kev-file`, `--epss-file`,
`--previous-kev-file`, `--previous-epss-file`, `--risk-as-of` and
`--risk-max-age-days`. These optional files remain read-only; see
[validation and fallback](external-evidence.md#supplied-kev-and-epss-context).

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

`backend_info` and `depcheck runtime` return `depcheck.runtime.v1` with backend
version, analysis revision, index schema and tool contract revision. They read
no repository and do not refresh a cache. These interfaces are absent from
older backends; use the available tool list and a compatible CLI fallback
rather than repeatedly retrying or refreshing through the older process.

For caller-approved public Maven coordinates, use
`depcheck scan "<root>" --security --no-compatibility --public-maven-coordinate org.slf4j:slf4j-api --format json`.
Repeat the option for each checked coordinate. Neither a lock record nor a
repository file grants this authority. `--offline` takes precedence, and the
assertion does not make incomplete security coverage complete.

## Reports and indexed queries

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

Add `--format text` for a terminal summary and paged change records. JSON is
the default; both formats report the same counts, diagnostics and next offset.
With `--fail-on-changes`, exit 1 indicates observed changes across all pages,
exit 2 indicates invalid or incomparable inputs, and exit 0 indicates no
observed changes. It counts additions and removals of declarations, resolved
dependencies, edges, and vulnerability identities with advisory IDs. Changes
to an existing advisory's fix boundaries or severity are not counted. With
incomplete security evidence, exit 0 does not establish unchanged risk or
verified remediation.

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
