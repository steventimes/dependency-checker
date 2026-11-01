# Explicit external evidence

These operations read repository-relative files without refreshing the index,
executing target code or fetching linked resources. JSON uses unique keys and
finite floating-point values, including exponent overflow checks, and Unicode
scalar strings and keys. Valid non-BMP characters and supported byte encodings
remain accepted. Inputs retain the normal 8 MiB limit. Each tool has explicit
format/entry budgets. Unsupported inputs return an operation error. Inspect
source hashes, reported tool versions, modes, unknown states and omitted fields.
An imported claim is not an authenticated observation.

## Security metadata and supplied reports

Use `inspect_evidence(evidence_file, kind, limit=20, offset=0)` or
`depcheck evidence ROOT KIND FILE --limit 20 --offset 0`. Follow `next_offset`
for every table/record collection. Supported kinds:

| Kind | Accepted input | Meaning |
| --- | --- | --- |
| `cve` | CVE JSON 5.0, 5.1 or 5.1.1 | CNA and ADP assertions remain separate, including affected products, weaknesses, revisions and rejection state; no product-name/CPE expansion into findings |
| `cwe` | Uncompressed CWE 4.x XML, `cwe-7` namespace | Classification/version/relationships only; no vulnerability match; DTD/entity declarations rejected |
| `vex` | Standalone OpenVEX 0.2.0 | Explicit products, timestamps, statuses and required explanations retained; no signature verification, precedence application or finding suppression |
| `attestation` | in-toto Statement v0.1/v1, optionally DSSE | Subjects, digests, predicate and signatures retained; no verification commands, key access or signature verification |
| `govulncheck` | Native JSON object stream, protocol v1.0.0 | Config/toolchain/mode and module/package/symbol findings retained; EOF does not prove successful producer completion |
| `callgraph` | `depcheck.call-graph.v1` | Paths from explicit entries through provided edges; no path means not observed in this graph |
| `runtime` | `depcheck.runtime-trace.v1` | Reported event/symbol/sequence, environment and sampling scope; unobserved calls remain unknown |
| `component-matches` | `depcheck.component-matches.v1` | Reported artifact, matched identity and method; fuzzy/vendor/shaded matches do not create public registry identities or CVE findings |
| `behavior` | `depcheck.behavior-evidence.v1` | Static/configuration/runtime capability assertions; maliciousness remains unestablished |
| `abi` | `depcheck.abi-evidence.v1` | Explicit before/after identities, scope and reported compatibility; other APIs/platforms remain unknown |
| `deps-dev` | Saved deps.dev v3 GetVersion response | Package/project/license/advisory/attestation assertions; reported verification is attributed to the provider |
| `scorecard` | Saved Scorecard JSON with repo/tool/checks | Repository hygiene assertions, including inconclusive checks; no package safety grade |
| `pip-inspect` | Native `pip inspect` JSON, report version `"1"` | Supplied installed-distribution and environment assertions; no automatic pip execution or public-origin inference |
| `pip-install-report` | Native `pip install --report` JSON, report version `"1"` | Reported selections and download assertions; may be a dry-run, so successful or current installation remains unknown |

For a saved pip report, use
`depcheck evidence "<root>" pip-inspect reports/pip-inspect.json --limit 20`.
The `distributions` table keeps each physical record, its `/installed/N` pointer,
name, version, metadata location and optional `installer`, `requested` and
`direct_url`. Follow `next_offset` for all instances. An absent `requested`
remains absent; it does not mean false. Invalid PEP 440 versions remain labeled
assertions. Core requirement metadata is retained; omitted descriptive fields
are listed in `omitted_metadata_fields`.

Metadata locations are opaque strings and are never opened. Direct URLs are
redacted and are not fetched. The reported environment is not evaluated against
the host or bound to a project. Neither an installer named pip nor a missing
direct URL identifies the package index. Inspection does not populate the scan
or index, query registries, verify the producer or establish current installation.
Unknown report versions and malformed required fields return an operation error.
Credential-bearing URL-shaped field names in environment, metadata or source
extensions also return an error without echoing the field name.

For an already saved installation report, use
`depcheck evidence "<root>" pip-install-report reports/install.json --limit 20`.
Its `distributions` table keeps each `/install/N` record separately, including
metadata, redacted `download_info`, `requested`, `is_direct`, and optional
`is_yanked` and `requested_extras`. Missing optional flags remain absent. Extras
do not establish active dependencies. Archive hashes and VCS revisions are
supplied assertions; artifact content is not fetched or verified.

Unlike `pip inspect`, an installation report may come from `--dry-run`. It is
neither a lock file nor proof of successful or current installation. An index or
`--find-links` can supply a non-direct download, so neither `is_direct=false`
nor a download URL establishes public package identity. The reader does not run
pip, inspect the host, populate the index or create vulnerability findings. See
the [pip installation report specification](https://pip.pypa.io/en/stable/reference/installation-report/).

For attestations only, `artifact_file` / `--artifact-file` selects one explicit
relative file for a SHA-256 comparison against subject assertions. Subject names
are never opened. A digest match does not authenticate the statement or issuer.

Interchange envelopes for runtime, component matches, behavior and ABI require
`schema`, `tool: {name, version}` and a `records` array. Preserve `environment`,
`scope`, `inputs`, `coverage` and `sampling` when available. Native engine reports
need an explicit conversion; changing a filename does not convert their schema.
Runtime records require `event`, `symbol` and nonnegative integer `sequence`.
Component matches require `artifact`, `matched_component` and `method`, with
optional `package_purl`. Behavior records require `capability` and `evidence_type`
(`static`, `configuration` or `runtime`). ABI records require `before`, `after`,
`scope` and `status` (`compatible`, `incompatible` or `unknown`).

Call graph records require `tool`, `nodes: [{id, symbol, package_purl?}]`,
`edges: [{source, target, kind}]`, explicit `entries` and optional
`vulnerability_symbols: [{advisory_id, node_id}]`. Node IDs must be unique and
all edges/entries/mappings must refer to retained nodes. Package PURLs, when
provided, must include a version. Edge kinds are `direct`, `inferred`, `dynamic`
or `observed`; keep dispatch provenance and source/instance assertions. Exact
input node IDs establish graph references, not independently verified package
or vulnerable-function identity.

## Offline vulnerability reevaluation

Use `reevaluate_vulnerabilities(inventory_file, advisory_file)` or
`depcheck reevaluate ROOT INVENTORY OSV_FILE`. Inventory accepts canonical
`depcheck.scan.v1` or CycloneDX JSON supported by `inspect_dependency_sbom`.
Advisories accept one OSV record or
`{schema: "depcheck.osv-database.v1", generated_at: "...", records: [...]}`.
Supply unique advisory IDs with explicit `modified` timestamps; select revisions
before import. Inputs are not downloaded or unpacked automatically.

Exact package/ecosystem coordinates and supported version ranges are matched.
Version membership is evaluated separately from forward fix candidates. An unfixed
range or a supported positive assertion can establish a match even when another
range cannot be ordered. Missing/unsupported negative coverage remains unknown;
unrelated packages do not affect this package's matching completeness.
`advisory_checks` retains each evaluated source ID, revision, membership and reason.
Matched issues preserve top-level and matching package-level severity assertions
with source pointers, raw scores and version applicability. Unknown or conflicting
scopes remain qualified in `severity_assertions` and `severity_status`; scores
from unrelated packages or nonaffected branches do not become effective severity.
These are supplied ratings, not computed CVSS scores or proof of exploitation.
PEP 440 equality and supported SemVer equality apply to explicit versions.
Go `ECOSYSTEM` ranges, explicit versions and fix comparisons accept full module
SemVer with an optional leading `v`. Prereleases and pseudo-versions follow
SemVer precedence; build metadata does not change that order. Shorthand and
toolchain versions remain unknown. `SEMVER` range boundaries still require
unprefixed SemVer, including for Go. npm and crates.io `ECOSYSTEM` ranges support
strict SemVer ordering; nonstandard/coerced versions remain unknown.
Maven ranges and normalized equality use the bounded ASCII
`ComparableVersion` profile from Apache Maven 3.10.0. Its implementation is
identical in 3.9.11 and 3.9.16. Non-ASCII ordering and symbolic boundaries remain
unknown; literal positive assertions survive unsupported neighboring evidence.
Missing comparisons cannot establish a nonmatch or a forward fix candidate.
RubyGems `ECOSYSTEM` ranges, version-list equality and fix candidates use a
bounded ASCII adaptation of RubyGems 3.6.9 `Gem::Version`. It preserves numeric
segments, case-sensitive prerelease letters, hyphen-to-`.pre.` conversion and
canonical zero segments. Only nonempty, unpadded version strings of at most
256 characters are compared. Invalid neighboring boundaries leave negative
coverage and fix selection unknown while supported positive evidence survives.
CycloneDX `pkg:gem` coordinates map to RubyGems without a namespace. Private or
ambiguous origins, qualifiers and subpaths remain unknown. Package names are
not converted between underscores, hyphens or case. These are explicit offline
inventory assertions, not Gemfile/lock collection, platform resolution, an
installed gem inventory or online RubyGems scanning.
A same-package affected entry without ranges or versions prevents a fix
candidate, including across aliases, while a supported positive match survives.
Raw fixed boundaries remain visible. Go inventory coordinates are supplied
assertions; `go.mod` minimum requirements and `go.sum` checksums do not establish
selected build versions or authorize vulnerability matches on their own.
OSV schema 1.x is accepted, including its implicit 1.0.0 default; other majors
are rejected. Package-less Git assertions are counted in the database metadata
without inferring package identities or executing Git/clone operations.
Qualified/subpath PURLs, malformed origins and canonical inventory without a
public-origin assertion remain unknown. An external unqualified supported PURL
without an origin is matched only as the producer's package-coordinate assertion,
not as proof of installed public provenance.
CycloneDX exports retain captured origins for manifest-only components too.
Conflicting origin assertions remain ambiguous, retain their assertion list and
have no public PURL. A declaration without a locked version remains unknown.
Canonical resolution `metadata` and CycloneDX `depcheck:resolution:metadata`
must be JSON objects. Reevaluation preserves these supplied assertions on each
observation's top-level `metadata`; absence is equivalent to an empty object.
The legacy `metadata.origin` source assertion is used in either format only
when no explicit origin is present. A private or null legacy origin does not
gain public eligibility through an unqualified PURL; explicit origin assertions
take precedence. Other metadata does not alter coordinate eligibility, activate
conditions or establish installation. Optional/platform context does not
suppress supported locked version matching.
Explicit alias relationships group records; withdrawal, per-source revisions,
unknown ranges, origins and instance assertions remain visible. A nonmatch is
`not-matched-in-supplied-records`, never a claim about the full current advisory
database. Database freshness and source authenticity remain unverified. Separate
inventory bytes from advisory bytes when comparing reevaluations. No original
snapshot, SBOM, index or finding is modified.

### Supplied KEV and EPSS context

The current source adds optional `kev_file`, `epss_file`, `previous_kev_file`,
`previous_epss_file`, `risk_as_of` and `risk_max_age_days` parameters to the same
reevaluation tool. Existing calls remain valid; there is no new MCP tool or
default network operation. CLI equivalents are:

```bash
depcheck reevaluate . reports/inventory.json reports/osv.json \
  --kev-file reports/kev.json --epss-file reports/epss.csv.gz \
  --previous-kev-file reports/previous-kev.json \
  --risk-as-of 2026-10-24 --risk-max-age-days 1
```

The example explicitly chooses a one-day age limit; it is not a default or a
universal risk threshold. Paths must be explicit, relative regular files within
the selected root. The operation does not download feeds, follow their URLs,
inspect adjacent provenance files, maintain a feed cache or change an index.

`risk_context.records` associates the current observation page's matched issues
with CVE identifiers already asserted by OSV IDs or aliases. Each association
retains the absolute observation index, source advisory and identifier field.
`related`, descriptions, package names and vendor/product strings never create
associations. Different CVEs retain separate results. `associations_complete`
qualifies bounded omissions; an empty page can be `not-applicable`.
Original observations, scores, version matches and policy findings are unchanged.

KEV uses native catalog JSON. Every record, the raw `count`, CVE format, required
fields and dates are validated before the snapshot can supply membership.
`listed`, `not_listed_in_snapshot` and `unavailable` are distinct. Catalog version,
publication time, raw/unique counts, unknown fields and selected entry pointers
remain available. Content hashes distinguish same-version publications.
An explicit previous snapshot allows membership comparison; additions/removals
are chronological only when the supplied dates establish their order. Removal
does not establish CVE withdrawal, a fix or absence of exploitation.
`knownRansomwareCampaignUse: "Unknown"` remains a string assertion.

EPSS accepts native CSV or gzip, including concatenated members. Columns are
read by name; `cve`, `epss` and `percentile` are required and extra columns are
retained within display budgets. All rows must validate, including unselected
CVEs. Both values must be finite in `[0,1]` and retain their raw decimal strings.
`probability` estimates observed exploitation activity over 30 days;
`percentile` ranks the score population. Neither proves this project's
exploitability. The states are `scored`, `no_row_in_snapshot` and `unavailable`;
missing rows never become zero. Historical files without comments keep unknown
model/date values. Model versions are not inferred from filenames or Git dates.
See [FIRST data](https://www.first.org/epss/data) and
[probability guidance](https://www.first.org/epss/faq#reading-the-score).

Identical duplicate records are counted and deduplicated with a diagnostic;
conflicting duplicates invalidate the complete candidate rather than letting
row order decide. Invalid candidates can fall back to explicitly supplied valid
previous files. Fallback is marked `stale`; no previous file means unavailable.
No file is replaced or deleted. File consistency errors retain the common I/O
boundary. Date/age, signal value and source authenticity remain separate.
Without an explicit age limit, age is reported and freshness stays unevaluated
or unknown. Future-dated candidates cannot be selected for an earlier as-of time.

Snapshot sources retain raw-byte SHA-256 IDs and local observation times.
Upstream URL/commit and retrieval time stay null when the native file does not
provide them. A hash does not authenticate a producer or establish full upstream
population coverage. EPSS metadata includes FIRST/Empirical Security attribution;
no unverified standard data license is assigned. Display omissions retain hashes
and membership/score states. KEV input is capped at 8 MiB; EPSS input and expanded
CSV each at 32 MiB, with one million rows, 64 gzip members and bounded fields,
associations and display details. None of these states changes the affected
version ranges, severity, reachability or exploitation assessment.

## Python callable propagation

Use `analyze_python_calls(analysis_file)` or
`depcheck python-calls ROOT ANALYSIS_FILE`. The explicit input is:

```json
{
  "schema": "depcheck.python-call-analysis.v1",
  "sources": [{"path": "app.py", "module": "app"}],
  "entries": ["app:main"],
  "vulnerability_symbols": []
}
```

Sources may carry a versioned `package_purl` for supplied library ownership.
Module/function IDs use `module:qualified.name`; the module entry is
`module:<module>`. Imports do not execute modules. Selected sources, entries and
source hashes define the analysis scope; changing any input requires rerunning.
At most 512 sources, 1 MiB per source, 16 MiB total, 100,000 AST nodes/facts and
64 propagation rounds are processed. Aliases, lexical shadowing, callback
parameters and returned callable candidates propagate to a fixed point.
Over-budget inputs fail; nonconvergence and unresolved calls remain incomplete.
Dynamic dispatch, reflection, decorators, constructors, native extensions and
absent library bodies are limitations. A candidate path is not exploitation
proof; no path cannot justify OpenVEX `not_affected`.

## Comparisons, provenance and network checks

- `compare_inventories` / `depcheck compare-inventories ROOT BEFORE AFTER` compares
  scan/CycloneDX coordinates, origin/metadata assertions and multiplicity across
  producers. Metadata-only differences remain visible without changing package
  identity. Scope, paths and
  producer-local instance IDs are not automatically aligned; differences do not
  establish false positives or false negatives.
- `compare_package_behavior` / `depcheck package-behavior ROOT BEFORE AFTER`
  compares supplied npm JSON scripts and selected metadata. Lifecycle and command
  capability candidates are configuration evidence; shell dialect, dataflow and
  actual execution remain unknown.
- `compare_package_names` / `depcheck package-names ROOT ECOSYSTEM NAME REF...`
  compares explicit reference names for bounded typo and scope-omission signals.
  Keep npm scopes and ecosystem normalization; never auto-replace a name.
- `export_evidence` / `depcheck export-evidence ROOT KIND SNAPSHOT` exports
  `provenance` as an unsigned in-toto statement or `policy` as unevaluated input.
  Optional `--input-file` and `--configuration-file` select exact files to hash.
  Current hashes do not establish historical scan freshness or invocation status.
  The export rejects truncated or inconsistent canonical scans, including count,
  capability-state and project-reference mismatches. Consistently reported
  incomplete scans remain valid inputs. Print the producer contracts with
  `depcheck schema scan`, `depcheck schema policy-input` or
  `depcheck schema provenance`; additive fields are allowed.
  No signing keys, verification layout commands or external evaluator are used.
- `verify_registry_package` / `depcheck registry ROOT ECOSYSTEM NAME
  --allow-network` requires explicit network authorization (`allow_network=true`
  for MCP). It sends only the selected public PyPI/npm name/version to the fixed
  registry, with no ambient credentials or redirects. Never use it for private
  or unknown-source names. `--package-version` selects a version/label query.
  Present, not found, and request failure are separate outcomes; existence does
  not establish source trust or maliciousness.

These tools provide evidence for an audit. They do not install target packages,
compile native code, deploy runtime instrumentation, upload artifacts or replace
the dependency scanner's capability results.
