# Explicit external evidence

These operations read repository-relative files without refreshing the index,
executing target code or fetching linked resources. JSON uses unique keys and
finite values; inputs retain the normal 8 MiB limit. Each tool has explicit
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
PEP 440 equality and supported SemVer equality apply to explicit versions; Go's
leading `v` is normalized. Maven nonliteral equality remains unsupported.
OSV schema 1.x is accepted, including its implicit 1.0.0 default; other majors
are rejected. Package-less Git assertions are counted in the database metadata
without inferring package identities or executing Git/clone operations.
Qualified/subpath PURLs, malformed origins and canonical inventory without a
public-origin assertion remain unknown. An external unqualified supported PURL
without an origin is matched only as the producer's package-coordinate assertion,
not as proof of installed public provenance.
Explicit alias relationships group records; withdrawal, per-source revisions,
unknown ranges, origins and instance assertions remain visible. A nonmatch is
`not-matched-in-supplied-records`, never a claim about the full current advisory
database. Database freshness and source authenticity remain unverified. Separate
inventory bytes from advisory bytes when comparing reevaluations. No original
snapshot, SBOM, index or finding is modified.

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
  scan/CycloneDX coordinates and multiplicity across producers. Scope, paths and
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
