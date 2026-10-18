# Usage and policy evidence

Read `usages` as well as `imports`: a `kind: "tool"` entry with
`mapping_confidence: "configured"` records a scoped user declaration in
`.depcheck.toml`. Preserve its reason and location when explaining use;
do not describe it as an observed import or command execution. Impact counts
both source and tool usages. A `kind: "command"` entry is a fixed mapping
from literal configuration to a declared tool, with exact mapping confidence.
Preserve its location and reason; it is neither an import nor proof of
execution. A `kind: "configuration"` entry records a literal TypeScript or
pytest or Go `tool` configuration reference. Read its location, scope and confidence;
it is excluded from source imports. Inheritance, custom type roots and unknown
plugin mappings can leave configuration evidence incomplete.
Unsupported command forms leave usage incomplete. Use existing
policy exemptions for temporary finding exceptions. Optional `advisory_ids`
selects vulnerability IDs or aliases for `risk: "vuln"`; `versions` selects
exact versions. Both must match when supplied, and unknown versions do not
match. Omitted selectors keep package-wide behavior. `ignore-packages` removes dependency evidence from
inventory, security checks, and SBOMs.

## Advisory fix candidates

Read `fix_versions` as raw fixed boundaries asserted for the matching package.
`fix_version_status: "candidate"` means `fix_version` is newer than the queried
version and outside all comparable affected ranges and explicit affected-version
lists in that advisory. It does not establish an available release, compatibility,
selected lock activation or safety against other advisories.

The backend compares PyPI `ECOSYSTEM` ranges with PEP 440 and `SEMVER` ranges
with SemVer precedence. Other ecosystem ordering, Git ancestry, missing fixes
and unconfirmed applicability retain `fix_version: null` and an unknown status.
Keep `fix_version_reason` in the explanation. Invalid details retain the matched
advisory ID and diagnostics; they must not become a clean security result.

## Advisory revisions and withdrawals

Details may be reused across queries only when their modification time is at
least the revision returned by `querybatch`. Nanosecond differences matter.
Missing revision hints force fresh details; malformed hints, stale details and
failed refreshes keep the matched ID with diagnostics rather than substituting
old metadata or a clean result.

`osv.withdrawn-advisory` records an excluded advisory ID and its effective
withdrawal time. It does not withdraw other active records sharing an alias.
`osv.withdrawal-pending` keeps a future-dated withdrawal active and preserves
the timestamp on the finding. Do not turn either diagnostic into a claim that
the package has no other vulnerabilities.

## Alias groups

Active records joined by `aliases` are one vulnerability within each exact
project/package/version/instance identity. Do not join `related` or `upstream`
records. A merged finding retains `advisory_ids` for the matched records and
`advisories` for each source's parsed evidence. Group aliases include member IDs,
so an existing advisory-specific exemption can match any member while its
project, ecosystem, package and version selectors still apply.

The representative ID is deterministic for the observed source set. Read all
members before interpreting severity or a fix: severity assertions are combined,
while group candidates must satisfy all comparable source ranges and versions.
Unavailable details or unconfirmed applicability keep the candidate unknown.
`osv.alias-group-incomplete` retains aggregate-budget or invalid-metadata errors.
Individual modification and future-withdrawal timestamps stay in `advisories`;
they do not give the whole group one revision or withdrawal time. A source's
withdrawal does not withdraw its active aliases.

## CVE identifiers and CWE assertions

`cve_ids` contains canonical CVE identifiers from OSV `id` and `aliases`.
`cwe_ids` contains the provider's `database_specific.cwe_ids` assertions.
`identifier_references` preserves the official lookup URL, source `advisory_id`
and `field`; use that provenance when explaining a classification. Group IDs
are unions, while `advisories` retains each source's assertions and status.
If a group's reference projection reaches 4096 entries,
`identifier_references_omitted` and `osv.identifier-group-incomplete` direct you
to the per-source records for all references.

Read `weaknesses_status` separately from vulnerability matching:
`not-provided` means no classification was supplied; `incomplete` means a source
was unavailable or had malformed or over-budget assertions. A warning retains
valid CWE IDs within the 256-entry source limit without discarding the matched
vulnerability or its fix evidence. `reported` does not establish exhaustive
weakness coverage. Missing CWE data must not become a claim of no weaknesses.

CVE identifies a vulnerability record; CWE describes a weakness type. The
backend does not fetch the current CVE/CWE records, verify their existence or
status, or collect taxonomy names and relationships. A URL is a lookup link,
not evidence that a record was checked. These fields add no network requests
and do not establish exploitation, source reachability or runtime use.

## Configuring tool usage

For a requested tool-usage configuration, use a scoped entry with a reason
supported by the project's build, test, or deployment files:

```toml
[[tool-usage]]
ecosystem = "PyPI"
project-id = "pypi:python:."
package = "ruff"
scope = "test"
reason = "Runs as the lint command in CI"
```

Confirm the exact project ID and direct declaration first. This records a user
configuration claim, not command execution; do not add it solely to silence a
warning or change the audited project's configuration during a read-only trial.
