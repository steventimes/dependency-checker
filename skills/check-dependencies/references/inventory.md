# Snapshots and external inventory

Use `compare_dependency_snapshots` only on explicitly selected relative scan
JSON files inside the repository. Matching revision, repository identity
and selection are required. Identity defaults to the local path; the same
explicit `repository-id` in `.depcheck.toml` permits comparisons across checkouts.
Treat that ID as a user assertion, not authenticated provenance. Legacy or mismatched reports return
`snapshot.incompatible`. Preserve qualified versions, instances, edges and
declaration occurrence counts. Read inventory/security completeness separately.
Declaration metadata changes, including a changed checksum assertion, remain
visible; they do not establish verified integrity or remediation.
Changes are static observations, and `remediation_verified` remains false.
Follow `next_offset` using the same filters and inspect each named change
collection; `counts` retain total sizes. Store scan outputs in `.tmp/`.

Use `inspect_dependency_sbom` for a requested CycloneDX JSON 1.4–1.7 file.
Follow component pagination. Preserve the input hash, generator versions,
project/instance properties, application edges, and unknown-identity/version or
dangling-edge diagnostics. Keep component types, CycloneDX scopes, repeated
source properties and reported license IDs, names or expressions. These license
assertions do not establish compatibility or compliance.

Keep the raw `purl` and decoded `package_url` fields. `identity.qualifiers` and
`identity.subpath` retain additional coordinate dimensions, including repository
URLs and Maven classifiers. `sbom.identity-qualified` leaves inventory/resolution
incomplete within the local package/version profile; do not merge these records
by package/version alone. Unsupported PURL types retain parsed fields and an
explicit diagnostic without a supported ecosystem mapping. Malformed coordinates
are rejected. A parsed PURL does not verify package existence or repository trust.

Trivy language-result application nodes with unambiguous Class/Type properties,
no package URL and no depcheck identity properties have
`kind: "dependency-group"`; the remaining entries have `kind: "package"`.
Groups remain in pagination, retain their dependency edges and do not need
package identities or versions. Packages list incoming groups in
`dependency_groups`. Group membership alone leaves `direct` unknown; do not
interpret all packages in a lock group as direct dependencies. Missing or
duplicate grouping properties keep the entry qualified as unknown.

Imported identities are `sbom-asserted`. This tool
does not add them to the source index, inspect the binary, establish usage,
or query vulnerabilities. Its usage capability is unsupported and security is
skipped. Both operations reject aliases, duplicate JSON keys and inputs above
8 MiB, and do not change the source or index.

For supplied CMake File API build models, read [CMake guidance](cmake.md) and use
`inspect_cmake_model`. Keep that external build-model projection separate from
SBOM package identities and source-index evidence. It does not establish
installed packages, current source contents, build execution or vulnerability
applicability.

External SBOM inspection retains raw component assertions and JSON pointers.
`quality.fields` reports presence/absence separately for package URL, version,
reference, scope, license, hash and evidence assertions. This is a field profile,
not full schema validation, legal compliance, artifact integrity or a safety score.
For supplied OSV reevaluation, cross-producer inventory comparison, VEX and
provenance, read [External evidence](external-evidence.md).
