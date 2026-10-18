# Go module and tool evidence

Go `require` is a minimum (`scheme: go-minimum`), not a selected exact version.
All-version module replacements retain `go-replacement` assertions; a
version-specific replacement's applicability remains unknown. `go.sum` lines
use `kind: checksum` with `go.mod` or module-archive context, raw hash/version,
positions and `integrity_verified: false`. Keep repeated and obsolete assertions;
do not use them to satisfy imports, infer installation, choose the highest
version, establish security clearance or recommend removal. CycloneDX preserves
checksum properties without versioned components or new application edges.
`resolved_versions: []` is intentional: MVS, workspace/vendor selection and
installed state remain unknown. `go.work`/`go.work.sum` expose uncovered manifest
paths. Refresh pre-revision-33 caches. Quoted literals
are supported, while escaped interpreted strings, ignore and uncollected
directives leave gaps. Respect the metadata expansion budget and retain file-only
locations when a span cannot be established.

Literal Go `tool` directives produce build-scoped `kind: configuration` usages,
with the full package reference, location and declared-prefix/configured mapping
reason. Repeated directives remain distinct; they are excluded from source imports.
An indirect `require` still declares the provider. Main-module/standard-library
tools are not external dependencies; a more-specific required module under the
main module's path remains an external candidate. Keep unknown tool owners and
budget-limited evidence incomplete. Explicit local replacement modules without
domain names still retain their configured ownership. These assertions establish configuration,
not package availability, execution, installation or an exact selected version.
Zero source imports do not make a configured tool unused. Refresh pre-revision-34
indexes before querying this evidence.
