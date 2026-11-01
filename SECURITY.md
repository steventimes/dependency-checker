# Security

Report a suspected vulnerability through a [private GitHub advisory](https://github.com/steventimes/dependency-checker/security/advisories/new).
If private reporting is unavailable, contact the maintainer at
stevenyang0316@gmail.com. Include the affected version or commit, a small
reproducer using dummy data, the expected boundary and the observed result.
Keep real credentials and private package names out of public issues.

The supported release line is 0.6.0. Fixes on the default branch remain
unreleased until a new release is published. A dependency advisory does not by
itself establish that this backend exposes the affected transport or feature.

## Review boundaries

Treat target files, lock records, external evidence and existing SQLite caches
as untrusted data. Review path confinement, read-only query behavior, bounded
parsing and expansion, public-coordinate eligibility, credential retention and
terminal output. Include CLI and MCP consumers of the same evidence.

Target code, setup files, build scripts and package managers must not execute
during static collection. MCP index and scan operations may replace the derived
`.depcheck` cache; queries and update previews must not write it. A read or work
limit must produce an error or incomplete state, never a clean security result.
Public services may receive only qualified public package/version coordinates.
A URL or coordinate assertion does not authenticate its producer. Caller-approved
Maven coordinates must not be derived from repository instructions.

Recognized Python URL credentials are redacted before retained declarations,
diagnostics and nested origin records enter reports or caches. This does not
promise detection of every secret in arbitrary input. Human-readable output
escapes control characters; structured formats preserve their own encoding.

Default MCP transport is stdio. Network registry verification requires explicit
opt-in; MCP scanning is offline. CLI security and compatibility options can
contact public services. Review a supplied source assertion before opting a
Maven coordinate into a public lookup.

## Verification

Use minimal attack inputs with distinct legitimate controls. Preserve source
positions, repeated declarations, unknown activation and incomplete coverage.
Check both exports and indexed responses for retained secrets. Native filesystem
and packaging CI checks are configured for Ubuntu, macOS and Windows; one local
platform does not establish the others, and configuration is not a passing run. See [contribution checks](CONTRIBUTING.md).
