# Cargo evidence

Cargo.toml and Cargo.lock v3/v4 provide workspace, alias, scope and conditional
inventory evidence. Use `ecosystem: "Cargo"` and the returned `cargo:cargo:PATH`
project ID for queries. Bare Cargo versions are ranges, not pins. Shared locks
contain a feature/target/member superset; deployed selection remains unknown.
Only verified crates.io records can provide OSV coordinates. Git/path/alternate
registry evidence, ambiguous matches and unsupported constraints stay qualified.

Dotted declarations such as `serde.workspace = true` retain the first defining
key's start position. Explicit dependency tables keep their header positions;
the inherited `workspace_origin` remains a separate location in the root
manifest. Missing syntax positions remain file-only. Position precision does
not establish workspace activation, installation or runtime use.

Lock records carry separate `origin` and resolution `metadata`, including the
raw package index, source content hash and unknown activation. Registry/Git
instances and different revisions remain distinct through queries and exports.
Git dependency IDs may omit the target's precise commit fragment; a matching
repository and query must still identify one target. Multiple candidates remain
unresolved. Displayed source URLs are redacted; content hashes preserve identity
distinctions without authenticating producers or downloaded content.

Workspace-root `[patch]` and `[replace]` assertions apply to member views.
Diagnostics retain their original manifest locations. Potentially affected
declarations and lock rows carry `cargo_override_status: "unsupported"` and
`directness_status: "unknown"`; these states do not establish that a replacement
was selected. Root patches can also affect transitive records. Unrelated direct
requests retain source checks, and a supported constraint that excludes every
same-name lock candidate still leaves a version contradiction. Member-local
overrides are reported as ignored.

Declaration metadata includes a bounded `cargo_overrides` summary: candidate
count, omitted count and, when within budget, the first original location and
redacted source selector. Malformed or over-budget scope keeps directness
unknown; omitted detail never proves an override absent. Empty override tables
have no effect. Git URL spelling equivalences prevent false contradictions
without rewriting raw identity or establishing source equality. Override
resolution, actual adoption and configuration/CLI precedence remain unsupported;
the collector does not inspect host Cargo settings or execute Cargo. See
[Cargo override rules](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html).

Legacy `dev_dependencies`/`build_dependencies` declarations preserve their raw
section, scope, target and source location. Inspect `metadata.legacy_section`:
`accepted` means the literal section is valid in a known pre-2024 edition;
`ignored` means a canonical table takes precedence, including an empty one.
`rejected` identifies edition 2024; `edition-unknown` retains unresolved edition
evidence. Only accepted legacy sections supply direct declarations. The other
states retain configuration inventory, with rejected/unknown states making the
manifest incomplete. Literal workspace edition inheritance is collected;
installation and active target/feature selection remain unknown. `[project]`
is the pre-2024 alias for `[package]`, which takes precedence when both exist.
Legacy `default_features` fields remain retained but uninterpreted.

Exact lock versions follow Rust SemVer: valid alpha/beta/rc identifiers and
build metadata are retained. Release components must fit Rust's unsigned 64-bit
fields; npm's smaller numeric and text limits do not apply. Malformed lock
records leave a diagnostic and incomplete security coverage without excluding
readable neighbors. Prerelease constraint selection remains unknown.

Owned `.rs` files provide literal `extern crate`, simple `use` and crate-path
candidates. Cargo aliases, including hyphen-to-underscore spelling, map with
`mapping_confidence: "inferred"`; references retain `scope: "unknown"` and
`kind: "conditional"`. Known local shadows, conflicting origins and undeclared
extern crates retain unknown owners. Comments and string/character examples
are skipped. Positions are one-based Unicode code points.

These references do not establish compiler binding, module/target/cfg selection,
macro expansion, generated code, custom crate names, installation, or execution.
Virtual workspaces have no application source owner; nested Cargo scopes stay
separate. Bounded files, tokens, context, and references, unreadable input and
unsupported lexical tails leave explicit coverage gaps. Usage and mapping
remain incomplete; zero references cannot justify removal. Cargo update
previews remain unsupported.
