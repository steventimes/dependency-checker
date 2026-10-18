# Cargo evidence

Cargo.toml and Cargo.lock v3/v4 provide workspace, alias, scope and conditional
inventory evidence. Use `ecosystem: "Cargo"` and the returned `cargo:cargo:PATH`
project ID for queries. Bare Cargo versions are ranges, not pins. Shared locks
contain a feature/target/member superset; deployed selection remains unknown.
Only verified crates.io records can provide OSV coordinates. Git/path/alternate
registry evidence, ambiguous matches and unsupported constraints stay qualified.

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
