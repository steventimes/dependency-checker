# JavaScript and frontend evidence

SCSS and Sass produce `usage.unsupported-source`. Vue/Svelte literal top-level
JavaScript/TypeScript script and CSS style regions retain imports and locations.
Template expressions, implicit framework imports and compilation remain
incomplete (`usage.unsupported-component-template`). Extraction stops after
template expressions can hide later markup. Preprocessors/custom attributes
stay qualified; known imports do not make component usage complete.
Astro frontmatter and supported script/style regions provide literal imports
with source positions and npm alias mapping. Template expressions and subsequent
template regions remain unparsed, even when frontmatter imports are known.
Browser scripts, external URLs, inline styles and preprocessors stay qualified.
CSS top-level `@import` strings and `url()` targets can identify a declared npm
installation or configured mapping. Safely discovered local files take
precedence. Unknown references, escapes, computed imports and plugin directives
leave usage incomplete; asset URLs do not establish npm usage. Inspect these
diagnostics before suggesting removal or treating a scan as complete.
CSS imports have build scope when the owning project declares Vite, Astro,
webpack, or Rollup and has the corresponding root configuration file. Otherwise
`usage.unsupported-css-scope` preserves unknown scope and incomplete usage; a
CSS import alone does not justify moving a devDependency into dependencies.
Static command evidence covers a limited set of tools and portable commands. Check frontend
scripts and test/build configuration before suggesting removal or scope moves.

Exact `package.json` imports string keys can map to bare npm package targets,
explicit safely discovered local files, or bare Node builtins such as `"fs"`
and `"fs/promises"`. An imports target of `"node:fs"` is invalid; direct source
imports using that specifier are valid. Package targets have
exact confidence and retain their package.json reason; local/builtin aliases
are not external dependencies. Conditions, arrays, nulls, wildcard patterns,
alias chains, missing/unsafe local files and unsupported targets produce
`mapping.alias-unsupported` and leave usage incomplete. Scoped configured
mappings take precedence. TypeScript paths and full Node resolution are not implemented.

pnpm v9 locks provide registry versions and instance edges per workspace importer,
including optional dependencies and peer instances. Other lock versions and
local, file, Git, or URL resolutions leave resolution incomplete. Check lock
diagnostics before claiming full coverage. npm installation aliases retain
their local import names but use the real registry identity for inventory,
OSV, and SBOMs; do not suggest installing the alias name as a separate package.
Declarations and resolutions retain `origin` assertions. Public npm PURLs and
OSV coordinates require a supported public registry assertion; Git, path,
download URL, alternate-registry and unknown instances retain inventory without
those coordinates. A public advisory must not be assigned to a private instance
sharing the same name and version. Skipped instances keep security incomplete.

Yarn Modern lock versions 8 and 10 use independent `npm:yarn-lock:<root>` scopes,
including standalone locks. Each descriptor keeps its request, physical record
position, locator/version assertions, alias installation name and conditional
dependency/peer/checksum/build context. Grouped and repeated requests survive
queries and CycloneDX conditional properties. Context is uninterpreted; a checksum
is not verified integrity. Malformed records, unsupported fields and bounded
expansion leave explicit gaps while readable siblings/prefixes remain available.
Classic and other Modern format versions remain unsupported.
Collection uses the shared 8 MiB file, 200,000 YAML-node and 64-level nesting
bounds, plus 20,000 descriptors, 8 MiB of expanded metadata, 64 diagnostics,
65,536 characters per descriptor group and 4,096 per descriptor/locator. These
are collection limits; exhausted budgets qualify omitted evidence.

Do not attribute this inventory to an application or workspace, treat a locator
version as installed/selected, infer public package identities or query advisories
from it. Registry/configuration selection, overrides, peer virtualization, PnP,
installation and source usage remain unknown. The separate scope supplies no
direct application edges and cannot satisfy application imports or justify removal.

Canonical lock versions follow SemVer with node-semver's 256-character bound
and `2**53 - 1` maximum for each major/minor/patch component. Leading zeroes
are invalid in numeric prerelease identifiers but valid in build metadata.
Valid alpha/beta/rc versions and prereleases with multiple identifiers remain intact;
Git tag prefixes do not establish registry package versions.
Invalid npm versions remain raw inventory without public PURLs/OSV coordinates;
invalid pnpm snapshot keys leave gaps while supported neighbors remain collected.
Do not normalize these assertions into published or installed versions. This
validation does not implement dependency request ranges or tag selection.

The repository-only `.npmrc` reader retains positioned default/scoped registry
assertions. It omits authentication settings and removes credentials, queries
and fragments from new origin URL fields. A lock's default-registry URL follows
the collected registry context. Missing lock `resolved` fields can retain a
registry assertion for a canonical version. Absent repository overrides use
npm's public default; that assertion does not verify package visibility,
installed sources or effective runtime configuration. User/global configuration,
environment expansion, command-line overrides and workspace precedence are not
evaluated. Dynamic/indirect, aliased, malformed or over-budget configuration
and conflicting candidates stay unknown. Limits are 64 ancestor directories,
256 KiB and 4096 lines per configuration file, and 256 total registry entries.
`source.registry-incomplete`, `source.registry-ambiguous` and
`resolution.source-incomplete` preserve gaps; do not turn them into a clean
security result. Configuration changes invalidate cached evidence. Existing raw
manifest constraints remain source assertions; origin URL sanitization is not a
general secret-redaction guarantee for arbitrary input fields.

Locks from different npm/pnpm/Yarn families produce
`resolution.package-manager-ambiguous`, incomplete resolution and unknown exact
versions. This also applies to inherited workspace locks and to projects with
a `packageManager` pin. Do not choose or delete a lockfile to obtain a clean
result. For npm's own lock formats, `npm-shrinkwrap.json` takes precedence over
`package-lock.json`.

Inherited pnpm locks need workspace ownership evidence. A closer
`pnpm-workspace.yaml` stops outer inheritance even when it has no lock.
Supported patterns retain exclusions and zero-directory globstars; unsupported
patterns and missing pnpm workspace metadata preserve unknown membership.
An npm workspace declaration or old importer alone does not confirm an active
inherited pnpm graph. Review `resolution.workspace-ambiguous` before interpreting
resolved versions or proposing lock changes.
