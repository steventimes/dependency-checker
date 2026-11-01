# Analysis limits

Use the [reference routing](../SKILL.md#read-the-relevant-guidance) for ecosystem
guidance. These constraints describe static evidence and advisory interpretation
for the current source.

Discovery excludes common generated and installed-package directories, including
`.tmp`, `node_modules`, `site-packages`, and `dist-packages`. It does not interpret
`.gitignore`. Use scoped `excluded-directories` settings or a stated source
snapshot when ignored artifacts should be outside the audit.

`scope.repository_complete` describes the index selection within registered
ecosystems. Scan `metadata.coverage` and context `coverage` list recognized
uncovered paths and reasons, independently of that selection. Unregistered
PHP, Ruby, Dart, and .NET manifests prevent a complete repository conclusion.
The list concerns recognized formats; an empty list does not prove support for
every file format. Browser/CDN dependencies remain outside the packs.
SCSS and Sass produce `usage.unsupported-source`. Vue and Svelte support bounded
literal top-level JavaScript/TypeScript script and CSS style regions, including
source positions and npm aliases. Template expressions, implicit framework
imports and compilation stay incomplete (`usage.unsupported-component-template`).
Extraction stops after template expressions can hide subsequent markup;
preprocessors and custom attributes remain qualified. See the
[Vue SFC specification](https://vuejs.org/api/sfc-spec.html) and
[Svelte file structure](https://svelte.dev/docs/svelte/svelte-files).

Astro frontmatter and literal imports in supported script/style regions retain
source locations and npm installation aliases. Template expressions and the
remaining template after the first expression are unparsed, preserving known
frontmatter imports while leaving usage incomplete. Browser scripts, external
URLs, inline styles, and style preprocessors remain qualified. `astro:` virtual
modules do not become npm package names.

CSS supports literal top-level `@import` strings and quoted or bare `url()`
targets. A safely discovered local file takes precedence over a package name.
Only a declared npm installation or scoped mapping establishes a package owner;
unknown names and external URLs remain unknown. Escapes, computed imports,
nested imports, and dependency-bearing preprocessor/plugin directives produce
diagnostics. A declared Vite, Astro, webpack, or Rollup tool and its root
configuration file establish build scope for CSS imports. Otherwise
`usage.unsupported-css-scope` preserves unknown scope and incomplete usage;
CSS imports alone do not require moving devDependencies into dependencies.
Asset `url()` values are not package imports. See the
[Astro script rules](https://docs.astro.build/en/guides/client-side-scripts/) and
[Vite CSS imports](https://vite.dev/guide/features.html#css-import-inlining-and-rebasing)
for the bundler behavior this collection models.

Projects with locks from more than one of npm, pnpm and Yarn produce
`resolution.package-manager-ambiguous`. Resolution remains incomplete, and no
single lock graph supplies exact versions for queries or OSV. A `packageManager`
pin does not resolve conflicting committed graphs. Confirm the intended manager
and lock before making changes; depcheck does not delete or regenerate either.
For npm's two lock formats, `npm-shrinkwrap.json` takes precedence over
`package-lock.json`, following the
[npm lockfile rules](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

npm inventory retains declaration and lock `origin` assertions. Git, local,
download URL, alternate-registry and unknown sources do not supply public npm
PURLs or OSV coordinates. Public advisory matches belong only to eligible
instances, including when a private instance has the same name and version.
Skipped instances keep security incomplete; their inventory and graph evidence
remain available. npm v1/v2/v3 locks and shrinkwrap retain these distinctions.
pnpm registry instances use the same configuration evidence; unsupported pnpm
source forms still leave explicit resolution gaps.

Yarn Modern lock versions 8 and 10 have separate `npm:yarn-lock:<root>` inventory
scopes, including standalone locks. Each descriptor retains its literal request,
the locator/version assertions and the physical record position. Repeated and
grouped requests retain their multiplicity; aliases retain their installation
names. Dependency and peer requests, optional/build metadata, conditions, checksums,
link types and cache keys remain uninterpreted assertions. Unsupported record
fields are omitted with a diagnostic. Invalid records and entry/context limits
retain readable prefixes and explicit coverage gaps.

These scopes do not establish application/workspace ownership, registry selection,
peer virtualization, PnP, installation or source usage. They add no selected
versions, public advisory queries or direct application SBOM edges. Patches, local
and Git locators retain their assertions without becoming public npm identities.
Classic locks and other Modern format versions remain unsupported. See the
[Yarn lock writer](https://github.com/yarnpkg/berry/blob/e4e423a1eb117b5129f20ac626a03eb7a97aedff/packages/yarnpkg-core/sources/Project.ts)
and [descriptor/locator definitions](https://yarnpkg.com/advanced/lexicon).

Exact npm lock coordinates require canonical SemVer text within node-semver's
256-character limit and safe-integer limit of `2**53 - 1` for each release
component. Prereleases such as `1.0.0-alpha.1`, `1.0.0-beta.0` and `1.0.0-rc.1`
remain valid. Numeric prerelease identifiers cannot have leading zeroes; build
metadata may contain them. Git tag prefixes do not establish package versions.
Invalid npm lock versions retain their raw inventory and incomplete source
state without public queries. Invalid pnpm snapshot keys
leave explicit gaps while supported neighbors remain available. Dependency
request ranges and tags are not normalized by this validation. See
[SemVer 2.0.0](https://semver.org/) and
[node-semver limits](https://github.com/npm/node-semver/blob/v7.5.4/internal/constants.js).

The bounded `.npmrc` reader collects only default and scoped registry settings
inside the audited root, with positions. Authentication settings are omitted;
new origin fields remove URL credentials, query strings and fragments. A default
registry URL in an npm lock is interpreted with the repository's registry
assertions, following npm's configured-registry convention. Missing `resolved`
fields can retain a registry assertion for a canonical version. Without a
repository override, the assertion is npm's public default. This describes
static configuration, not verified package visibility or an installed registry.
User/global files, environment expansion and command-line overrides are not read
or evaluated. Indirection, aliased configuration paths, malformed or bounded inputs and conflicting
ancestor/duplicate candidates remain unknown; workspace precedence is unevaluated.
Registry inputs and their creation/removal invalidate cached evidence. See
[npm registry configuration](https://docs.npmjs.com/cli/configuring-npm/npmrc/).

Python pyprojects with a literal PEP 621 or Poetry project name establish
component roots. Each component owns its nearest manifests, locks and sources;
nested components cannot supply each other's local modules or command usage.
IDs are repository-relative, such as `pypi:python:apps/api`. Scanning `apps/api`
as the repository root gives that component `pypi:python:.`. Read the returned
identities rather than carrying an aggregate ID into a split repository.
If the old `pypi:python:.` ID disappears, update matching `[mappings.PyPI]`
tables and `[[tool-usage]]` entries in `.depcheck.toml` to their owning component
IDs. Scans reject that orphaned scope and list the available IDs. Keep a rule
only in components whose configuration supports it. When a root Python project
still exists, `pypi:python:.` applies to that root alone. Component-root scans
continue to use `pypi:python:.` within their selected root.
Anonymous pyprojects without explicit `python-roots` retain conservative aggregate
handling; multiple dependency-bearing roots produce
`analysis.python-component-scope-ambiguous`. uv members keep component IDs and
`resolution.uv-workspace-activation-unknown`; the shared lock inventory does not
establish a member's active graph. See [uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/).
After updating scoped configuration, run `depcheck index .` to rebuild the
derived cache with the current analysis revision. A failed refresh leaves the
previous cache intact; queries reject it while it is stale. Index refresh replaces old
project rows; schema v7 stores Python origins, captured requirement metadata and
independent resolution metadata. Queries
reject older schemas without writing them; indexing rebuilds the derived cache.
Component indexing currently
rescans evidence rather than reusing individual Python parse results.
Unchanged selected-index queries check content digests, file topology and
ownership controls without reparsing evidence. A changed guard falls back to
the full selected scan. Queries keep the cache read-only; freshness is never
inferred from modification times alone.
Compiled `requirements*.lock` and `*-requirements.lock`
files retain exact versions and requirement markers, including multiline hash
options. Locks are evidence sources; update previews target supported text
requirements or explicit static PEP 621 groups.

PEP 735 dependency groups compare names after normalization while retaining their
original spelling in `metadata.group` as `dev:NAME`. Includes preserve list order,
repeated occurrences and the original requirement location. Reaching one physical
assertion through multiple includes does not by itself create a duplicate-source
finding. Separate source declarations and their columns remain distinct.
Colliding/invalid names, non-exact include tables, missing targets, cycles and
entry/context/diagnostic limits leave explicit gaps. Group declarations do not
establish which groups were installed. Update previews still cover requirements
text and supported PEP 621 entries. See the [dependency groups specification](https://packaging.python.org/en/latest/specifications/dependency-groups/).

Legacy `tool.uv.dev-dependencies` strings are collected in the development group,
alongside standard `dependency-groups.dev` declarations. Their original locations,
markers, extras and source assertions are retained. Following uv's behavior,
legacy entries are appended after standard includes are expanded: another group
that includes `dev` does not inherit those legacy entries. Invalid entries retain
diagnostics and valid siblings; the shared group budgets still apply.
Neither form establishes installed selection or supports an update preview.
See [uv's legacy development dependencies](https://docs.astral.sh/uv/concepts/projects/dependencies/#legacy-dev-dependencies).

Constraint intersections are checked within each declared Python development
group, including its expanded includes. A group-local conflict retains that
group in the finding details. Incompatible requests across development groups,
or between those groups and runtime scope, produce
`analysis.python-group-selection-unknown` when no group-local conflict is proven.
This keeps hygiene incomplete without asserting an active-environment conflict.
Installer rules, uv conflict/default-group settings and actual group selection
remain unevaluated; these checks do not validate native lock generation.
Different PEP 508 marker predicates leave their joint applicability unknown;
marker overlap is not solved. A conflict under one shared predicate retains it
in finding details, without establishing that it is active.
Analysis diagnostics survive indexing, and a project with an analysis error
retains `evidence_complete: false` in dependency queries. Source-usage completeness
is reported separately.

Python declarations and lock entries retain static source assertions. Explicit
uv lock sources must identify public PyPI before supplying OSV coordinates;
local/editable paths, Git, private registries and unknown sources keep versions
in inventory without asserting a public package URL. Resolution and security
remain incomplete for those sources, and public PyPI compatibility checks skip
them. Conflicting declared uv sources conservatively block public lock lookup.

uv locks retain bounded environment and fork context in `origin.lock`: format
version/revision, Python constraints, root/package resolution markers,
supported/required environments, conflicts and dependency/extra/group assertions.
Each physical entry has a distinct `lock:uv:` instance, even for repeated
name/version pairs. Conditions are retained as data; the scanner does not use
the agent's OS or an explicit Python version to choose an installed branch.
Conditional inventories keep resolution incomplete and return
`compatibility.uv-lock-selection-unknown` instead of selecting one version,
reporting a flat version conflict or suggesting an upgrade from that graph.
Known public versions may still be checked separately against OSV; affected
candidate findings retain `lock_context` and `activation: "unknown"`.
CycloneDX preserves origin context without adding inferred application edges.
Unsupported field shapes and context/package limits produce explicit gaps.
Refresh indexes older than analysis revision 45. See
[uv's universal resolution](https://docs.astral.sh/uv/concepts/resolution/#universal-resolution).

Source-qualified instances remain distinct in snapshots/SBOMs; CycloneDX also
retains `depcheck:source:origin`. This does not prove installed provenance.
See [uv dependency sources](https://docs.astral.sh/uv/concepts/projects/dependencies/#dependency-sources).
PEP 751 pylock v1.0 records are static inventory. Known versions, source
assertions and informational record selectors survive independently, including
repeats. VCS/directory versions, selected environments, artifact execution and
installation remain unknown. Informational selectors do not create required
edges; fingerprints and attestation identities do not authenticate a producer.
Native structural validation does not fetch URLs or verify artifact contents.
See the [Python reference](ecosystems/python.md#pep-751-pylock-inventories).

Pipfile and Pipfile.lock use literal named index selectors and their configured
default source. Private, missing or duplicate source names remain unverified;
they do not silently acquire public PyPI coordinates. Local and Git assertions
retain their source fields. See [Pipenv index restrictions](https://pipenv.pypa.io/en/latest/indexes.html).

Maven versions inherited from unavailable parents or BOMs remain unresolved.
Literal child declarations survive a mismatched local parent, while the evidence
stays incomplete. Review local reactor SNAPSHOT versions in their build context.
Declared Maven build/reporting plugins are collected as conditional configuration
inventory. Effective plugin merges, lifecycle/profile activation, execution, and
parts of Java namespace ownership remain unknown.

Declaration locations in `pyproject.toml`, Pipfile, supported Python locks,
`setup.cfg`, literal `setup.py` lists/tuples, `package.json`, and `pom.xml` retain
line and column positions, including repeated declarations, group includes and
inherited Maven evidence. Structural positions refer to the parsed input.
TOML positions preserve raw boolean items and repeated array entries. Dotted
keys give implicit tables the start of their first defining key; explicit
headers keep their own locations. These are start positions, not inferred spans.
Quoted dots remain part of one key segment. Syntax positioning uses an
iterative walk and does not change the authoritative TOML values.
Interpolated or unmatched values keep file-only locations. Invalid
setup.cfg interpolation is reported. Duplicate keys and non-finite or
invalid-Unicode values in Pipfile.lock are rejected. Related parse diagnostics
use the entry's location where available. JavaScript
uncertainty reports the first unsupported construct and its reason; unresolved
namespace diagnostics identify the project and representative source reference.
Some legacy manifests and lock records still have file-level locations. Some
Python lock formats beyond the retained uv context still have uncollected
variant conditions; inspect the original lock before interpreting multiple
versions as an installed conflict.

Python import names without a configured or built-in distribution mapping remain
`inferred`; they do not establish a missing dependency. Add a scoped mapping when
you know the distribution name.

Literal `package.json` scripts and GitHub Actions `run` fields can provide
`usages.kind: "command"` evidence for a fixed set of declared test/build tools.
It has exact command-to-package mapping, a configuration location and a reason;
it is not an observed import or proof of execution. Workflow working directories
must identify the owning project. Supported prefixes include bounded `uv run`,
`python -m`, and local npm/pnpm/yarn script references. Unknown executables,
shell control flow, dynamic directories, and script cycles leave usage
incomplete. Commands are included in impact counts and excluded from `imports`.
Configured `kind: "tool"` evidence retains its separate user-provided reason.

Literal tsconfig `types`, `extends` and plugin names, plus pytest `addopts -p`
and `required_plugins`, can provide `kind: "configuration"` usage. Explanations
keep configuration locations and reasons; these entries are excluded from
source `imports`. TypeScript JSONC comments and trailing commas are accepted.
Local inheritance stays inside the repository and has file/depth limits.
Package-provided configuration, custom type roots, unsupported values and unknown
pytest plugin mappings leave usage incomplete. The scanner does not load
configuration modules or infer that a configured tool ran.

Inherited pnpm locks require workspace membership evidence. The nearest
`pnpm-workspace.yaml` forms a boundary, even without a lock. Supported literal
workspace patterns include `*`, `?`, `**` and exclusions. Extglobs and other
unsupported forms preserve unknown ownership. npm `workspaces` and stale pnpm
importers alone cannot confirm an inherited active pnpm graph. An unrelated
parent lock is excluded from an independent child's lock selection.

Non-literal Python module loads produce `usage.dynamic` diagnostics and suppress
unused-dependency conclusions. Literal `importlib` calls, including imported
aliases, retain usage evidence. Local-module detection uses top-level names in
the repository and its `src` directory; arbitrary Python path changes are not
resolved.

Exact `package.json` imports string keys support bare npm packages and subpaths,
safely discovered local files, and bare Node builtins such as `"fs/promises"`.
The target `"node:fs"` is invalid in that field, although source imports can use
it directly. Conditions, arrays, nulls, wildcards, alias chains, and unsafe or
absent local targets retain unknown usage with `mapping.alias-unsupported`.
Scoped configured mappings take precedence. TypeScript paths and full Node
resolution are not implemented.

Installation aliases such as `"safe-name": "npm:lodash@4.17.20"` retain their
local names for import matching and use the registry name for inventory,
vulnerability queries, and SBOMs.

Malformed dependency fields
or lockfile structures make evidence incomplete. Security still checks known
versions, but reports `security.collection-incomplete` if manifest or resolution
coverage is incomplete.

Python compatibility uses bounded resolvelib backtracking over public release
metadata. `resolution_status` distinguishes `resolved`, `unsatisfiable` and
`incomplete`; missing metadata or exhausted budgets cannot establish an
unsatisfiable graph. Runtime requirements are selected by default; add
`--dependency-group dev:test` or `--dependency-group optional:docs` to select
additional groups in each selected Python project. Extras add their dependencies
to the base dependencies; their versions and Requires-Python constraints
participate in backtracking. Markers without a supported evaluation context
retain an incomplete result rather than crashing or establishing compatibility.
Non-public homonyms are blocked. A selected graph
does not establish wheel availability, installation or API compatibility.
Non-Python indexing still rescans selected evidence rather than reusing
individual parsed files. `depcheck --profile index ROOT` writes inclusive local
work measurements to stderr; nested durations overlap and must not be summed.
The `io.work` entry counts completed reads and bytes; repeated captured reads
are counted only while a scan records read receipts. Counts describe work,
not distinct dependency evidence. Reads still validate pinned filesystem paths.

`context.refresh_plan` explains whether refresh is required and lists conservative
recomputation stages. Available Python/manifest or selected-evidence changes
include counts and up to 20 paths per category. Configuration and analysis
revision changes share a reason. Other ecosystem changes can remain a general
workspace-content reason. This read-only plan does not predict exact parser work
or apply a refresh.

Dependency explanations include a page-local `derivation`: source locations,
assertion pointers, content-derived references and rules for observed declaration
or import presence. Repeated assertions keep separate references. Support lists
distinguish alternatives from jointly required facts. Follow the existing evidence
pagination to inspect omitted facts. These references do not authenticate sources,
establish activation or provide minimal proofs for analyzer findings.

The wheel includes standalone JSON Schemas for
scan,
policy input and
unsigned provenance. Print one with
`depcheck schema scan`, `depcheck schema policy-input` or
`depcheck schema provenance`. They describe the current producer contract and
allow additive fields. Exporting a canonical scan also checks summary counts,
explicit capability states, project references and truncation. Incomplete scans
remain exportable when reported consistently; partial or inconsistent inputs
are rejected. These semantic checks do not implement a general schema validator
or change the compatibility rules of other evidence readers.

PEP 723 scripts have independent `pypi:pep723:path/to/script.py` identities.
Only actual comment blocks are read; examples inside strings are ignored.
Declarations retain positions, markers, extras and interpreter assertions.
Script source ownership does not absorb adjacent scripts or project requirements.
Runner locks, interpreter selection and imported local helpers remain unknown;
unobserved imports do not justify removing a script dependency.

Supplied CVE/CWE, VEX, attestations, call graphs, govulncheck streams, runtime,
artifact, ABI, deps.dev and Scorecard records have separate read-only inspection
interfaces. Offline OSV reevaluation, static Python callable propagation,
package-script comparisons, inventory comparison and unsigned provenance/policy
exports are described in the Skill's
[external evidence reference](external-evidence.md).
These operations do not suppress existing findings or install target packages.
Public registry existence checks require an explicit network flag and do not
establish publisher trust or package safety.
Offline OSV matching separates affected-version membership from fix availability,
retains per-advisory reasons, and normalizes supported ecosystem version equality.
Unsupported negative evidence stays unknown. Package-less Git assertions remain
unmapped; the tool does not clone repositories to infer package identity.

Use `repository_context.runtime_capabilities` or a project's
`supported_capabilities` to check which operations its ecosystem pack supports.
The project's `capabilities` report the state of indexed evidence. Update previews
support version entries in `requirements*.txt` and explicitly selected static
PEP 621 groups in `pyproject.toml`; other targets return diagnostics.

OSV `fix_versions` retain the matching package's raw fixed boundaries.
`fix_version` is a forward candidate for the queried version, using PEP 440 for
PyPI `ECOSYSTEM` ranges, strict SemVer precedence for `SEMVER` ranges, and full
Go module SemVer for Go `ECOSYSTEM` ranges. Go explicit versions and fix operands
normalize an optional leading `v`; `SEMVER` boundaries remain unprefixed. A candidate
must fall outside every comparable affected range and explicit affected-version
list in that advisory or its alias group. Reintroduced vulnerabilities and
parallel maintained branches therefore do not turn an earlier fix into a
downgrade suggestion.
`fix_version_status: "unknown"` preserves unsupported ordering, missing fixes,
unconfirmed range applicability and same-package entries without version
assertions. A positive match can survive these gaps without establishing a fix.
Invalid or over-budget detail data keeps
the matched advisory ID and a diagnostic. A candidate does not establish an
available release, dependency compatibility or safety against other advisories.
See the [OSV range evaluation rules](https://ossf.github.io/osv-schema/#evaluation).

OSV severity ratings are captured provider assertions. Package-level ratings
retain their original pointer and version scope; unknown applicability, mixed
top/package scopes or omitted assertions keep severity metadata incomplete.
Valid vulnerability membership survives malformed nested score metadata.
No CVSS calculation or severity threshold changes the existing risk policy.

OSV detail reuse follows `querybatch` modification times, including nanosecond
precision. Newer revisions trigger a refresh. Missing or invalid revision hints
cannot authorize reuse across calls; older details and failed refreshes retain
matched advisory IDs with diagnostics. Withdrawals that have taken effect are
excluded from active findings, with `osv.withdrawn-advisory` recording the ID and
withdrawal time. A future withdrawal remains active and carries a warning.
Withdrawal applies to that record alone; it does not withdraw an active alias
record or establish that the package is safe.

Active OSV records connected by `aliases` become one vulnerability for each
project/package/version/instance identity. `advisory_ids` lists the matched
source IDs and `advisories` preserves each source's parsed metadata, including
severity, fix assertions and timestamps. Group-level aliases include all member
IDs for policy matching. `related` and `upstream` do not merge vulnerabilities.

A group's fix candidate must satisfy all comparable source assertions. Missing
details or unconfirmed applicability keep the fix unknown; aggregate metadata
limits retain the sources and an incomplete diagnostic. Modification and future
withdrawal timestamps remain per source rather than describing the whole group.
Grouping follows the sources' alias assertions and does not prove runtime use.

Advisory metadata includes `cve_ids` from canonical CVE IDs in OSV `id` and
`aliases`, and `cwe_ids` from `database_specific.cwe_ids`. CVE identifies a
vulnerability record; CWE classifies a weakness. `identifier_references` gives
each assertion's official lookup URL, source advisory ID and field. These
fields survive JSON and SARIF exports; text reports show the lookup links.
Alias groups combine the IDs while retaining each source's assertions. A
group's reference projection is limited to 4096 entries; an omission count and
diagnostic point to the complete per-source assertions in `advisories`.

`weaknesses_status` is `reported`, `not-provided` or `incomplete`. Malformed or
over-budget CWE metadata retains valid IDs within a 256-entry per-source limit
and emits a warning; vulnerability matching and fix evaluation remain separate.
An absent classification does not establish the absence of weaknesses. IDs and
links are provider assertions: the backend does not fetch or validate the
current CVE/CWE records, their status, weakness names or taxonomy relationships.
See the [CVE List](https://github.com/CVEProject/cvelistV5) and
[CWE API guide](https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md).
Extracting these advisory identifiers adds no network requests. Supplied CVE/CWE
files can be inspected separately through the external evidence interface;
inspection does not fetch or authenticate the current upstream records.
