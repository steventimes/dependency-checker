# Python declarations and source assertions

Source columns start at one and count Unicode code points. Python AST byte
offsets are converted for imports and dynamic-load diagnostics, including source
decoded with a coding cookie. Universal newlines retain logical line boundaries.
Static Python/Conan/Bzlmod syntax readers parse captured text without asking
CPython to reopen target filenames when constructing errors; evidence retains
the actual file separately.
Refresh pre-revision-53 indexes to replace old byte-based Python columns.

On Python 3.15, explicit lazy imports retain `kind: "lazy"` and their source
positions. Parsing does not load the modules or prove that the lazy names are
accessed. Older backend interpreters report unsupported syntax rather than
claiming complete coverage of a source they cannot parse.

Notebook import locations use virtual lines across code cells and code-point
columns within each cell. Do not interpret these as physical lines in the JSON
file. SARIF uses a file-only location and preserves the virtual coordinates in
`depcheck:reported-region` with `depcheck:region-status: notebook-virtual`.
Invalid Unicode cells leave a diagnostic while readable cells remain collected;
cell-to-JSON character mapping and actual notebook execution remain unsupported.

Compiled `requirements*.lock` and `*-requirements.lock` files provide exact
Python version evidence, including multiline hash options and markers. These
locks are read-only evidence sources; update previews still target supported
requirements text entries or explicit static PEP 621 groups.

PEP 735 group names are compared after normalization; declarations retain
`metadata.group: dev:NAME` with the original spelling. Includes preserve order,
repeated occurrences and original requirement locations. Several occurrences at
one physical source can result from includes; do not call them separate source
declarations or automatically recommend removal. Entry/context/diagnostic limits,
invalid/colliding names, unsupported include tables, absent targets and cycles
leave qualified evidence. Group inventory does not establish installed selection,
and development-group update previews remain unsupported. Refresh pre-revision-38
indexes for the corrected counts and group-name matching.

Legacy `tool.uv.dev-dependencies` entries contribute to the development `dev`
group alongside standard `dependency-groups.dev`, retaining each declaration's
location, marker, extras and source assertions. uv appends legacy entries after
standard include expansion; groups including `dev` do not inherit those entries.
Invalid shapes or entries leave diagnostics while valid siblings remain visible.
Group budgets apply to both forms. Installed selection stays unknown and update
previews remain unsupported for these development declarations. Refresh indexes
older than analysis revision 40 to collect the legacy entries.

Python constraint checks preserve declared development groups. A proven
group-local conflict includes its group in finding details; incompatible
cross-group/runtime requests produce `analysis.python-group-selection-unknown`
when no local conflict is proven. Treat that as incomplete hygiene, not proof
that the installed environment conflicts or that native resolution succeeded.
uv conflict/default-group rules and actual selection remain unevaluated.
Different marker predicates leave intersection applicability unknown. A conflict
under one shared predicate retains its marker; do not infer activation from it.
Analysis errors persist in cached project evidence: `evidence_complete` remains
false even when source `usage_complete` is true. Read context coverage and scan
diagnostics to identify the reason. Refresh pre-revision-39 indexes.

Python inventory retains `origin` on resolutions and in declaration metadata.
Local/editable, Git, private-registry and unknown sources do not establish public
PyPI package URLs or OSV coordinates; keep resolution/security incomplete and
public PyPI compatibility checks skipped for them. Known versions remain visible.
Source assertions describe configuration, not verified installed provenance.

Requirements index options apply to the complete include/constraint graph,
including later or compound option lines and recognized long-option prefixes.
Repeated collector entry paths cannot restore public identity after a private
context was observed. Local find-links, no-index, private/mixed indexes and
incomplete includes suppress public lookups. Private constraints also qualify
otherwise public lock assertions. Bare requirements without overrides retain
the default PyPI assumption.

Recognized URL `userinfo` and query values are redacted before requirements,
diagnostics and complete origin assertions enter reports or indexes, including
nested uv dependency contexts. Classification uses the original source. This
is not a general secret scanner for arbitrary input fields. `setup.cfg` retains
valid interpolation with one shared output/work budget for runtime and extras.
Refresh pre-revision-58 indexes for these corrections.

Poetry, PDM and uv lock records retain occurrence IDs, original package indices
and bounded resolution `metadata`. Groups, extras, Python conditions and raw
dependency requests remain assertions with unknown activation. Repeated rows
survive independently even when package names and versions match. Only
unconditional requests with one comparable lock-local target supply required
edges; conditional, ambiguous, omitted and over-budget requests remain incomplete.
Captured private index policy also qualifies default-source transitive rows.
An explicit lock source remains separate from a declaration's effective origin.

For Poetry, PDM, uv, Pipfile and pylock occurrences, `direct: true` requires a unique
compatible public occurrence for a direct declaration. A same-name version outside its PEP 440 range is not a direct
binding. Captured Pipenv categories are compared separately. Multiple matching
occurrences, unverified/private source bindings and exhausted work budgets retain
`directness_status: "unknown"` and incomplete resolution. Other statuses are
`matched-declaration` and `not-bound-to-declaration`. These compare captured
declarations with inventory; they do not establish installation, active groups,
extras or workspace availability. Recorded prereleases participate in range
comparison, while installer prerelease policy remains unknown. No version or
origin is changed by this comparison, and eligible advisory queries still include
other locked versions. Refresh pre-revision-70 indexes for these corrections.

The current source uses one bounded uv source profile for root declarations and
workspace inheritance. A non-table `tool.uv.sources`, invalid package key,
normalized-name collision or exhausted table budget remains unverified instead
of becoming an empty public-PyPI default. Known requirement constraints and
source locations stay available; `uv_source_status` qualifies incomplete details.

The table permits 1024 entries and 64 KiB. Each source assertion has an 8 KiB
budget and at most 128 alternatives; root and inherited projections each have
a shared 1 MiB detail budget. Literal Git/URL/path/index/workspace fields,
revision/tag/branch/subdirectory, markers, extra/group and editable/package/lfs
flags are retained when their types fit the profile. Unsupported or malformed
fields are omitted with a diagnostic; this is not complete uv schema validation.
A conditional list remains a list with unknown activation, including its order
and markers. The analysis host never selects one of those alternatives.

Omitted or redacted assertions retain `source_assertion_sha256` when bounded
canonical JSON is available. This identifies supplied content before projection;
it does not authenticate a producer, establish source equality or prove an
installation. The original direct-URL assertion remains separate in
`metadata.uv_declared_origin`, or keeps an omission marker and digest when its
budget is exhausted. Unsupported raw fields and URL-shaped keys are not emitted.
Existing credential redaction remains in effect. Refresh pre-revision-74 indexes.
See [uv dependency sources](https://docs.astral.sh/uv/concepts/dependencies/#dependency-sources).

uv workspace root `tool.uv.sources` and index assertions qualify member
pyproject declarations. A member's source entry replaces the root entry for
that name, including when the member entry has an unselected marker. Root
source positions and the workspace-relative path base are captured under
`metadata.inherited_uv_source`; source paths and URLs are not followed. Unknown
membership, malformed or ambiguous tables and source budgets preserve unknown
origins rather than public PyPI identities. Excluded or unmanaged components,
standalone requirements and Hatch environment declarations do not acquire
workspace source policy. Shared lock activation and cross-member availability
remain unknown; the root lock is not copied into each member's installed graph.
Root configuration changes invalidate selected member evidence; queries remain
read-only until an explicit index refresh. Refresh pre-revision-72 indexes.
Source tables have 1024-entry and 64 KiB budgets; inherited origin details have
a shared one-MiB projection budget. An exhausted budget leaves an unverified
origin and diagnostic, retaining the declaration and configuration file. Unknown
spans stay file-only. These are policy assertions, not source-content identity.
The lock-only `registry` field in `tool.uv.sources` stays unverified; uv source
tables select named indexes through `index`. Actual lock registry assertions
retain their separate classification.
Project index policy is captured separately under `metadata.uv_index_policy`.
Within the selected repository, lookup starts at the workspace root for members
and otherwise at the owning pyproject directory. The nearest configuration wins;
`uv.toml` takes precedence over a same-directory `[tool.uv]` configuration. The
selected configuration location remains visible even when its index settings
are empty. This does not select an installer or authenticate a registry.

The bounded profile reads `index`, legacy `index-url`/`extra-index-url`,
`find-links` and `no-index`. Index entries retain `name`, `url`, `default`,
`explicit`, `authenticate` and `format`; other entry fields are omitted with a
diagnostic. URL credentials are redacted, and referenced URLs or directories
are not read. Index assertions have an 8 KiB budget and configuration search a
64-directory limit. Malformed, unreadable, unsupported or over-budget selection
stays unverified instead of becoming a public PyPI identity. A file-content
consistency error still aborts the operation.

uv pip index settings have a separate diagnostic and do not choose the project
registry. Requirements and PEP 723 installation scopes remain separate. Captured
uv policy qualifies the corresponding PEP 621/group/build declarations. Poetry
and PDM declarations and lock origins keep their manager's source assertions.
uv lock metadata retains configuration provenance without rewriting its captured
registry origin or selecting an installed graph. Configuration additions, changes and removals invalidate cached
member evidence. Queries stay read-only. User/system configuration, environment,
CLI overrides and actual installation remain uncollected. Refresh pre-revision-73
indexes. See [uv configuration](https://docs.astral.sh/uv/concepts/configuration-files/).

See [uv workspace sources](https://docs.astral.sh/uv/concepts/projects/workspaces/#workspace-sources)
and [workspace configuration](https://docs.astral.sh/uv/concepts/configuration-files/).

uv locks also retain the compatible `origin.lock`: the format version/revision, `requires-python`,
root/package resolution markers, supported/required environments, conflicts and
literal dependency/extra/group assertions. These are bounded inventory, with
`activation: "unknown"`; no marker is evaluated against the agent's host to pick
a branch. Conditions, repeated package names or omitted context leave resolution
incomplete. Distinct physical lock entries have `lock:uv:` instance IDs, including
repeated name/version pairs. They survive refreshes and read-only queries.
Conditional locks cannot seed the single-environment compatibility graph:
`compatibility.uv-lock-selection-unknown` (or
`compatibility.python-lock-selection-unknown` for legacy TOML locks) returns no selected versions or upgrade
suggestions. An explicit Python version alone does not select OS, extras or groups.
Public known versions may still receive separate OSV queries. Conditional findings
retain `lock_context` and unknown activation; matching an advisory is not proof of
an active vulnerable installation. CycloneDX retains the lock context in origin
and resolution metadata properties. Lock edges do not prove an active application
graph. Invalid fields, package limits
and context budgets leave explicit gaps. This does not implement uv resolution,
installation, checksum verification, build selection or shared-workspace activation.
Refresh older indexes with the current backend. Schema v7 also keeps captured
requirement metadata in the incremental declaration cache; queries do not migrate
older caches or reread source to fill missing cached assertions.

Pipfile/Pipfile.lock use literal named indexes and their configured default
source. Private, missing, duplicate or malformed source selections stay
unverified; do not replace them with a public PyPI lookup.
Pipfile custom categories retain `metadata.group: pipenv:NAME`; their scope is
unknown and their declarations are conditional. A custom category does not
imply development use or a Python extra. Explicit compatibility group selection
can include that named category when the remaining evidence is supported.
Bare wildcard versions remain PEP 440 constraints. Inline environment fields
are combined with `markers` using AND, preserving grouped OR expressions.
Pipfile.lock retains each category/name occurrence, including repeated versions,
with a JSON pointer, unknown activation and bounded context. Markers, extras,
source assertions and `_meta` remain inventory. Missing VCS/path versions stay
unknown declarations. This flat lock format supplies no per-package dependency
edges. Conditional locks cannot seed a selected compatibility graph; a target
Python version does not select a category or activate its records.
Pipenv context details have an 8 KiB per-record limit and a shared 256 KiB
retained-detail budget, including redaction expansion. Fixed occurrence shells
are separately bounded by the 20,000-record limit. Omitted details and invalid
records leave explicit diagnostics. Refresh pre-revision-68 indexes for these
category and metadata corrections. The current index schema is v8.
Artifact hash lists stay in the supplied lock and are excluded from displayed
context so they do not crowd out selection conditions. Their presence and a
valid list's count are retained; hashes and downloaded contents are not verified.
Pipfile, supported Python locks, setup.cfg and literal setup.py lists/tuples
carry structural declaration positions. Uncollected `setup(**kwargs)` expansions
report incomplete manifest coverage, including inline mapping expansions. Explicit
literal arguments remain separate evidence; the parser does not execute setup.py
or resolve assignments to discover the expanded keys. Interpolated, unordered or unmatched
values may retain file-only locations. Duplicate Pipfile.lock keys and invalid
setup.cfg interpolation are reported; do not turn missing spans into guessed
line numbers or a claim of complete usage coverage.

### PEP 751 pylock inventories

The current source reads `pylock.toml` and named `pylock.NAME.toml` version 1.0
files with Packaging 26.3 or newer. Packaging validates the bounded header and
each package separately. A malformed sibling does not discard other captured
records. Unsupported format versions retain `manifest.pylock-unsupported`.
Invalid data and omitted details leave explicit diagnostics. Package names have
structural locations, with file-only fallback where a span is unavailable.

Each known-version occurrence keeps `lock:pylock:` identity, package index and
`/packages/N` pointer, including repeated name/version pairs and multiple named
files. A VCS or directory source does not acquire a version from its path, ref,
artifact name or a conflicting declaration. Such records remain located,
unversioned lock declarations. PEP 440 prerelease strings are retained.

`metadata.context` keeps bounded root and package assertions: environments,
Python requirements, extras/groups/defaults, markers, VCS revisions, directories,
archives, sdists, wheels and optional attestation identities. Upload times use
the TOML decoder's datetime precision and are serialized as ISO strings. Hashes,
sizes, URLs, paths and publisher identities are supplied assertions. They are
not downloaded, opened, verified or authenticated. Disposable `tool` tables are
represented by presence flags. Source-only and whole-package fingerprints stay
separate; fingerprints identify supplied assertions, not source equivalence.

Only a validated distribution record with an explicit canonical public PyPI
index and canonical remote PyPI artifacts can supply public query coordinates.
Local artifact paths, direct VCS/directory/archive sources, missing/private
indexes, conflicting or omitted source details and unsupported extensions remain
unverified. A CDN URL alone never supplies the missing index identity. No artifact
content or current installation is inferred from a public coordinate.

Informational dependency selectors retain their own JSON pointers and match
raw records before credential redaction. `target_package_indices` refers only to
records in the same file. Statuses distinguish `matched-record`, `ambiguous`,
`unresolved`, `unsupported` and `budget-exceeded`. They do not create required
installation edges. Optional malformed attestation data has its own status and
does not erase otherwise supported package-version evidence.

The parser never calls `Pylock.select()` or chooses the analysis host's markers,
extras, groups or wheels. `resolution.pylock-activation-unknown` qualifies the
inventory, including an empty supplied package array. These records cannot seed
a selected compatibility graph. Manifest declarations, lock inventory and active
installation remain separate.

Limits are 20,000 packages, an 8 KiB root context, 16 KiB per-record details and
1 MiB shared retained details, excluding bounded occurrence shells. Literal
projection is limited to eight levels and 2,048 nodes. Informational selectors
have a 128-entry per-record limit and 100,000 comparison steps per file. Wheel
validation allows 128 artifacts per record, at most 4,096 expanded tags per
filename and 100,000 tag-validation work units per file, before calling the
native validator. Exhaustion preserves unknown states and omission diagnostics.

Configured exclusions and Python component ownership still apply. Full
repository scans with Python disabled by configuration retain generic
unsupported coverage; an explicit ecosystem selection keeps its selection scope.
Creation, modification and deletion invalidate the snapshot. Queries remain
read-only and require explicit refresh. Refresh pre-revision-77 indexes.
See the [pylock specification](https://packaging.python.org/en/latest/specifications/pylock-toml/)
and [Packaging's validation boundary](https://packaging.pypa.io/en/stable/pylock.html#validation).

## Hatch environments and Poe tasks

Current source collects literal `tool.hatch.envs.NAME.dependencies` and
`extra-dependencies` from pyproject files. These declarations have kind
`environment`, group/scope `hatch:NAME`, original locations and unknown
activation. Repeated physical entries remain distinct. They do not seed
application resolutions, public registry requests or compatibility solving.
Their markers are retained without evaluating the agent's host environment.
Source imports matching only an environment declaration leave
`analysis.python-environment-selection-unknown`, rather than asserting missing
availability or a scope mismatch.

Literal Hatch scripts become `environment-command` evidence when a fixed tool
maps to a declaration in that same environment. That evidence does not suppress
unused application dependencies. The scanner does not expand template
inheritance, script aliases, matrices, project-group selection or context
formatting. Those gaps remain explicit. A separate `hatch.toml` is inventoried
but not evaluated and prevents mapping the pyproject Hatch commands.

Poe string tasks and `{cmd = "..."}` tasks, optionally with help text, reuse the
existing command grammar and fixed mappings to this component's direct tools.
Shell/script/sequence tasks, custom executors, includes, task defaults,
environment overrides and working-directory changes remain unsupported. No task
or hook runs. Task selection and execution remain unknown even for literal
commands. Refresh pre-revision-59 indexes for this evidence.

Calls to recognized `importlib.metadata.entry_points` APIs, including aliases,
leave `usage.dynamic`: installed plugins may have no source import. Discovery
does not prove any plugin was loaded or unused. Reflective calls, decorators and
reexports retain the callable analysis's separate uncertainty rules.

## Component identity

Named PEP 621 or Poetry pyprojects establish
separate Python component IDs, such as `pypi:python:apps/api`. Scanning that
component as the repository root gives `pypi:python:.`; discover identities again
when the root changes. Do not carry a legacy aggregate ID into a split
repository. If that ID disappears, migrate matching scoped mappings and tool-usage
entries to their verified component owners before retrying; do not copy rules
to every component to silence the error. A remaining root project owns that ID
only for its own files. Refresh pre-revision-28 indexes before querying.
Schema v4 stores Python source assertions; queries reject older schemas without
changing them, and explicit indexing rebuilds the derived cache.
Explicit `python-roots` in `.depcheck.toml` can establish anonymous component
scopes; do not add them just to silence a read-only trial. uv members retain
separate source/declaration owners, while shared lock activation and cross-member
availability remain unknown. Unconfigured anonymous roots can stay incomplete
even without repeated names. Retain the stated root
and scope in component decisions.

## Metadata compatibility and script scopes

Compatibility uses resolvelib backtracking with a public metadata provider.
`resolution_status` distinguishes resolved, unsatisfiable and incomplete models;
missing metadata, direct URLs and budgets do not prove unsatisfiability. Report
candidate graphs separately from artifact availability, installation and API
compatibility. Extras retain both base and selected-extra dependencies, sharing
one base version through backtracking. Requires-Python also participates.
Markers that need unavailable contexts or unsupported comparisons leave
compatibility incomplete; a root with unknown applicability retains its
declaration and a diagnostic. Do not interpret it as an active environment or
use it to establish missing/unused dependency advice. Root
constraints do not add packages; non-public homonyms are never replaced with
public PyPI records. Conditional uv locks remain blocked before metadata queries.

Runtime is the default compatibility context. Explicit
`--dependency-group dev:test` / `--dependency-group optional:docs` selections
apply to each selected Python project. Read `resolution.selected_groups` and
`unselected_groups`; no default/native group policy is inferred. Lock-relaxation
suggestions require a consistent relaxed graph; a failed branch does not become
`selected_versions`. Highest eligible versions are preferences, not a proof of
optimal security, minimum edits or semantic compatibility.

Closed PEP 723 comment blocks create independent
`pypi:pep723:path/to/script.py` projects. Metadata inside Python strings is
ignored. Dependencies preserve their physical positions, extras, markers and
source assertions. Arbitrary runner `tool` configuration makes public source
identity unknown. Adjacent runner locks, interpreter selection, shared local
helpers and execution remain unknown. Normal Python components exclude these
script files from their source ownership. Do not use zero observed imports to
remove script requirements. Rebuild older indexes with the current backend and schema.

### Requested Python versions and lock inventory

An explicit Python target filters each declaration or lock record by its own
marker. An excluded direct declaration does not remove independently locked
records with the same name: another dependency can still reference them. Retain
those records for inventory and qualified advisory matching. Lock presence alone
does not establish installation, group selection or runtime activation. Refresh
pre-revision-80 indexes to recover records removed by the earlier name-based
filter.

The v7 index stores Python source digests separately from manifest digests.
A setup.py file can occupy both roles without dropping imports, declarations or
change tracking. Indexing rebuilds older caches; queries leave them unchanged.

Requirements `-r`/`-c` relative paths may contain `..` when their normalized target
remains inside the caller-selected project root. The parser does not widen that
root. Absolute includes and paths escaping through parent traversal or symlinks
remain rejected; remote includes are not fetched. Included declarations retain
their original locations, inherited group and direct/constraint role. Cycles,
include budgets and incomplete-source qualifications remain in effect. Refresh
pre-revision-86 indexes for corrected in-root parent-include evidence.

`setup.cfg` `[options]` supports literal `install_requires` as `runtime`,
`setup_requires` as `build` and `tests_require` as `dev:test`, matching the existing
`setup.py` field roles. Both formats share that fixed mapping; each retains its
own bounded AST or INI reader. Extras stay `optional:<name>`. Repeated lines,
markers, requested extras and raw requirements survive canonical JSON/index
projection. Interpolation shares one budget across all fields and extras;
expanded values without literal spans keep file-only positions. Unsupported
`file:`/`attr:` values receive requirement diagnostics without reading/evaluating
them. Build and test declarations do not prove a build/test run, installed copies
or an authenticated registry download. Bare registry names retain the existing
default-PyPI assumption, not verified installed provenance. CycloneDX is component
inventory; use canonical JSON/index for complete group/marker/occurrence details.
Legacy flat parsing excludes build requirements, as `setup.py` already does.
Refresh pre-revision-87 indexes for this inventory.
