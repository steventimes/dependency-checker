# Python declarations and source assertions

Source columns start at one and count Unicode code points. Python AST byte
offsets are converted for imports and dynamic-load diagnostics, including source
decoded with a coding cookie. Universal newlines retain logical line boundaries.
Static Python/Conan/Bzlmod syntax readers parse captured text without asking
CPython to reopen target filenames when constructing errors; evidence retains
the actual file separately.
Refresh pre-revision-53 indexes to replace old byte-based Python columns.

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

uv locks retain `origin.lock`: the format version/revision, `requires-python`,
root/package resolution markers, supported/required environments, conflicts and
literal dependency/extra/group assertions. These are bounded inventory, with
`activation: "unknown"`; no marker is evaluated against the agent's host to pick
a branch. Conditions, repeated package names or omitted context leave resolution
incomplete. Distinct physical lock entries have `lock:uv:` instance IDs, including
repeated name/version pairs. They survive refreshes and read-only queries.
Conditional locks cannot seed the single-environment compatibility graph:
`compatibility.uv-lock-selection-unknown` returns no selected versions or upgrade
suggestions. An explicit Python version alone does not select OS, extras or groups.
Public known versions may still receive separate OSV queries. Conditional findings
retain `lock_context` and unknown activation; matching an advisory is not proof of
an active vulnerable installation. CycloneDX retains the lock context in origin
properties without inventing application edges. Invalid fields, package limits
and context budgets leave explicit gaps. This does not implement uv resolution,
installation, checksum verification, build selection or shared-workspace activation.
Refresh indexes older than analysis revision 45; schema v4 stores this context.

Pipfile/Pipfile.lock use literal named indexes and their configured default
source. Private, missing, duplicate or malformed source selections stay
unverified; do not replace them with a public PyPI lookup.
Pipfile, supported Python locks, setup.cfg and literal setup.py lists/tuples
carry structural declaration positions. Interpolated, unordered or unmatched
values may retain file-only locations. Duplicate Pipfile.lock keys and invalid
setup.cfg interpolation are reported; do not turn missing spans into guessed
line numbers or a claim of complete usage coverage.

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
remove script requirements. Rebuild pre-revision-55 indexes; schema v4 is unchanged.
