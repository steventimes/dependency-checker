# Maven and Gradle evidence

For Gradle use `ecosystem: Maven` and the qualified `maven:gradle:<root>` ID.
Supported literal calls are conditional configuration assertions, with original
positions, `gradle-required` requests, wrappers and lexical contexts; constraints
remain separate. They do not establish evaluated project ownership, selected
versions or installation. Both DSL build filenames can contribute assertions
without selecting the active script. Comments/documentation strings are not
declarations. Interpolation, aliases, map notation, triple-quoted arguments and
uncollected DSL syntax stay qualified. Unsupported slash syntax and exhausted
budgets retain only a qualified prefix.
Project/buildscript locks retain repeated instances and configuration names in
`origin`. `resolved_versions` describes asserted lock inventory, not the active
configuration or installed graph. Source requests do not supply exact OSV versions;
known lock assertions need a separate caller-approved public coordinate before
OSV queries. Overall security can remain incomplete.
Settings and helper scripts expose coverage/freshness gaps;
Gradle Kotlin scripts do not become Java application imports. No Gradle execution
or native resolution is performed. Refresh pre-revision-35 indexes before queries.

`*.versions.toml` library definitions use separate `maven:gradle-catalog:<directory>`
scopes in the Maven ecosystem. One scope can contain several files; version and
bundle references never cross file boundaries. Read `gradle_catalog_alias`,
`accessor_path`, `catalog_file`, `version_assertion`, version/reference sources
and repeated bundle memberships in declaration metadata. Catalog text queries
search those aliases/files/bundle names before evidence pagination. Definitions
are `kind: conditional`, `scope: unknown`, with `gradle-catalog` version requests.
They do not establish script binding, activation, selected versions, installation
or source usage. Rich constraints retain all supported fields without choosing
one as an exact version. Do not infer `libs` as the catalog extension name.
Plugin IDs, arbitrary catalog filenames and imported/published catalogs stay
uncollected. Missing or ambiguous references, unsupported shapes and entry/context
budgets keep coverage incomplete. Zero usages do not justify removal. Refresh
pre-revision-37 indexes before querying this evidence.

Maven build/reporting plugins, `pluginManagement` definitions and explicit plugin
dependencies use `kind: conditional`, `scope: build` with `maven_kind`, declaring
source/property context, executions/report sets, profile conditions and unknown
activation. Parent assertions retain provenance and literal inheritance flags;
execution-level flags can override a plugin's inheritance default. This is
configuration inventory, not a merged effective plugin model. Management alone
does not activate a plugin or establish its selected version. Profile-local
properties, lifecycle defaults and configuration bodies remain unevaluated.
Plugin dependencies belong to the plugin/build-extension classpath; do not use
them to satisfy an application's imports. No installed version, direct application
edge, public version query or removal advice follows from these assertions.
Zero Java imports do not prove that a plugin is unused. Unsupported activation
conditions retain explicit gaps. Respect XML node and metadata expansion limits.
Implicit lifecycle
plugins and the installed graph remain unknown even without explicit plugins.
Local parent paths can name directories; slash/backslash forms resolve bounded
`pom.xml` files. Parent coordinate checks and outside-root alias rejection still
apply; no local/remote repository or package-manager resolution is performed.

Maven versions inherited from unavailable parents/BOMs remain unresolved;
absence of a literal version is not proof that an installed dependency is
unpinned. Local reactor SNAPSHOT references also need build-context review.

Maven/Gradle coordinates alone do not establish public origin. Static collection
leaves public PURLs and OSV eligibility unknown. With user-authorized network
access and a checked source, pass `--public-maven-coordinate group:artifact` to
CLI scan (or `RepositoryScanOptions.public_maven_packages` for a trusted API
caller). Repeat the CLI option for additional checked coordinates. `--offline`
still disables queries; MCP scanning stays offline. Repository files cannot opt
themselves in. Unqualified versions remain
inventory with `security.identity-unverified`. One property-expansion/work budget
covers each POM, local parents, dependencies and plugins. Revision 58 indexes
retain these source qualifications.

Local Maven management can supply a missing dependency version through captured
root properties. An explicit dependency version takes precedence. Repeated
dependency and management occurrences in the nearest declaring local POM retain
their individual positions instead of being overwritten by coordinate. Child POM
overrides still take precedence over matching inherited declarations. These are
static requests, not a complete effective Maven model or evidence of multiple
installed copies. External parent/BOM contents remain unknown. Refresh
pre-revision-82 indexes for corrected occurrence evidence.

Explicit plugin-level `annotationProcessorPaths/path` entries of the Maven
compiler plugin use `maven_kind: annotation-processor` and
`classpath: annotation-processor`, with `scope: build` and `kind: conditional`.
Owner plugin,
individual path positions and declaring/inherited/profile context are retained.
These paths do not provide application imports, installed versions, selected
compiler configuration or public OSV eligibility. Full configuration bodies,
execution-specific processor configuration and implicit/default processors remain
uncollected. Refresh pre-revision-83 indexes to collect the explicit paths.

Explicit `build/extensions/extension` entries use `maven_kind: build-extension`,
`classpath: build-extension`, `scope: build` and `kind: conditional`. Their owner
is the declaring POM; parent extension configuration is not merged into children.
Original positions, version requests and explicit scope/type/classifier values
are retained. Missing fields stay empty; raw property expressions are preserved.
A locally normalized version is a static request, not a selected or installed
version. Activation, inheritance and public origin remain unknown. Extension
coordinates do not receive a default plugin group. Invalid identities leave a
diagnostic without inventing a component. Refresh pre-revision-84 indexes for
this inventory. These records do not establish download, execution or application
imports, and do not authorize public advisory queries.

Explicit profile libraries and management rows use `maven_kind: profile-dependency`
and `maven_kind: profile-management`, respectively, with `kind: conditional` and
`scope: unknown`. Keep declaring-POM ownership, each physical occurrence, profile
ID/index, captured activation conditions and activation XML, source positions,
raw version/scope/type/classifier requests and unknown activation/inheritance.
The library type uses the existing Maven `jar` default when omitted. Profile
properties and effective merging are not evaluated, including expressions that
also occur in root properties. Conditional management never supplies an
unconditional version. Imports declared only in profile libraries receive
`analysis.maven-profile-availability-unknown`, without implying availability or
confirmed absence. These assertions neither satisfy Java imports nor create
selected application edges, installed versions, public PURLs or advisory queries.
Same-coordinate unconditional requests remain separate. Profile library and
management assertions stay in the declaring POM rather than being merged into
children. Refresh pre-revision-85 indexes for this inventory.
