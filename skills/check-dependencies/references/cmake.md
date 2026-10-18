# CMake configuration evidence

CMake `FetchContent_Declare`, `find_package` and `find_dependency` assertions use `CMake` identities
under `cmake:cmake:<root>`. Each top-level CMake list groups its directory tree,
including nested lists, `.cmake` helpers and `*.cmake.in` templates. This is lexical inventory, not an
evaluated include/subdirectory graph: unreferenced helpers can contribute claims.
Scripts outside those trees use separate `cmake:cmake-script:<root>` scopes and
do not absorb nested CMake projects. All owned input files appear in the scope's
manifest list; no entry point or execution order is inferred. Adding a CMake
list can change scope boundaries: refresh and rediscover IDs before querying.
CMake package names match case-insensitively, while displayed assertions retain
their source spelling.
Keep repeated declarations, variable arguments and unsupported options qualified.
`FetchContent_MakeAvailable` is inferred configuration evidence. Conditions,
first-declaration precedence, providers and overrides leave activation unknown;
do not infer installed versions, registry coordinates or source non-use from it.
Source/target usage, ExternalProject collection and CMake update previews remain
unsupported. Template assertions retain `metadata.template: true`; `@...@`
arguments are dynamic and standalone `@PACKAGE_INIT@` is skipped without expansion.
Every template reports `manifest.unsupported-cmake-template-expansion`, even when
literal dependency calls were retained. Substitution, injected code, generated
dependencies and exported/installed contents remain unknown. Unknown command
substitutions and malformed input can stop collection after prior assertions.
Refresh pre-revision-41 indexes for these inputs and `find_dependency` evidence.
CPMAddPackage/CPMFindPackage calls produce
positioned coverage gaps; do not infer their shorthand or override semantics.

## Supplied File API replies

For a user-selected existing reply, use `inspect_cmake_model` with a relative
`index_file`; do not configure CMake to create it. Select an actual
`index-*.json`, an explicit configuration when there is more than one, and
optionally an exact target ID. The tool does not select the newest index.

Keep build-system and abstract target collections distinct. Codemodel 2.9 adds
`abstractTargets` and `imported`, `local`, `abstract` and `symbolic` flags;
abstract targets cannot be built. Do not map CMake target names to registry
packages. Legacy `dependencies` are build-order assertions, including transitive
edges, not direct linking. Separate link/compile/object/order relationships
are supported from 2.9; absent fields in older replies leave linkage unknown.
Source and interface-source assertions retain separate collections and version
context. Paths, generated flags, indices, JSON pointers and shell fragments are
reported data; the tool does not resolve source paths or run commands.

Follow `next_offset` for every table with the same filters and limit. Read
`counts`, omitted targets, diagnostics and target `detail_status`. A relationship's
`target_present` only establishes membership in the selected configuration;
`target_detail_status` distinguishes reported, unavailable, unselected and unread
details. `import_complete` covers the supported projection, while
`evidence_complete` stays false. Missing detail or inconsistent versions do not
erase readable neighboring assertions.
`from_dependency_id` also retains target membership and detail status; an absent
origin target leaves a diagnostic. Use the effective returned `limit`; the
service caps pages at 50 by default.

The tool reads bounded JSON reply files inside the repository, with plain
`jsonFile` basenames, at most 8 MiB per file, 16 MiB total and 1024 read attempts.
It leaves source and cache unchanged. Input hashes identify captured bytes, not
authenticated provenance or fresh source. Build execution remains unknown,
package mapping unsupported and security skipped. Directory objects, compile
groups, interface include directories, resolved backtrace graphs, artifact
contents and installed packages remain uncollected. This inspection does not
add records to the source index.
