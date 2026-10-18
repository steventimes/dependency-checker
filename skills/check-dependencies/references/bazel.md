# Bzlmod declaration evidence

Bzlmod literal top-level `bazel_dep` inventory uses `Bazel` identities and
`bazel:bzlmod:<root>` scopes, one per physical `MODULE.bazel`. Requested versions,
explicit aliases/dev/nodep/compatibility assertions and original locations remain
configuration evidence. Conditional build/development scope does not establish
native root selection, availability or activation. Single unescaped quoted
strings, booleans and integer literals are supported; expressions, escapes,
prefixes/concatenation, ambiguous arguments and other statements retain gaps.
Syntax and token/node/declaration/context/diagnostic limits keep evidence qualified.
Includes, overrides, extensions, registry selection and module resolution remain
unevaluated. Locks, WORKSPACE, BUILD and `.bzl` inputs expose uncovered paths.
No resolved/installed versions, public security coordinates, source ownership or
direct application edges follow from these declarations. Zero unsupported
build/source usages cannot justify removal. Bazel update previews are unsupported.
Refresh indexes older than analysis revision 42 for this evidence and coverage.
