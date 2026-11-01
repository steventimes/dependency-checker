# Conan and vcpkg evidence

For Conan/vcpkg, `gtest/` and `gmock/` headers map to `gtest`. C/C++ `*_test` and
`*_unittest` files and `test/` or `tests/` directories carry test scope. This
filename/path heuristic does not establish build-target membership; other files
retain runtime scope. CMake `find_package(GTest)` is a build hint for a declared package,
not proof of execution.

C/C++ includes skip comments and quoted/raw-string examples, join standard
escaped newlines and keep physical positions. A header under a preprocessor
condition has `kind: conditional`, inferred confidence and unknown activation;
do not turn it into a missing-package or scope-mismatch conclusion. Macro
operands, unsupported directives and malformed/budget-limited input leave usage
incomplete. Compiler-dependent translation retains only preceding evidence.
No compiler/preprocessor is executed. Refresh pre-revision-36 indexes.

Conan text/literal Python requirements and supported JSON inventory retain
declaration positions. Conan v2 lock instances preserve `requires`,
`build_requires`, `python_requires` and `config_requires` contexts, recipe
revisions and raw references. A merged lock may retain unused versions; ranges,
active build selection and installation remain unknown. Do not treat a range as
an exact version or collapse equal-version instances across contexts.

vcpkg root and feature dependencies retain platform expressions, minimum versions, feature
assertions, default-feature flags and override sources. Multiple overrides for
one name are ambiguous; no pin is selected. Feature dependency lists use
`kind: conditional` with feature/group, support expressions, default-feature
assertions and unknown activation. A default assertion can be conditional or
disabled by a caller; it is not installed-state evidence. Keep self-feature
references and host requests distinct. Conditional declarations do not establish
resolved versions or direct application edges. Repeated assertions survive
explanations and CycloneDX properties. They produce no unused/unpinned/duplicate
or scope-mismatch advice before activation is known. Zero observed imports do
not justify removal. Invalid feature scopes, invalid defaults and exhausted
context expansion budgets qualify coverage; file-only positions remain valid
fallbacks. Native `vcpkg-lock.json`
contains registry references, not a resolved port graph. The legacy supplied
`dependencies`-object inventory remains readable, with unknown activation; it is
not a native vcpkg lock. Do not infer triplets, active features or installation.
