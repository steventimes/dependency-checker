# Authorized dependency maintenance

For an audit-only request, finish with evidence and unresolved coverage. If the
user asks for changes, carry the findings into a separate maintenance step:

1. Inspect Git status and preserve existing edits. Identify the component's
   package manager and version from committed metadata, runtime pins, locks and
   CI. Conflicting locks need an explicit choice supported by those files and
   the user's scope; do not introduce another package manager.
2. Capture the baseline before editing: declared constraints, known locked
   versions, affected usages, advisories, coverage limits and relevant checks.
   Distinguish existing failures and checks that have not run.
3. Select one ecosystem or coupled package family. Inspect official migration
   notes for major changes and verify advisory reachability and fixed versions.
   An advisory count change alone does not establish remediation.
4. Use the native package manager only within the separately authorized change
   workflow. Preserve its pinned version and regenerate generated locks through
   it. Do not hand-edit lock resolutions, delete locks, or add force flags to
   bypass a conflict. Depcheck previews remain read-only.
5. Reinstall in the project's locked mode, compare resolved versions and edges,
   then run focused checks and the relevant build/type/test gates. Re-scan with
   the same depcheck scope and network settings for a comparable final result.

Report changed manifests/locks, versions before and after, actual commands and
checks, baseline versus final failures, remaining advisories, and migrations or
overrides. Mark installation, graph checks and tests as not run until executed.
Do not treat support in a general maintenance skill as collector coverage here;
Ruby, PHP and .NET manifests can still be unsupported by depcheck.
