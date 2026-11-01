# Contributing

Dependency Checker is an Agent Skill with a CLI and MCP backend. Start with the
[architecture map](README.md#architecture) and the relevant
[Skill reference](skills/check-dependencies/SKILL.md). Keep changes within the
existing modules and supported Python versions. The ecosystem registry contains
built-in providers; it does not discover or load third-party entry points.

Preserve source assertions, repeated instances, source locations and qualified
unknown states. Do not execute target code or package managers to fill evidence
gaps. Keep parser changes independent of transport. Public-network eligibility
must be established before querying a registry or OSV. Add a distinct regression
case and a legitimate control when changing a consequential boundary.

Use the five test modules and the [Development commands](README.md#development).
Finish a coherent implementation before focused verification. Keep reports,
benchmark baselines, environments and trial output in `.tmp/`. Do not include
those files in a patch or bundle. Evidence semantics changes update
`ANALYSIS_REVISION`; schema changes require a migration/rebuild decision.
Package version changes belong to a selected release.

The pinned corpus evaluator checks annotated npm lock inventory and offline
matching against supplied OSV records. Its results do not measure general
dependency, usage or vulnerability accuracy. Keep truth annotations independent
of scanner output, retain upstream licenses, commits and hashes, and state
unsupported cases. Expected unknown results must remain visible as coverage
gaps when upstream affectedness is known. Real agent trials remain separate
from synthetic scorer fixtures and protocol checks.

From a source checkout or extracted source distribution, build local candidates
with `python scripts/build_skill_bundle.py --output .tmp/skill-bundle`. The ZIP
includes the complete Skill tree and backend sources, uses fixed metadata and
provides member and archive hashes. The builder checks package-relative links.
Source archives include the scripts and metadata needed to rebuild that ZIP;
the wheel distributes the backend.

Building a candidate does not publish it. Preserve the package version until a
release is selected. Inspect the diff and actual artifacts, run the required
native CI jobs and verify installation outside the checkout before publishing.
Report local checks separately from remote and native-platform results. Report
vulnerabilities through [SECURITY.md](SECURITY.md).
