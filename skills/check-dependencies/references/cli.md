# CLI fallback

Use the installed executable and quote paths and specifiers. All examples use
`<root>` as a placeholder for the target repository. Context, index, query,
explain, impact, and update print JSON without a format flag.

| MCP operation | CLI equivalent |
| --- | --- |
| `repository_context` | `depcheck context "<root>"` |
| `index_repository` | `depcheck index "<root>"` |
| `scan_repository` | `depcheck scan "<root>" --offline --format json`, then `depcheck index "<root>"` if indexed queries are needed |
| `query_dependencies` | `depcheck query "<root>" --limit 20 --offset 0` |
| `explain_dependency` | `depcheck explain "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `dependency_impact` | `depcheck impact "<root>" requests --ecosystem PyPI --project 'pypi:python:.'` |
| `plan_dependency_updates` | `depcheck update "<root>" 'requests=2.32.4' --ecosystem PyPI --project 'pypi:python:.'` |
| `compare_dependency_snapshots` | `depcheck compare "<root>" .tmp/before.json .tmp/after.json --limit 20 --offset 0` |
| `inspect_dependency_sbom` | `depcheck sbom "<root>" .tmp/bom.json --limit 20 --offset 0` |
| `inspect_cmake_model` | `depcheck cmake-model "<root>" build/.cmake/api/v1/reply/index-selected.json --configuration Debug --limit 20 --offset 0` |

For an explicit pyproject preview, use
`depcheck update "<root>" 'requests==2.32.4' --file pyproject.toml --group project`;
optional groups use
`--group optional:NAME`. Without `--file`, keep the default requirements route.

CLI query text is an optional positional argument, not a `--package` flag.
It uses substring matching, not glob patterns: to list `package-*`, use
`depcheck query "<root>" package- --limit 20 --offset 0` and follow pagination.

CLI `scan` does not refresh the index. Add `--ecosystem`/`--project` to queries
when the identity is known; filter index/scan only when the task asks for that
scope. Respect configured exclusions. CLI exit 1 is a policy failure, exit 2 an
operation error; exit 0 alone does not establish complete coverage.

For SARIF, use `depcheck scan "<root>" --offline --format sarif --output .tmp/depcheck.sarif`.
Repository-relative artifact URIs use `%SRCROOT%`; map that symbolic base to the
checkout in the consumer. The base mapping omits the local checkout directory;
diagnostic messages retain provider text and may contain paths. Explicit
outside-root locations remain absolute file URIs. Diagnostics preserve known
file/line/column locations. A finding without a location can use its own project's known
manifest; otherwise `locations` stays empty with `depcheck:location-status` set to
`unavailable`. Do not claim a known source location or infer a file from `.`.
Export does not reread/resolve sources or materialize unrelated inventory.

SARIF export retains incomplete coverage and invocation state. It does not add
GitHub's `primaryLocationLineHash`; the upload action can generate it from source.
Schema validation is separate from GitHub ingestion or alert display acceptance.
Column numbers count Unicode code points from one; SARIF declares that unit and
CRLF/CR/LF line breaks. Notebook lines are virtual cell coordinates. SARIF keeps
only the file as a physical location, preserving virtual coordinates in
`depcheck:reported-region` with a `notebook-virtual` region status.
