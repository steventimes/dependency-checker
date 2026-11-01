## README 任务入口

创建、重写或实质修改 README时，读取[本仓库约定](.codex/guidance/readme.md)；普通代码任务不为此加载全文。

## GitHub Actions 任务入口

修改 workflow、诊断 Actions 或进行 CI 预检时，读取[本仓库约定](.codex/guidance/actions.md)；普通代码任务不为此加载全文。

# Dependency Checker maintenance

Read applicable parent AGENTS.md instructions and [README.md](README.md). Preserve
existing work. Keep reports, caches, benchmark output and raw trial material in
`.tmp/`; exclude them from commits and release bundles. Commit, push and publish
only within the user's requested scope.

## Current baseline

The project is an Agent Skill with an MCP server and CLI backend. The selected
release line is 0.6.0, chosen on 2026-11-01; source and plugin metadata use 0.6.0,
analysis revision 88 and index schema v8. The prior GitHub release is
[0.5.0](https://github.com/steventimes/dependency-checker/releases/tag/v0.5.0).
Release publication and CI status must be verified separately. The PyPI name
`depcheck` belongs to an unrelated project; distribution here uses GitHub assets.
Do not change the package name or publish to PyPI without a separately approved
namespace. See [Unreleased](CHANGELOG.md#unreleased) for future source changes.

Historical implementation and verification records remain under `.tmp/`.
`.tmp/implementation-report-20261018.md` is archived. Continue the active record
in `.tmp/implementation-report-20261019.md`; do not create parallel progress or
design documents. Historical test counts and CI results do not verify current
source. Report local checks, remote CI and published artifacts separately.

## Implementation boundaries

- Parse target repositories as bounded data. Do not import target code, evaluate
  setup/build files or execute package managers to improve static evidence.
- Preserve incomplete, skipped, unsupported and ambiguous states. Missing
  coverage, unknown versions and zero observed usages need qualified reporting.
- Keep queries and update previews read-only. Index/scan MCP tools can replace
  the derived cache; their annotations and the Skill must state that side effect.
- Resolve helper executables outside the audited repository. Keep metadata
  subprocesses non-interactive with `stdin=subprocess.DEVNULL`.
- Evidence semantics changes require an `analysis_revision` update in
  `depcheck/model.py`. Table changes require an index schema/rebuild decision in
  `depcheck/indexing/models.py` and `store.py`. Pure internal refactors retain
  the current revision and schema when their evidence is unchanged.
- Keep backend version markers consistent in `pyproject.toml`,
  `depcheck/_version.py`, both plugin descriptors and the lockfile at release.
- Keep repeated declarations, physical lock instances, origin assertions and
  source locations distinct. Retain file-only locations when spans are unknown.
- Keep resolution metadata separate from identity, origin and required edges.
  npm context assertions retain unknown activation; do not filter advisory
  matching by the analysis host or treat optional/peer requests as required edges.
- Public registry queries require supported, verified public coordinates.
  Private, local, ambiguous or unknown sources must not become public identities.
- External SBOM, security, call, runtime and build records remain supplied
  assertions. Input hashes do not authenticate producers, establish source
  freshness, installation, exploitation or ABI/API compatibility.
- CMake File API inspection reads an explicitly selected existing codemodel v2
  reply without configuring or building. Preserve configuration/target identities,
  relationship kinds, assertions and JSON-pointer provenance. Build execution
  stays unknown, package mapping unsupported and security skipped.

## Module responsibilities

Use the [architecture map](README.md#architecture) when changing shared code.

- `engine.py` coordinates discovery, collection and optional stages. Security
  and compatibility scan projections live in their respective `scanning.py`
  modules. Clients are selected by the scanner and passed into those stages.
- `agent/service.py` is the common CLI/MCP application interface. Keep root
  authorization, result limits and public method parameters there. Update
  preview discovery and maintenance handoffs live in `compatibility/planning.py`.
- `indexing/store.py` owns connections, staging, transactions and publication.
  `indexing/queries.py` reads from an existing connection and does not open or
  commit databases. Keep input freshness and transaction checks in the indexer.
- `output.py` retains text/JSON rendering and compatible public imports. SARIF,
  CycloneDX and exemption policy have separate modules under `reporting/`.
  Report projections must preserve captured evidence and must not reopen source paths.
- `evidence/input.py` owns shared bounded input mechanics. Format inspectors
  depend on it; it must not depend on individual formats or transport modules.
- Keep pure OSV advisory interpretation independent of HTTP. Keep parsers
  independent of CLI/MCP transport. Prefer existing modules over new forwarding
  layers, dynamic dispatch frameworks or duplicated validation rules.
- Keep ecosystem collectors and parsers in their language packages. Shared
  command/configuration readers live in `ecosystems/configuration/`; bounded
  file access and source positions live in `filesystem/`. The top-level package
  and `output.py` are supported Python entry points; other module paths are
  internal. Do not keep forwarding files for retired internal paths.

## Remaining analysis priorities

Address one coherent scope at a time and preserve qualified limitations.

1. Improve remaining legacy manifest and lock positions without merging repeats
   or inventing spans. Preserve inherited origin and component identities.
2. Extend Python installation evidence and uv member ownership conservatively.
   Shared lock activation and cross-member availability remain unknown.
3. Extend bounded build/plugin/command evidence where ownership is known.
   Separate configuration, source imports and execution. Maven effective merges,
   lifecycle/profile activation and runtime use remain uncollected.
4. Expose unsupported manifests and source formats. Keep Rust compiler binding,
   framework template/implicit imports, SCSS/Sass and browser/CDN dependencies
   qualified. Preserve environment and variant conditions in lock evidence.
5. Measure discovery, hashing, parsing, storage and queries before optimizing
   cache reuse. Use `scripts/benchmark_monorepo.py` with recorded parameters and
   runtime. Compare inventory, diagnostics and completeness with timings. Keep
   baselines in `.tmp/`; do not change CI thresholds without evidence.

Current coverage and format-specific limitations are documented in the README
and `skills/check-dependencies/references/`. Treat those as the current feature
map rather than the older dated iteration notes.

## Verification

Start with `git status --short --branch` and inspect the affected interfaces.
Finish the complete agreed implementation scope before concentrated verification.
Prefer realistic upstream fixtures, cross-module scenarios and consequential
boundaries over mechanical field tests. Reuse relevant coverage under `test/`;
organize it by behavior rather than a fixed module count. Consolidate repeated
scenarios without weakening independent assertions or growing giant test files.

Use the [README Development commands](README.md#development) as a menu. Select
checks for the changed behavior and its necessary callers: relevant regressions,
static checks and affected MCP contracts. An internal runtime edit does not by
itself require full pytest, all MCP contracts, all corpora or package builds.

Expand to the corresponding interpreter/native-OS matrix, corpus or installation
checks only when interpreter semantics, platform I/O or stdio, root authorization,
parsing formats, lock semantics or dependencies, public package entry points or
shipped resources actually change. Match each check to that impact; do not run
unrelated versions or ecosystems. Rebuild or install an artifact only when the
task requires validating that artifact and its inputs changed. Do not claim an
older artifact contains changed source. Local Linux results do not replace
native platform or remote CI checks; record unavailable checks precisely.

After a local repair, rerun its regression and dependent checks. For example, an
error-response budget fix needs the affected branch, paging/error contracts and
relevant static checks; it does not automatically reset the full Python matrix
or corpus. Broaden verification only for a concrete new impact, failure or risk.
Evidence remains valid for unchanged inputs and behavior. Documentation, rule,
progress-record and receipt edits do not invalidate unrelated runtime evidence
or reopen completed work. Finish at the agreed scope; continuation alone does
not authorize another batch.

For documentation changes, verify local links and run changed command examples
against temporary fixtures. Do not add tests that compare documentation text
with itself. Keep the full Skill tree in bundles and validate its relative links.

The Skill entry is `skills/check-dependencies/SKILL.md`. Keep shared constraints
and reference routing there. Update the applicable reference when a tool contract
or coverage rule changes. The evaluation directory separates live MCP checks,
recorded agent trials and synthetic scorer fixtures. Synthetic traces do not
establish observed agent behavior, and public product material does not establish
vendor accuracy or internal behavior.

## Reference records

The user reference catalog and per-entry status are in [REFERENCES.md](REFERENCES.md).
The 2026-10-18 review read 26 supplied papers in full and reviewed the remaining
public entries. The following round read nine more scoped papers, recorded in
`.tmp/implementation-20261019/papers/`. Preserve the reading ledgers and archived
reports when deleting reproducible environments or caches.

Dependency-Track and Xerj were initially list-only references, then reviewed as
public overviews on 2026-10-18. Those reviews did not deploy either project or
upload data. Any later machine-wide installation has its own authorization and
verification; it does not change this repository's recorded review scope.

<!-- BEGIN SCOPE_CONTROL -->
## 范围控制与简洁实现

- 为推测出来、几乎不会发生的并发或安全边界增加复杂度前，先向用户说明具体问题、发生概率及依据、增加的代码与维护负担，得到用户同意后再加。无法可靠估计概率时直说，不编造数字，不为了“理论上更稳”悄悄扩大范围。
- 外部数据只在入口校验一次，内部传递已校验且类型明确的值，不在每一层重复判断。独立的外部入口各自保留必要校验。
- 只用一次的简单逻辑直接写在调用处，仅在确实复用或封装复杂逻辑时抽取函数。
- 能不用 `try/catch` 就不用，能在一个函数里清楚写完就不拆分。简化时保留实际需要的错误语义、资源释放与信任边界。
- 修改或重写前先读本节；审核时沿实际调用链核对这些规则，不以删行数量代替功能与验证，也不自动添加常驻 hook 或新的审批框架。
<!-- END SCOPE_CONTROL -->

<!-- BEGIN TEST_AND_GENERATION_RULES -->
## 测试与生成物

- 不为每次修改默认新增测试。只为重要且稳定的可观察行为或可信回归补充缺失的长期用例，先复用已有检查。一次性诊断留在临时目录，不锁死无关实现细节，不靠用例数量证明质量。相似场景合并，按行为职责组织，不限定模块数或继续堆大文件。
- 回归测试要能识别所修错误：必要时用修复前代码或等价负向变体确认会失败。不要复制生产算法作为预期值，不 mock 掉正在断言的行为，也不以被测输出自身作为正确性依据；外部依赖替身仍按真实边界使用，不强制先写测试。
- 等待状态或事件，不用固定 sleep、盲目重试或增大超时掩盖竞态；计时逻辑优先使用已有可控时钟。保留真正验证超时、I/O 和事件循环调度所需的等待。偶发失败先判断产品还是测试有错，用户也能遇到的交错应修产品，保留有效断言。
- 生成文件只通过其源定义、模板或生成脚本修改并重新生成，不直接手改生成物；核对生成入口、来源与产物对应关系，不为未受影响范围机械重生成。
- UI 测试适用时复用真实生产组件，测试夹具隔离副作用，不复制一套视觉实现。
<!-- END TEST_AND_GENERATION_RULES -->
