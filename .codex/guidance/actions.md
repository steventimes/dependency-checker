文中命令及行内路径均以仓库根为基准。仅在对应任务读取。

## GitHub Actions 编写、维护与排错约定

新建或修改 workflow、选择 Action、修复 Actions 失败，以及实现后进行 CI 预检时应用本节。
参考 [awesome-actions](https://github.com/sdras/awesome-actions/blob/0edccf33480b95bf7547b90187c31e9ab2cb070d/README.md)
按环境、测试、分析、缓存、产物和部署等任务分类发现工具。它是目录，不代表收录项已审计、
仍维护或适合本项目。安全与具体语法以 [GitHub 官方说明](https://docs.github.com/en/actions/reference/security/secure-use)
及所选 Action 当前实现为准，本节不授权安装整套工具或执行发布。

- 先读当前 workflow、项目指令、构建配置、锁文件及检查脚本，复用实际入口。
  实现完成后集中验证，按改动映射 lint/format、类型、构建、测试与打包，不能只看单测。
  使用 gh-fix-ci 做故障诊断和必要预检，具体命令与版本始终以目标仓库当前配置为准。
- 选型优先比较现有脚本、合适的官方 setup/cache/artifact Action 与必要的社区实现。
  新增依赖前核对真实发布者、源码、维护状态、许可证、运行时、权限和数据去向。
  模板只作起点。沿用可用的工作流依赖锁机制；否则新增远程 Action/可复用工作流引用
  使用核对过来源的完整提交 SHA，附可读版本注释。固定版本不能替代源码审查。
- 明确事件、工作目录、shell、runner、工具链、依赖组、服务和矩阵范围。
  依赖按项目锁或现有约束安装，不靠浮动 latest 修好 CI。Linux 结果不能证明其他 OS。
  只在责任相同且确有重复时抽取 composite/reusable workflow，保持参数、权限与 secrets 显式。
- PR 验证与写入、部署、发布分开。Token 默认只给任务必需的最小权限，写权限限必要 job。
  不在带凭据的 pull_request_target/workflow_run 路径检出或执行不可信 PR 代码。
  来自 PR 的标题、分支、日志和 artifact 均按不可信输入处理，不直接插入 shell 程序文本。
  不把 secrets、私有配置或原始个人数据写入日志、缓存或上传产物。
- [缓存与产物](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts)
  分别设计。缓存按 OS、架构、工具链及相关锁文件等实际兼容条件区分，失效时仍能重新构建。
  不用陈旧环境、native 二进制或跨信任边界的缓存制造假通过，不因 cache hit 跳过必要验证。
  产物按提交与矩阵身份命名，限定上传路径和保留期，保留必要的报告、包、哈希和失败证据。
- 按实际需要设计服务 readiness、timeout、矩阵与 concurrency，避免无界等待和重复负载。
  cancel-in-progress 只用于可安全取消的任务，不机械套到发布、迁移或有持久化副作用的任务。
  paths/条件跳过须核对 required checks 与依赖变更覆盖，不能让门禁永久 pending 或漏检。
- 故障记录 workflow/run URL、事件、分支、SHA、job/step 与首个可操作失败，比较本地状态。
  保留完整相关失败块，区分源码、格式、类型、锁、服务、OS、打包和基础设施问题。
  不以无限重跑、吞退出码、跳过测试、降阈值或新增 continue-on-error 掩盖必要门禁失败。
  已明确为实验性的现有 job 保留其定位，不将其成功与否冒充发布保证。
- 修改 workflow 时运行现有 codex-actionlint，配合受影响的项目检查。静态通过只证明其检查范围，
  本地或 act 模拟也不能替代真实 GitHub runner、跨平台、服务及凭据环境验收。
  区分本地检查、对应 SHA 的远端 CI 和实际发布产物。查询日志保持只读，rerun/dispatch、评论、
  推送、部署、发布、外部通知、账号或权限变更，须有对应任务授权，不因目录收录自动启用。

### 本仓库的 CI 重点

- 对照当前 Python 矩阵、Ruff（含 eval 脚本）、mypy、锁一致性、离线 MCP 合同和真实语料入口。
  synthetic trace 不证明 agent 行为，离线检查不证明在线公告查询或外部来源完整。
- stdio、roots、子进程、文件边界、wheel 安装和 Skill bundle 按原生 OS 检查。
  Unix 专有导入和路径语义需保留跨平台边界，不把 Linux 套件通过当作 Windows/macOS 证明。
