# Dependency Checker 参考清单

项目：https://github.com/steventimes/dependency-checker

2026-10-17 收录用户提供的 92 条参考，保留原编号、标题、链接和用途。
用途是候选改进方向，不表示仓库已经具备对应能力。除下表另有记录，
标题与链接的对应关系、内容和适用性均待核验，不能直接用作实现依据。
论文中的方法、开源实现和商业产品说明应分别评估。

方向包括多语言依赖证据、静态使用分析、版本与漏洞匹配、SBOM/SARIF、
增量索引、MCP 接口、函数级可达性、完整回溯求解与 C/C++ 证据。
【拓展】表示需要新增能力或额外输入。外部 SBOM、构建模型和运行轨迹
不能直接替代源码使用、已安装版本或已完成漏洞检查的证据。

## 处理记录

| 编号 | 状态 | 记录 |
| --- | --- | --- |
| 57 | 本轮实现 | 已核验解析库及官方规范，改进外部 SBOM PURL 身份保留。其他坐标和输出路径仍待核验，验证记录放在 `.tmp/reference-purl-20261017/`。 |
| 46 | 本轮实现 | 保留 uv 锁文件的环境、分支和依赖上下文，修复将不同分支当作同一环境版本冲突的问题。未实现原生环境选择或安装，验证记录放在 `.tmp/uv-lock-context-20261017/`。 |
| 29 | 本轮实现 | 核对 OSV 区间规则和公开 Django、lodash 公告，修复跨分支取最低修复版本的问题，并补上 SEMVER 区间。候选不代表兼容性或整体安全结论，验证记录放在 `.tmp/osv-fix-context-20261017/`。 |
| 29 | 后续实现 | 按 querybatch 修订时间刷新详情，按记录处理已生效的撤回，保留有效别名记录。该轮尚未合并别名，验证记录放在 `.tmp/osv-lifecycle-20261017/`。 |
| 27、29 | 后续实现 | 对照 OSV-Scanner 的分组实现和 OSV 别名规则，合并同一依赖实例的别名告警，保留来源记录和修复分歧。相关记录不自动合并，验证记录放在 `.tmp/osv-aliases-20261017/`。 |
| 31 | 后续实现 | 保留公告中的 CVE 标识和 CWE 分类，增加官方查询链接与来源字段。未独立查询 CVE/CWE 当前记录，验证记录放在 `.tmp/cve-cwe-20261017/`。 |
| 47 | 后续实现 | 对照 npm 官方锁文件与 registry 文档，以及 Arborist 的两组 Git 依赖夹具，补上来源断言和仓库内 registry 配置。公共漏洞匹配不再归到同名同版本的私有实例，用户级配置及实际安装来源仍未核验。验证记录放在 `.tmp/npm-origins-20261017/`。 |
| 47 | 后续修复 | 对照 SemVer 规范和本机 `node-semver`，修复非法预发布版本与超出 npm 限制的锁版本被当作精确坐标的问题。合法构建元数据和可读邻接记录仍保留。开发对照不增加后端 Node 依赖，验证记录放在 `.tmp/npm-semver-20261017/`。 |
| 36 | 已阅读公开概览 | 按 2026-10-18 最新要求核对 README；未部署服务、运行项目或上传 SBOM。 |
| 76 | 本轮实现 | 只读检查显式选择的 CMake File API codemodel v2 回复，保留抽象/导入目标、关系类型与输入哈希；源码新鲜度、构建执行和包归属仍未验证。实现及集中验证记录放在 `.tmp/cmake-file-api-20261018/`。 |
| 68 | 后续修复 | 核对 Python AST 的字节列号和 SARIF 字符单位规则，将 Python 导入位置转换为 Unicode 码点列号，并声明 SARIF 单位。Notebook 虚拟坐标保留在带说明的属性中，避免误指向原始 JSON 行。验证记录放在 `.tmp/unicode-columns-20261017/`。 |
| 68 | 本轮实现 | 核对 OASIS SARIF schema、Microsoft SDK 的 URI base 规则和有效/无效夹具，补上诊断位置、源码根标识与缺失位置说明，修复外部同名文件被错误归到仓库的问题。尚未运行原生 SDK 或 GitHub 接收服务，也未生成 GitHub 行内容指纹。验证记录放在 `.tmp/sarif-locations-20261017/`。 |
| 48 | 本轮实现 | 对照固定提交的 Yarn 官方读写器及格式 8/10 锁文件，增加独立锁清单作用域，保留请求、别名、来源断言、条件和位置。应用与 workspace 归属、registry 选择、peer 虚拟实例和 PnP 仍待实现，不推断安装或发起公共漏洞查询。验证记录放在 `.tmp/yarn-inventory-20261017/`。 |
| 1–26 | 已通读全文 | 2026-10-18 完成 26 篇、505 页阅读；题录、版本、全文来源和逐篇限制保存在 `.tmp/papers-20261018/`。个别原题省略副标题，未改变编号。 |
| 27–92 及补充入口 | 已完成公开资料概览审查 | 按条目记录 README、官方文档或相关代码的实际阅读范围；不是对每个仓库的全仓审计。75 个非论文入口的来源快照与意见保存在 `.tmp/references-20261018/`。不能读取的补充页面不算已核验内部实现。 |

当前源码已加入有界 Python 元数据回溯、独立 PEP 723 脚本作用域、离线 OSV
重评估，以及显式提供的安全、调用、运行、组件和 ABI 证据检查。相关入口及
输入要求见 [README](README.md) 和
[外部证据说明](skills/check-dependencies/references/external-evidence.md)。
这些实现没有部署参考项目的分析引擎，外部断言也不等于已安装状态、实际执行
或漏洞可利用性。能力仍属于未发布的源码更新，0.4.0 发布包不包含本轮新增入口。

2026-10-18 补充核对 [cargo-machete](https://github.com/bnjbvr/cargo-machete)
的固定提交 `135555c9cd9f3b4723dee2766f0cacb99aac092b`：阅读引用匹配实现，
选取六组上游静态夹具对照。借鉴依赖别名和 crate 路径证据，增加注释、
字符串及已知局部遮蔽的处理。未运行其原生扫描器或 `cargo metadata`；
自定义库名、生成代码和目标选择仍保留未知状态。
同时核对 [Cargo 依赖规则](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
与 [Rust semver 解析器](https://github.com/dtolnay/semver/blob/1.0.27/src/parse.rs)，
收紧精确锁版本校验，保留合法的 alpha、beta、rc 和构建元数据。
实验与验证记录放在 `.tmp/cargo-source-20261018/`，不改动下方 92 条编号。

## 补充官方数据来源

2026-10-17 按用户建议补充，不改动下方 92 条参考的编号。

| 来源 | 官方入口 | 当前用途与边界 |
| --- | --- | --- |
| CVE Program | [CVE List JSON 5](https://github.com/CVEProject/cvelistV5) | 核对官方漏洞记录格式。报告保留 OSV 提供的 CVE 标识及官方链接，尚未接入独立记录更新与状态核验。 |
| MITRE CWE | [REST API 指南](https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md)、[分类下载](https://cwe.mitre.org/data/downloads.html) | 核对弱点分类及免注册查询接口。当前保留公告提供的 CWE 断言，不拉取分类库或推断弱点关系。 |

## 用户提供的 92 条参考

| 编号 | 类型 | 参考 | 用途 |
| --- | --- | --- | --- |
| 1 | 论文 | [Beyond Metadata: Code-centric and Usage-based Analysis of Known Vulnerabilities in Open-source Software](https://arxiv.org/abs/1806.05893) | 把包级告警细化为漏洞函数及调用路径证据。 |
| 2 | 论文 | [PyCG: Practical Call Graph Generation in Python](https://arxiv.org/abs/2103.00587) | 为 Python 导入证据增加函数调用图和传播分析。 |
| 3 | 论文 | [Scalable and Precise Application-Centered Call Graph Construction for Python](https://arxiv.org/abs/2305.05949) | 按应用入口按需构图，控制依赖库分析成本。 |
| 4 | 论文 | [Präzi: From Package-based to Call-based Dependency Networks](https://arxiv.org/abs/2101.09563) | 将依赖图边细化到跨包调用，改善影响分析。 |
| 5 | 论文 | [Vuln4Real: A Methodology for Counting Actually Vulnerable Dependencies](https://ieeexplore.ieee.org/document/9201023/) | 区分真正受影响依赖与元数据匹配产生的误报。 |
| 6 | 论文 | [A Comprehensive Study of Bloated Dependencies in the Maven Ecosystem](https://arxiv.org/abs/2001.07808) | 完善 Maven 直接、传递和继承依赖的冗余判断。 |
| 7 | 论文 | [Automatic Specialization of Third-Party Java Dependencies](https://arxiv.org/abs/2302.08370) | 从包级未使用检测延伸到类级裁剪分析。 |
| 8 | 论文 | [Mininode: Reducing the Attack Surface of Node.js Applications](https://www.usenix.org/conference/raid2020/presentation/koishybayev) | 研究 Node 模块与函数裁剪，量化多余依赖的攻击面。 |
| 9 | 论文 | [Flexible and Optimal Dependency Management via Max-SMT](https://arxiv.org/abs/2203.13737) | 联合优化安全版本、升级幅度和重复依赖数量。 |
| 10 | 论文 | [Knowledge-Based Environment Dependency Inference for Python Programs](https://conf.researchr.org/details/icse-2022/icse-2022-papers/90/Knowledge-Based-Environment-Dependency-Inference-for-Python-Programs) | 补强导入名到发行包映射及解释器兼容性推断。 |
| 11 | 论文 | [Less is More? An Empirical Study on Configuration Issues in Python PyPI Ecosystem](https://arxiv.org/abs/2310.12598) | 按真实配置错误设计不完整证据状态和回归样例。 |
| 12 | 论文 | [Breaking Bad? Semantic Versioning and Impact of Breaking Changes in Maven Central](https://arxiv.org/abs/2110.07889) | 升级建议结合实际 API 使用和破坏性变更证据。 |
| 13 | 论文 | [Demystifying the Vulnerability Propagation and Its Evolution via Dependency Trees in the NPM Ecosystem](https://arxiv.org/abs/2201.03981) | 沿真实 npm 依赖树定位传播路径与可修复上游。 |
| 14 | 论文 | [A Comparative Study of Vulnerability Reporting by Software Composition Analysis Tools](https://arxiv.org/abs/2108.12078) | 建立多扫描器对照基准，分别评价误报和漏报。 |
| 15 | 论文 | [On the Security Blind Spots of Software Composition Analysis](https://arxiv.org/abs/2306.05534) | 补查 shaded JAR、复制代码等形成的隐藏依赖。 |
| 16 | 论文 | [SBOM Generation Tools in the Python Ecosystem: an In-Detail Analysis](https://arxiv.org/abs/2409.01214) | 核对可选依赖、远程依赖和版本字段的完整性。 |
| 17 | 论文 | [A Reality Check on SBOM-based Vulnerability Management: An Empirical Study and A Path Forward](https://arxiv.org/abs/2511.20313) | 将组件清单准确性与函数可达性拆成两阶段验证。 |
| 18 | 论文，2026 预印本 | [A Large Scale Empirical Analysis on the Adherence Gap between Standards and Tools in SBOM](https://arxiv.org/abs/2601.05622) | 为标识符、许可证和跨版本一致性增加质量检查。 |
| 19 | 论文，2026 预印本 | [Mind the Gap: How SBOM Specification Ambiguities Lead to Divergent Software Bills of Materials](https://arxiv.org/abs/2609.19920) | 明确组件纳入边界，减少不同解析器口径漂移。 |
| 20 | 论文 | [Small World with High Risks: A Study of Security Threats in the npm Ecosystem](https://www.usenix.org/conference/usenixsecurity19/presentation/zimmerman) | 加入依赖集中度和维护者影响范围等独立风险信号。 |
| 21 | 论文 | [Backstabber’s Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://arxiv.org/abs/2005.09535) | 按真实供应链攻击类型扩展规则与恶意包测试集。 |
| 22 | 论文 | [Beyond Typosquatting: An In-depth Look at Package Confusion](https://www.usenix.org/conference/usenixsecurity23/presentation/neupane) | 增加包名混淆与来源异常检测。 |
| 23 | 论文 | [DONAPI: Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping](https://www.usenix.org/conference/usenixsecurity24/presentation/huang-cheng) | 用敏感 API 行为链补充已知 CVE 以外的恶意包信号。 |
| 24 | 论文 | [in-toto: Providing farm-to-table guarantees for bits and bytes](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | 绑定报告哈希、分析步骤和签名，形成可验证证据链。 |
| 25 | 论文 | [Bilingual Problems: Studying the Security Risks Incurred by Native Extensions in Scripting Languages](https://www.usenix.org/conference/usenixsecurity23/presentation/staicu) | 补充 Python/Node 原生扩展背后的 C/C++ 风险边界。 |
| 26 | 论文 | [We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen) | 在 Agent 更新预览中验证包是否真实存在及来源是否可信。 |
| 27 | 开源 | [OSV-Scanner](https://github.com/google/osv-scanner) | 借鉴锁文件覆盖、离线漏洞库和升级候选筛选。 |
| 28 | 开源 | [OSV-SCALIBR](https://github.com/google/osv-scalibr) | 拆分采集、检测与证据增强插件，按能力启用。 |
| 29 | 开源 | [OSV.dev](https://github.com/google/osv.dev) | 参考漏洞版本范围、别名去重和数据更新处理。 |
| 30 | 开放 API／开源示例 | [deps.dev](https://github.com/google/deps.dev) | 补充依赖图、项目关联和包元数据查询。 |
| 31 | 开放数据 | [GitHub Advisory Database](https://github.com/github/advisory-database) | 追踪公告来源、修复提交和版本范围修订。 |
| 32 | 开源 | [Syft](https://github.com/anchore/syft) | 对照多生态组件识别和文件位置证据建模。 |
| 33 | 开源 | [Grype](https://github.com/anchore/grype) | 借鉴匹配器分层、离线数据库和告警去重。 |
| 34 | 开源 | [Trivy](https://github.com/aquasecurity/trivy) | 对照锁文件解析、漏洞库缓存和扫描结果结构。 |
| 35 | 开源 | [cdxgen](https://github.com/cdxgen/cdxgen) | 补全多生态 SBOM 关系、作用域和解析器测试。 |
| 36 | 开源 | [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | 参考 SBOM 持续重评估、豁免审计和漏洞生命周期。 |
| 37 | 开源 | [Eclipse Steady](https://github.com/eclipse-steady/steady) | 学习漏洞代码指纹、调用证据和安全升级推荐。 |
| 38 | 开源 | [Jelly](https://github.com/cs-au-dk/jelly) | 为 JavaScript/TypeScript 增加跨包调用与漏洞匹配。 |
| 39 | 开源 | [govulncheck / golang/vuln](https://github.com/golang/vuln) | 参考 Go 符号级漏洞匹配和调用链解释。 |
| 40 | 开源 | [deptry](https://github.com/osprey-oss/deptry) | 对照 Python 缺失、传递和开发依赖误用规则。 |
| 41 | 开源 | [Knip](https://github.com/webpro-nl/knip) | 补齐前端工具配置、入口与未使用依赖识别。 |
| 42 | 开源 | [DepClean](https://github.com/ASSERT-KTH/depclean) | 参考 Maven 继承、传递依赖和测试作用域分析。 |
| 43 | 开源 | [resolvelib](https://github.com/sarugaku/resolvelib) | 通过可替换 provider 增加完整依赖回溯求解。 |
| 44 | 开源 | [pubgrub-rs](https://github.com/pubgrub-rs/pubgrub) | 生成可解释的版本冲突链。 |
| 45 | 开源 | [Resolvo](https://github.com/prefix-dev/resolvo) | 参考可扩展 SAT 求解接口和冲突诊断。 |
| 46 | 开源 | [uv](https://github.com/astral-sh/uv) | 对照环境标记、extras 和通用锁文件语义。 |
| 47 | 开源 | [npm Arborist](https://github.com/npm/cli/blob/latest/workspaces/arborist/README.md) | 校准 npm 实例身份、依赖提升和 peer/optional 依赖边。 |
| 48 | 开源 | [Yarn Berry](https://github.com/yarnpkg/berry) | 补上 Yarn 锁文件、workspace 和 PnP 解析支持。 |
| 49 | 开源 | [pnpm](https://github.com/pnpm/pnpm) | 对照原生锁文件语义，完善 peer 实例与 workspace 边。 |
| 50 | 开源 | [Renovate](https://github.com/renovatebot/renovate) | 借鉴版本规则、分组更新和最小变更升级策略。 |
| 51 | 开源 | [Dependabot Core](https://github.com/dependabot/dependabot-core) | 参考多生态更新器及清单、锁文件一致性处理。 |
| 52 | 开源 | [pip-audit](https://github.com/pypa/pip-audit) | 对照 Python 漏洞匹配、修复版本和失败状态语义。 |
| 53 | 开源 | [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort) | 参考分析、许可证、策略评估和报告的分层架构。 |
| 54 | 开源 | [ScanCode Toolkit](https://github.com/aboutcode-org/scancode-toolkit) | 补充清单以外的包识别、许可证和源文件证据。 |
| 55 | 开源 | [python-inspector](https://github.com/aboutcode-org/python-inspector) | 对照 Python 包元数据获取与依赖解析边界。 |
| 56 | 开源 | [pip-requirements-parser](https://github.com/aboutcode-org/pip-requirements-parser) | 强化 requirements 递归引用、选项和复杂语法处理。 |
| 57 | 开源 | [packageurl-python](https://github.com/package-url/packageurl-python) | 统一包坐标编码、限定属性和跨生态身份规范化。 |
| 58 | 开源 | [CycloneDX Python Library](https://github.com/CycloneDX/cyclonedx-python-lib) | 校验现有 SBOM 数据模型、序列化和版本兼容性。 |
| 59 | 开源 | [sbomqs](https://github.com/interlynk-io/sbomqs) | 为生成的 SBOM 增加质量评分和字段完整性检查。 |
| 60 | 开源 | [vexctl](https://github.com/openvex/vexctl) | 输出带依据的 VEX 状态，保留“未确定”与“未受影响”的区别。 |
| 61 | 开源 | [GUAC](https://github.com/guacsec/guac) | 关联依赖、漏洞、构建证明和报告哈希，支持溯源查询。 |
| 62 | 开源 | [OpenSSF Scorecard](https://github.com/ossf/scorecard) | 将维护状态和供应链卫生指标作为独立策略信号。 |
| 63 | 开源 | [GuardDog](https://github.com/DataDog/guarddog) | 增加恶意包静态启发式和元数据异常检测。 |
| 64 | 开源 | [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | 导入隔离分析结果，补充安装脚本、文件和网络行为证据。 |
| 65 | 开源 | [Cosign](https://github.com/sigstore/cosign) | 给扫描报告和 SBOM 添加签名与身份验证。 |
| 66 | 开源 | [SLSA Verifier](https://github.com/slsa-framework/slsa-verifier) | 验证构建来源证明，补充依赖来源风险判断。 |
| 67 | 开源 | [Open Policy Agent](https://github.com/open-policy-agent/opa) | 将证据完整性和风险阈值交给独立策略引擎。 |
| 68 | 开源 | [SARIF SDK](https://github.com/microsoft/sarif-sdk) | 验证 SARIF 结构、位置和告警指纹，改善平台互通。 |
| 69 | 开源 | [Salsa](https://github.com/salsa-rs/salsa) | 按输入依赖失效分析缓存，减少非 Python 全量重扫。 |
| 70 | 开源 | [in-toto](https://github.com/in-toto/in-toto) | 将扫描器版本、输入摘要和评估结果打包为证明。 |
| 71 | 开源 | [Conan](https://github.com/conan-io/conan) | 对照锁文件修订号及主机、构建依赖的身份建模。 |
| 72 | 开源 | [vcpkg](https://github.com/microsoft/vcpkg) | 补全 baseline、features、registry 和覆盖版本解析。 |
| 73 | 开源 | [CVE Binary Tool](https://github.com/ossf/cve-bin-tool) | 用二进制特征补充 C/C++ 组件发现与漏洞映射。 |
| 74 | 开源客户端 | [SCANOSS Python Library](https://github.com/scanoss/scanoss.py) | 以代码片段指纹补查复制、内嵌和改名组件。 |
| 75 | 开源 | [Libabigail](https://sourceware.org/libabigail/) | 比较类型和符号 ABI，解释 C/C++ 升级兼容风险。 |
| 76 | 开源接口 | [CMake File API](https://cmake.org/cmake/help/latest/manual/cmake-file-api.7.html) | 导入已有构建模型，区分链接依赖与构建顺序。 |
| 77 | 开源 | [SVF](https://github.com/SVF-tools/SVF) | 用指针分析补足 C/C++ 间接调用和函数可达性。 |
| 78 | 开源 | [ABI Compliance Checker](https://github.com/lvc/abi-compliance-checker) | 检查库版本间 API/ABI 破坏，补充升级预览证据。 |
| 79 | 商业 | [Endor Labs](https://www.endorlabs.com/use-case/sca-with-reachability) | 借鉴函数可达性、隐藏依赖和升级破坏性分析。 |
| 80 | 商业 | [Socket](https://docs.socket.dev/docs/socket-for-github) | 参考依赖变更中的行为差异、恶意包和分级阻断。 |
| 81 | 商业，配套开源引擎 | [Semgrep Supply Chain](https://semgrep.dev/products/semgrep-supply-chain/) | 参考漏洞专用匹配模式和跨文件数据流可达性。 |
| 82 | 商业，配套开源 CLI | [Snyk Open Source](https://snyk.io/product/open-source-security-management/) | 学习调用图、漏洞上下文联合排序和升级建议解释。 |
| 83 | 商业 | [Sonatype Lifecycle](https://help.sonatype.com/en/reachability-analysis.html) | 参考可达性证据展示、策略豁免和组件生命周期。 |
| 84 | 商业，配套开源工具 | [Mend SCA](https://docs.mend.io/platform/latest/mend-sca) | 参考恶意依赖、许可证和可达性结果的统一治理。 |
| 85 | 商业 | [JFrog Xray / Advanced Security](https://docs.jfrog.com/security/docs/contextual-analysis-of-cves) | 区分不可达、缺少上下文与未支持，保留适用性依据。 |
| 86 | 商业 | [FOSSA](https://fossa.com/solutions/code-security/) | 借鉴多来源漏洞、许可证政策和跨项目组件管理。 |
| 87 | 商业 | [Black Duck SCA](https://www.blackduck.com/software-composition-analysis-tools/black-duck-sca.html) | 参考清单、文件签名、代码片段和二进制结合的组件识别。 |
| 88 | 商业 | [ReversingLabs Spectra Assure](https://www.reversinglabs.com/products/spectra-assure) | 补充发行包篡改、嵌套二进制和恶意内容检测视角。 |
| 89 | 商业，含开源组件 | [Aikido Security](https://help.aikido.dev/getting-started/reachability-analysis/reachability-engine-to-remove-false-positives) | 参考生产、开发和测试用途区分及证据驱动降噪。 |
| 90 | 商业 | [Oligo Security](https://www.oligo.security/runtime-platform/runtime-vulnerability-management) | 【拓展】导入运行轨迹，补充实际调用证据并校准静态分析。 |
| 91 | 商业，基于 Syft/Grype | [Anchore Enterprise](https://docs.anchore.com/current/docs/overview/capabilities/) | 参考已存 SBOM 随漏洞库更新持续重评估。 |
| 92 | 商业 | [Veracode SCA](https://www.veracode.com/products/software-composition-analysis) | 参考直接与传递风险、恶意包情报和修复工作流。 |

## 此前登记的其他参考

| 项目 | 链接 | 状态 |
| --- | --- | --- |
| xerj-org/xerj | https://github.com/xerj-org/xerj | 2026-10-18 已阅读公开概览；未安装、启动、上传或发送反馈 |
