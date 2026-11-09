# Launch Readiness · 上线前代码风险自检

**AI 帮你把产品做出来了，上线前还有哪些值得追查的风险？**

[English](README.md) · 简体中文

**v0.4.0 · 实验性／内部草稿方法 · 只读代码审阅，不是安全认证或上线许可。**

面向用 AI 构建产品的非技术创始人及其工程师。Launch Readiness 是一个 agent skill：包含审阅指令、证据契约和本地 Python 工具，不是托管审计服务，也不是自动漏洞检测器。

## 它能帮你做什么

- **先识别真实技术栈**：不预设 React、Supabase 或 Stripe。
- **追查两到四条高业务影响链路**：跨路由、调用方、共享 helper 和相关数据库／配置，而不只看关键词。
- **区分事实、假设和资料缺口**：有反证就排除怀疑，不强行凑漏洞数量。
- **生成两份报告**：老板 HTML 行动页说明业务影响、未知项及下一步；工程 Markdown 保留证据引用、稳定任务编号、验收和有范围的复查建议。
- **跟随提问语言**：明确指定输出语言时以指定为准。当前审阅渲染器内置中文／英文固定文案，不会翻译输入的审阅描述。

典型链路包括：登录 → 资源归属 → 数据查询；上传 → 存储 → 授权下载；AI 接口 → 配额 → 外部调用；部署 → 数据迁移 → 回滚。支付仅在实际适用时纳入。

## 安装

需要支持 Agent Skills 的宿主。必须安装**整个目录**，不要只复制 SKILL.md。

对于支持用户级 `~/.agents/skills` 的 macOS/Linux 宿主：

```bash
git clone https://github.com/myouzh/launch-readiness-skill.git \
  ~/.agents/skills/launch-readiness
```

目标目录必须尚不存在。已有安装请先备份本地修改，再更新；刷新技能列表或重启宿主，确认出现 `launch-readiness`。其他宿主按其文档选择目录。不同位置的源码和已安装副本不会自动同步。

本地工具需要 **macOS/Linux + Python 3.10 及以上**，不需要也不应安装或执行客户项目依赖。AI 审阅还需要兼容的 agent／模型宿主。

## 中文怎么用

安装后直接对 agent 说：

> 使用 launch-readiness 帮我的项目做上线前代码风险自检。先确认目录、排除项及最小相关源码发送给实际模型提供方的授权；不要执行项目、修改代码或访问生产环境。请用中文生成老板行动页和工程报告。

接着提供已授权、脱敏的本地项目快照、产品用途、上线阶段、关键用户流程和排除项。**不要提交生产密钥或真实客户记录。** 本地读取许可与模型处理同意是两件事。

## 英文怎么用

> Use launch-readiness to review my app before launch. First confirm the repository scope, exclusions, and consent for sending minimal relevant source context to the actual model provider. Do not execute my project, modify code, or access production. Write the founder action page and engineer report in English.

也可以用中文提问并明确要求英文报告；提问语言不是技术栈限制。

## 先看两份合成示例

下列项目专为演示编写，从未执行或部署；不是客户案例、运行时漏洞复现或准确率基准。

| 场景 | 展示什么 | 报告 |
| --- | --- | --- |
| 查询缺少租户过滤 | 追查身份和查询链路后提出有前提条件的静态关注点 | [老板 HTML 源码／下载](examples/code-review-demo/unscoped/owner.html) · [工程报告](examples/code-review-demo/unscoped/report.md) |
| 保护在共享 helper 中 | 沿调用链找到保护，排除初步怀疑，不误报 | [老板 HTML 源码／下载](examples/code-review-demo/scoped/owner.html) · [工程报告](examples/code-review-demo/scoped/report.md) |

GitHub 不直接渲染这些 HTML 页面；下载后本地打开即可查看。更多信息见[演示说明](examples/code-review-demo/README.md)及[合成项目说明](evals/fixtures/README.md)。

两例的旧收集器均输出十项 unknown，但实际审阅结论不同：**收集器占位数量不能当成项目诊断。**

## 工作流程

1. 确认范围、数据处理与模型授权，标识源码快照。
2. 识别真实架构，选择最影响客户、收入或运营的链路。
3. 将已授权源码当作静态文本阅读，检查调用方、helper、保护和反证。
4. 写入独立的 `review.json`（契约 1.0），记录证据、关注点与任务。
5. 由可信渲染器生成关联的老板页和工程报告，原始证据另行保留。

补充收集的 `result.json`（契约 0.1）保持独立，当前最终渲染器的快照契约要求提供它。**只运行收集器不算完成审阅。** 没有发现问题也可以交付，但必须说明查了哪些链路、保护和边界。

### 本地工具

在此可信 skill 目录运行。须先获得授权；输出父目录存在，输出文件／目录必须新建且位于被审阅快照之外。

```bash
# 可选导航：可能的技术栈与入口，不作漏洞结论
python3 -B scripts/project_context.py --root /authorized/snapshot --output /outside/context.json

# 补充静态收集，不是代码审阅
python3 -B scripts/scan.py --root /authorized/snapshot --output /outside/result.json

# AI／人工完成实际审阅并编写符合契约的 review.json 后再渲染
python3 -B scripts/render_review.py --input /outside/review.json --static /outside/result.json --root /authorized/snapshot --output-dir /outside/new-delivery

# 仅运行本 skill 自身的工具测试，不是客户项目测试
python3 -B -m unittest discover -s tests -v
```

创建证据与调用渲染器前请读[交付契约](references/report-delivery.md)。哈希、行号和引用通过校验，不代表审阅推理一定正确。

## 安全与隐私边界

- 不执行客户代码、安装依赖、运行项目测试、访问生产环境或自动修复／部署。
- 不发起真实支付、客户消息、破坏性操作或真实客户跨租户测试。
- 静态结论不等于部署环境事实，不是渗透测试、合规评估、专家认证或上线许可。
- 确认严重漏洞／利用结论需要合格人员验证和独立复核；动态 TEST 必须另行授权，由合格人员在隔离环境使用合成数据执行。
- Python 收集器本地确定性运行，但 AI 审阅可能将已授权的最小源码发送给实际模型提供方。必须先披露实际数据流和已知保留限制，不能宣传整个流程“完全离线”。
- 接收材料前约定保留政策。草案要求操作人员在每次交付后七个自然日内手动删除临时副本；脚本不自动删除，本地删除也不会清除提供方保留的数据。

## 维护入口

- [SKILL.md](SKILL.md)：主流程、授权与完成门槛。
- [代码审阅方法](references/code-review.md)：跨文件链路、反证及分类。
- [双报告交付契约](references/report-delivery.md)：证据侧车与关联报告。
- [语言策略](references/report-language.md)：输出语言和证据保真。
- [检查清单](references/checklist.md)：独立人工 TEST 的规划参考，不是测试结果。
- [更新记录](CHANGELOG.md)：版本历史。
- [评测提示](evals/evals.json)：提示存在不等于完成验证，也不能据此宣传准确率。

此目录是独立 skill 包；外层商业规划不属于安装内容。`metadata.version` 为 skill 版本来源，JSON 契约单独演进。

## 反馈与许可证

欢迎通过 [GitHub Issues](https://github.com/myouzh/launch-readiness-skill/issues) 反馈工具问题和首次使用体验。请提供最小合成示例，**不要公开凭证、私有源码或客户数据**。

采用 [MIT 许可证](LICENSE)。许可证不是安全担保；本实验性流程不保证发现所有漏洞或业务风险。
