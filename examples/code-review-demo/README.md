# 0.4.0 合成项目正反演示

不是客户报告，不是漏洞复现；源文件专为评测编写，从未执行或部署。

- [无租户过滤：老板页](unscoped/owner.html) · [工程报告](unscoped/report.md) · [审阅侧车](unscoped/review.json)：已挂载 JWT 登录，但文档查询仅按客户端 id，形成有条件的静态关注点。
- [helper 有保护：老板页](scoped/owner.html) · [工程报告](scoped/report.md) · [审阅侧车](scoped/review.json)：追到 helper 的身份租户过滤后排除同类怀疑，允许 findings 为空。

两例的静态收集结果都是十项 unknown；实际审阅结果却不同，说明收集占位不该充当项目诊断。原始静态 JSON 与审阅 JSON 独立保留。输入在[合成夹具说明](../../evals/fixtures/README.md)相邻两个目录。可按[交付契约](../../references/report-delivery.md)使用本包渲染器、对应快照与 JSON 在新目录重现输出。校验哈希与行号不证明推理正确。

旧 dual-report-demo 仅作历史页面样式，不代表 v0.4.0 的完整审阅交付。
