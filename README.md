# Launch Readiness

**Know what to investigate before your first customers arrive.**

[English](#what-it-does) · [简体中文](README.zh-CN.md)

**v0.4.0 · Experimental / internal-draft methodology · Read-only code review, not security certification.**

Built your app with AI? Launch Readiness helps you investigate risks that could affect customers, revenue, and operations. It is an agent skill: instructions, evidence contracts, and local Python tools—not a hosted audit service or an autonomous vulnerability detector.

## What it does

- Discovers the actual stack rather than assuming React, Supabase, or Stripe.
- Traces two to four high-business-impact code chains across routes, helpers, and relevant schema/configuration.
- Separates supported static observations, conditional hypotheses, and missing evidence; checks counterevidence instead of forcing findings.
- Produces a **founder HTML action page** and a **traceable engineer Markdown report**, with task IDs, evidence references, acceptance criteria, and scoped recheck instructions.
- Matches the report language to your request unless you explicitly choose another language. The current review renderer has fixed English and Simplified Chinese labels; it does not translate review descriptions.

Typical chains include identity → ownership → database access, upload → storage → authorized download, AI API → quota → provider call, and deployment → migration → rollback. Payments are reviewed when applicable, not assumed.

## Install

Use a host that supports Agent Skills. Copy the **entire package**, not just `SKILL.md`.

For hosts supporting user-level `~/.agents/skills` discovery on macOS/Linux:

```bash
git clone https://github.com/myouzh/launch-readiness-skill.git \
  ~/.agents/skills/launch-readiness
```

This command expects the destination not to exist. If already installed, back up local changes before updating. Refresh the host's skills list or restart it if necessary, and confirm `launch-readiness` appears. Other hosts may use different skill directories; follow their documentation. Installed copies do not automatically follow edits to another source copy.

The bundled static tools require **Python 3.10+ on macOS/Linux**. Customer project dependencies are not required and must not be installed or executed for this workflow. Using the skill's AI review also requires a compatible agent/model host.

## Quick start

After installation, tell your agent:

> Use launch-readiness to review my app before launch. First confirm the repository scope, exclusions, and consent for sending minimal relevant source context to the actual model provider. Do not execute my project, modify code, or access production. Write the founder action page and engineer report in English.

Or in Chinese:

> 使用 launch-readiness 帮我的项目做上线前代码风险自检。先确认目录、排除项及最小相关源码发送给实际模型提供方的授权；不要执行项目、修改代码或访问生产环境。请用中文生成老板行动页和工程报告。

Then provide an authorized, redacted local snapshot, app purpose, launch stage, critical customer flows, and any exclusions. **Do not provide production credentials or customer records.** Repository-read permission and model-processing consent are separate.

## See the difference: two synthetic examples

These are purpose-built, unexecuted fixtures—not customer audits, runtime reproductions, or accuracy benchmarks.

| Example | What the review illustrates | Outputs |
| --- | --- | --- |
| Document query without tenant filtering | A conditional static concern after tracing identity and query behavior | [Founder HTML source/download](examples/code-review-demo/unscoped/owner.html) · [Engineer report](examples/code-review-demo/unscoped/report.md) |
| Tenant protection inside a shared helper | Why an initially suspicious handler should not be reported without following the helper | [Founder HTML source/download](examples/code-review-demo/scoped/owner.html) · [Engineer report](examples/code-review-demo/scoped/report.md) |

GitHub displays HTML as source; download the HTML file and open it locally to view the action page. Current sample reports are in Chinese. See [demo notes](examples/code-review-demo/README.md) and [synthetic fixtures](evals/fixtures/README.md).

Both examples have the same ten legacy collector unknowns, yet different review conclusions. **Collector counts are not project findings.**

## How it works

1. Agree scope, data handling, model consent, and snapshot identity.
2. Discover the actual architecture and select the highest-impact chains.
3. Read authorized source as inert text, tracing callsites, helpers, guards, and counterevidence.
4. Record evidence and tasks in a separate `review.json` (contract 1.0).
5. Render linked founder/engineer reports with the trusted review renderer; preserve original evidence artifacts.

The supplementary collector's `result.json` (contract 0.1) remains separate and is required by the current final renderer's snapshot contract. A collector-only run is **not** a completed code review. Finding no issues is valid when the reviewed chains, protections, and limits are documented.

### Local tooling

Run these trusted bundled tools from this skill directory. Obtain authorization first. Output parents must exist; output files/directories must be new and outside the reviewed snapshot.

```bash
# Optional navigation: likely stack and entrypoints, not vulnerability conclusions
python3 -B scripts/project_context.py --root /authorized/snapshot --output /outside/context.json

# Supplementary static collection, not code review
python3 -B scripts/scan.py --root /authorized/snapshot --output /outside/result.json

# After an authorized AI/manual review creates a contract-valid review.json
python3 -B scripts/render_review.py --input /outside/review.json --static /outside/result.json --root /authorized/snapshot --output-dir /outside/new-delivery

# Tests of this skill's own tooling, not tests of a customer project
python3 -B -m unittest discover -s tests -v
```

Read the [delivery contract](references/report-delivery.md) before creating review artifacts or invoking the renderer. Valid paths/hashes do not prove that the review's reasoning is correct.

## Boundaries and privacy

- No customer code execution, dependency installation, project test runs, production access, or automatic fixes/deployments.
- No real payments, customer messages, destructive actions, or live cross-tenant tests.
- Static reasoning is **not** deployed-environment proof, a penetration test, compliance assessment, expert certification, or permission to launch.
- Confirmed critical vulnerability/exploit claims need qualified verification and independent review. Any dynamic TEST phase is separate, isolated, synthetic-data-only, and qualified-human-led.
- Python collection is local and deterministic, but AI review may transmit authorized source context to the actual model provider. Disclose that data flow and known retention limits; do not call the whole workflow offline.
- Agree retention before intake. The draft policy calls for operator-managed deletion of temporary copies within seven calendar days after delivery; scripts do not automate deletion, and local deletion cannot erase provider-retained data.

## Package guide

- [SKILL.md](SKILL.md): agent instructions, consent, workflow, completion gates.
- [Code-review method](references/code-review.md): chain tracing, counterevidence, classification.
- [Delivery contract](references/report-delivery.md): evidence sidecar and linked reports.
- [Language policy](references/report-language.md): language selection and evidence preservation.
- [Checklist](references/checklist.md): supplementary human TEST planning, not test results.
- [Changelog](CHANGELOG.md): version history.
- [Evaluation prompts](evals/evals.json): prompts are not completed validation or accuracy claims.

## Feedback and license

Report reproducible tooling problems or onboarding feedback through [GitHub Issues](https://github.com/myouzh/launch-readiness-skill/issues). **Do not post secrets, private source, or customer data in public issues.** Use a minimal synthetic example.

Licensed under [MIT](LICENSE). The license is not a security warranty. This experimental workflow does not guarantee finding every vulnerability or business risk.
