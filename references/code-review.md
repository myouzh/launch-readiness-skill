# Static code-review method — v0.4.0

Use with [the workflow](../SKILL.md) and [delivery contract](report-delivery.md). This is mandatory AI/manual reasoning, not a scanner feature. Read source only after repository authorization and actual model-provider/source-context consent. Summary-only consent does not permit AI source reading.

## Map before judging

Read the actual manifests and relevant entrypoints. Identify browser/server boundaries, identity source, privileged clients, persistence, storage, external API spend, jobs and deployment definitions. Support stack claims with files read; do not assume React/Supabase/Stripe. Never execute customer code, imports, dependencies, scripts or tests, access network/production or repair anything.

Choose two to four real chains by reachable business consequence. Explain selection and omissions. If the snapshot supports fewer, record partial coverage rather than inventing flows. Adapt auth → route guard → ownership → database; upload → storage → download; external AI API → auth → rate/budget guard; deployment → migration → rollback; or payment → entitlement where actually applicable.

For each chain locate the true entrypoint, caller-controlled input, identity/trust transitions, helper calls, privileged operation, persistence/output and failure path. Follow across files until the relevant business effect or explicit evidence boundary. Cite evidence IDs for the inspected paths, inclusive line ranges and file SHA-256. Explain what the steps mean; a filename list is not a trace.

## Challenge every suspicion

Before an absent-auth/ownership/rate-limit claim, inspect callers, route wrappers, shared helpers, middleware registration, adapters and relevant database policies/config. A leaf function may rely on an enforced caller invariant. Inspect relevant reachable callsites within the chain; if some cannot be read, narrow the claim or retain a hypothesis. A grep miss is not proof of absence.

Ask: who controls the identifier? Is identity server-derived? Does the final operation scope by owner/tenant? Can a privileged client bypass policies? Is the guard registered on this route? Can downloads bypass upload protections? Is budget reserved before paid provider work? Does migration order remain compatible with rollback? Select questions matching the actual stack.

Seek counterevidence deliberately: owner predicates, deny policies, signed-object checks, centralized wrappers, quota reservation/release, transaction boundaries, webhook signature/idempotency or rollback compatibility. Record why it defeats, narrows or does not defeat the suspicion. “None found” states which places were inspected, not universal absence.

## Classify and qualify

| kind | Required reasoning | Not established |
| --- | --- | --- |
| static_observation | Direct behavior, bounded consequence, source evidence and chain | Runtime reproduction, deployed protection or confirmed exploit |
| hypothesis | Supporting evidence, explicit prerequisites, counterevidence, uncertainty and validation action | Demonstrated failure merely because plausible |
| evidence_gap | Exact question, business relevance, missing artifact and evidence-request task | Failure or an invented evidence reference |

Put explicit conditions in observation/uncertainty. Missing hosted policy is unknown, not proof of public access. A test file shows intended checks, not execution success. A backup definition is not restore proof. A public key alone is not a leak. Source configuration does not prove deployment.

Rank P1/P2/P3 by affected business flow, reachability, blast radius and confidence. Explain action order; invent no deadlines, monetary loss or incident probability. Priority is not exploit confirmation. Confirmed critical/exploit claims require qualified verification and independent review; ordinary read-only reasoning has no blanket expert gate.

## Evidence and completion

Use the exact [sidecar contract](report-delivery.md). Cite real repository-relative regular files actually read, real inclusive lines, SHA-256 of file bytes and descriptive summaries. No source snippets, secrets or customer records in outputs. Do not fabricate missing cloud artifacts. Reconcile snapshot changes before rendering. The trusted renderer checks references/hashes, not correctness of interpretation.

Keep E-001 evidence, C-001 chains, F-001 findings and T-001 tasks stable in both reports and explicitly map them on recheck. Non-gap findings link evidence and chain. Each task has acceptance criteria and safe retest proposal, not execution permission. Never rewrite result.json or promote its ten placeholder unknowns into project findings.

Dismissed suspicions belong in chain assessments with evidence references, not fabricated active findings. No-findings reviews still need substantive traces and residual limits. If consent, access or context/scope limits stop work, record reviewed/not-reviewed boundaries and partial/not_started rather than claiming completion.

## Illustrative examples — never copy as project evidence

### Supported observation

A paid-generation route checks identity, accepts a caller-selected model and invokes a paid provider. Reading registered middleware, relevant callers and the provider helper shows no in-code account budget reservation on this chain. Authentication is counterevidence against an “unauthenticated API” claim. The narrower observation concerns authenticated spend control. Hosted gateway limits are unavailable, so exposure depends on reachable deployment and absent external enforcement. Cite the actual route/helper evidence; propose an account-budget decision and synthetic TEST acceptance criteria. Do not call it a reproduced billing exploit.

### Dismissed suspicion / positive guard

A database helper fetches an invoice by ID without an owner parameter. Inspection of relevant callers and the registered route wrapper shows server-derived identity and ownership rejection before the helper. Record those guard/callsite references in the chain assessment; dismiss the proposed cross-account finding for that path. Do not demand a redundant patch or generalize safety to unread entrypoints.

### Gap, not failure

Upload code names a bucket but hosted visibility policy is unavailable. Ask for a redacted environment-specific policy export. Do not invent a policy path or claim public exposure. If download code uses public URLs, distinguish that direct static observation from unknown deployment policy and conditions.

### No actionable findings

The agreed resource-access chain has server identity and owner-scoped queries at each inspected callsite; the paid-generation chain reserves user quota before invoking the provider and handles failed reservations. After counterevidence review no actionable issue is supported. Use an empty findings array if no specific actionable gap exists, explain positive controls in chain assessments, and preserve deployment/TEST limitations in scope. Say “No actionable findings in these reviewed chains,” never “the app is secure” or a general no-static-blocker conclusion from a secret scan. Do not add weak findings to meet a quota.
