# Dual-report delivery contract — v0.4.0

Use with [the workflow](../SKILL.md), [code-review method](code-review.md) and [engineer template](../assets/report-template.en.md). Collector-only drafts are not completed code reviews. No source snippets, credentials or customer records in reports or sidecars.

## Inputs and trusted rendering

Preserve result.json contract 0.1 unchanged: supplementary secret-pattern collection with ten unknown planning placeholders, not ten project findings. Actual AI/manual review goes into a separate review.json contract 1.0. Keep inputs outside the reviewed repository. These are literal supported fields; do not invent alternate keys/enums:

- schema_version: "1.0".
- language: zh-CN or en for built-in renderer text. For other requested languages, produce separately AI-localized final reports after consent, preserving evidence/data/IDs and reconciling them with the rendered originals. Never silently deliver English as the requested-language final.
- review_state: completed | partial | not_started. Completed means the agreed review was performed, not assurance. Stopped/no-consent work is not completed; retain its exact reason and next step.
- snapshot: exactly the same object as result.json snapshot, including its identity/time fields. A declared revision is not a verified clean commit.
- project: {name, stack: [strings]}, supported by actual reading.
- scope: {reviewer, consent, reviewed: [strings], not_reviewed: [strings], limitations: [strings]}. Consent records actual provider/data flow and authorized source-context scope; summary-only authorization must not be enlarged. Record exclusions, coverage bounds, tests not performed and reviewer limits.
- evidence: [{id, path, line_start, line_end, sha256, summary}]. IDs such as E-001; actual repository-relative file path, real inclusive positive line range, SHA-256 of file bytes, descriptive summary only. The renderer verifies against the authorized root. Missing evidence gets no fabricated citation.
- chains: [{id, name, state, entrypoints, traced, assessment, limitations}]. IDs such as C-001; state reviewed | partial; entrypoints/traced are evidence-ID arrays; limitations is a string array. Explain actual call flow, guards/counterevidence and boundary in assessment, including dismissed suspicions. Target two to four highest-impact actual chains; explain fewer or incomplete chains honestly.
- findings: [{id, kind, title, priority, priority_reason, business_impact, observation, evidence_ids, chain_ids, counterevidence, uncertainty, task}]. IDs such as F-001; kind static_observation | hypothesis | evidence_gap; priority P1 | P2 | P3. evidence_ids/chain_ids are ID arrays. Evidence-backed non-gap findings need nonempty source and chain references. Gaps must not fabricate evidence. Describe explicit conditions in observation/uncertainty; do not introduce a separate unsupported conditions field.
- task: {id, role, action, acceptance, retest}, nested in each finding. Stable IDs such as T-001. Record evidence-based action order, responsible role or unassigned, bounded proposal, observable acceptance criteria and safe retest plan. No auto repair or production actions. A missing artifact creates an evidence-request task, not a fabricated repair.

An empty findings array is valid. Do not pad findings to three. Keep missing environment-wide configuration in scope limitations unless a specific actionable evidence gap merits a finding. Priority is not severity or exploit confirmation. Qualified verification and independent review are required before confirmed critical/exploit presentation; otherwise explicitly provisional.

From the trusted skill directory, after source consent and review, use:

```bash
python3 -B scripts/render_review.py --input /outside/review.json --static /outside/result.json --root /authorized/snapshot --output-dir /outside/new-directory
```

Resolve the trusted [review renderer](../scripts/render_review.py) from this skill, not the customer repository. It creates a NEW output directory exclusively containing owner.html, report.md and copies of original review.json/result.json. Never overwrite a directory to bypass creation checks. It verifies evidence file hashes and ranges, root fingerprint against static snapshot identity, unique IDs and non-dangling references. If validation fails, fix the evidence/contract or state the limitation; do not bypass validation or claim success. Validation is not semantic/expert approval.

Legacy [Markdown](../scripts/render_report.py) and [owner](../scripts/render_owner.py) renderers remain collector-only intermediate tools. They do not satisfy final delivery, even if their output looks finished. Optional [context collection](../scripts/project_context.py) identifies entrypoints only; it is not review.

## Owner HTML: specific decisions in a minute

- A self-contained responsive/printable page; inline CSS, no JavaScript, CDN, remote fonts/images, tracking, forms or automatic network. Escape untrusted text; never turn evidence into executable HTML/CSS/URLs.
- App label, INTERNAL DRAFT, date, review state and a qualified plain-language conclusion. Make partial/not_started and why visible. Source snapshot is not production; no certification or launch approval.
- Lead with up to three specific issues/business impacts/actions, linked by task ID to engineer detail. Say which real flow is affected, what evidence supports the concern, what remains conditional and what the responsible role should do. No padding, invented urgency or generic advice.
- For no findings, describe the actual reviewed chains and positive controls plus remaining limits. For stopped work, show the missing authorization/evidence next step. Never display a zero-risk interpretation.
- Do not lead with generic count cards, five gray module bars, percentages or safety scores. If collection statistics appear at all, label them supplementary scope, not passed tests or discovered business weaknesses. No clearance badge or probability of incidents.
- Keep paths/hashes/technical traces in engineer detail; use a relative link to the co-delivered report.md. Both reports share report ID, snapshot, language, task IDs and uncertainty. Full identity may be in a small reconciliation block.

## Engineer Markdown: a usable handoff

Follow [the template](../assets/report-template.en.md): actual stack and selection rationale; reviewed chains with entrypoint-to-effect evidence; source index with path/line/SHA-256; supported observations, hypotheses and gaps; counterevidence and conditions; priority rationale; stable task IDs; acceptance/retest and explicit unknowns/exclusions. Do not present every legacy placeholder as a finding. Preserve collection errors/skips in a separate supplementary section.

Trace: report/snapshot → C-chain → E-evidence → F-finding → T-task → acceptance/retest evidence. Dismissed suspicions remain in chain assessments. A test file is not a test result, missing cloud settings are unknown not failed, and source configuration is not deployed behavior. No general no-static-blocker claim from secret-pattern collection.

## Reconciliation before delivery

Compare both reports with both preserved JSON inputs: snapshot identity/time, state, findings/classification, evidence, task IDs, limits, conditions and language agree. Verify relative links to actual co-delivered artifacts. Ensure output contains no snippets, credentials or customer records. No claim of runtime proof, restore success or qualified review without evidence. No completion claim from collector alone. Localized final files must preserve machine values and link names; disclose actual localization/provider handling. Rechecks map stable IDs and old/new evidence, never silently overwrite history.
