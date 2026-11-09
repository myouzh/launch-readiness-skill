<!-- Structure source, not fixed output language. Follow ../references/report-language.md and ../references/report-delivery.md. The trusted review renderer drives delivery; this template explains required meaning, not extra JSON keys. Remove instructions/placeholders from final output. -->
# {{APP_NAME}} — Engineer evidence and proposed tasks

Report ID: {{REPORT_ID}} · [Owner page](owner.html) · [Review evidence](review.json) · [Supplementary collection](result.json)

> **INTERNAL DRAFT — not expert certification, a penetration test or launch approval.**
> Review state: {{completed_partial_not_started}}. {{EXACT_STOP_REASON_IF_ANY}}
> Operator/reviewer: {{ACTUAL_ROLE_AND_LIMITS}}. {{SIMULATED_LABEL_ONLY_IF_APPLICABLE}}

## 1. What matters for this launch

{{SPECIFIC_CUSTOMER_REVENUE_OR_OPERATIONAL_CONSEQUENCE_WITH_CONDITIONS_AND_UNCERTAINTY}}

| Priority | Specific issue or decision | Business impact | Next action / stable task / role |
| --- | --- | --- | --- |
| {{P1_P2_P3_AND_REASON}} | {{SUPPORTED_FINDING_OR_SPECIFIC_EVIDENCE_REQUEST}} | {{BOUNDED_IMPACT}} | {{ACTION_T_ID_ROLE}} |

Show up to three real priorities, not three mandatory findings. If no actionable finding exists, say so only for the reviewed chains, explain observed positive controls and residual limits. If no source review occurred, say not started/incomplete; do not present collector output as review. Never infer general no-static-blocker from a secret-pattern scan.

## 2. Actual stack, scope and authorization

| Item | Recorded evidence/value |
| --- | --- |
| Project / actual stack | {{NAME_AND_COMPONENTS_SUPPORTED_BY_FILES_READ}} |
| Repository authorization | {{OWNER_ALLOWED_PATHS_PURPOSE_EXCLUSIONS}} |
| Model-provider consent | {{ACTUAL_PROVIDER_DATA_PATH_SOURCE_CONTEXT_PERMISSION_TIME_OR_NOT_GRANTED}} |
| Reviewed / not reviewed | {{EXPLICIT_SCOPE_AND_REASONS}} |
| Snapshot root label | {{ROOT_LABEL_NOT_SENSITIVE_ABSOLUTE_PATH}} |
| Declared revision | {{DECLARED_ONLY_NOT_VERIFIED_CLEAN_COMMIT}} |
| Manifest SHA-256 / checked_at | {{EXACT_SHARED_SNAPSHOT_VALUES}} |
| Static review limits | {{SKIPS_ERRORS_CONTEXT_BOUNDS_INACCESSIBLE_HELPERS_OR_CONFIG}} |
| Dynamic TEST | {{NOT_PERFORMED_OR_SEPARATE_AUTHORIZATION_ISOLATION_REVIEWER_AND_EVIDENCE}} |

Repository permission is not model source-processing consent; earlier summary-only consent must not be expanded. No customer code, tests, hooks, imports or dependencies were executed as part of static review. No network, production access or automatic repairs. Source snapshot is not deployed behavior.

## 3. Real chains and why selected

{{WHY_THESE_TWO_TO_FOUR_CHAINS_HAVE_HIGHEST_BUSINESS_IMPACT_AND_WHAT_WAS_OMITTED}}

### {{C_ID}} — {{REAL_CHAIN_NAME}} — {{reviewed_or_partial}}

- Entry point(s): {{E_IDS_AND_ACTUAL_PATH_LINE_LINKS}}.
- Trace: {{ENTRYPOINT_TO_GUARD_TO_HELPER_TO_BUSINESS_EFFECT_WITH_ORDERED_E_IDS}}.
- Trust boundaries and caller-controlled input: {{OBSERVED}}.
- Guards and counterevidence inspected: {{CALLSITES_WRAPPERS_HELPERS_POLICIES_AND_REFERENCES}}.
- Assessment: {{WHAT_THE_TRACE_SUPPORTS_NOT_A_FILENAME_LIST}}.
- Dismissed suspicion: {{INITIAL_CONCERN_AND_EVIDENCE_THAT_DEFEATS_OR_NARROWS_IT_OR_NONE}}.
- Boundary/limitations: {{WHERE_REVIEW_STOPPED_WHAT_COULD_CHANGE_CONCLUSION}}.

Do not claim absent guards before inspecting relevant callers/helpers. If fewer chains exist or scope is exhausted, explain without inventing chains. Partial work remains partial.

## 4. Source evidence index

| Evidence ID | Actual repository-relative path / inclusive lines | File SHA-256 | Descriptive summary |
| --- | --- | --- | --- |
| {{E_ID}} | {{ACTUAL_FILE_LINK_AND_LINE_START_END}} | {{FILE_BYTES_SHA256}} | {{NO_SNIPPET_SECRET_OR_CUSTOMER_RECORD}} |

References must match the authorized snapshot and files actually read. Missing artifacts get no invented path, line or hash. Renderer verification checks identity/references, not semantic correctness.

## 5. Findings, hypotheses and actionable gaps

Repeat only for actual findings; an empty findings array is valid. Keep dismissed suspicions in chain assessments rather than active findings. Do not import the scanner's ten fixed unknowns as project findings.

### {{F_ID}} — {{SPECIFIC_TITLE}}

| Field | Value |
| --- | --- |
| kind | {{static_observation_hypothesis_evidence_gap}} |
| priority / priority_reason | {{P1_P2_P3_AND_EVIDENCE_BASED_ORDER}} |
| evidence_ids / chain_ids | {{REAL_E_IDS_C_IDS_OR_NO_FABRICATED_REFERENCES_FOR_GAP}} |
| business_impact | {{CUSTOMER_REVENUE_OR_OPERATIONAL_EFFECT_WITHOUT_INVENTED_PROBABILITY}} |
| observation | {{EXPECTED_VS_OBSERVED_BEHAVIOR_AND_EXPLICIT_CONDITIONS}} |
| counterevidence | {{GUARDS_OR_CONTRARY_FACTS_CHECKED_AND_EFFECT_ON_CLAIM}} |
| uncertainty | {{PREREQUISITES_MISSING_CONFIGURATION_RUNTIME_LIMITS_AND_CONFIRMATION_STATE}} |

A static observation is source-backed, not reproduced runtime behavior. A hypothesis is conditional, not a demonstrated failure. An evidence gap is missing information, not fail. Missing cloud config is unknown; a test file is not a test result; backup configuration is not restore proof. Confirmed critical/exploit claims require qualified verification and independent review; otherwise label provisional.

#### {{T_ID}} — proposed task, not execution permission

- Role: {{ACTUAL_RESPONSIBLE_ROLE_OR_UNASSIGNED}}.
- Action: {{BOUNDED_FIX_OR_EVIDENCE_REQUEST_LINKED_TO_FINDING}}.
- Acceptance: {{OBSERVABLE_CRITERIA_TIED_TO_ORIGINAL_CLAIM}}.
- Retest: {{NEW_STATIC_SNAPSHOT_CHECKS_AND_SEPARATELY_AUTHORIZED_SYNTHETIC_TEST_PLAN_IF_NEEDED}}.

Do not auto apply patches, run customer hooks, rotate credentials, alter production policies, deploy or restore. Preserve stable task IDs on recheck; map changes explicitly.

## 6. Remaining limits and supplementary collection

- Unreviewed paths/chains and exact reasons: {{SCOPE_BOUNDARIES}}.
- Missing cloud/deployment evidence: {{QUESTIONS_AND_REDACTED_ARTIFACTS_NEEDED}}.
- Dynamic checks/restore tests not performed: {{EXPLICIT_LIST}}.
- Collection scope/errors/skips: {{UNCHANGED_RESULT_JSON_COVERAGE_AND_LIMITS}}.
- Secret-pattern candidates: {{SUPPLEMENTARY_UNVERIFIED_CANDIDATES_OR_NONE_NOT_SAFETY_PROOF}}.
- The unchanged result.json contract 0.1 includes ten fixed unknown planning controls; these are not project findings or reviewed outcomes. Collection alone cannot support a complete report.

## 7. Recheck and handling

Recheck only the agreed original scope on a fresh authorized snapshot. Record old/new hashes, evidence, stable finding/task mappings, regression checks and unresolved gaps. A patch or green-test assertion alone is not closure. Separate TEST work needs qualified human leadership, written authorization, isolation, synthetic data and cleanup/stop conditions; never production.

Temporary local customer copies/evidence/prompts/drafts: {{RESPONSIBLE_PERSON}} manually deletes within seven calendar days after each delivery, by {{DUE_DATE_ZONE}}, earlier if agreed; record confirmation/exceptions and separately retained final records. Provider retention limits: {{ACTUAL_LIMITS}}. A 14-day original-scope retest request window does not extend retention; request a fresh snapshot when needed.

Validation/evaluation status: {{ONLY_ACTUALLY_PERFORMED_VALIDATION}}. Generated reports, evaluation prompts and simulations are not completed expert review or certification. The owner decides launch; no safety score, pass badge or blanket approval is provided.
