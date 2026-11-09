#!/usr/bin/env python3
"""Render an internal-draft, static-only Markdown report; never issues clearance."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys

from scan import CONTROLS, PATTERNS, MAX_RESULT_BYTES, MAX_SKIPPED, redact_label

STATUSES = {"pass", "fail", "unknown", "not_applicable", "tool_error"}
MODULES = {"payments", "auth", "data", "backup", "failure"}
SEVERITIES = {"high", "medium", "low", "info", "undetermined"}
MAX_INPUT_BYTES = MAX_RESULT_BYTES


def text(value: object, max_length: int = 4096) -> str:
    if not isinstance(value, str) or len(value) > max_length:
        raise ValueError("Invalid text field.")
    # Treat all report input as data, not Markdown or instructions.
    value = html.escape(redact_label(value), quote=True)
    for char in ("\\", "`", "*", "_", "[", "]", "(", ")", "#", "!", "|"):
        value = value.replace(char, "\\" + char)
    return value


def validate(result: dict) -> None:
    if not isinstance(result, dict) or result.get("schema_version") != "0.1" or result.get("mode") != "static_only":
        raise ValueError("Unsupported schema or mode.")
    snapshot = result["snapshot"]
    for field in ("root_label", "manifest_sha256", "checked_at"):
        text(snapshot[field])
    if snapshot.get("revision_declared") is not None:
        text(snapshot["revision_declared"])
    findings = result["findings"]
    if not isinstance(findings, list) or len(findings) > 211:
        raise ValueError("Invalid findings.")
    # This renderer accepts collector evidence, not independently signed manual review.
    # Business controls must remain unknown, even if a hand-edited JSON claims pass.
    for rid, _, _, _ in CONTROLS:
        controls = [f for f in findings if f.get("rule_id") == rid]
        if len(controls) != 1 or controls[0].get("status") != "unknown":
            raise ValueError("Required static-only unknown controls missing or altered.")
    allowed = {rid: (module, "undetermined", "unknown") for rid, module, _, _ in CONTROLS}
    allowed.update({rid: ("data", severity, "fail") for rid, severity, _ in PATTERNS})
    allowed["DATA-SECRET-SERVICE-ROLE"] = ("data", "high", "fail")
    allowed["SCAN-COVERAGE"] = ("data", "undetermined", "tool_error")
    if sum(f.get("rule_id") == "SCAN-COVERAGE" for f in findings) > 1:
        raise ValueError("Duplicate coverage error.")
    for finding in findings:
        if allowed.get(finding["rule_id"]) != (finding["module"], finding["severity"], finding["status"]):
            raise ValueError("Unsupported static finding combination.")
        if finding["status"] not in STATUSES or finding["module"] not in MODULES or finding["severity"] not in SEVERITIES:
            raise ValueError("Invalid finding enum.")
        for field in ("rule_id", "affected_flow", "business_impact", "recommendation", "retest"):
            text(finding[field])
        if not isinstance(finding["evidence"], list) or len(finding["evidence"]) > 20:
            raise ValueError("Invalid evidence.")
        for evidence in finding["evidence"]:
            text(evidence["path"])
            text(evidence["summary"])
            if type(evidence["line"]) is not int or evidence["line"] < 1:
                raise ValueError("Invalid evidence line.")
    coverage = result["coverage"]
    for field in ("files_scanned", "bytes_scanned", "bytes_read", "skipped_omitted"):
        if type(coverage[field]) is not int or coverage[field] < 0:
            raise ValueError("Invalid coverage count.")
    if type(coverage["limits_reached"]) is not bool or not isinstance(coverage["skipped"], list):
        raise ValueError("Invalid coverage.")
    if len(coverage["skipped"]) > MAX_SKIPPED:
        raise ValueError("Exclusion metadata exceeds budget.")
    for skipped in coverage["skipped"]:
        text(skipped["path"])
        text(skipped["reason"])
    expected_counts = {status: sum(f["status"] == status for f in findings) for status in STATUSES}
    expected_decision = "static_blockers_found" if expected_counts["fail"] else "insufficient_evidence"
    if result["summary"]["counts"] != expected_counts or result["summary"]["decision"] != expected_decision:
        raise ValueError("Inconsistent summary.")
    limitations = result["summary"]["limitations"]
    if not isinstance(limitations, list) or len(limitations) > 50:
        raise ValueError("Invalid limitations.")
    for limitation in limitations:
        text(limitation)


def render(result: dict) -> str:
    validate(result)
    findings = result["findings"]
    candidates = [f for f in findings if f["status"] == "fail"]
    errors = [f for f in findings if f["status"] == "tool_error"]
    snapshot, coverage = result["snapshot"], result["coverage"]
    lines = [
        "# Launch Readiness — Static Evidence Draft", "",
        "> INTERNAL DRAFT. Not an expert audit, certification, or permission to launch.", "",
        "## Engineer handoff summary", "",
        f"Report ID: {text(snapshot['manifest_sha256'])}@{text(snapshot['checked_at'])}",
        "Owner dashboard: [owner.html](owner.html)", "",
        "**Launch decision: cannot be established from this static collection.**", "",
        f"Found {len(candidates)} credential-shaped candidate(s), {len(errors)} collection error(s), and 10 unverified business controls.",
        "Candidates require qualified review. A source match does not establish that a credential is real, deployed or exposed.", "",
        "### Next three actions", "",
        "1. If candidates exist, have a qualified reviewer privately verify them and rotate real exposed secrets through the owner.",
        "2. Complete authorized test-environment checks for account isolation and payment behavior; do not test production.",
        "3. Obtain backup/restore and failure-handling evidence; keep all unverified areas explicitly unknown.", "",
        "## Snapshot and coverage", "",
        f"- Project label: {text(snapshot['root_label'])}",
        f"- Owner-declared revision (not verified): {text(snapshot.get('revision_declared') or 'not supplied')}",
        f"- Checked at: {text(snapshot['checked_at'])}",
        f"- Inspected-content manifest SHA-256: {text(snapshot['manifest_sha256'])}",
        f"- UTF-8 files scanned: {coverage['files_scanned']}; bytes: {coverage['bytes_scanned']}",
        f"- Total bytes read (including rejected content): {coverage['bytes_read']}",
        f"- Limits reached: {'yes' if coverage['limits_reached'] else 'no'}; recorded exclusions: {len(coverage['skipped'])}; additional exclusions omitted: {coverage['skipped_omitted']}",
        "- No deployed environment was inspected. This is not a complete repository or production fingerprint.", "",
        "## Findings and unverified controls", "",
    ]
    ordered = candidates + errors + [f for f in findings if f["status"] not in {"fail", "tool_error"}]
    lines += ["Each F/T identifier below is unique within this delivery. Evidence references are redacted; missing artifacts remain unavailable.", ""]
    for index, finding in enumerate(ordered, 1):
        fid, tid = f"F-{index:03d}", f"T-{index:03d}"
        lines += [f"### {fid} — {text(finding['rule_id'])} — {text(finding['affected_flow'])}", "",
                  f"- Finding ID: {fid}; proposed task ID: {tid}",
                  f"- snapshot_checked_at: {text(snapshot['checked_at'])}",
                  "- Evidence kind: static collection only; no dynamic reproduction or qualified review performed.",
                  "- Verification / closure: unverified / open. Severity is provisional; not an exploit or deployed-exposure claim.",
                  f"- Module: {finding['module']}; status: {finding['status']}; severity: {finding['severity']}",
                  f"- Business impact: {text(finding['business_impact'])}",
                  f"- Action: {text(finding['recommendation'])}",
                  f"- Retest: {text(finding['retest'])}"]
        if not finding["evidence"]:
            lines += ["- Evidence: none collected for this control; no pass inferred."]
        for evidence_index, evidence in enumerate(finding["evidence"], 1):
            lines += [f"- Evidence E-{index:03d}-{evidence_index:02d}: {text(evidence['path'])}, line {evidence['line']}: {text(evidence['summary'])}"]
        lines += [f"- Task {tid} owner: engineer / qualified reviewer, unassigned. Proposal only; no execution or deployment authorized.",
                  "- Expected vs observed: the narrow requirement and observed result must be verified against the evidence above; unknown controls were not tested.",
                  f"- Proposed scope: {text(finding['recommendation'])}",
                  f"- Acceptance / retest evidence required: {text(finding['retest'])}",
                  "- Retest gate: separate written scope, qualified reviewer, isolated TEST environment and synthetic data. No production testing.",
                  "- Closure gate: record actual new-snapshot evidence and regression checks; a patch or green unit test alone is insufficient."]
        lines.append("")
    lines += ["## Coverage exclusions", ""]
    if not coverage["skipped"]:
        lines += ["No per-entry exclusions recorded. Built-in static-only limitations still apply.", ""]
    for skipped in coverage["skipped"]:
        lines.append(f"- {text(skipped['path'])}: {text(skipped['reason'])}")
    lines += ["", "## Limitations", ""]
    for limitation in result["summary"]["limitations"]:
        lines.append(f"- {text(limitation)}")
    lines += ["", "## Human review gate", "",
              "A qualified security reviewer must validate high-risk conclusions before a paid review is represented as an audit.",
              "No automatic repair, external probing, account access, deletion policy enforcement or credential revocation was performed.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.input.is_symlink() or not args.input.is_file():
            raise ValueError("Input must be a regular file.")
        with args.input.open("rb") as handle:
            content = handle.read(MAX_INPUT_BYTES + 1)
        if len(content) > MAX_INPUT_BYTES:
            raise ValueError("Input exceeds size limit.")
        result = json.loads(content)
        markdown = render(result)
        if args.output.exists() or args.output.is_symlink() or not args.output.resolve().parent.is_dir():
            raise ValueError("Choose a new output with an existing parent.")
        # Do not trust JSON to choose or write to any path; CLI output is explicit.
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(markdown)
        print("Internal draft Markdown generated. Business checks remain unverified.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        print("Rendering refused or failed. Check schema and choose a new output path; no untrusted values are printed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
