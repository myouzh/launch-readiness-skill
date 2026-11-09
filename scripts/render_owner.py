#!/usr/bin/env python3
"""Render an offline English owner dashboard from validated static JSON evidence."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys

from render_report import MAX_INPUT_BYTES, validate
from scan import CONTROLS, redact_label

MODULES = (("payments", "Payments"), ("auth", "Accounts & access"),
           ("data", "Customer data"), ("backup", "Backup & restore"),
           ("failure", "Failure handling"))


def text(value: str) -> str:
    """Redact known credential patterns before escaping inert HTML text."""
    return html.escape(redact_label(value), quote=True)


def render(result: dict) -> str:
    validate(result)
    findings = result["findings"]
    candidates = [f for f in findings if f["status"] == "fail"]
    errors = [f for f in findings if f["status"] == "tool_error"]
    unknowns = sum(f["status"] == "unknown" for f in findings)
    snapshot, coverage = result["snapshot"], result["coverage"]
    ordered = candidates + errors + [f for f in findings if f["status"] not in {"fail", "tool_error"}]
    tasks = [(f"T-{index:03d}", finding) for index, finding in enumerate(ordered, 1)]

    def task_refs(predicate) -> str:
        return ", ".join(tid for tid, finding in tasks if predicate(finding))

    # Shared count scale, never a percentage of controls passed or safety.
    bar_max = max(2, len(candidates), len(errors))
    parts = ["""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Launch readiness — owner draft</title>
<style>
:root{color-scheme:light;font-family:system-ui,sans-serif;color:#182b39;background:#f2f5f6}
*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:auto;padding:40px 24px}
h1{font-size:clamp(2rem,5vw,3.2rem);letter-spacing:-.04em;margin:.4em 0}h2{font-size:1.3rem;margin-top:0}
h3{font-size:1.1rem}p,li,dd{line-height:1.6}a{color:#155968}a:focus-visible{outline:3px solid #b05b16}
.eyebrow{font-size:.8rem;letter-spacing:.12em;text-transform:uppercase;color:#6c4a19;font-weight:700}
.muted{color:#4b626e}.notice{border-left:4px solid #b88235;padding:12px 20px;background:#fff6e7}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin:24px 0}
.card,section{background:white;border:1px solid #dbe4e8;border-radius:16px;padding:24px}section{margin:24px 0}
.metric{font-size:2.5rem;font-weight:750;margin:0;color:#174e5b}.unit{margin:0;font-weight:650}
.modules .card{border-top:4px solid #a6b9bf}.modules ul{padding-left:20px;font-size:.9rem}
.count-label{font-size:.9rem;margin:10px 0 4px}.track{height:8px;background:#f0f2f3;border-radius:4px;overflow:hidden}
.bar{display:block;height:8px}.unknown{background:#71818b}.candidate{background:#b7791f}.error{background:#9a4c44}
dl{display:grid;grid-template-columns:minmax(130px,1fr) 3fr;gap:12px}dt{font-weight:650}dd{margin:0}
code,dd,li{overflow-wrap:anywhere}summary{cursor:pointer;font-weight:650}footer{font-size:.9rem}
@media(max-width:540px){main{padding:24px 16px}.card,section{padding:20px}dl{display:block}dd{margin:4px 0 16px}}
@media print{body{background:white}main{max-width:none}.card,section{break-inside:avoid}}
</style></head><body><main>
<header><p class="eyebrow">Internal draft · static evidence only</p>
<h1>Your launch questions, in focus.</h1>
<p class="muted">English intermediate draft · owner dashboard</p>
<p class="notice"><strong>A launch decision cannot be established from this collection.</strong>
Not an expert audit, certification, or permission to launch. No deployed environment was inspected.</p></header>
<div class="grid" aria-label="Evidence counts">"""]
    for count, unit in ((len(candidates), "unverified credential-shaped candidates"),
                        (unknowns, "unknown business controls"),
                        (len(errors), "collection errors")):
        parts.append(f'<div class="card"><p class="metric">{count}</p><p class="unit">{unit}</p></div>')
    parts.append("""</div><p class="muted">Candidates are not confirmed vulnerabilities. A pattern match does not prove a real,
 deployed, or exposed credential. Zero candidates does not establish safety. Collection errors describe incomplete evidence, not vulnerabilities.</p>
<h2>Five areas to discuss with your engineer</h2><div class="grid modules">""")
    for module, label in MODULES:
        records = [f for f in findings if f["module"] == module]
        counts = {status: sum(f["status"] == status for f in records)
                  for status in ("unknown", "fail", "tool_error")}
        parts.append(f'<article class="card"><h3>{label}</h3>')
        for status, unit, color in (("unknown", "unknown business controls", "unknown"),
                                    ("fail", "unverified candidates", "candidate"),
                                    ("tool_error", "collection errors", "error")):
            count = counts[status]
            parts.append(f'<p class="count-label">{count} {unit}</p>'
                         f'<div class="track" aria-hidden="true"><span class="bar {color}" '
                         f'style="width:{count * 100 / bar_max:.2f}%"></span></div>')
        parts.append('<details><summary>Checks still needing evidence</summary><ul>')
        for _, control_module, flow, _ in CONTROLS:
            if control_module == module:
                parts.append(f'<li>{text(flow)} — unknown</li>')
        parts.append('</ul></details></article>')
    parts.append('</div><p class="muted">Bars compare record counts on a shared scale relative to the largest displayed count, not a completion or safety ratio. Gray: unknown controls; amber: unverified candidates; muted red: collection errors. Payment applicability is not established by missing source matches.</p>')
    actions = []
    if candidates:
        actions.append(("Ask a qualified reviewer to privately verify credential candidates; if real and exposed, arrange owner-controlled rotation. Never paste secrets into chat.",
                        task_refs(lambda f: f["status"] == "fail"), "Qualified reviewer / engineer"))
    if errors or coverage["limits_reached"]:
        actions.append(("Ask your engineer to review exclusions and collection limits, resolve access or scope gaps, and collect a fresh snapshot.",
                        task_refs(lambda f: f["status"] == "tool_error"), "Engineer"))
    actions.append(("Agree on qualified, separately authorized isolated TEST checks with synthetic data for account access, data permissions and payment behavior; never probe production.",
                    task_refs(lambda f: f["status"] == "unknown" and f["module"] in {"payments", "auth", "data"}),
                    "Engineer / qualified reviewer"))
    if len(actions) < 3:
        actions.append(("Request backup coverage, isolated restore evidence and failure-handling records; keep missing evidence explicitly unknown.",
                        task_refs(lambda f: f["module"] in {"backup", "failure"}), "Engineer / qualified reviewer"))
    parts.append('<section><h2>Next actions</h2><ol>')
    for action, refs, role in actions[:3]:
        parts.append(f'<li>{action}<p class="muted">Proposed role: {role}, unassigned. '
                     f'Engineer task IDs: {refs or "No matching task; scope review required"}.</p></li>')
    parts.append('</ol></section><section><h2>Snapshot & collection coverage</h2><dl>')
    parts.append(f'<dt>Project label</dt><dd>{text(snapshot["root_label"])}</dd>'
                 f'<dt>Checked at (UTC)</dt><dd>{text(snapshot["checked_at"])}</dd>')
    parts.extend([f'<dt>Scanned files</dt><dd>{coverage["files_scanned"]} UTF-8 files</dd>',
                  f'<dt>Skips</dt><dd>{len(coverage["skipped"])} recorded exclusions; {coverage["skipped_omitted"]} additional exclusions omitted</dd>',
                  f'<dt>Limits reached</dt><dd>{"Yes" if coverage["limits_reached"] else "No"}</dd></dl>'])
    parts.append('<details><summary>Technical snapshot & exclusion details</summary><dl>')
    metadata = (("Report ID", text(snapshot["manifest_sha256"]) + "@" + text(snapshot["checked_at"])),
                ("Declared revision (not verified)", text(snapshot.get("revision_declared") or "Not supplied")),
                ("Inspected-content manifest SHA-256", text(snapshot["manifest_sha256"])))
    for label, value in metadata:
        parts.append(f'<dt>{label}</dt><dd>{value}</dd>')
    parts.extend([f'<dt>Scanned bytes</dt><dd>{coverage["bytes_scanned"]} accepted UTF-8 bytes</dd>',
                  f'<dt>Read bytes</dt><dd>{coverage["bytes_read"]} bytes, including rejected content</dd></dl>',
                  '<p class="muted">The manifest identifies inspected bytes, not a complete repository revision or production deployment.</p>',
                  '<h3>Recorded exclusions</h3><ul>'])
    for item in coverage["skipped"]:
        parts.append(f'<li>{text(item["path"])} — {text(item["reason"])}</li>')
    if not coverage["skipped"]:
        parts.append('<li>No per-entry exclusions recorded; static-only limitations still apply.</li>')
    parts.append('</ul></details></section>')
    if candidates or errors:
        parts.append('<section><details><summary>Technical evidence references (for engineer)</summary><ul>')
        for finding in candidates + errors:
            kind = "Unverified candidate" if finding["status"] == "fail" else "Collection error"
            parts.append(f'<li>{kind}: {text(finding["rule_id"])}<ul>')
            for evidence in finding["evidence"]:
                parts.append(f'<li>{text(evidence["path"])} · line {evidence["line"]}: {text(evidence["summary"])}</li>')
            parts.append('</ul></li>')
        parts.append('</ul></details></section>')
    parts.append('<section><h2>Limits of this draft</h2><ul>')
    parts.extend(f'<li>{text(item)}</li>' for item in result["summary"]["limitations"])
    parts.append('''</ul><p>All ten business controls remain unknown. No automatic repairs, live tests, credential revocation or restoration were performed.</p></section>
<footer><p><a href="report.md">Engineer report (report.md)</a> — companion file, if separately generated alongside this dashboard.</p>
<p>Offline standalone HTML · no scripts or external resources. Human review is still required.</p></footer>
</main></body></html>''')
    return "\n".join(parts) + "\n"


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
        dashboard = render(json.loads(content))
        if args.output.exists() or args.output.is_symlink() or not args.output.resolve().parent.is_dir():
            raise ValueError("Choose a new output with an existing parent.")
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(dashboard)
        print("Internal draft HTML generated. Business checks remain unverified.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        print("Rendering refused or failed. Check schema and choose a new output path; no untrusted values are printed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
