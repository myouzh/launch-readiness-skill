#!/usr/bin/env python3
"""Validate a human/AI code-review sidecar and render two evidence-led drafts.

Never runs target code. Hash/range checks prove references exist, NOT that reasoning
is correct. Only use on stable, authorized, redacted local snapshots.
"""
from __future__ import annotations
import argparse
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

from scan import collect, open_relative, MAX_FILE_BYTES, MAX_RESULT_BYTES, SKIP_DIRS, redact_label
from render_report import validate as validate_static, text as md


def shape(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys.split()):
        raise ValueError("Invalid object fields.")


def string(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("Expected nonempty text of at most 512 characters.")
    if redact_label(value) != value or any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise ValueError("Sensitive or invalid text; supply redacted summaries only.")
    return value


def items(value, maximum=100):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("Invalid list or list budget exceeded.")
    return value


def strings(value):
    for v in items(value):
        string(v)


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r'-[0-9]{3}', value):
        raise ValueError("Invalid stable ID.")
    return value


def unique(rows, prefix):
    ids = [identity(x['id'], prefix) for x in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate ID.")
    return set(ids)


def refs(value, allowed, required=False):
    strings(value)
    if (required and not value) or len(value) != len(set(value)) or not set(value) <= allowed:
        raise ValueError("Missing, duplicate, or dangling reference.")


def validate(review, baseline):
    validate_static(baseline)
    shape(review, 'schema_version language review_state snapshot project scope evidence chains findings')
    if review['schema_version'] != '1.0' or review['language'] not in {'zh-CN', 'en'}:
        raise ValueError("Unsupported review schema or renderer language (zh-CN/en).")
    if review['review_state'] not in {'completed', 'partial', 'not_started'}:
        raise ValueError("Invalid review state.")
    shape(review['snapshot'], 'root_label revision_declared manifest_sha256 checked_at')
    if review['snapshot'] != baseline['snapshot']:
        raise ValueError("Review and static snapshot identities differ.")
    shape(review['project'], 'name stack')
    string(review['project']['name'])
    strings(review['project']['stack'])
    scope = review['scope']
    shape(scope, 'reviewer consent reviewed not_reviewed limitations')
    string(scope['reviewer'])
    string(scope['consent'])
    for key in ('reviewed', 'not_reviewed', 'limitations'):
        strings(scope[key])
    evidence = items(review['evidence'], 200)
    for e in evidence:
        shape(e, 'id path line_start line_end sha256 summary')
        string(e['path'])
        string(e['summary'])
        p = PurePosixPath(e['path'])
        if p.is_absolute() or '..' in p.parts or str(p) != e['path'] or '\\' in e['path'] or any(part in SKIP_DIRS for part in p.parts):
            raise ValueError("Evidence path must be canonical and relative.")
        if not re.fullmatch(r'[a-f0-9]{64}', str(e['sha256'])):
            raise ValueError("Invalid evidence SHA256.")
        if type(e['line_start']) is not int or type(e['line_end']) is not int or not 1 <= e['line_start'] <= e['line_end']:
            raise ValueError("Invalid evidence line range.")
    eids = unique(evidence, 'E')
    chains = items(review['chains'], 20)
    for c in chains:
        shape(c, 'id name state entrypoints traced assessment limitations')
        string(c['name'])
        string(c['assessment'])
        strings(c['limitations'])
        if c['state'] not in {'reviewed', 'partial'}:
            raise ValueError("Invalid chain state.")
        refs(c['entrypoints'], eids, True)
        refs(c['traced'], eids, True)
    cids = unique(chains, 'C')
    findings = items(review['findings'], 50)
    for f in findings:
        shape(f, 'id kind title priority priority_reason business_impact observation evidence_ids chain_ids counterevidence uncertainty task')
        if f['kind'] not in {'static_observation', 'hypothesis', 'evidence_gap'} or f['priority'] not in {'P1', 'P2', 'P3'}:
            raise ValueError("Invalid finding type or priority.")
        for field in ('title', 'priority_reason', 'business_impact', 'observation', 'counterevidence', 'uncertainty'):
            string(f[field])
        refs(f['evidence_ids'], eids, f['kind'] != 'evidence_gap')
        refs(f['chain_ids'], cids, f['kind'] != 'evidence_gap')
        if f['kind'] != 'evidence_gap' and not set(f['evidence_ids']) <= set().union(*(set(c['entrypoints'] + c['traced']) for c in chains if c['id'] in f['chain_ids'])):
            raise ValueError("Finding evidence not present in linked chains.")
        shape(f['task'], 'id role action acceptance retest')
        for value in f['task'].values():
            string(value)
    unique(findings, 'F')
    unique([f['task'] for f in findings], 'T')
    if review['review_state'] == 'completed' and (not scope['reviewed'] or not any(c['state'] == 'reviewed' for c in chains)):
        raise ValueError("Completed bounded review requires a reviewed chain and scope.")
    if review['review_state'] == 'not_started' and (evidence or chains or findings or scope['reviewed']):
        raise ValueError("Not-started review cannot claim inspected evidence or findings.")


def checked_absolute(path):
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError("Symlink path components are not allowed.")
    return path


def read_bytes(path, limit):
    path = checked_absolute(path)
    fd = open_relative(Path('/'), path.relative_to('/'))
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Expected regular file.")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File byte budget exceeded.")
    return data


def verify_sources(review, baseline, root):
    root = checked_absolute(root)
    if not root.is_dir():
        raise ValueError("Snapshot root is not a directory.")
    current = collect(root, baseline['snapshot']['revision_declared'])
    if (current['snapshot']['manifest_sha256'] != baseline['snapshot']['manifest_sha256']
            or current['coverage'] != baseline['coverage'] or current['findings'] != baseline['findings']
            or current['summary'] != baseline['summary']):
        raise ValueError("Snapshot changed or collector coverage differs; rescan and re-review.")
    total = 0
    for e in review['evidence']:
        path = root / e['path']
        data = read_bytes(path, MAX_FILE_BYTES)
        total += len(data)
        if total > 16 * 1024 * 1024:
            raise ValueError("Evidence byte budget exceeded.")
        content = data.decode('utf-8')
        if '\x00' in content or hashlib.sha256(data).hexdigest() != e['sha256'] or e['line_end'] > len(content.splitlines()):
            raise ValueError("Evidence hash or line range does not match snapshot.")
    return root


LABELS = {
 'en': ['Project code review — INTERNAL DRAFT', 'Not certification or launch permission. Static source is not deployed behavior.', 'Review state', 'Top decisions', 'Business impact', 'Next action', 'Evidence and engineering tasks', 'No project-specific concern was established within the reviewed scope. This is not launch assurance.', 'Actual stack (reviewer assessment)', 'Scope and limitations', 'Traced chains', 'Project findings', 'Evidence index', 'Collector appendix (not project diagnosis)', 'Priority rationale', 'Observation', 'Counterevidence checked', 'Uncertainty', 'Acceptance criteria', 'Isolated TEST retest proposal', 'Reviewer', 'Processing consent', 'Reviewed', 'Not reviewed', 'Limitations', 'Finding type', 'Responsible role'],
 'zh-CN': ['项目代码审阅 — 内部草稿', '不是安全认证或上线许可。静态源码不等于已部署行为。', '审阅进度', '优先决策', '业务影响', '下一步', '证据与工程任务', '本次已审阅范围内尚未形成项目具体问题，不代表可以安全上线。', '实际技术栈（审阅者判断）', '范围与限制', '已追查链路', '项目关注点', '证据索引', '收集器附录（不是项目诊断）', '优先级理由', '观察', '已检查的反证', '尚不确定', '验收条件', '隔离 TEST 复测建议', '审阅者', '模型处理授权', '已审阅', '未审阅', '限制', '证据类型', '负责角色']
}
KINDS = {'zh-CN': {'static_observation': '静态事实（不等于漏洞复现）', 'hypothesis': '待验证假设', 'evidence_gap': '决策证据缺口'}, 'en': {'static_observation': 'Static observation (not exploit reproduction)', 'hypothesis': 'Hypothesis', 'evidence_gap': 'Decision evidence gap'}}
STATES = {'zh-CN': {'completed': '约定范围审阅已完成', 'partial': '部分完成', 'not_started': '尚未开始', 'reviewed': '已追查'}, 'en': {'completed': 'Bounded review completed', 'partial': 'Partial', 'not_started': 'Not started', 'reviewed': 'Reviewed'}}


def render(review, baseline):
    validate(review, baseline)
    lang = review['language']
    l = LABELS[lang]
    h = lambda v: html.escape(string(v), quote=True)
    state = STATES[lang][review['review_state']]
    ordered = sorted(review['findings'], key=lambda f: (f['priority'], f['kind'] == 'evidence_gap', f['id']))
    cards = []
    for f in ordered[:3]:
        t = f['task']
        cards.append(f'<article><span class="tag">{h(f["id"])} · {h(f["priority"])} · {h(KINDS[lang][f["kind"]])}</span><h3>{h(f["title"])}</h3><p><b>{l[4]}：</b>{h(f["business_impact"])}</p><p><b>{l[14]}：</b>{h(f["priority_reason"])}</p><p><b>{l[5]} · {h(t["id"])}：</b>{h(t["action"])}</p><p>{l[26]}：{h(t["role"])}</p><p class="muted">{l[17]}：{h(f["uncertainty"])}</p></article>')
    if not cards:
        empty = l[7] if review['review_state'] == 'completed' else ("审阅尚未完成；没有形成发现不等于未发现风险。请先补齐已标明的审阅范围。" if lang == 'zh-CN' else "Review is incomplete; no findings does not mean no risk. Complete the declared review scope first.")
        cards = [f'<article><p>{empty}</p></article>']
    not_reviewed = ''.join(f'<li>{h(v)}</li>' for v in review['scope']['not_reviewed'] + review['scope']['limitations'])
    chain_html = ''.join(f'<li><b>{h(c["name"])}</b> — {h(STATES[lang][c["state"]])}：{h(c["assessment"])}<ul>' + ''.join(f'<li class="muted">{l[24]}：{h(v)}</li>' for v in c['limitations']) + '</ul></li>' for c in review['chains'])
    owner = f'''<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>{l[0]}</title><style>body{{background:#f4f6fa;color:#172234;font:16px/1.7 system-ui;margin:0}}main{{max-width:1000px;margin:auto;padding:36px 22px}}h1{{line-height:1.3}}article,section{{background:white;padding:22px;border:1px solid #dce2eb;border-radius:14px;margin:18px 0}}article{{border-left:5px solid #e5a53a}}.tag,.muted,footer{{color:#52637a;font-size:14px}}.banner{{padding:16px;background:#fff0d6;border-radius:12px}}a{{color:#1555a2}}h3{{margin:10px 0}}ul{{padding-left:24px}}</style></head><body><main><p class="tag">{h(review['project']['name'])}</p><h1>{l[0]}</h1><p class="banner">{l[1]}<br>{l[2]}：{h(state)}</p><p>{l[8]}：{h(' / '.join(review['project']['stack']) or '—')}</p><h2>{l[3]}</h2>{''.join(cards)}<section><h2>{l[10]}</h2><ul>{chain_html}</ul></section><section><h2>{l[23]} / {l[24]}</h2><ul>{not_reviewed}</ul></section><p><a href="report.md">{l[6]}</a></p><footer>{h(review['snapshot']['checked_at'])}<br>SHA256: {h(review['snapshot']['manifest_sha256'])}</footer></main></body></html>'''
    lines = [f'# {l[0]}', '', l[1], '', f"{md(review['project']['name'])} · {l[2]}: {state}", '', f"{l[8]}: {md(' / '.join(review['project']['stack']) or '—')}", '', '[owner.html](owner.html)', '', '## '+l[9], '']
    scope = review['scope']
    for key, index in [('reviewer',20),('consent',21)]:
        lines += [f'**{l[index]}**: {md(scope[key])}', '']
    for key, index in [('reviewed',22),('not_reviewed',23),('limitations',24)]:
        lines += [f'### {l[index]}', *['- '+md(v) for v in scope[key]], '']
    lines += ['## '+l[10], '']
    for c in review['chains']:
        lines += [f"### {c['id']} · {md(c['name'])}", STATES[lang][c['state']], md(c['assessment']), ', '.join(c['entrypoints']) + ' → ' + ', '.join(c['traced']), *['- '+md(v) for v in c['limitations']], '']
    lines += ['## '+l[11], '']
    if not ordered:
        empty = l[7] if review['review_state'] == 'completed' else ("审阅尚未完成；没有形成发现不等于未发现风险。" if lang == 'zh-CN' else "Review is incomplete; no findings does not mean no risk.")
        lines += [empty, '']
    for f in ordered:
        lines += [f"### {f['id']} · {f['priority']} · {md(f['title'])}", f"{l[25]}: {KINDS[lang][f['kind']]}", ', '.join(f['evidence_ids'] + f['chain_ids']), '']
        for key, index in [('priority_reason',14),('business_impact',4),('observation',15),('counterevidence',16),('uncertainty',17)]:
            lines += [f'**{l[index]}**: {md(f[key])}', '']
        t = f['task']
        lines += [f"#### {t['id']} · {md(t['role'])}", f'{l[5]}: {md(t["action"])}', f'{l[18]}: {md(t["acceptance"])}', f'{l[19]}: {md(t["retest"])}', '']
    lines += ['## '+l[12], '']
    for e in review['evidence']:
        lines += [f"- {e['id']} · {md(e['path'])}:{e['line_start']}–{e['line_end']} · SHA256 {e['sha256']} · {md(e['summary'])}"]
    lines += ['', '## '+l[13], '', 'result.json · schema 0.1 · static_only', 'review.json · schema 1.0', f"SHA256: {review['snapshot']['manifest_sha256']}", f"UTC: {md(review['snapshot']['checked_at'])}", '', '~~~json', json.dumps({'coverage': baseline['coverage'], 'counts': baseline['summary']['counts']}, ensure_ascii=False, indent=2).replace('<', '\u003c'), '~~~', '']
    return owner, '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('input', 'static', 'root', 'output-dir'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = read_bytes(args.input, MAX_RESULT_BYTES)
        static_raw = read_bytes(args.static, MAX_RESULT_BYTES)
        review, baseline = json.loads(raw), json.loads(static_raw)
        validate(review, baseline)
        root = verify_sources(review, baseline, args.root)
        destination = checked_absolute(args.output_dir)
        if destination == root or root in destination.parents:
            raise ValueError("Delivery directory must be outside snapshot.")
        owner, report = render(review, baseline)
        # Parent must already exist. Exclusive directory creation prevents overwrite.
        parent_fd = open_relative(Path('/'), destination.parent.relative_to('/'))
        try:
            os.mkdir(destination.name, dir_fd=parent_fd)
            out_fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                for name, data in [('owner.html', owner.encode()), ('report.md', report.encode()), ('review.json', raw), ('result.json', static_raw)]:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out_fd)
                    with os.fdopen(fd, 'wb') as handle:
                        handle.write(data)
            finally:
                os.close(out_fd)
        finally:
            os.close(parent_fd)
        print("Created validated evidence-led draft delivery; no target code executed.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError, UnicodeError):
        print("Review rejected or delivery incomplete: check schema, source identity, references, authorization and unused output directory. No input overwritten.", file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
