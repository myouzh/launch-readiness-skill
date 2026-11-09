"""Evidence-led review regressions; stdlib only, inert synthetic snapshots."""
from __future__ import annotations

import copy
import hashlib
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import scan
import render_review
import render_report


class Tags(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="review-test-")
        self.addCleanup(temporary.cleanup)
        # macOS /var is normally a symlink; do not confuse it with hostile input.
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "app"
        self.root.mkdir()
        self.source = self.root / "handler.ts"
        self.source.write_text("// Synthetic inert source; never execute.\nexport const handler = 'placeholder';\n", encoding="utf-8")
        self.baseline = scan.collect(self.root, revision="synthetic-review-v1")
        self.review = {
            "schema_version": "1.0", "language": "en", "review_state": "completed",
            "snapshot": copy.deepcopy(self.baseline["snapshot"]),
            "project": {"name": "Synthetic appointments", "stack": ["React", "Supabase"]},
            "scope": {"reviewer": "Synthetic reviewer", "consent": "Authorized local redacted source review only",
                      "reviewed": ["Appointment handler source"], "not_reviewed": ["Deployment and live accounts"],
                      "limitations": ["Static reading only; no target code executed"]},
            "evidence": [{"id": "E-001", "path": "handler.ts", "line_start": 1, "line_end": 2,
                          "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                          "summary": "Handler placeholder observed"}],
            "chains": [{"id": "C-001", "name": "Appointment write path", "state": "reviewed",
                        "entrypoints": ["E-001"], "traced": ["E-001"],
                        "assessment": "Only placeholder behavior established", "limitations": ["No runtime test"]}],
            "findings": [{"id": "F-001", "kind": "hypothesis", "title": "Appointment ownership needs verification",
                          "priority": "P1", "priority_reason": "Customer records require ownership checks",
                          "business_impact": "Cross-account records could be affected if checks are absent",
                          "observation": "Placeholder source does not establish ownership enforcement",
                          "evidence_ids": ["E-001"], "chain_ids": ["C-001"],
                          "counterevidence": "No enforcement demonstrated by the traced placeholder",
                          "uncertainty": "Deployment policies remain unknown",
                          "task": {"id": "T-001", "role": "Backend engineer",
                                   "action": "Verify appointment ownership enforcement",
                                   "acceptance": "Document narrowly scoped ownership checks",
                                   "retest": "Propose isolated TEST accounts and synthetic appointments"}}],
        }
        self.review_path = self.base / "input-review.json"
        self.static_path = self.base / "input-result.json"
        self.save_inputs()

    def save_inputs(self):
        self.review_path.write_text(json.dumps(self.review, ensure_ascii=False), encoding="utf-8")
        self.static_path.write_text(json.dumps(self.baseline, ensure_ascii=False), encoding="utf-8")

    def cli(self, destination=None, root=None, review_path=None, static_path=None):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPTS / "render_review.py"),
             "--input", str(review_path if review_path is not None else self.review_path),
             "--static", str(static_path if static_path is not None else self.static_path),
             "--root", str(root if root is not None else self.root),
             "--output-dir", str(destination if destination is not None else self.base / "delivery")],
            capture_output=True, text=True, timeout=15, check=False)

    def assert_rejected(self, process):
        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
        self.assertIn("Review rejected", process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        self.assertLess(len(process.stdout + process.stderr), 1024)

    def test_valid_schema_hash_and_no_mutation(self):
        before = copy.deepcopy((self.review, self.baseline))
        render_review.validate(self.review, self.baseline)
        self.assertEqual(render_review.verify_sources(self.review, self.baseline, self.root), self.root)
        render_review.render(self.review, self.baseline)
        self.assertEqual((self.review, self.baseline), before)
        self.assertEqual(self.baseline["summary"]["counts"]["unknown"], 10)

    def test_localized_owner_and_markdown_share_decisions_and_tasks(self):
        for language, heading in [("en", "Project code review"), ("zh-CN", "项目代码审阅")]:
            with self.subTest(language=language):
                self.review["language"] = language
                if language == "zh-CN":
                    self.review["findings"][0]["title"] = "预约归属检查需要验证"
                    self.review["findings"][0]["task"]["action"] = "核实预约归属限制"
                owner, report = render_review.render(self.review, self.baseline)
                self.assertIn(heading, owner)
                self.assertIn(heading, report)
                for value in ["F-001", "T-001", "P1", self.review["findings"][0]["title"],
                              self.review["findings"][0]["business_impact"],
                              self.review["findings"][0]["priority_reason"],
                              self.review["findings"][0]["task"]["action"],
                              self.review["findings"][0]["task"]["role"]]:
                    self.assertIn(html.escape(value), owner)
                    self.assertIn(render_report.text(value), report)
                self.assertIn('href="report.md"', owner)
                self.assertNotIn("10 unknown", owner)
                self.assertNotIn('"unknown": 10', owner)
                for finding in self.baseline["findings"]:
                    self.assertNotIn(finding["affected_flow"], owner)
                self.assertIn("E-001", report)
                self.assertIn("C-001", report)
                self.assertIn(self.review["evidence"][0]["sha256"], report)
                labels = ({"reviewer": "Reviewer", "consent": "Processing consent",
                           "acceptance": "Acceptance criteria", "retest": "Isolated TEST retest proposal"}
                          if language == "en" else
                          {"reviewer": "审阅者", "consent": "模型处理授权",
                           "acceptance": "验收条件", "retest": "隔离 TEST 复测建议"})
                for key in ["reviewer", "consent"]:
                    self.assertIn("**" + labels[key] + "**: " + render_report.text(self.review["scope"][key]), report)
                for key in ["acceptance", "retest"]:
                    self.assertIn(labels[key] + ": " + render_report.text(self.review["findings"][0]["task"][key]), report)

    def test_source_hash_and_out_of_range_are_rejected(self):
        for changes in [{"sha256": "0" * 64}, {"line_end": 999}]:
            with self.subTest(changes=changes):
                review = copy.deepcopy(self.review)
                review["evidence"][0].update(changes)
                render_review.validate(review, self.baseline)
                with self.assertRaises(ValueError):
                    render_review.verify_sources(review, self.baseline, self.root)

    def test_invalid_line_ranges_and_hash_shapes(self):
        for changes in [{"line_start": 0}, {"line_start": True}, {"line_end": False},
                        {"line_start": 3, "line_end": 2}, {"sha256": "not-a-hash"}]:
            with self.subTest(changes=changes):
                review = copy.deepcopy(self.review)
                review["evidence"][0].update(changes)
                with self.assertRaises(ValueError):
                    render_review.validate(review, self.baseline)

    def test_snapshot_mismatch_and_changed_source_rejected(self):
        review = copy.deepcopy(self.review)
        review["snapshot"]["manifest_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            render_review.validate(review, self.baseline)
        self.source.write_text("// changed after review\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            render_review.verify_sources(self.review, self.baseline, self.root)
        self.assert_rejected(self.cli())
        self.assertFalse((self.base / "delivery").exists())

    def test_duplicate_entity_ids_rejected(self):
        for field in ["evidence", "chains", "findings"]:
            with self.subTest(field=field):
                review = copy.deepcopy(self.review)
                review[field].append(copy.deepcopy(review[field][0]))
                with self.assertRaises(ValueError):
                    render_review.validate(review, self.baseline)
        review = copy.deepcopy(self.review)
        second = copy.deepcopy(review["findings"][0])
        second["id"] = "F-002"
        review["findings"].append(second)
        with self.assertRaises(ValueError):
            render_review.validate(review, self.baseline)

    def test_dangling_duplicate_and_missing_references_rejected(self):
        for row, field in [("chains", "entrypoints"), ("chains", "traced"),
                           ("findings", "evidence_ids"), ("findings", "chain_ids")]:
            prefix = "C" if field == "chain_ids" else "E"
            for value in [[], [prefix + "-999"], [prefix + "-001", prefix + "-001"]]:
                with self.subTest(row=row, field=field, value=value):
                    review = copy.deepcopy(self.review)
                    review[row][0][field] = value
                    with self.assertRaises(ValueError):
                        render_review.validate(review, self.baseline)
        for value in ["T-9999", "E-001", "../T-001", ""]:
            review = copy.deepcopy(self.review)
            review["findings"][0]["task"]["id"] = value
            with self.subTest(task=value), self.assertRaises(ValueError):
                render_review.validate(review, self.baseline)

    def test_finding_evidence_must_belong_to_linked_chain(self):
        second = copy.deepcopy(self.review["evidence"][0])
        second["id"] = "E-002"
        self.review["evidence"].append(second)
        self.review["findings"][0]["evidence_ids"] = ["E-002"]
        with self.assertRaises(ValueError):
            render_review.validate(self.review, self.baseline)

    def test_html_and_markdown_payloads_are_inert(self):
        payload = '<script>alert("x")</script><img src=x onerror=x> [click](javascript:alert(1)) ![x](https://evil.invalid) **bold**'
        self.review["project"]["name"] = payload
        self.review["scope"]["reviewer"] = payload
        self.review["chains"][0]["assessment"] = payload
        self.review["evidence"][0]["summary"] = payload
        for key in ["title", "business_impact", "observation", "priority_reason", "counterevidence", "uncertainty"]:
            self.review["findings"][0][key] = payload
        for key in ["action", "acceptance", "retest", "role"]:
            self.review["findings"][0]["task"][key] = payload
        owner, report = render_review.render(self.review, self.baseline)
        self.assertIn(html.escape(payload), owner)
        self.assertIn(render_report.text(payload), report)
        self.assertNotIn("<script", owner)
        self.assertNotIn("<img", owner)
        self.assertNotIn("<script", report)
        self.assertNotIn("[click](javascript:", report)
        self.assertNotIn("![x](https://", report)
        for tag, attrs in Tags(owner).tags:
            self.assertNotIn(tag, {"script", "img", "iframe", "object"})
            self.assertFalse(any(key.startswith("on") for key in attrs))

    def test_chain_limitations_are_visible_in_both_languages(self):
        limitation = "Synthetic chain-specific gap: deployment enforcement not inspected"
        self.review["chains"][0]["limitations"] = [limitation]
        for language in ["en", "zh-CN"]:
            with self.subTest(language=language):
                self.review["language"] = language
                owner, report = render_review.render(self.review, self.baseline)
                self.assertIn(html.escape(limitation), owner)
                self.assertIn(render_report.text(limitation), report)

    def test_multiline_markdown_spoofing_is_rejected(self):
        for payload in ["innocent\n# Forged clearance", "innocent\n~~~html\n<script>x</script>\n~~~",
                        "Forged clearance\n================", "innocent\tforged label"]:
            for field in ["title", "action", "summary", "reviewer"]:
                review = copy.deepcopy(self.review)
                if field == "title":
                    review["findings"][0][field] = payload
                elif field == "action":
                    review["findings"][0]["task"][field] = payload
                elif field == "summary":
                    review["evidence"][0][field] = payload
                else:
                    review["scope"][field] = payload
                with self.subTest(payload=payload, field=field), self.assertRaises(ValueError):
                    render_review.render(review, self.baseline)

    def test_secret_labels_rejected_without_echo(self):
        secret = "sb_secret_" + "SYNTHETICNOTREAL1234567890"
        for target in ["project", "scope", "evidence", "finding", "task"]:
            with self.subTest(target=target):
                review = copy.deepcopy(self.review)
                if target == "project":
                    review["project"]["name"] = secret
                elif target == "scope":
                    review["scope"]["consent"] = secret
                elif target == "evidence":
                    review["evidence"][0]["path"] = secret
                elif target == "finding":
                    review["findings"][0]["title"] = secret
                else:
                    review["findings"][0]["task"]["action"] = secret
                with self.assertRaises(ValueError) as caught:
                    render_review.render(review, self.baseline)
                self.assertNotIn(secret, str(caught.exception))
                self.review_path.write_text(json.dumps(review), encoding="utf-8")
                result = self.cli()
                self.assert_rejected(result)
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_no_findings_is_allowed_without_clearance(self):
        self.review["findings"] = []
        for language, disclaimer in [("en", "not launch assurance"), ("zh-CN", "不代表可以安全上线")]:
            with self.subTest(language=language):
                self.review["language"] = language
                owner, report = render_review.render(self.review, self.baseline)
                for output in [owner, report]:
                    self.assertIn(disclaimer, output)
                    self.assertNotIn("production-ready", output.lower())
                    self.assertNotIn("overall pass", output.lower())
                    self.assertNotIn("安全认证通过", output)

    def test_completed_without_reviewed_trace_rejected(self):
        for change in ["no_chains", "partial_chain", "no_scope", "no_trace"]:
            review = copy.deepcopy(self.review)
            review["findings"] = []
            if change == "no_chains":
                review["chains"] = []
            elif change == "partial_chain":
                review["chains"][0]["state"] = "partial"
            elif change == "no_scope":
                review["scope"]["reviewed"] = []
            else:
                review["chains"][0]["traced"] = []
            with self.subTest(change=change), self.assertRaises(ValueError):
                render_review.validate(review, self.baseline)

    def not_started(self):
        self.review["review_state"] = "not_started"
        self.review["scope"]["reviewed"] = []
        for field in ["evidence", "chains", "findings"]:
            self.review[field] = []

    def test_not_started_stays_honest_in_both_reports(self):
        self.not_started()
        for language, state, completed_claim in [
                ("en", "Not started", "No project-specific concern was established within the reviewed scope"),
                ("zh-CN", "尚未开始", "本次已审阅范围内尚未形成项目具体问题")]:
            with self.subTest(language=language):
                self.review["language"] = language
                owner, report = render_review.render(self.review, self.baseline)
                for output in [owner, report]:
                    self.assertIn(state, output)
                    self.assertNotIn(completed_claim, output)

    def test_not_started_cannot_claim_evidence(self):
        original = copy.deepcopy(self.review)
        for field in ["evidence", "chains", "findings", "reviewed"]:
            self.review = copy.deepcopy(original)
            self.not_started()
            if field == "reviewed":
                self.review["scope"][field] = original["scope"][field]
            else:
                self.review[field] = original[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                render_review.validate(self.review, self.baseline)

    def test_cli_creates_new_delivery_preserves_inputs_and_snapshot(self):
        before = {path: path.read_bytes() for path in [self.source, self.review_path, self.static_path]}
        destination = self.base / "delivery"
        result = self.cli(destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in destination.iterdir()}, {"owner.html", "report.md", "review.json", "result.json"})
        self.assertEqual((destination / "review.json").read_bytes(), before[self.review_path])
        self.assertEqual((destination / "result.json").read_bytes(), before[self.static_path])
        generated = {p: p.read_bytes() for p in destination.iterdir()}
        self.assert_rejected(self.cli(destination))
        self.assertEqual({p: p.read_bytes() for p in destination.iterdir()}, generated)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual(set(self.root.iterdir()), {self.source})

    def test_inside_root_existing_file_and_root_output_rejected(self):
        existing = self.base / "existing-file"
        existing.write_text("keep", encoding="utf-8")
        for destination in [self.root / "delivery", self.root, existing, Path(self.root.anchor)]:
            with self.subTest(destination=destination):
                self.assert_rejected(self.cli(destination))
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
        self.assertFalse((self.root / "delivery").exists())

    def test_file_instead_of_snapshot_root_rejected(self):
        self.assert_rejected(self.cli(root=self.source))
        self.assertFalse((self.base / "delivery").exists())

    def test_symlink_input_root_and_output_components_rejected(self):
        linked_review = self.base / "linked-review.json"
        linked_review.symlink_to(self.review_path)
        linked_root = self.base / "linked-app"
        linked_root.symlink_to(self.root, target_is_directory=True)
        real_output_parent = self.base / "outside"
        real_output_parent.mkdir()
        linked_parent = self.base / "linked-outside"
        linked_parent.symlink_to(real_output_parent, target_is_directory=True)
        linked_destination = self.base / "linked-destination"
        linked_destination.symlink_to(real_output_parent, target_is_directory=True)
        for kwargs in [{"review_path": linked_review}, {"static_path": linked_review}, {"root": linked_root},
                       {"destination": linked_parent / "delivery"}, {"destination": linked_destination}]:
            with self.subTest(kwargs=kwargs):
                self.assert_rejected(self.cli(**kwargs))
        self.assertEqual(list(real_output_parent.iterdir()), [])

    def test_evidence_traversal_absolute_and_symlink_rejected(self):
        for path in ["../input-review.json", str(self.review_path), "./handler.ts", "a/../handler.ts", "a\\handler.ts"]:
            review = copy.deepcopy(self.review)
            review["evidence"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                render_review.validate(review, self.baseline)
        outside = self.base / "outside.ts"
        outside.write_bytes(self.source.read_bytes())
        link = self.root / "link.ts"
        link.symlink_to(outside)
        self.baseline = scan.collect(self.root, revision="synthetic-review-v1")
        self.review["snapshot"] = copy.deepcopy(self.baseline["snapshot"])
        self.review["evidence"][0]["path"] = "link.ts"
        render_review.validate(self.review, self.baseline)
        with self.assertRaises(ValueError):
            render_review.verify_sources(self.review, self.baseline, self.root)

    def test_oversized_deep_and_malformed_json_fail_with_bounded_errors(self):
        bad = self.base / "bad.json"
        for label, content in [("oversized", b" " * (scan.MAX_RESULT_BYTES + 1)),
                               ("deep", b"[" * 2000 + b"0" + b"]" * 2000),
                               ("malformed", b"{no-json"), ("utf8", b"\xff"),
                               ("wrong-shape", b"[]")]:
            bad.write_bytes(content)
            for argument in ["review_path", "static_path"]:
                with self.subTest(label=label, argument=argument):
                    self.assert_rejected(self.cli(**{argument: bad}))
                    self.assertFalse((self.base / "delivery").exists())

    def test_forged_baseline_cannot_hide_behind_matching_manifest(self):
        for field in ["findings", "summary"]:
            baseline = copy.deepcopy(self.baseline)
            if field == "findings":
                baseline[field][0]["business_impact"] = "Forged diagnostic statement"
            else:
                baseline[field]["limitations"] = ["Forged limitation"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                render_review.verify_sources(self.review, baseline, self.root)

    def test_evidence_in_excluded_directory_rejected(self):
        excluded = self.root / "node_modules"
        excluded.mkdir()
        hidden = excluded / "hidden.ts"
        hidden.write_bytes(self.source.read_bytes())
        self.baseline = scan.collect(self.root, revision="synthetic-review-v1")
        self.review["snapshot"] = copy.deepcopy(self.baseline["snapshot"])
        self.review["evidence"][0]["path"] = "node_modules/hidden.ts"
        with self.assertRaises(ValueError):
            render_review.validate(self.review, self.baseline)
        self.save_inputs()
        self.assert_rejected(self.cli())

    def test_schema_list_and_text_budgets_rejected(self):
        for field, count in [("evidence", 201), ("chains", 21), ("findings", 51)]:
            review = copy.deepcopy(self.review)
            review[field] *= count
            with self.subTest(field=field), self.assertRaises(ValueError):
                render_review.validate(review, self.baseline)
        self.review["project"]["name"] = "x" * 513
        with self.assertRaises(ValueError):
            render_review.validate(self.review, self.baseline)


if __name__ == "__main__":
    unittest.main()
