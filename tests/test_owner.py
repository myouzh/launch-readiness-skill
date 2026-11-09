"""Offline owner dashboard regression tests; synthetic fixtures only."""
from __future__ import annotations

import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import scan
import render_owner
import render_report


class Document(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.tags = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owner-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "app"
        self.root.mkdir()
        (self.root / "app.ts").write_text("export const app = 1;", encoding="utf-8")

    def result(self, candidate=False, error=False):
        if candidate:
            (self.root / "key.env").write_text("sk_live_" + "SYNTHETICNOTREAL1234567890")
        if error:
            with patch.object(scan, "MAX_TOTAL_BYTES", 1):
                return scan.collect(self.root)
        return scan.collect(self.root, revision="owner-label")

    def cli(self, source, target):
        return subprocess.run([sys.executable, "-B", str(SCRIPTS / "render_owner.py"),
                               "--input", str(source), "--output", str(target)],
                              capture_output=True, text=True, check=False)

    def test_counts_units_modules_snapshot_and_no_mutation(self):
        result = self.result(candidate=True)
        original = copy.deepcopy(result)
        page = render_owner.render(result)
        self.assertEqual(result, original)
        self.assertIn('>1</p><p class="unit">unverified credential-shaped candidates', page)
        self.assertIn('>10</p><p class="unit">unknown business controls', page)
        self.assertIn('>0</p><p class="unit">collection errors', page)
        self.assertEqual(page.count("2 unknown business controls</p>"), 5)
        self.assertEqual(page.count('<article class="card">'), 5)
        self.assertIn("1 unverified candidates</p>", page)
        self.assertIn("2 UTF-8 files", page)
        for value in result["snapshot"].values():
            self.assertIn(value, page)
        for _, _, flow, _ in scan.CONTROLS:
            self.assertIn(render_owner.text(flow), page)
        self.assertIn("not confirmed vulnerabilities", page)
        self.assertIn("cannot be established", page)
        self.assertNotIn("overall pass", page.lower())
        self.assertNotIn("safety score:", page.lower())
        self.assertLessEqual(page.split("<ol>")[1].split("</ol>")[0].count("<li>"), 3)

    def test_errors_limits_skips_and_omissions_are_visible(self):
        result = self.result(error=True)
        result["coverage"]["skipped_omitted"] = 7
        page = render_owner.render(result)
        self.assertIn('>1</p><p class="unit">collection errors', page)
        self.assertIn("0 UTF-8 files", page)
        self.assertIn("1 recorded exclusions; 7 additional exclusions omitted", page)
        self.assertIn("<dt>Limits reached</dt><dd>Yes", page)
        self.assertIn("total_byte_limit", page)
        self.assertIn("collect a fresh snapshot", page)
        self.assertIn("0 accepted UTF-8 bytes", page)
        self.assertIn("0 bytes, including rejected content", page)

    def test_html_escaping_and_known_secret_redaction_every_displayed_field(self):
        result = self.result(candidate=True)
        secret = "sb_secret_" + "SYNTHETICNOTREAL1234567890"
        malicious = '<script>alert("x")</script><img src="https://evil.invalid" onerror="x"> & ' + secret
        for field in result["snapshot"]:
            result["snapshot"][field] = malicious
        result["findings"][-1]["evidence"][0].update(path=malicious, summary=malicious)
        result["coverage"]["skipped"] = [{"path": malicious, "reason": malicious}]
        result["summary"]["limitations"] = [malicious]
        page = render_owner.render(result)
        self.assertNotIn(secret, page)
        self.assertNotIn("<script>", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&quot;x&quot;", page)
        self.assertIn("&amp; [REDACTED]", page)
        doc = Document(page)
        self.assertEqual([attrs["href"] for _, attrs in doc.tags if "href" in attrs], ["report.md"])
        self.assertFalse(any("src" in attrs or any(a.startswith("on") for a in attrs)
                             for _, attrs in doc.tags))

    def test_no_remote_resources_or_javascript(self):
        page = render_owner.render(self.result())
        doc = Document(page)
        self.assertFalse({tag for tag, _ in doc.tags} & {"script", "iframe", "object", "embed", "link", "img", "form"})
        self.assertNotIn("@import", page)
        self.assertNotIn("url(", page)
        self.assertNotIn("https://", page)
        self.assertNotIn("http://", page)
        self.assertNotIn("javascript:", page.lower())
        self.assertIn("default-src 'none'", page)
        self.assertIn('name="viewport"', page)
        self.assertIn("@media(max-width:540px)", page)
        self.assertIn('lang="en"', page)

    def test_reuses_existing_validator_and_size_budget(self):
        result = self.result()
        with patch.object(render_owner, "validate", wraps=render_report.validate) as validate:
            render_owner.render(result)
        validate.assert_called_once_with(result)
        self.assertEqual(render_owner.MAX_INPUT_BYTES, render_report.MAX_INPUT_BYTES)

    def test_fake_pass_unknown_rule_and_inconsistent_summary_refused(self):
        baseline = self.result()
        for mutation in ("pass", "missing", "extra", "summary", "decision"):
            with self.subTest(mutation=mutation):
                result = copy.deepcopy(baseline)
                if mutation == "pass":
                    result["findings"][0]["status"] = "pass"
                elif mutation == "missing":
                    result["findings"].pop()
                elif mutation == "extra":
                    result["findings"].append(dict(result["findings"][0], rule_id="FAKE", status="pass"))
                elif mutation == "summary":
                    result["summary"]["counts"]["pass"] = 10
                else:
                    result["summary"]["decision"] = "pass"
                with self.assertRaises(ValueError):
                    render_owner.render(result)

    def test_report_id_and_technical_details_collapsed_scope_visible(self):
        result = self.result()
        page = render_owner.render(result)
        report_id = result["snapshot"]["manifest_sha256"] + "@" + result["snapshot"]["checked_at"]
        self.assertIn(report_id, page)
        self.assertIn(report_id, render_report.render(result))
        marker = "<details><summary>Technical snapshot & exclusion details</summary>"
        details = page.split(marker, 1)[1].split("</details>", 1)[0]
        for label in ("Report ID", "Declared revision", "Scanned bytes", "Read bytes", "Recorded exclusions"):
            self.assertIn(label, details)
        self.assertNotIn("open", page.split("<details", 1)[1].split(">", 1)[0])
        visible_scope = page.split(marker, 1)[0]
        for label in ("Scanned files", "Skips", "Limits reached"):
            self.assertIn(label, visible_scope)

    def test_module_bars_have_labeled_units_and_shared_count_scale(self):
        page = render_owner.render(self.result(candidate=True))
        doc = Document(page)
        bars = [attrs for tag, attrs in doc.tags if tag == "span" and attrs.get("class", "").startswith("bar ")]
        self.assertEqual(len(bars), 15)
        self.assertEqual(sum(attrs["class"] == "bar unknown" for attrs in bars), 5)
        self.assertEqual(sum(attrs["class"] == "bar candidate" for attrs in bars), 5)
        self.assertEqual(sum(attrs["class"] == "bar error" for attrs in bars), 5)
        self.assertIn('style="width:50.00%"', page)
        self.assertIn("not a completion or safety ratio", page)
        self.assertIn("Gray: unknown controls; amber: unverified candidates", page)

    def test_action_task_ids_match_engineer_ordering_and_unassigned_roles(self):
        for has_error in (False, True):
            with self.subTest(error=has_error):
                result = self.result(candidate=True)
                if has_error:
                    error = self.result(error=True)["findings"][-1]
                    result["findings"].insert(3, error)
                    result["summary"]["counts"]["tool_error"] = 1
                    result["coverage"]["limits_reached"] = True
                page = render_owner.render(result)
                markdown = render_report.render(result)
                actions = page.split("<ol>", 1)[1].split("</ol>", 1)[0].split("<li>")[1:]
                self.assertLessEqual(len(actions), 3)
                self.assertIn("Engineer task IDs: T-001.", actions[0])
                if has_error:
                    self.assertIn("Engineer task IDs: T-002.", actions[1])
                for action in actions:
                    self.assertIn("unassigned", action)
                    refs = action.split("Engineer task IDs: ", 1)[1].split(".", 1)[0].split(", ")
                    for tid in refs:
                        self.assertIn("proposed task ID: " + tid, markdown)
                controls_start = 3 if has_error else 2
                expected = ", ".join(f"T-{index:03d}" for index in range(controls_start, controls_start + 6))
                self.assertIn("Engineer task IDs: " + expected, actions[2 if has_error else 1])

    def test_cli_roundtrip_and_no_overwrite(self):
        source = self.base / "result.json"
        encoded = json.dumps(self.result(candidate=True))
        source.write_text(encoded, encoding="utf-8")
        target = self.base / "owner.html"
        completed = self.cli(source, target)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        page = target.read_text(encoding="utf-8")
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertEqual(source.read_text(), encoded)
        self.assertEqual(self.cli(source, target).returncode, 2)
        self.assertEqual(target.read_text(), page)

    def test_cli_symlink_inputs_and_outputs_refused(self):
        source = self.base / "result.json"
        source.write_text(json.dumps(self.result()))
        linked_input = self.base / "linked.json"
        linked_input.symlink_to(source)
        target = self.base / "owner.html"
        self.assertEqual(self.cli(linked_input, target).returncode, 2)
        self.assertFalse(target.exists())
        for name, destination in (("existing.html", source), ("dangling.html", self.base / "absent")):
            with self.subTest(name=name):
                link = self.base / name
                link.symlink_to(destination)
                original = source.read_bytes()
                self.assertEqual(self.cli(source, link).returncode, 2)
                self.assertTrue(link.is_symlink())
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse((self.base / "absent").exists())

    def test_cli_bad_json_fake_pass_and_oversize_refused_without_leaks(self):
        source = self.base / "invalid.json"
        target = self.base / "owner.html"
        fake = self.result()
        fake["findings"][0]["status"] = "pass"
        secret = "sk_live_" + "SYNTHETICNOTREAL1234567890"
        for content in (secret, json.dumps(fake), "[" * 1100 + "0" + "]" * 1100,
                        " " * (render_owner.MAX_INPUT_BYTES + 1)):
            source.write_text(content)
            completed = self.cli(source, target)
            self.assertEqual(completed.returncode, 2)
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)
            self.assertFalse(target.exists())

    def test_cli_requires_existing_parent_and_both_arguments(self):
        source = self.base / "result.json"
        source.write_text(json.dumps(self.result()))
        target = self.base / "missing" / "owner.html"
        self.assertEqual(self.cli(source, target).returncode, 2)
        self.assertFalse(target.parent.exists())
        completed = subprocess.run([sys.executable, "-B", str(SCRIPTS / "render_owner.py"),
                                    "--input", str(source)], capture_output=True, check=False)
        self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
