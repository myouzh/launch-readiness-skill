"""Detailed Markdown traceability checks using synthetic inert snapshots."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan
import render_report


class TraceTests(unittest.TestCase):
    def test_unique_finding_tasks_and_real_evidence_refs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.env").write_text("sk_live_" + "SYNTHETICNOTREAL1234567890")
            (root / "b.env").write_text("sk_live_" + "SYNTHETICNOTREAL1234567890")
            result = scan.collect(root)
        original = copy.deepcopy(result)
        report = render_report.render(result)
        self.assertEqual(result, original)
        self.assertIn(result["snapshot"]["manifest_sha256"] + "@" + result["snapshot"]["checked_at"], report)
        candidates = [f for f in result["findings"] if f["status"] == "fail"]
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0]["rule_id"], candidates[1]["rule_id"])
        ordered = candidates + [f for f in result["findings"] if f["status"] == "tool_error"] + [f for f in result["findings"] if f["status"] not in {"fail", "tool_error"}]
        for index, finding in enumerate(ordered, 1):
            self.assertEqual(report.count(f"### F-{index:03d} —"), 1)
            self.assertIn(f"proposed task ID: T-{index:03d}", report)
            for ei, evidence in enumerate(finding["evidence"], 1):
                self.assertIn(f"Evidence E-{index:03d}-{ei:02d}: {render_report.text(evidence['path'])}, line {evidence['line']}", report)
        self.assertEqual(report.count("Closure gate:"), len(ordered))
        self.assertEqual(report.count("Acceptance / retest evidence required:"), len(ordered))
        self.assertEqual(report.count("snapshot_checked_at:"), len(ordered))
        self.assertNotIn("SYNTHETICNOTREAL1234567890", report)
        self.assertIn("no dynamic reproduction", report)
        self.assertIn("no pass inferred", report)


if __name__ == "__main__":
    unittest.main()
