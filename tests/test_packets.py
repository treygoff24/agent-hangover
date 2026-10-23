import copy
import json
import tempfile
import unittest
from pathlib import Path

from hangover.packets import REVIEW_ARTIFACTS, compact_fix_packet, compact_review_issue, fix_packet
from hangover.oracles import _delegate_prompt, _validate_review, prepare_review_packet, TOOL_ROOT


class PacketTests(unittest.TestCase):
    def test_manual_review_gets_a_named_run_local_schema_inside_its_artifact_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet_path = prepare_review_packet(root, root / "run", "initial", {})
            schema = packet_path.parent / "review-schema.json"
            self.assertTrue(schema.is_file())
            self.assertEqual(json.loads((TOOL_ROOT / "schemas/review.schema.json").read_text()), json.loads(schema.read_text()))
            packet = json.loads(packet_path.read_text())
            self.assertEqual(str(schema), packet["review_schema"])
            prompt = (packet_path.parent / "review-prompt.md").read_text()
            self.assertIn(f"Review schema: {schema}", prompt)
            self.assertIn("review-schema.json", REVIEW_ARTIFACTS)

    def test_fix_packet_differs_only_in_finish_rule_and_extras(self):
        member = {"id": "dslp-0000000001", "fix_dir": "d", "title": "t"}
        state = {"baseline_run": "b", "latest_run": "l"}
        started = fix_packet(state, "/repo", member, [member], "base", "/b.patch", "Finish with X.")
        handed = fix_packet(state, "/repo", member, [member], "base", None, "Hand back.", activated=False)
        self.assertEqual("Finish with X.", started["rules"][-1])
        self.assertEqual("Hand back.", handed["rules"][-1])
        self.assertEqual(started["rules"][:-1], handed["rules"][:-1])
        self.assertNotIn("activated", started)
        self.assertIs(handed["activated"], False)
        self.assertEqual(("b", "l", "base"), (handed["baseline_run"], handed["latest_run"], handed["fix_base_commit"]))
        # An unactivated card has no remediation fields; compacting must not require them.
        self.assertEqual({"fix_dir": "d"}, compact_fix_packet(handed)["remediation"])

    def batch(self):
        shared = {"fix_dir": "/repo/.hangover/fixes/one", "fix_base_commit": "base",
                  "fix_notes": [{"id": "note-one", "text": "CLAIM-" * 1000}],
                  "fix_finding_ids": [f"dslp-{n:010x}" for n in range(100)],
                  "waivers": [{"id": "waived", "reason": "explicit acceptance"}]}
        return [{"id": f"dslp-{n:010x}", "status": "in_progress", "title": f"Claim {n}",
                 "evidence": [f"evidence {n}"], "invariants": [f"invariant {n}"],
                 "harm": f"harm {n}", "proposed_change": f"change {n}",
                 "history": [{"event": "old review", "verdict": "PRIOR-VERDICT" * 1000}],
                 **copy.deepcopy(shared)} for n in range(20)]

    def test_fix_packet_keeps_complete_contracts_and_shared_facts_once(self):
        members = self.batch()
        original = {"issue": members[0], "issues": members, "latest_run": "scan-1"}
        before = copy.deepcopy(original)
        packet = compact_fix_packet(original)
        self.assertEqual(before, original)
        self.assertEqual("scan-1", packet["latest_run"])
        self.assertEqual(members[0]["fix_notes"], packet["remediation"]["fix_notes"])
        self.assertEqual(members[0]["fix_dir"], packet["issue"]["fix_dir"])
        self.assertEqual([m["id"] for m in members], [m["id"] for m in packet["issues"]])
        for raw, member in zip(members, packet["issues"]):
            for field in ("evidence", "invariants", "harm", "proposed_change"):
                self.assertEqual(raw[field], member[field])
            self.assertNotIn("fix_notes", member)
            self.assertNotIn("history", member)
        self.assertLess(len(json.dumps(packet)), len(json.dumps(original)) // 10)

    def test_review_primary_and_companions_never_repeat_shared_notes_or_prior_verdicts(self):
        members = self.batch()
        issue, remediation = compact_review_issue({**members[0], "batch_issues": members})
        self.assertEqual(members[0]["id"], issue["id"])
        self.assertEqual(members[0]["fix_base_commit"], issue["fix_base_commit"])
        self.assertEqual([m["id"] for m in members[1:]], [m["id"] for m in issue["batch_issues"]])
        self.assertNotIn("fix_notes", remediation)  # top-level implementer_notes is its sole owner
        text = json.dumps([issue, remediation])
        self.assertNotIn("PRIOR-VERDICT", text)
        self.assertNotIn("CLAIM-", text)
        self.assertEqual(members[0]["waivers"], remediation["waivers"])

    def test_review_packet_retains_full_context_but_delivers_only_current_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            members = self.batch()
            original = {**members[0], "batch_issues": members}
            path = prepare_review_packet(root, root, "post_fix", {"id": "scan-one"}, original)
            packet = json.loads(path.read_text())
            self.assertTrue("PRIOR-VERDICT" not in path.read_text(), "prior verdict leaked into review input")
            self.assertEqual(original, json.loads((root / "review-context.json").read_text())["issue"])
            self.assertEqual(members[0]["fix_notes"], packet["implementer_notes"])
            self.assertEqual(path.stat().st_size, packet["evidence"]["packet_bytes"])
            self.assertTrue(packet["evidence"]["contracts_complete"])
            self.assertIn("not a review input", packet["evidence"]["retained_context_purpose"])

    def test_initial_packet_names_scope_and_does_not_claim_exhaustive_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("a = 1\n")
            path = prepare_review_packet(root, root / ".hangover/run", "initial", {})
            packet = json.loads(path.read_text())
            self.assertIsNone(packet["review_scope"]["files"])
            self.assertEqual(1, packet["review_scope"]["selected_count"])
            self.assertEqual(["a.py"], json.loads((path.parent / "review-context.json").read_text())["review_scope"]["files"])
            prompt = (path.parent / "review-prompt.md").read_text()
            self.assertIn("reviewed_files", prompt)
            self.assertIn("not exhaustive", prompt)

    def test_scoped_packet_does_not_inline_the_unselected_repository_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = {"kind": "selected", "requested": ["a.py"], "files": ["a.py"],
                     "unselected_files": [f"elsewhere/{n}.py" for n in range(10000)], "finding_limit": 12}
            path = prepare_review_packet(root, root / "run", "initial", {}, review_scope=scope)
            packet = json.loads(path.read_text())
            self.assertEqual(["a.py"], packet["review_scope"]["files"])
            self.assertEqual(10000, packet["review_scope"]["unselected_count"])
            self.assertNotIn("unselected_files", packet["review_scope"])
            self.assertLess(path.stat().st_size, 4096)
            self.assertEqual(scope, json.loads((path.parent / "review-context.json").read_text())["review_scope"])

    def test_delegate_does_not_hide_unavailable_packet_or_patch_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet = root / "review-packet.json"
            schema = TOOL_ROOT / "schemas/review.schema.json"
            with self.assertRaises(RuntimeError):
                _delegate_prompt("Review.", schema, packet)
            packet.write_text(json.dumps({"after_patch": str(root / "missing.patch")}))
            with self.assertRaises(RuntimeError):
                _delegate_prompt("Review.", schema, packet)

    def test_reviewer_can_report_inspected_files_without_claiming_completeness(self):
        _validate_review({"verdict": "reviewed", "summary": "Scoped inspection.",
                          "findings": [], "reviewed_files": ["src/a.py"]}, "initial")
        for value in ("src/a.py", [1], [""]):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                _validate_review({"verdict": "reviewed", "summary": "Scope.",
                                  "findings": [], "reviewed_files": value}, "initial")
