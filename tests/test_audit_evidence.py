import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.audit_evidence import begin_audit, record_audit_review, require_audit, seal_audit
from hangover.model import load_state, paths, write_json
from hangover.oracles import prepare_review_packet
from hangover.repository import capture_patch


# The analyzer plan of the fixture's Python-only change (cli._analyzer_plan).
NOT_APPLICABLE = {"fallow": {"run": False, "status": "not_applicable"},
                  "rust": {"run": False, "status": "not_applicable"}}


class AuditEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        (self.repo / "source.py").write_text("value = 1\n")
        subprocess.run(["git", "-C", self.repo, "add", "source.py"], check=True)
        subprocess.run(["git", "-C", self.repo, "-c", "user.name=Hangover Test", "-c",
                        "user.email=fixture@example.invalid", "commit", "-qm", "baseline"], check=True)
        (self.repo / ".git/info/exclude").write_text(".hangover/\n")
        write_json(paths(self.repo)["config"], {"checks": [], "fallow": {"enabled": True}})
        self.version = patch("hangover.evidence.fallow_version", return_value="fallow 3.31.0")
        self.version.start()
        self.addCleanup(self.version.stop)
        (self.repo / "source.py").write_text("value = 2\n")

    def prepare(self, run="audit-one", *, seal=True):
        directory = paths(self.repo)["runs"] / run
        directory.mkdir(parents=True)
        pending = begin_audit(self.repo, run, "HEAD", False, None)
        snapshot = {"id": run, "kind": "audit", "base": pending["base"],
                    "repo": str(self.repo), "inventory": {"javascript": False, "typescript": False},
                    "diff_check": {"status": "passed"}, "checks": [],
                    "fallow": {"status": "not_applicable", "verdict": None}}
        write_json(directory / "snapshot.json", snapshot)
        capture_patch(self.repo, directory / "after.patch", base=pending["base"])
        prepare_review_packet(self.repo, directory, "prevention", snapshot,
                              after_patch=directory / "after.patch", verification_token=pending["token"])
        return seal_audit(self.repo, pending, None, NOT_APPLICABLE) if seal else pending

    def verdict(self, proof):
        return {"verdict": "pass", "summary": "Synthetic protocol test, not model review.",
                "findings": [], "declared_changes_assessed": [], "reviewed_files": ["source.py"],
                "verification_token": proof["token"]}

    def finding(self, priority="P2"):
        return {"category": "behavior_regression", "title": "A concrete defect",
                "evidence": ["The fixture changed the value"], "files": ["source.py"], "symbols": [],
                "harm": "A result changed", "proposed_change": "Restore the contract",
                "invariants": ["The result stays compatible"], "verification": ["Run the focused check"],
                "chesterton": "The value is required", "risk": "medium", "priority": priority, "confidence": "high"}

    def test_prevention_review_cannot_pass_with_a_blocking_finding_or_fail_without_an_action(self):
        for index, update in enumerate(({"findings": [self.finding("P1")]}, {"verdict": "fail"})):
            proof = self.prepare("audit-verdict-" + str(index))
            review = {**self.verdict(proof), **update}
            with self.subTest(verdict=review["verdict"]), self.assertRaises(RuntimeError):
                record_audit_review(self.repo, proof, review, "review-one", None)

    def test_partial_review_never_consumes_audit_proof(self):
        proof = self.prepare()
        review = {**self.verdict(proof), "verdict": "partial", "summary": "Other cited locations remain."}
        with self.assertRaisesRegex(RuntimeError, "invalid for prevention"):
            record_audit_review(self.repo, proof, review, "partial-review", None)
        pending = require_audit(self.repo, "HEAD", False, None)
        self.assertEqual(proof, pending)
        self.assertFalse(pending["consumed"])
        self.assertFalse((paths(self.repo)["runs"] / "partial-review/review.json").exists())
        self.assertTrue(record_audit_review(self.repo, pending, self.verdict(pending), "fresh-review", None))

    def test_failed_review_preserves_pending_evidence_for_an_explicit_fresh_review(self):
        proof = self.prepare()
        review = {**self.verdict(proof), "verdict": "fail", "findings": [self.finding()]}
        self.assertFalse(record_audit_review(self.repo, proof, review, "failed-review", None))
        pending = require_audit(self.repo, "HEAD", False, None)
        self.assertFalse(pending["consumed"])
        self.assertEqual(proof["artifacts"], pending["artifacts"])
        self.assertTrue(record_audit_review(self.repo, pending, self.verdict(pending), "fresh-review", None))

    def test_prevention_cannot_accept_an_unissued_behavior_change_note(self):
        proof = self.prepare()
        review = {**self.verdict(proof), "declared_changes_assessed": [
            {"note_id": "not-issued", "note": "Change the contract", "verdict": "accepted", "evidence": ["An unissued claim"]}]}
        with self.assertRaisesRegex(RuntimeError, "issued note_id"):
            record_audit_review(self.repo, proof, review, "review-one", None)

    def test_whole_change_proof_needs_no_fake_remediation_and_is_single_use(self):
        proof = self.prepare()
        self.assertEqual(proof, require_audit(self.repo, "HEAD", False, None))
        self.assertIsNone(load_state(self.repo)["active_issue"])
        self.assertTrue(record_audit_review(self.repo, proof, self.verdict(proof), "review-one", None))
        with self.assertRaises(RuntimeError):
            record_audit_review(self.repo, proof, self.verdict(proof), "review-again", None)
        state = load_state(self.repo)
        self.assertTrue(state["audit_reviews"][proof["id"]]["consumed"])
        self.assertIsNone(state["pending_audit_review"])
        self.assertEqual(self.verdict(proof), json.loads((paths(self.repo)["runs"] / "review-one/review.json").read_text()))

    def test_a_proof_copied_to_another_repository_is_not_its_receipt(self):
        self.prepare()
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "clone"
            shutil.copytree(self.repo, clone)
            state = json.loads(paths(clone)["state"].read_text())
            state["repo"] = str(clone)  # The receiving campaign is valid; only the receipt is foreign.
            write_json(paths(clone)["state"], state)
            with self.assertRaisesRegex(RuntimeError, "audit inputs"):
                require_audit(clone, "HEAD", False, None)

    def test_symlinked_evidence_is_refused_even_when_its_bytes_match(self):
        proof = self.prepare()
        artifact = paths(self.repo)["runs"] / proof["run"] / "review-context.json"
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "context.json"
            outside.write_bytes(artifact.read_bytes())
            artifact.unlink()
            artifact.symlink_to(outside)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                require_audit(self.repo, "HEAD", False, None)

    def test_source_policy_and_requested_check_scope_changes_invalidate_the_proof(self):
        proof = self.prepare()
        with self.assertRaises(RuntimeError):
            require_audit(self.repo, "HEAD", True, None)
        source = self.repo / "source.py"
        source.write_text("unchecked = 3\n")
        with self.assertRaises(RuntimeError):
            require_audit(self.repo, "HEAD", False, None)
        source.write_text("value = 2\n")
        write_json(paths(self.repo)["config"], {"checks": [{"name": "changed", "command": ["false"]}], "fallow": {"enabled": True}})
        with self.assertRaises(RuntimeError):
            record_audit_review(self.repo, proof, self.verdict(proof), "review-one", None)

    def test_different_base_cannot_reuse_an_otherwise_identical_tree(self):
        self.prepare()
        subprocess.run(["git", "-C", self.repo, "-c", "user.name=Hangover Test", "-c",
                        "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "new base"], check=True)
        with self.assertRaises(RuntimeError):
            require_audit(self.repo, "HEAD", False, None)

    def test_new_audit_supersedes_old_work_before_running_gates(self):
        old = self.prepare()
        new = self.prepare("audit-two", seal=False)
        with self.assertRaises(RuntimeError):
            record_audit_review(self.repo, old, self.verdict(old), "old-review", None)
        with self.assertRaises(RuntimeError):
            require_audit(self.repo, "HEAD", False, None)
        self.assertEqual("checking", load_state(self.repo)["audit_reviews"][new["id"]]["status"])
        seal_audit(self.repo, new, None, NOT_APPLICABLE)
        with self.assertRaises(RuntimeError):
            record_audit_review(self.repo, old, self.verdict(old), "old-review", None)

    def test_input_changes_during_audit_cannot_be_sealed(self):
        pending = self.prepare(seal=False)
        (self.repo / "source.py").write_text("changed during audit\n")
        with self.assertRaises(RuntimeError):
            seal_audit(self.repo, pending, None, NOT_APPLICABLE)

    def test_failed_or_incomplete_gate_cannot_be_sealed(self):
        pending = self.prepare(seal=False)
        snapshot_path = paths(self.repo)["runs"] / pending["run"] / "snapshot.json"
        original = json.loads(snapshot_path.read_text())
        fallow_planned = {**NOT_APPLICABLE, "fallow": {"run": True}}
        for update, plan in (({"diff_check": {"status": "failed"}}, NOT_APPLICABLE),
                             ({"checks": [{"name": "gate", "status": "timeout"}]}, NOT_APPLICABLE),
                             ({"inventory": {"typescript": True}, "fallow": {"status": "unavailable"}}, fallow_planned),
                             ({"fallow": {"status": "completed", "verdict": "fail"}}, fallow_planned)):
            with self.subTest(update=update):
                write_json(snapshot_path, {**original, **update})
                with self.assertRaises(RuntimeError):
                    seal_audit(self.repo, pending, None, plan)

    def test_every_prepared_artifact_and_raw_gate_log_is_bound(self):
        for index, name in enumerate(("snapshot.json", "after.patch", "review-packet.json", "review-prompt.md", "review-context.json", "review-schema.json", "checks/gate.log")):
            with self.subTest(name=name):
                run = "audit-" + str(index)
                pending = self.prepare(run, seal=False)
                path = paths(self.repo)["runs"] / run / name
                path.parent.mkdir(exist_ok=True)
                if not path.exists():
                    path.write_text("original log")
                proof = seal_audit(self.repo, pending, None, NOT_APPLICABLE)
                path.write_text("changed artifact")
                with self.assertRaises(RuntimeError):
                    require_audit(self.repo, "HEAD", False, None, expected=proof)

    def test_missing_artifact_wrong_token_and_changed_tool_identity_are_refused(self):
        proof = self.prepare()
        wrong = {**self.verdict(proof), "verification_token": "wrong"}
        with self.assertRaises(RuntimeError):
            record_audit_review(self.repo, proof, wrong, "review-one", None)
        with patch("hangover.evidence.fallow_version", return_value="changed analyzer"):
            with self.assertRaises(RuntimeError):
                require_audit(self.repo, "HEAD", False, None)
        (paths(self.repo)["runs"] / proof["run"] / "review-context.json").unlink()
        with self.assertRaises(RuntimeError):
            require_audit(self.repo, "HEAD", False, None)
