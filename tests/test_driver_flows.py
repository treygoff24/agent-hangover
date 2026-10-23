import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import test_cli as fixtures
from test_cli import packet_token_runner
from hangover.cli import main
from hangover.model import load_state, next_issue, paths
from hangover.repository import _definition_digest


class DriverFlowTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.CliTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.repo = self.case.repo

    def invoke_json(self, *arguments):
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(StringIO()):
            try:
                code = main(["--repo", str(self.repo), *arguments, "--json"])
            except SystemExit as exc:
                code = exc.code
        return code, json.loads(output.getvalue())

    def test_fix_and_resume_use_compact_packets_without_rewriting_evidence(self):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        code, started = self.invoke_json("fix", identifier)
        self.assertEqual(0, code)
        packet = started["data"]["packet"]
        self.assertEqual(2, packet["schema_version"])
        self.assertEqual({"id", "fix_dir"}, set(packet["issue"]))
        directory = Path(packet["issue"]["fix_dir"])
        context = (directory / "fix-context.json").read_bytes()
        self.assertIn("history", json.loads(context)["issue"])
        (self.repo / "src/dead.ts").unlink()
        self.assertEqual(0, self.case.invoke("verify", "--no-review", "--note", "A fixture claim"))
        before = paths(self.repo)["state"].read_bytes()
        code, resumed = self.invoke_json("fix", identifier)
        self.assertEqual(0, code)
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        self.assertEqual(context, (directory / "fix-context.json").read_bytes())
        compact = resumed["data"]["packet"]
        self.assertTrue(resumed["data"]["resumed"])
        self.assertEqual("A fixture claim", compact["remediation"]["fix_notes"][0]["text"])
        self.assertTrue(all("history" not in issue and "fix_notes" not in issue for issue in compact["issues"]))

    def test_next_json_is_a_selection_projection_not_a_history_dump(self):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        code, result = self.invoke_json("next")
        self.assertEqual(0, code)
        self.assertNotIn("history", result["data"]["issue"])
        self.assertEqual(0, self.case.invoke("fix", result["issue_id"]))
        code, active = self.invoke_json("next")
        self.assertEqual(0, code)
        self.assertNotIn("history", active["data"]["issue"])

    def test_scoped_prepare_keeps_scope_in_the_import_action(self):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        code, result = self.invoke_json("review", "--scope", "src/index.ts", "--prepare")
        self.assertEqual(0, code)
        action = shlex.split(result["next_action"])
        self.assertIn("--scope", action)
        self.assertEqual("src/index.ts", action[action.index("--scope") + 1])

    def test_scoped_import_records_honest_coverage_before_merging_findings(self):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        output = paths(self.repo)["root"] / "scope-verdict.json"
        output.write_text(json.dumps({"verdict": "reviewed", "summary": "A synthetic scoped review.",
                                      "findings": [], "reviewed_files": ["src/index.ts"]}))
        code, result = self.invoke_json("review", "--scope", "src/index.ts", "--import", str(output))
        self.assertEqual(0, code)
        coverage = json.loads(Path(result["artifacts"]["coverage"]).read_text())
        self.assertEqual(["src/index.ts"], coverage["coverage"]["reported_files"])
        self.assertFalse(coverage["coverage"]["exhaustive"])
        self.assertIn("src/dead.ts", coverage["coverage"]["unselected_files"])
        summary = result["data"]["review"]["coverage"]
        self.assertEqual(1, summary["reported_count"])
        self.assertNotIn("unselected_files", summary)

    def test_invalid_scope_or_unreported_coverage_cannot_merge_a_review(self):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        output = paths(self.repo)["root"] / "scope-verdict.json"
        before = load_state(self.repo)["issues"]
        for reported in (None, ["src/dead.ts"]):
            review = {"verdict": "reviewed", "summary": "Synthetic scope claim.", "findings": []}
            if reported is not None:
                review["reviewed_files"] = reported
            output.write_text(json.dumps(review))
            with self.subTest(reported=reported):
                code, result = self.invoke_json("review", "--scope", "src/index.ts", "--import", str(output))
                self.assertEqual(2, code)
                self.assertEqual("tool_error", result["state"])
                self.assertEqual(before, load_state(self.repo)["issues"])

    def test_post_fix_cannot_narrow_its_scope(self):
        identifier = self.case._ready_fix_for_preflight()
        self.assertEqual(0, self.case.invoke("verify", "--no-review"))
        with patch("hangover.cli.run_codex_review", side_effect=AssertionError("ran reviewer")):
            code, result = self.invoke_json("review", "--issue", identifier, "--scope", "src", "--prepare")
        self.assertEqual(2, code)
        self.assertIn("scope", " ".join(result["blockers"]))

    def verified(self):
        identifier = self.case._ready_fix_for_preflight()
        self.assertEqual(0, self.case.invoke("verify", "--no-review"))
        state = load_state(self.repo)
        return identifier, state["remediations"][state["active_remediation"]]["verification"]

    def test_retry_reuses_exact_proof_and_records_a_fresh_review_attempt(self):
        identifier, proof = self.verified()
        with patch("hangover.cli._scan", side_effect=AssertionError("retry ran the gate")):
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "none")
        self.assertEqual(0, code)
        self.assertEqual("review_pending", result["state"])
        self.assertEqual(proof["id"], result["proof"])
        self.assertEqual(proof["run"], result["run"])
        self.assertEqual("reused", result["data"]["deterministic"])
        state = load_state(self.repo)
        record = state["remediations"][state["active_remediation"]]
        self.assertEqual(proof, record["verification"])
        self.assertEqual(result["review_run"], record["pending_review"]["id"])
        self.assertTrue(any(event["event"] == "review_retry" for event in state["history"]))

    def test_stale_retry_reports_its_proof_and_a_full_verify_action(self):
        identifier, proof = self.verified()
        (self.repo / "src/index.ts").write_text("export const live = 99;\n")
        with patch("hangover.cli._scan", side_effect=AssertionError("stale retry ran gates")):
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "none")
        self.assertEqual(2, code)
        self.assertEqual("tool_error", result["state"])
        self.assertEqual(proof["id"], result["proof"])
        self.assertEqual("not_checked", result["proof_freshness"])
        self.assertIn("verify", shlex.split(result["next_action"]))
        self.assertNotIn("--retry-review", result["next_action"])

    def test_retry_refuses_notes_waivers_and_skipping_review(self):
        _, proof = self.verified()
        for flags in (("--note", "new claim"), ("--no-review",), ("--accept-reason", "new policy")):
            with self.subTest(flags=flags):
                code, result = self.invoke_json("verify", "--retry-review", *flags)
                self.assertEqual(2, code)
                self.assertIn("cannot combine", " ".join(result["blockers"]))
        state = load_state(self.repo)
        self.assertEqual(proof, state["remediations"][state["active_remediation"]]["verification"])

    def test_next_suggests_validating_a_recorded_proof_for_review_only_retry(self):
        self.verified()
        code, result = self.invoke_json("next")
        self.assertEqual(0, code)
        self.assertIn("--retry-review", shlex.split(result["next_action"]))
        self.assertEqual("not_checked", result["proof_freshness"])

    def test_retry_cannot_adopt_a_concurrent_verifications_new_proof(self):
        from hangover.cli import _review
        identifier, proof = self.verified()

        def interleaved(*args, **kwargs):
            self.assertEqual(0, self.case.invoke("verify", "--no-review"))
            return _review(*args, **kwargs)

        with patch("hangover.cli._review", side_effect=interleaved):
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "none")
        self.assertEqual(2, code)
        self.assertEqual(proof["id"], result["proof"])
        state = load_state(self.repo)
        record = state["remediations"][state["active_remediation"]]
        self.assertNotEqual(proof["id"], record["verification"]["id"])
        self.assertIsNone(record["pending_review"])
        self.assertEqual("in_progress", state["issues"][identifier]["status"])

    def test_retry_can_explicitly_change_reviewer_route_and_resolve(self):
        _, proof = self.verified()
        review = {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic protocol review.", "findings": []}
        with patch("hangover.cli._scan", side_effect=AssertionError("retry ran gate")), patch(
            "hangover.cli.run_delegate_review", side_effect=packet_token_runner({"status": "completed", "review": review})
        ) as runner:
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "delegate", "--lane", "claude")
        self.assertEqual(0, code)
        self.assertEqual("resolved", result["state"])
        self.assertEqual(proof["run"], result["run"])
        self.assertEqual("claude", runner.call_args.kwargs["lane"])
        self.assertEqual("delegate", result["data"]["review"]["runner"])

    def prepared_audit(self, full=False):
        self.assertEqual(0, self.case.invoke("init"))
        (self.repo / "src/dead.ts").unlink()
        flags = ["--full"] if full else []
        code, result = self.invoke_json("audit", "--require-review", "--prepare", *flags)
        self.assertEqual(0, code)
        self.assertEqual("review_pending", result["state"])
        packet = json.loads(Path(result["artifacts"]["review_packet"]).read_text())
        self.assertEqual("prevention", packet["mode"])
        self.assertTrue(packet["change"]["base"])
        self.assertEqual(full, packet["change"]["full_gate"])
        self.assertEqual("full" if full else "all_no_quick_checks", packet["change"]["check_selection"])
        output = paths(self.repo)["root"] / "audit-verdict.json"
        output.write_text(json.dumps({"verdict": "pass", "summary": "Synthetic whole-change verdict.",
                                      "findings": [], "declared_changes_assessed": [], "reviewed_files": ["src/dead.ts"],
                                      "verification_token": packet["verification_token"]}))
        return output, result

    def test_audit_import_reuses_the_original_gate_and_consumes_once(self):
        output, prepared = self.prepared_audit()
        with patch("hangover.cli.run_fallow_audit", side_effect=AssertionError("import reran analyzer")), patch(
            "hangover.cli.run_checks", side_effect=AssertionError("import reran gate")
        ):
            code, result = self.invoke_json("audit", "--require-review", "--import", str(output))
            self.assertEqual(0, code)
            self.assertEqual("passed", result["state"])
            self.assertEqual(prepared["run"], result["run"])
            self.assertEqual(prepared["proof"], result["proof"])
            code, replay = self.invoke_json("audit", "--require-review", "--import", str(output))
            self.assertEqual(2, code)
            self.assertEqual("tool_error", replay["state"])

    def test_audit_import_refuses_missing_inspected_files_without_consuming_proof(self):
        output, prepared = self.prepared_audit()
        verdict = json.loads(output.read_text())
        verdict.pop("reviewed_files")
        output.write_text(json.dumps(verdict))
        code, result = self.invoke_json("audit", "--require-review", "--import", str(output))
        self.assertEqual(2, code)
        self.assertEqual("tool_error", result["state"])
        self.assertIn("reviewed_files", " ".join(result["blockers"]))
        state = load_state(self.repo)
        self.assertFalse(state["audit_reviews"][prepared["proof"]]["consumed"])

    def test_audit_import_refuses_source_drift_without_adopting_a_new_run(self):
        output, prepared = self.prepared_audit()
        (self.repo / "src/index.ts").write_text("export const live = 999;\n")
        with patch("hangover.cli.run_fallow_audit", side_effect=AssertionError("stale import ran analysis")):
            code, result = self.invoke_json("audit", "--require-review", "--import", str(output))
        self.assertEqual(2, code)
        self.assertEqual(prepared["run"], result["run"])
        self.assertEqual("not_checked", result["proof_freshness"])

    def test_reviewed_audit_honours_a_disabled_fallow_through_import(self):
        self.assertEqual(0, self.case.invoke("init"))
        config = json.loads(paths(self.repo)["config"].read_text())
        config["fallow"] = {**config.get("fallow", {}), "enabled": False}
        paths(self.repo)["config"].write_text(json.dumps(config))
        (self.repo / "src/dead.ts").unlink()
        with patch("hangover.cli.run_fallow_audit", side_effect=AssertionError("audit ran a disabled Fallow")):
            code, plain = self.invoke_json("audit")
            self.assertEqual(0, code, plain)
            code, result = self.invoke_json("audit", "--require-review", "--prepare")
            self.assertEqual(0, code, result)
            self.assertEqual("review_pending", result["state"])
            packet = json.loads(Path(result["artifacts"]["review_packet"]).read_text())
            output = paths(self.repo)["root"] / "audit-verdict.json"
            output.write_text(json.dumps({"verdict": "pass", "summary": "Synthetic whole-change verdict.",
                                          "findings": [], "declared_changes_assessed": [],
                                          "reviewed_files": ["src/dead.ts"],
                                          "verification_token": packet["verification_token"]}))
            code, imported = self.invoke_json("audit", "--require-review", "--import", str(output))
        self.assertEqual(0, code, imported)
        self.assertEqual("passed", imported["state"])
        self.assertEqual(result["proof"], imported["proof"])

    def test_audit_prepare_action_keeps_the_full_gate_selection(self):
        _, prepared = self.prepared_audit(full=True)
        action = shlex.split(prepared["next_action"])
        self.assertIn("--full", action)
        self.assertIn("--require-review", action)
        self.assertIn("--repo", action)

    def test_audit_review_options_need_an_explicit_opt_in(self):
        with patch("hangover.cli.run_fallow_audit", side_effect=AssertionError("invalid arguments ran analyzer")):
            code, result = self.invoke_json("audit", "--prepare")
        self.assertEqual(2, code)
        self.assertIn("--require-review", " ".join(result["blockers"]))

    def test_automatic_reviewed_audit_uses_the_sealed_prompt_and_records_a_pass(self):
        self.assertEqual(0, self.case.invoke("init"))
        (self.repo / "src/dead.ts").unlink()
        def review(repo, directory, packet_path, mode, timeout, **kwargs):
            packet = json.loads(packet_path.read_text())
            self.assertEqual("prevention", mode)
            self.assertNotEqual(directory, packet_path.parent)
            self.assertEqual(packet_path.parent / "review-prompt.md", kwargs["prompt_path"])
            return {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic review.", "findings": [],
                    "verification_token": packet["verification_token"]}}
        with patch("hangover.cli.run_codex_review", side_effect=review):
            code, result = self.invoke_json("audit", "--require-review")
        self.assertEqual(0, code)
        self.assertEqual("passed", result["state"])
        self.assertTrue(result["proof"])

    def test_failed_retry_action_preserves_the_selected_reviewer(self):
        self.verified()
        with patch("hangover.cli.run_delegate_review", side_effect=packet_token_runner({"status": "failed", "error": "fixture transport failure"})):
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "delegate", "--lane", "claude")
        self.assertEqual(2, code)
        action = shlex.split(result["next_action"])
        self.assertEqual("delegate", action[action.index("--runner") + 1])
        self.assertEqual("claude", action[action.index("--lane") + 1])
        self.assertIn("--retry-review", action)

    def test_a_reported_engine_change_after_preflight_is_an_error_not_an_approval(self):
        identifier, _ = self.verified()
        with patch("hangover.cli.run_delegate_review", side_effect=packet_token_runner({
            "status": "completed", "reported_route": {"engine": "unexpected-engine"},
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic mismatched route.", "findings": []}
        })):
            code, result = self.invoke_json("verify", "--retry-review", "--runner", "delegate", "--lane", "claude")
        self.assertEqual(2, code)
        self.assertEqual("tool_error", result["state"])
        self.assertIn("changed after preflight", " ".join(result["blockers"]))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_blocked_audit_does_not_drop_prepare_full_or_review_opt_in(self):
        self.assertEqual(0, self.case.invoke("init"))
        config = paths(self.repo)["config"]
        value = json.loads(config.read_text())
        value["checks"] = [{"name": "test", "command": ["/bin/sh", "-c", "exit 1"]}]
        config.write_text(json.dumps(value))
        code, result = self.invoke_json("audit", "--require-review", "--prepare", "--full", "--runner", "delegate", "--lane", "claude")
        self.assertEqual(1, code)
        self.assertEqual("blocked", result["state"])
        action = shlex.split(result["next_action"])
        for flag in ("--require-review", "--prepare", "--full"):
            self.assertIn(flag, action)
        self.assertEqual("claude", action[action.index("--lane") + 1])

    def test_default_audit_recovery_cannot_drop_a_failing_full_gate(self):
        self.assertEqual(0, self.case.invoke("init"))
        config = paths(self.repo)["config"]
        value = json.loads(config.read_text())
        value["checks"] = [{"name": "test", "command": ["/bin/sh", "-c", "exit 1"]}]
        config.write_text(json.dumps(value))
        code, result = self.invoke_json("audit", "--full")
        self.assertEqual(1, code)
        self.assertIn("--full", shlex.split(result["next_action"]))

    def test_failed_audit_runner_keeps_evidence_and_offers_a_no_gate_manual_import(self):
        self.assertEqual(0, self.case.invoke("init"))
        (self.repo / "src/dead.ts").unlink()
        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner({"status": "timeout", "error": "fixture timeout"})):
            code, result = self.invoke_json("audit", "--require-review")
        self.assertEqual(2, code)
        action = shlex.split(result["next_action"])
        self.assertIn("--import", action)
        self.assertEqual("manual-review.json", Path(action[action.index("--import") + 1]).name)
        self.assertEqual(result["data"]["base"], action[action.index("--base") + 1])
        self.assertEqual("not_checked", result["proof_freshness"])

    def test_a_copy_of_failed_audit_runner_output_cannot_be_imported(self):
        self.assertEqual(0, self.case.invoke("init"))
        (self.repo / "src/dead.ts").unlink()

        def failing(repo, directory, packet_path, mode, timeout, **kwargs):
            packet = json.loads(packet_path.read_text())
            (directory / "review.json").write_text(json.dumps({
                "reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Transport died after writing.",
                "findings": [], "verification_token": packet["verification_token"]}))
            return {"status": "failed", "error": "fixture transport failure", "output": str(directory / "review.json")}

        with patch("hangover.cli.run_codex_review", side_effect=failing):
            code, result = self.invoke_json("audit", "--require-review")
        self.assertEqual(2, code)
        manual = Path(shlex.split(result["next_action"])[shlex.split(result["next_action"]).index("--import") + 1])
        failed = manual.with_name("review.json")
        self.assertTrue(failed.is_file())
        manual.write_text(json.dumps(json.loads(failed.read_text()), indent=2))
        code, result = self.invoke_json("audit", "--require-review", "--import", str(manual))
        self.assertEqual(2, code)
        self.assertIn("failed runner output", " ".join(result["blockers"]))
        verdict = json.loads(failed.read_text())
        verdict["summary"] = "Fresh manual review."
        manual.write_text(json.dumps(verdict))
        code, result = self.invoke_json("audit", "--require-review", "--import", str(manual))
        self.assertEqual(0, code)
        self.assertEqual("passed", result["state"])


class GateCostTests(unittest.TestCase):
    """verify spends the cheap evidence first and the gate at most once per tree."""

    def setUp(self):
        self.case = fixtures.CliTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.repo = self.case.repo
        self.scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def stage(self, name, *, fail_flag=None, narrow=False, chain=False):
        """A check that appends to a per-stage run log and fails while its flag file exists."""
        log = self.scratch / f"{name}.runs"
        flag = self.scratch / (fail_flag or f"{name}.fail")
        script = (
            f"import pathlib,sys; open({str(log)!r},'a').write('x'); "
            f"print('{name}: boom ' + 'detail ' * 12) if pathlib.Path({str(flag)!r}).exists() else None; "
            f"sys.exit(1 if pathlib.Path({str(flag)!r}).exists() else 0)"
        )
        check = {"name": name, "command": [sys.executable, "-c", script], "timeout_seconds": 60}
        if narrow:
            check["narrow"] = True
        if chain:
            # A declared chain (adopted stages): verify stops at its first blocking stage.
            check["stage_of"] = "gate"
            check["adopted_from"] = {"script": "gate", "sha256": _definition_digest(Path("."), {}, "gate")}
        return check

    def runs(self, name):
        log = self.scratch / f"{name}.runs"
        return len(log.read_text()) if log.exists() else 0

    def configure(self, *checks):
        self.assertEqual(0, self.case.invoke("init"))
        config = paths(self.repo)["config"]
        value = json.loads(config.read_text())
        value["checks"] = list(checks)
        config.write_text(json.dumps(value))

    def set_checks(self, *checks):
        config = paths(self.repo)["config"]
        value = json.loads(config.read_text())
        value["checks"] = list(checks)
        config.write_text(json.dumps(value))

    def start_fix(self, *, remove=True):
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.case.invoke("fix", identifier))
        if remove:
            (self.repo / "src/dead.ts").unlink()
        return identifier

    def latest(self):
        state = load_state(self.repo)
        return json.loads((paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text())

    def verify(self, *arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(self.repo), "verify", "--no-review", *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_introduced_finding_blocks_before_the_gate_runs(self):
        self.configure(self.stage("test"))
        self.start_fix()
        baseline_runs = self.runs("test")
        (self.repo / "src/new-dead.ts").write_text("export const fresh = 3;\n")

        code, _, stderr = self.verify()

        self.assertEqual(1, code)
        self.assertIn("introduced new deterministic finding", stderr)
        self.assertEqual(baseline_runs, self.runs("test"))
        gate = self.latest()["gate"]
        self.assertEqual("not_run", gate["mode"])
        self.assertEqual([], self.latest()["checks"])

    def test_original_finding_still_present_costs_no_gate_run(self):
        self.configure(self.stage("test"))
        self.start_fix(remove=False)
        baseline_runs = self.runs("test")

        code, _, stderr = self.verify()

        self.assertEqual(1, code)
        self.assertIn("original Fallow finding is still present", stderr)
        self.assertEqual(baseline_runs, self.runs("test"))

    def test_git_diff_check_failure_blocks_before_the_gate(self):
        self.configure(self.stage("test"))
        self.start_fix()
        baseline_runs = self.runs("test")
        (self.repo / "src/index.ts").write_text("export const live = 1;   \n")

        code, _, stderr = self.verify()

        self.assertEqual(1, code)
        self.assertIn("git diff --check failed", stderr)
        self.assertEqual(baseline_runs, self.runs("test"))

    def test_separately_discovered_checks_all_run_even_after_a_failure(self):
        self.configure(self.stage("lint"), self.stage("test"))
        self.start_fix()
        (self.scratch / "lint.fail").touch()
        test_runs = self.runs("test")

        code, _, _ = self.verify()

        self.assertEqual(1, code)
        self.assertEqual(test_runs + 1, self.runs("test"))
        self.assertEqual(["failed", "passed"], [c["status"] for c in self.latest()["checks"]])

    def test_verify_stops_at_the_first_blocking_stage_and_names_it(self):
        self.configure(self.stage("lint", chain=True), self.stage("test", chain=True))
        self.start_fix()
        (self.scratch / "lint.fail").touch()
        test_runs = self.runs("test")

        code, stdout, stderr = self.verify()

        self.assertEqual(1, code)
        self.assertEqual(test_runs, self.runs("test"))
        statuses = {item["name"]: item["status"] for item in self.latest()["checks"]}
        self.assertEqual({"lint": "failed", "test": "not_run"}, statuses)
        self.assertIn("native check lint regressed", stderr)
        self.assertIn("failing stage: lint", stdout)
        self.assertIn("| lint: boom detail", stdout)
        self.assertIn("log: ", stdout)
        self.assertIn("test: not_run", stdout)

    def test_a_stage_red_in_the_baseline_does_not_stop_later_stages(self):
        (self.scratch / "lint.fail").touch()
        self.configure(self.stage("lint"), self.stage("test"))
        self.start_fix()
        self.assertEqual(["lint"], json.loads(self.status_json())["baseline_red_stages"])
        test_runs = self.runs("test")

        code, _, _ = self.verify()

        self.assertEqual(0, code)
        self.assertEqual(test_runs + 1, self.runs("test"))
        comparison = {item["name"]: item["classification"] for item in self.latest()["check_comparison"]}
        self.assertEqual("pre_existing_failure", comparison["lint"])

    def status_json(self):
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "status", "--json"])
        return stdout.getvalue()

    def test_status_lists_baseline_red_stages(self):
        (self.scratch / "lint.fail").touch()
        self.configure(self.stage("lint"), self.stage("test"))
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "status"])
        self.assertIn("baseline red stages: lint\n", stdout.getvalue())

    def test_identical_tree_and_config_reuses_a_passing_gate(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        first_runs = self.runs("test")

        code, stdout, stderr = self.verify()

        self.assertEqual(0, code)
        self.assertEqual(first_runs, self.runs("test"))
        self.assertEqual("reused", self.latest()["gate"]["mode"])
        self.assertIn("reusing the passing gate", stderr)
        self.assertIn("gate: reused the passing gate", stdout)

    def test_a_changed_tree_or_fresh_gate_runs_the_gate_again(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        first_runs = self.runs("test")

        self.assertEqual(0, self.verify("--fresh-gate")[0])
        self.assertEqual(first_runs + 1, self.runs("test"))
        self.assertEqual("full", self.latest()["gate"]["mode"])

        (self.repo / "src/index.ts").write_text("export const live = 2;\n")
        self.assertEqual(0, self.verify()[0])
        self.assertEqual(first_runs + 2, self.runs("test"))

    def test_a_changed_check_config_does_not_reuse_the_gate(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        config = paths(self.repo)["config"]
        value = json.loads(config.read_text())
        value["checks"][0]["timeout_seconds"] = 61
        config.write_text(json.dumps(value))

        code, _, _ = self.verify()

        self.assertNotEqual("reused", self.latest()["gate"]["mode"])

    def test_a_failed_gate_is_never_reused(self):
        self.configure(self.stage("test"))
        self.start_fix()
        (self.scratch / "test.fail").touch()
        self.assertEqual(1, self.verify()[0])
        before = self.runs("test")

        self.assertEqual(1, self.verify()[0])

        self.assertEqual(before + 1, self.runs("test"))

    def test_affected_runs_narrow_checks_and_records_a_partial_proof_that_resolves_nothing(self):
        self.configure(self.stage("lint", narrow=True), self.stage("test"))
        identifier = self.start_fix()
        test_runs = self.runs("test")
        lint_runs = self.runs("lint")

        code, stdout, _ = self.verify("--affected")

        self.assertEqual(0, code)
        self.assertEqual(lint_runs + 1, self.runs("lint"))
        self.assertEqual(test_runs, self.runs("test"))
        self.assertEqual("partial", self.latest()["gate"]["mode"])
        self.assertEqual(["test"], self.latest()["gate"]["checks_not_run"])
        self.assertIn("PARTIAL proof", stdout)
        state = load_state(self.repo)
        verification = state["remediations"][state["active_remediation"]]["verification"]
        self.assertEqual("partial", verification["status"])
        self.assertEqual("in_progress", state["issues"][identifier]["status"])
        code, result = DriverFlowTests.invoke_json(self, "next")
        self.assertNotIn("--retry-review", shlex.split(result["next_action"]))
        status = StringIO()
        with redirect_stdout(status), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "status"])
        self.assertIn("partial proof: " + identifier, status.getvalue())

    def test_a_partial_proof_cannot_be_reviewed_or_reused_as_the_gate(self):
        self.configure(self.stage("lint", narrow=True), self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify("--affected")[0])
        test_runs = self.runs("test")

        with patch("hangover.cli.run_codex_review", side_effect=AssertionError("reviewed a partial proof")):
            code, _, _ = self.verify("--retry-review")
        self.assertNotEqual(0, code)

        code, _, _ = self.verify()
        self.assertEqual(0, code)
        self.assertEqual(test_runs + 1, self.runs("test"))
        self.assertEqual("full", self.latest()["gate"]["mode"])

    def test_affected_still_blocks_on_cheap_evidence_and_a_failing_narrow_check(self):
        self.configure(self.stage("lint", narrow=True), self.stage("test"))
        self.start_fix()
        (self.scratch / "lint.fail").touch()

        code, _, stderr = self.verify("--affected")

        self.assertEqual(1, code)
        self.assertIn("native check lint regressed", stderr)

    def test_affected_json_reports_partial_without_claiming_review(self):
        self.configure(self.stage("lint", narrow=True))
        self.start_fix()
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(StringIO()):
            code = main(["--repo", str(self.repo), "verify", "--affected", "--json"])
        result = json.loads(output.getvalue())
        self.assertEqual(0, code)
        self.assertEqual("partial", result["data"]["deterministic"])
        self.assertEqual("in_progress", result["state"])

    def test_scan_runs_analyzers_only_unless_checks_are_requested(self):
        self.configure(self.stage("test"))
        self.assertEqual(0, self.case.invoke("scan"))
        self.assertEqual(0, self.runs("test"))
        self.assertEqual([], self.latest()["checks"])

        self.assertEqual(0, self.case.invoke("scan", "--checks"))

        self.assertEqual(1, self.runs("test"))
        self.assertEqual(["test"], [item["name"] for item in self.latest()["checks"]])

    def test_scan_baseline_without_checks_says_how_to_record_them(self):
        self.configure(self.stage("test"))
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(self.repo), "scan"]))
        self.assertIn("scan --rebaseline --checks", stdout.getvalue())

    def test_affected_refuses_to_combine_with_retry_or_fresh_gate(self):
        self.configure(self.stage("lint", narrow=True))
        self.start_fix()
        self.assertEqual(2, self.verify("--affected", "--fresh-gate")[0])
        self.assertEqual(2, self.verify("--affected", "--retry-review")[0])

    def test_a_failed_fresh_gate_leaves_no_older_pass_reusable(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        (self.scratch / "test.fail").touch()
        self.assertEqual(1, self.verify("--fresh-gate")[0])
        (self.scratch / "test.fail").unlink()
        before = self.runs("test")

        self.assertEqual(0, self.verify()[0])

        self.assertEqual(before + 1, self.runs("test"))
        self.assertEqual("full", self.latest()["gate"]["mode"])

    def stage_then_revert(self):
        """Stage a different file content, then restore the working tree: only the index differs."""
        path = self.repo / "src/index.ts"
        original = path.read_text()
        path.write_text("export const live = 7;\n")
        subprocess.run(["git", "-C", self.repo, "add", "src/index.ts"], check=True)
        path.write_text(original)

    def test_a_staged_change_or_ignored_output_or_lockfile_disables_reuse(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        runs = self.runs("test")
        (self.repo / ".gitignore").write_text("generated/\nnode_modules/\n")
        subprocess.run(["git", "-C", self.repo, "add", ".gitignore"], check=True)
        mutations = {
            "staged": self.stage_then_revert,
            "ignored": lambda: ((self.repo / "generated").mkdir(exist_ok=True),
                                (self.repo / "generated/out.js").write_text("x")),
            "lockfile": lambda: (self.repo / "node_modules").mkdir(exist_ok=True) or
                                (self.repo / "node_modules/.package-lock.json").write_text("{}"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.assertEqual(0, self.verify()[0])  # fresh run records the new state
                runs = self.runs("test")
                self.assertEqual(0, self.verify()[0])
                self.assertEqual("reused", self.latest()["gate"]["mode"])
                self.assertEqual(runs, self.runs("test"))
                mutate()
                self.assertEqual(0, self.verify()[0])
                self.assertEqual("full", self.latest()["gate"]["mode"])
                self.assertEqual(runs + 1, self.runs("test"))

    def test_a_symlink_outside_the_repository_disables_reuse_and_says_so(self):
        self.configure(self.stage("test"))
        self.start_fix()
        (self.repo / "outside-link").symlink_to(self.scratch)
        self.assertEqual(0, self.verify()[0])
        runs = self.runs("test")

        code, stdout, stderr = self.verify()

        self.assertEqual(0, code)
        self.assertEqual(runs + 1, self.runs("test"))
        self.assertIn("proof reuse disabled", stderr)
        self.assertIn("symlink points outside", self.latest()["gate"]["reuse_disabled"])

    def test_too_many_ignored_files_disable_reuse(self):
        self.configure(self.stage("test"))
        self.start_fix()
        (self.repo / ".gitignore").write_text("generated/\n")
        (self.repo / "generated").mkdir()
        for index in range(5):
            (self.repo / "generated" / f"{index}.txt").write_text("x")
        with patch("hangover.gates.MAX_IGNORED_FILES", 3):
            self.assertEqual(0, self.verify()[0])
            runs = self.runs("test")
            self.assertEqual(0, self.verify()[0])
        self.assertEqual(runs + 1, self.runs("test"))
        self.assertIn("ignored files", self.latest()["gate"]["reuse_disabled"])

    def test_reuse_is_visible_in_the_proof_record(self):
        self.configure(self.stage("test"))
        self.start_fix()
        self.assertEqual(0, self.verify()[0])
        first = self.latest()["id"]
        self.assertEqual(0, self.verify()[0])
        state = load_state(self.repo)
        proof = state["remediations"][state["active_remediation"]]["verification"]
        self.assertEqual({"mode": "reused", "from_run": first}, proof["gate"])

    def test_a_trivial_baseline_failure_output_does_not_pass_as_pre_existing(self):
        quiet = {"name": "lint", "command": [sys.executable, "-c", "raise SystemExit(1)"], "timeout_seconds": 60}
        quiet.update(stage_of="gate", adopted_from=self.stage("x", chain=True)["adopted_from"])
        self.configure(quiet, self.stage("test", chain=True))
        self.start_fix()
        test_runs = self.runs("test")

        code, _, stderr = self.verify()

        self.assertEqual(1, code)
        self.assertIn("native check lint regressed", stderr)
        self.assertEqual(test_runs, self.runs("test"))

    def test_a_pre_existing_failure_is_named_in_the_proof_and_output(self):
        (self.scratch / "lint.fail").touch()
        self.configure(self.stage("lint"), self.stage("test"))
        self.start_fix()

        code, stdout, _ = self.verify()

        self.assertEqual(0, code)
        self.assertIn("passed with pre-existing failure in lint", stdout)
        state = load_state(self.repo)
        proof = state["remediations"][state["active_remediation"]]["verification"]
        self.assertEqual(["lint"], proof["gate"]["pre_existing_failures"])

    def test_a_gate_that_changed_since_init_is_rediscovered_before_verify(self):
        package = json.loads((self.repo / "package.json").read_text())
        package["scripts"] = {"gate": "npm run lint && npm test", "lint": "node -e 0", "test": "node -e 0",
                              "security": "node -e 0"}
        (self.repo / "package.json").write_text(json.dumps(package))
        self.assertEqual(0, self.case.invoke("init", "--force"))
        self.start_fix()
        config = json.loads(paths(self.repo)["config"].read_text())
        self.assertEqual(["lint", "test"], [c["name"] for c in config["checks"]])
        package["scripts"]["gate"] = "npm run lint && npm test && npm run security"
        (self.repo / "package.json").write_text(json.dumps(package))

        code, stdout, stderr = self.verify()

        self.assertIn("re-discovered stages: lint, test, security", stderr)
        config = json.loads(paths(self.repo)["config"].read_text())
        self.assertEqual(["lint", "test", "security"], [c["name"] for c in config["checks"]])
        self.assertEqual(["lint", "test", "security"], self.latest()["gate"]["stages_rediscovered"])
        # The stale list never ran: security is a stage of this run.
        self.assertIn("security", [item["name"] for item in self.latest()["checks"]])

    def gate_script_repo(self, body="npm run lint\nnpm test\n"):
        (self.repo / "scripts").mkdir(exist_ok=True)
        (self.repo / "scripts/gate.sh").write_text(body)
        package = json.loads((self.repo / "package.json").read_text())
        package["scripts"] = {"gate": "bash scripts/gate.sh", "lint": "node -e 0", "test": "node -e 0",
                              "security": "node -e 0"}
        (self.repo / "package.json").write_text(json.dumps(package))

    def test_init_proposes_gate_script_stages_without_applying_them(self):
        self.gate_script_repo()
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(self.repo), "init", "--force"]))
        self.assertIn("proposed stages from the `gate` gate script (not applied): lint", stdout.getvalue())
        self.assertIn("init --stages-from-gate", stdout.getvalue())
        config = json.loads(paths(self.repo)["config"].read_text())
        self.assertEqual([["npm", "run", "gate"]], [c["command"] for c in config["checks"]])

    def test_adopting_gate_stages_writes_explicit_checks_and_blocks_verify_when_the_script_changes(self):
        self.gate_script_repo()
        self.assertEqual(0, self.case.invoke("init", "--force", "--stages-from-gate"))
        config = json.loads(paths(self.repo)["config"].read_text())
        self.assertEqual(["lint", "test"], [c["name"] for c in config["checks"]])
        self.assertEqual("gate", config["checks"][0]["adopted_from"]["script"])
        self.start_fix()
        (self.repo / "scripts/gate.sh").write_text("npm run lint\nnpm test\nnpm run security\n")
        with patch("hangover.cli.run_checks", side_effect=AssertionError("ran a stale stage list")):
            code, _, _ = self.verify()
        self.assertEqual(2, code)
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "verify", "--no-review", "--json"])
        self.assertIn("adopted gate stages are stale: gate", json.dumps(json.loads(stdout.getvalue())))

    def test_adoption_replaces_only_the_gate_check_in_place_and_keeps_the_others(self):
        self.gate_script_repo()
        self.assertEqual(0, self.case.invoke("init", "--force"))
        before = self.stage("before")
        after = self.stage("after")
        self.set_checks(before, {"name": "gate", "command": ["npm", "run", "gate"], "timeout_seconds": 5}, after)

        self.assertEqual(0, self.case.invoke("init", "--stages-from-gate"))

        checks = json.loads(paths(self.repo)["config"].read_text())["checks"]
        self.assertEqual(["before", "lint", "test", "after"], [c["name"] for c in checks])
        self.assertEqual([before, after], [checks[0], checks[3]])
        # Re-adopting after the script changes replaces the earlier adopted stages, again in place.
        (self.repo / "scripts/gate.sh").write_text("npm run lint\nnpm test\nnpm run security\n")
        self.assertEqual(0, self.case.invoke("init", "--stages-from-gate"))
        checks = json.loads(paths(self.repo)["config"].read_text())["checks"]
        self.assertEqual(["before", "lint", "test", "security", "after"], [c["name"] for c in checks])

    def test_adoption_refuses_a_stage_name_that_clashes_with_another_check(self):
        self.gate_script_repo()
        self.assertEqual(0, self.case.invoke("init", "--force"))
        self.set_checks(self.stage("lint"), {"name": "gate", "command": ["npm", "run", "gate"]})
        config = paths(self.repo)["config"].read_text()

        self.assertEqual(1, self.case.invoke("init", "--stages-from-gate"))

        self.assertEqual(config, paths(self.repo)["config"].read_text())

    def test_adopting_without_a_readable_gate_script_changes_nothing(self):
        before = None
        self.assertEqual(0, self.case.invoke("init"))
        before = paths(self.repo)["config"].read_text()
        self.assertEqual(1, self.case.invoke("init", "--stages-from-gate"))
        self.assertEqual(before, paths(self.repo)["config"].read_text())

    def test_identical_rewritten_ignored_output_still_matches_but_changed_content_does_not(self):
        self.configure(self.stage("test"))
        self.start_fix()
        (self.repo / ".gitignore").write_text("generated/\n")
        (self.repo / "generated").mkdir()
        out = self.repo / "generated/out.txt"
        out.write_text("aaaa")
        self.assertEqual(0, self.verify()[0])
        runs = self.runs("test")
        out.write_text("aaaa")  # new mtime, same content
        self.assertEqual(0, self.verify()[0])
        self.assertEqual("reused", self.latest()["gate"]["mode"])
        out.write_text("bbbb")  # same size, different content
        self.assertEqual(0, self.verify()[0])
        self.assertEqual("full", self.latest()["gate"]["mode"])
        self.assertEqual(runs + 1, self.runs("test"))

    def test_ignored_bytes_cap_and_directory_symlinks_disable_reuse(self):
        self.configure(self.stage("test"))
        self.start_fix()
        (self.repo / ".gitignore").write_text("generated/\nlinked\n")
        (self.repo / "generated").mkdir()
        (self.repo / "generated/big.bin").write_text("x" * 50)
        with patch("hangover.gates.MAX_IGNORED_BYTES", 10):
            self.assertEqual(0, self.verify()[0])
        self.assertIn("MB of ignored files", self.latest()["gate"]["reuse_disabled"])
        (self.repo / "generated/big.bin").unlink()
        (self.repo / "inside").mkdir()
        (self.repo / "linked").symlink_to(self.repo / "inside")
        self.assertEqual(0, self.verify()[0])
        self.assertIn("ignored symlink to a directory", self.latest()["gate"]["reuse_disabled"])
        (self.repo / "linked").unlink()
        (self.repo / "generated/nested").symlink_to(self.repo / "inside")
        self.assertEqual(0, self.verify()[0])
        self.assertIn("generated/nested", self.latest()["gate"]["reuse_disabled"])

    def test_a_gate_that_changes_its_own_inputs_is_never_recorded(self):
        (self.repo / ".gitignore").write_text("generated/\n")
        script = (
            "import pathlib; p = pathlib.Path('generated/out.txt'); p.parent.mkdir(exist_ok=True); "
            "p.write_text((p.read_text() if p.exists() else '') + 'x')"
        )
        counting = {"name": "build", "command": [sys.executable, "-c", script], "timeout_seconds": 60}
        self.configure()
        self.start_fix()
        self.set_checks(counting)
        for _ in range(3):
            self.assertEqual(0, self.verify()[0])
            self.assertEqual("full", self.latest()["gate"]["mode"])
        self.assertIn("changed its own inputs", self.latest()["gate"]["not_recorded"])

    def test_a_deterministic_gate_that_rewrites_identical_output_records_on_its_second_run(self):
        (self.repo / ".gitignore").write_text("generated/\n")
        script = (
            "import pathlib; p = pathlib.Path('generated/out.txt'); p.parent.mkdir(exist_ok=True); "
            "p.write_text('stable')"
        )
        deterministic = {"name": "build", "command": [sys.executable, "-c", script], "timeout_seconds": 60}
        self.configure()
        self.start_fix()
        self.set_checks(deterministic)
        modes = []
        for _ in range(3):
            self.assertEqual(0, self.verify()[0])
            modes.append(self.latest()["gate"]["mode"])
        self.assertEqual(["full", "full", "reused"], modes)
