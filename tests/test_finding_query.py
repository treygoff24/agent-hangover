import copy
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from hangover.finding_query import member_results, query_members
from hangover.cli import main
from hangover.model import load_state, mutate_state, paths, write_json
import test_driver_flows as flows


FIXTURES = Path(__file__).parent / "fixtures/finding-query"


def captured(name):
    return {"status": "completed", "data": json.loads((FIXTURES / f"{name}.json").read_text())}


FINDING_ID = captured("found")["data"]["finding_id_query"]["requested"][0]
MEMBERS = {"hang-member": {"finding_id": FINDING_ID}}


class FindingQueryTests(unittest.TestCase):
    def result(self, name, seen=()):
        return member_results(captured(name), MEMBERS, list(seen))["hang-member"]

    def test_real_conclusive_missing_is_gone_with_fingerprint(self):
        result = self.result("missing")
        self.assertEqual("gone", result["status"])
        self.assertEqual(FINDING_ID, result["finding_id"])
        self.assertEqual(captured("missing")["data"]["finding_id_query"]["analysis_fingerprint"],
                         result["analysis_fingerprint"])

    def test_real_found_is_still_present(self):
        self.assertEqual("still present", self.result("found", ["hang-member"])["status"])

    def test_found_under_a_repo_wide_reason_is_still_present(self):
        command = captured("found")
        query = command["data"]["finding_id_query"]
        query.update(conclusive=False, inconclusive_reasons=["production"])
        self.assertEqual("still present", member_results(command, MEMBERS, ["hang-member"])["hang-member"]["status"])
        self.assertEqual("unknown", member_results(command, MEMBERS, [])["hang-member"]["status"])

    def test_conclusive_answer_with_reasons_is_invalid(self):
        command = captured("missing")
        command["data"]["finding_id_query"]["inconclusive_reasons"] = ["production"]
        self.assertEqual("unknown", member_results(command, MEMBERS, [])["hang-member"]["status"])

    def test_real_scoped_missing_is_unknown(self):
        result = self.result("inconclusive")
        self.assertEqual("unknown", result["status"])
        self.assertIn("file", result["reason"])

    def test_inconclusive_unfiltered_missing_is_unknown(self):
        command = captured("inconclusive")
        command["data"]["finding_id_query"]["filtered"] = []
        self.assertEqual("unknown", member_results(command, MEMBERS, [])["hang-member"]["status"])

    def test_filtered_even_if_conclusive_is_unknown(self):
        command = captured("inconclusive")
        command["data"]["finding_id_query"]["conclusive"] = True
        self.assertEqual("unknown", member_results(command, MEMBERS, [])["hang-member"]["status"])

    def test_full_scan_disagreement_blocks_in_both_directions(self):
        for name, seen in (("missing", ["hang-member"]), ("found", [])):
            with self.subTest(name=name):
                result = self.result(name, seen)
                self.assertEqual("unknown", result["status"])
                self.assertIn("disagree", result["reason"])

    def test_rule_off_is_unknown_only_for_the_affected_member_rule(self):
        command = captured("missing")
        command["data"]["finding_id_query"].update(conclusive=False, inconclusive_reasons=["rule-off"])
        members = {"hang-member": {"finding_id": FINDING_ID, "category": "unused_files"}}
        for disabled, expected in (({"unused_files": "unused-files"}, "unknown"), ({}, "not applicable")):
            with self.subTest(disabled=disabled):
                result = member_results(command, members, [], disabled)["hang-member"]
                self.assertEqual(expected, result["status"])

    def test_missing_malformed_or_failed_evidence_is_unknown(self):
        original = captured("missing")
        commands = [{"status": "unavailable"}, {"status": "completed", "data": []}]
        for key, value in (("requested", []), ("missing", None), ("conclusive", "true"),
                           ("analysis_fingerprint", None), ("found", [FINDING_ID])):
            command = copy.deepcopy(original)
            command["data"]["finding_id_query"][key] = value
            commands.append(command)
        failed = copy.deepcopy(original)
        failed["status"] = "error"
        commands.append(failed)
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual("unknown", member_results(command, MEMBERS, [])["hang-member"]["status"])


class FindingQueryFlowTests(unittest.TestCase):
    setUp = flows.GateCostTests.setUp
    stage = flows.GateCostTests.stage
    runs = flows.GateCostTests.runs
    configure = flows.GateCostTests.configure
    latest = flows.GateCostTests.latest
    verify = flows.GateCostTests.verify

    def start(self, remove=True):
        self.configure(self.stage("test"))
        identifier = flows.GateCostTests.start_fix(self, remove=remove)
        mutate_state(self.repo, lambda state: state["issues"][identifier].update(finding_id=FINDING_ID))
        return identifier

    def test_query_unknown_stops_before_gate_and_reports(self):
        identifier = self.start()
        baseline_runs = self.runs("test")
        with patch("hangover.finding_query._run_fallow", return_value=captured("inconclusive")):
            code, stdout, stderr = self.verify()
        self.assertEqual(1, code)
        self.assertEqual(baseline_runs, self.runs("test"))
        snapshot = self.latest()
        self.assertEqual("not_run", snapshot["gate"]["mode"])
        self.assertEqual("unknown", snapshot["dead_code_query"]["members"][identifier]["status"])
        self.assertIn(f"dead-code {identifier}: unknown", stderr)
        self.assertNotIn(f"dead-code {identifier}: gone", stdout + stderr)
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_present_member_blocks_without_querying(self):
        identifier = self.start(remove=False)
        baseline_runs = self.runs("test")
        with patch("hangover.finding_query._run_fallow", side_effect=AssertionError("queried present member")):
            code, _, stderr = self.verify()
        self.assertEqual(1, code)
        self.assertEqual(baseline_runs, self.runs("test"))
        self.assertIn(f"dead-code {identifier}: still present", stderr)
        self.assertEqual("still present", self.latest()["dead_code_query"]["members"][identifier]["status"])

    def test_gone_member_still_requires_gate_and_query_uses_scan_mode(self):
        identifier = self.start()
        baseline_runs = self.runs("test")
        with patch("hangover.finding_query._run_fallow", return_value=captured("missing")) as runner:
            code, _, stderr = self.verify()
        self.assertEqual(0, code)
        self.assertEqual(baseline_runs + 1, self.runs("test"))
        self.assertIn(f"dead-code {identifier}: gone", stderr)
        snapshot = self.latest()
        self.assertEqual("gone", snapshot["dead_code_query"]["members"][identifier]["status"])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])
        args = runner.call_args.args
        self.assertEqual(self.repo, args[0])
        self.assertEqual(paths(self.repo)["runs"] / snapshot["id"], args[1])
        self.assertEqual(["dead-code", "--no-type-aware", "--finding-id", FINDING_ID], args[3])

    def test_type_aware_batch_queries_each_id_with_the_scan_mode(self):
        identifier = self.start()
        second_id = "dc1:unused-file:0000000000000000"
        state = load_state(self.repo)
        state["issues"]["second"] = {"source": "fallow", "finding_id": second_id}
        command = captured("missing")
        command["data"]["finding_id_query"]["requested"].append(second_id)
        command["data"]["finding_id_query"]["missing"].append(second_id)
        with patch("hangover.finding_query._run_fallow", return_value=command) as runner:
            result = query_members(self.repo, self.scratch, state, [identifier, "second"],
                                   {"fallow": {"dead_code_mode": "type-aware"}}, [])
        self.assertEqual(["dead-code", "--type-aware", "--finding-id", FINDING_ID,
                          "--finding-id", second_id], runner.call_args.args[3])
        self.assertEqual({identifier, "second"}, set(result["members"]))
        self.assertTrue(all(member["status"] == "gone" for member in result["members"].values()))

    def test_old_dispositions_do_not_gate_current_missing_evidence(self):
        identifier = self.start()
        old_run = "old-disposition"
        for previous in ({}, {"dead_code_query": {"members": {identifier: {"analysis_fingerprint": "af1:old"}}}}):
            with self.subTest(previous=previous):
                write_json(paths(self.repo)["runs"] / old_run / "snapshot.json", previous)
                mutate_state(self.repo, lambda state: state["issues"][identifier].update(verified_run=old_run))
                with patch("hangover.finding_query._run_fallow", return_value=captured("missing")):
                    self.assertEqual(0, self.verify()[0])
                member = self.latest()["dead_code_query"]["members"][identifier]
                self.assertEqual("gone", member["status"])
                self.assertEqual("af1:aa6a6c9125c84ff2", member["analysis_fingerprint"])

    def test_config_wide_query_limits_are_not_applicable_and_do_not_block(self):
        self.start()
        baseline_runs = self.runs("test")
        package_baselines = captured("missing")
        package_baselines["data"]["finding_id_query"].update(
            conclusive=False, inconclusive_reasons=["package-baselines"])
        for command in (captured("production"), captured("entry-exports"), package_baselines):
            with self.subTest(query=command["data"]["finding_id_query"]):
                with patch("hangover.finding_query._run_fallow", return_value=command):
                    code, _, stderr = self.verify()
                self.assertEqual(0, code)
                self.assertEqual("not_applicable", self.latest()["dead_code_query"]["status"])
                self.assertEqual(1, stderr.count("dead-code query: not_applicable"))
                self.assertNotIn("dead-code hang-", stderr)
        self.assertGreater(self.runs("test"), baseline_runs)

    def test_missing_query_evidence_still_blocks(self):
        identifier = self.start()
        baseline_runs = self.runs("test")
        for command in ({"status": "unavailable"}, {"status": "completed", "data": {}}):
            with self.subTest(command=command["status"]):
                with patch("hangover.finding_query._run_fallow", return_value=command):
                    code, _, stderr = self.verify()
                self.assertEqual(1, code)
                self.assertEqual(baseline_runs, self.runs("test"))
                self.assertEqual("unknown", self.latest()["dead_code_query"]["members"][identifier]["status"])
                self.assertIn(f"dead-code {identifier}: unknown", stderr)

    def test_other_cheap_blockers_skip_the_query(self):
        self.start()
        baseline_runs = self.runs("test")
        (self.repo / "src/new-dead.ts").write_text("export const fresh = 3;\n")
        with patch("hangover.finding_query._run_fallow", side_effect=AssertionError("queried despite cheap blocker")):
            code, _, stderr = self.verify()
        self.assertEqual(1, code)
        self.assertEqual(baseline_runs, self.runs("test"))
        self.assertEqual("skipped", self.latest()["dead_code_query"]["status"])
        self.assertIn("introduced new deterministic finding", stderr)

    def test_scan_fallback_and_query_fallback_use_syntactic_evidence(self):
        identifier = self.start()
        state = load_state(self.repo)
        scan_fallback = {"fallow": {"dead_code_mode": "type-aware", "commands": {
            "dead_code": {"fallback": "type_aware_failed"}}}}
        with patch("hangover.finding_query._run_fallow", return_value=captured("missing")) as runner:
            result = query_members(self.repo, self.scratch, state, [identifier], scan_fallback, [])
        self.assertEqual("--no-type-aware", runner.call_args.args[3][1])
        self.assertEqual("gone", result["members"][identifier]["status"])
        failed = {"status": "error", "error": "sidecar unavailable"}
        with patch("hangover.finding_query._run_fallow", side_effect=[failed, captured("missing")]) as runner:
            result = query_members(self.repo, self.scratch, state, [identifier],
                                   {"fallow": {"dead_code_mode": "type-aware"}}, [])
        self.assertEqual(["--type-aware", "--no-type-aware"],
                         [call.args[3][1] for call in runner.call_args_list])
        self.assertEqual("gone", result["members"][identifier]["status"])
        self.assertIn("syntactic retry", result["members"][identifier]["reason"])
        self.assertIn("sidecar unavailable", result["members"][identifier]["reason"])
        self.assertEqual(failed, result["command"]["type_aware_attempt"])

    def test_missing_batch_card_is_skipped_and_present_ids_are_not_queried(self):
        identifier = self.start()
        state = load_state(self.repo)
        second_id = "dc1:unused-file:0000000000000000"
        state["issues"]["present"] = {"source": "fallow", "finding_id": second_id}
        with patch("hangover.finding_query._run_fallow", return_value=captured("missing")) as runner:
            result = query_members(self.repo, self.scratch, state, [identifier, "missing", "present"], {}, ["present"])
        self.assertEqual({identifier, "present"}, set(result["members"]))
        self.assertEqual("still present", result["members"]["present"]["status"])
        self.assertEqual(["dead-code", "--no-type-aware", "--finding-id", FINDING_ID], runner.call_args.args[3])

    def test_passing_json_exposes_query_and_quiet_suppresses_member_progress(self):
        identifier = self.start()
        stdout, stderr = StringIO(), StringIO()
        with patch("hangover.finding_query._run_fallow", return_value=captured("missing")), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(self.repo), "--quiet", "verify", "--no-review", "--json"])
        self.assertEqual(0, code)
        result = json.loads(stdout.getvalue())
        self.assertEqual("gone", result["data"]["dead_code_query"]["members"][identifier]["status"])
        self.assertNotIn("dead-code", stderr.getvalue())

    def test_query_changing_inputs_cannot_spend_the_gate(self):
        self.start()
        baseline_runs = self.runs("test")

        def changed_query(*args):
            (self.repo / "src/index.ts").write_text("export const live = 42;\n")
            return captured("missing")

        with patch("hangover.finding_query._run_fallow", side_effect=changed_query):
            code, _, stderr = self.verify()
        self.assertEqual(1, code)
        self.assertEqual(baseline_runs, self.runs("test"))
        self.assertIn("verification inputs changed", stderr)

    def test_legacy_members_do_not_query(self):
        self.configure(self.stage("test"))
        flows.GateCostTests.start_fix(self)
        with patch("hangover.finding_query._run_fallow", side_effect=AssertionError("queried legacy id")):
            self.assertEqual(0, self.verify()[0])


if __name__ == "__main__":
    unittest.main()
