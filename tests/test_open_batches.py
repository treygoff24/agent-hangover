"""Campaign flows for several open batches: packet, fix --branch/--add, verify --merged, worktrees."""
import json
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import test_cli as fixtures
from test_cli import packet_token_runner
from hangover.cli import _blame_for, _scan, main
from hangover.model import load_state, paths
from hangover.repository import run_checks

GIT = ["git", "-c", "user.name=Hangover Test", "-c", "user.email=hangover@example.invalid"]
PASS = {
    "status": "completed", "exit_code": 0, "duration_seconds": 0.01, "packet": "p.json", "output": "r.json",
    "stdout": "r.out", "stderr": "r.err",
    "review": {"verdict": "pass", "summary": "Behavior-preserving.", "findings": []},
}


class OpenBatchFlowTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.CliTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.repo = self.case.repo
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.git("add", "src/also-dead.ts")
        self.git("commit", "-qm", "second dead file")
        self.assertEqual(0, self.case.invoke("run", "--no-review"))
        cards = [c for c in load_state(self.repo)["issues"].values() if c.get("source") == "fallow"]
        by_file = {c["files"][0]: c["id"] for c in cards}
        self.dead, self.also = by_file["src/dead.ts"], by_file["src/also-dead.ts"]

    def git(self, *args, cwd=None):
        return subprocess.run([*GIT, "-C", str(cwd or self.repo), *args], check=True,
                              capture_output=True, text=True).stdout

    def run_main(self, *arguments, repo=None):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--repo", str(repo or self.repo), *arguments])
        return code, out.getvalue(), err.getvalue()

    def lane(self, branch, path):
        self.git("checkout", "-q", "-b", branch)
        self.git("rm", "-q", path)
        self.git("commit", "-qm", f"delete {path}")
        self.git("checkout", "-q", "main")

    def two_branched_batches(self):
        self.assertEqual(0, self.run_main("fix", self.dead, "--branch", "lane-a")[0])
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        self.lane("lane-a", "src/dead.ts")
        self.lane("lane-b", "src/also-dead.ts")

    def test_second_batch_needs_a_branch(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        code, _, err = self.run_main("fix", self.also)
        self.assertEqual(2, code)
        self.assertIn("--branch", err)
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        state = load_state(self.repo)
        self.assertEqual("in_progress", state["issues"][self.dead]["status"])
        self.assertEqual(self.also, state["active_issue"])

    def test_resuming_a_parked_batch_refocuses_it(self):
        self.two_branched_batches()
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        self.assertEqual(self.dead, load_state(self.repo)["active_issue"])

    def test_add_extends_the_open_batch_and_json_refusal_is_one_record(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        code, out, _ = self.run_main("fix", self.dead, self.also, "--json")
        self.assertEqual(2, code)
        self.assertEqual("tool_error", json.loads(out)["state"])
        self.assertIn("--add", json.loads(out)["blockers"][0])
        code, out, _ = self.run_main("fix", self.dead, self.also, "--add", "--json")
        self.assertEqual(0, code)
        self.assertEqual([self.dead, self.also], load_state(self.repo)["active_batch"])
        self.assertEqual([self.dead, self.also], [i["id"] for i in json.loads(out)["data"]["packet"]["issues"]])
        packet = json.loads((Path(load_state(self.repo)["issues"][self.dead]["fix_dir"]) / "fix-packet.json").read_text())
        self.assertEqual([self.dead, self.also], [i["id"] for i in packet["issues"]])

    def test_add_refuses_a_card_in_another_open_batch(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        code, _, err = self.run_main("fix", self.dead, self.also, "--add")
        self.assertEqual(2, code)
        self.assertIn("companions must be open", err)

    def test_packet_writes_without_activating(self):
        before = paths(self.repo)["state"].read_bytes()
        target = self.repo / "handoff.json"
        code, out, _ = self.run_main("packet", self.dead, self.also, "--out", str(target))
        self.assertEqual(0, code)
        packet = json.loads(target.read_text())
        self.assertEqual([self.dead, self.also], [i["id"] for i in packet["issues"]])
        self.assertFalse(packet["activated"])
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), packet["fix_base_commit"])
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        code, out, _ = self.run_main("packet", self.dead)
        self.assertEqual(self.dead, json.loads(out)["issues"][0]["id"])

    def test_packet_applies_the_batch_membership_rules(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        for ids in ([self.dead], [self.also, self.also], ["hang-0000000000"], ["nonsense"], []):
            with self.subTest(ids=ids):
                self.assertEqual(2, self.run_main("packet", *ids)[0])

    def test_verify_merged_runs_cheap_phase_and_gate_once_for_both_batches(self):
        self.two_branched_batches()
        self.git("merge", "-q", "--no-ff", "-m", "merge a", "lane-a")
        self.git("merge", "-q", "--no-ff", "-m", "merge b", "lane-b")
        with patch("hangover.cli._scan", wraps=_scan) as scanner, \
                patch("hangover.cli.run_checks", wraps=run_checks) as gate, \
                patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(PASS)):
            code, _, err = self.run_main("verify", "--merged")
        self.assertEqual(0, code, err)
        self.assertEqual(1, scanner.call_count)
        self.assertEqual(1, gate.call_count)
        state = load_state(self.repo)
        self.assertEqual(["resolved", "resolved"], [state["issues"][i]["status"] for i in (self.dead, self.also)])
        self.assertIsNone(state["active_issue"])
        runs = {state["issues"][i]["verified_run"] for i in (self.dead, self.also)}
        self.assertEqual(2, len(runs))

    def test_verify_merged_skips_an_unmerged_branch_and_leaves_it_open(self):
        self.two_branched_batches()
        self.git("merge", "-q", "--no-ff", "-m", "merge a", "lane-a")
        code, out, _ = self.run_main("verify", "--merged", "--no-review", "--json")
        payload = json.loads(out)
        self.assertEqual(0, code, out)
        self.assertEqual([self.dead], payload["batch"])
        self.assertEqual([self.also], [item["batch"] for item in payload["data"]["skipped"]])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][self.also]["status"])
        self.assertEqual("review_pending", payload["state"])

    def test_verify_merged_without_a_merged_branch_refuses(self):
        self.two_branched_batches()
        code, out, _ = self.run_main("verify", "--merged", "--json")
        self.assertEqual(2, code)
        self.assertIn("no open batch can be verified against HEAD", json.loads(out)["blockers"][0])

    def test_one_failing_gate_blocks_every_batch_after_one_run(self):
        self.two_branched_batches()
        self.git("merge", "-q", "--no-ff", "-m", "merge a", "lane-a")
        self.git("merge", "-q", "--no-ff", "-m", "merge b", "lane-b")
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["checks"] = [{**check, "command": ["node", "-e", "process.exit(3)"]} if "command" in check else check
                            for check in config["checks"]]
        config_path.write_text(json.dumps(config))
        with patch("hangover.cli.run_checks", wraps=run_checks) as gate, \
                patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(PASS)):
            code, out, _ = self.run_main("verify", "--merged", "--json")
        self.assertEqual(1, code, out)
        self.assertEqual(1, gate.call_count)
        payload = json.loads(out)
        self.assertEqual("blocked", payload["state"])
        self.assertEqual(2, len(payload["data"]["batches"]))
        state = load_state(self.repo)
        self.assertEqual(["in_progress", "in_progress"], [state["issues"][i]["status"] for i in (self.dead, self.also)])

    def test_introduced_finding_blocks_only_the_batch_whose_files_it_touches(self):
        snapshot = {"attribution": {"touched": {"a": ["src/a.ts"], "b": ["src/b.ts"]}}}
        in_a, in_b, nowhere = {"files": ["src/a.ts"]}, {"files": ["src/b.ts"]}, {"files": ["src/c.ts"]}
        blame_a, blame_b = _blame_for(snapshot, "a"), _blame_for(snapshot, "b")
        self.assertEqual([True, False, True], [blame_a("x", c) for c in (in_a, in_b, nowhere)])
        self.assertEqual([False, True, True], [blame_b("x", c) for c in (in_a, in_b, nowhere)])
        self.assertTrue(blame_a("x", None))
        self.assertIsNone(_blame_for({}, "a"))
        self.assertIsNone(_blame_for({"attribution": None}, "a"))

    def merge_both(self):
        self.git("merge", "-q", "--no-ff", "-m", "merge a", "lane-a")
        self.git("merge", "-q", "--no-ff", "-m", "merge b", "lane-b")

    def third_card(self):
        (self.repo / "src" / "side-effect.ts").write_text("export const s = 1;\n")
        self.git("add", "src/side-effect.ts")
        self.git("commit", "-qm", "third")
        self.assertEqual(0, self.run_main("scan")[0])
        return next(c["id"] for c in load_state(self.repo)["issues"].values() if c["files"] == ["src/side-effect.ts"])

    def test_a_tree_change_between_batches_records_stale_evidence_for_every_unfinished_batch(self):
        third = self.third_card()
        self.assertEqual(0, self.run_main("fix", self.dead, "--branch", "lane-a")[0])
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        self.assertEqual(0, self.run_main("fix", third, "--branch", "lane-c")[0])
        self.lane("lane-a", "src/dead.ts")
        self.lane("lane-b", "src/also-dead.ts")
        self.lane("lane-c", "src/side-effect.ts")
        for name in ("lane-a", "lane-b", "lane-c"):
            self.git("merge", "-q", "--no-ff", "-m", f"merge {name}", name)

        def edit_during_first_review(*args, **kwargs):
            (self.repo / "src" / "index.ts").write_text("export const live = 99;\n")
            return packet_token_runner(PASS)(*args, **kwargs)

        with patch("hangover.cli.run_codex_review", side_effect=edit_during_first_review) as reviewer:
            code, out, _ = self.run_main("verify", "--merged", "--json")
        self.assertEqual(1, reviewer.call_count)
        payload = json.loads(out)
        # Evidence that no longer describes the tree is unknown, not a verdict: the state and the exit agree.
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual(2, code)
        self.assertTrue(any("changed since the shared scan" in line for line in payload["blockers"]))
        state = load_state(self.repo)
        records = list(state["remediations"].values())
        self.assertEqual(["passed", "stale_shared_evidence", "stale_shared_evidence"],
                         sorted((r["verification"]["status"] for r in records), key=lambda v: v != "passed"))
        stale = [r for r in records if r["verification"]["status"] == "stale_shared_evidence"]
        self.assertTrue(all("changed since the shared scan" in r["verification"]["reason"] for r in stale))
        self.assertEqual(2, len(payload["data"]["skipped"]) + len(payload["data"]["batches"]) - 1)
        self.assertTrue(all(state["issues"][i]["status"] == "in_progress" for i in (self.dead, self.also, third)))

    def test_stale_shared_evidence_is_detected_before_the_batch_proof_is_overwritten(self):
        self.two_branched_batches()
        self.merge_both()

        def edit_during_first_review(*args, **kwargs):
            (self.repo / "src" / "index.ts").write_text("export const live = 99;\n")
            return packet_token_runner(PASS)(*args, **kwargs)

        with patch("hangover.cli.run_codex_review", side_effect=edit_during_first_review), \
                patch("hangover.cli._mark_stale_shared_evidence"):
            self.assertEqual(2, self.run_main("verify", "--merged", "--json")[0])
        untouched = [r for r in load_state(self.repo)["remediations"].values() if "verification" not in r]
        self.assertEqual(1, len(untouched))

    def test_proof_and_attribution_use_the_pinned_commit_when_the_branch_moves_after_selection(self):
        self.two_branched_batches()
        self.merge_both()
        pinned = {name: self.git("rev-parse", name).strip() for name in ("lane-a", "lane-b")}
        base = self.git("rev-parse", "main~2").strip()
        touched = {name: sorted(self.git("diff", "--name-only", f"{base}...{name}").split()) for name in pinned}

        def advance_branches(*args, **kwargs):
            for name in pinned:
                moved = self.git("commit-tree", "HEAD^{tree}", "-p", name, "-m", "ahead").strip()
                self.git("branch", "-f", name, moved)
            return packet_token_runner(PASS)(*args, **kwargs)

        with patch("hangover.cli.run_codex_review", side_effect=advance_branches):
            code, out, _ = self.run_main("verify", "--merged", "--json")
        self.assertEqual(0, code, out)
        for name in pinned:
            self.assertNotEqual(pinned[name], self.git("rev-parse", name).strip())
        state = load_state(self.repo)
        for record in state["remediations"].values():
            self.assertEqual(pinned[record["branch"]], record["verification"]["branch"]["commit"])
        for issue in (self.dead, self.also):
            snapshot = json.loads((paths(self.repo)["runs"] / state["issues"][issue]["verified_run"] / "snapshot.json").read_text())
            self.assertEqual(sorted(touched.values()), sorted(snapshot["attribution"]["touched"].values()))

    def test_squash_merged_branch_is_refused_not_guessed(self):
        self.two_branched_batches()
        self.git("merge", "-q", "--squash", "lane-a")
        self.git("commit", "-qm", "squash a")
        code, out, _ = self.run_main("verify", "--merged", "--json")
        self.assertEqual(2, code)
        self.assertIn("squash or rebase", json.loads(out)["blockers"][0])

    def test_all_skips_an_unmerged_branch_and_says_unbranched_is_proven_by_the_tree(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        self.lane("lane-b", "src/also-dead.ts")
        (self.repo / "src" / "dead.ts").unlink()
        code, out, _ = self.run_main("verify", "--all", "--no-review", "--json")
        payload = json.loads(out)
        self.assertEqual(0, code, out)
        self.assertEqual([self.dead], payload["batch"])
        self.assertEqual([self.also], [i["batch"] for i in payload["data"]["skipped"]])
        self.assertIn("proven by the tree alone", payload["data"]["notes"][0])

    def test_closure_rechecks_that_the_pinned_commit_is_still_in_head(self):
        from hangover.evidence import require_proof
        from hangover.oracles import _fallow_path
        self.two_branched_batches()
        self.merge_both()
        self.assertEqual(0, self.run_main("verify", "--merged", "--no-review")[0])
        state = load_state(self.repo)
        require_proof(self.repo, state, state["active_issue"], _fallow_path())
        real = subprocess.run

        def gone(command, *args, **kwargs):
            if "--is-ancestor" in command:
                return subprocess.CompletedProcess(command, 1, "", "")
            return real(command, *args, **kwargs)

        with patch("hangover.repository.subprocess.run", side_effect=gone):
            with self.assertRaisesRegex(RuntimeError, "no longer an ancestor of HEAD"):
                require_proof(self.repo, state, state["active_issue"], _fallow_path())

    def test_introduced_finding_in_one_batch_does_not_block_the_clean_one(self):
        self.assertEqual(0, self.run_main("fix", self.dead, "--branch", "lane-a")[0])
        self.assertEqual(0, self.run_main("fix", self.also, "--branch", "lane-b")[0])
        self.lane("lane-a", "src/dead.ts")
        self.git("checkout", "-q", "-b", "lane-b")
        self.git("rm", "-q", "src/also-dead.ts")
        (self.repo / "src" / "new-dead.ts").write_text("export const introduced = 4;\n")
        self.git("add", "src/new-dead.ts")
        self.git("commit", "-qm", "delete one, add another")
        self.git("checkout", "-q", "main")
        self.merge_both()
        code, out, _ = self.run_main("verify", "--merged", "--no-review", "--json")
        payload = json.loads(out)
        results = {r["issue_id"]: r for r in payload["data"]["batches"]}
        self.assertEqual("review_pending", results[self.dead]["state"], out)
        self.assertEqual("blocked", results[self.also]["state"])
        self.assertTrue(any("introduced" in b for b in results[self.also]["blockers"]))
        self.assertEqual(1, code)

    def test_a_legacy_state_is_attached_before_bulk_verify(self):
        self.assertEqual(0, self.run_main("fix", self.dead)[0])
        legacy = load_state(self.repo)
        for key in ("remediations", "active_remediation", "open_remediations"):
            legacy.pop(key, None)
        legacy["issues"][self.dead].pop("remediation", None)
        from hangover.model import save_state
        save_state(self.repo, legacy)
        (self.repo / "src" / "dead.ts").unlink()
        code, out, _ = self.run_main("verify", "--all", "--no-review", "--json")
        self.assertEqual(0, code, out)
        self.assertEqual([self.dead], json.loads(out)["batch"])

    def test_deferring_a_parked_primary_defers_its_whole_batch(self):
        (self.repo / "src" / "side-effect.ts").write_text("export const s = 1;\n")
        self.git("add", "src/side-effect.ts")
        self.git("commit", "-qm", "third")
        self.assertEqual(0, self.run_main("scan")[0])
        third = next(c["id"] for c in load_state(self.repo)["issues"].values() if c["files"] == ["src/side-effect.ts"])
        self.assertEqual(0, self.run_main("fix", self.dead, self.also)[0])
        self.assertEqual(0, self.run_main("fix", third, "--branch", "lane-c")[0])
        self.assertEqual(0, self.run_main("fix", "--defer", "not now", self.dead)[0])
        state = load_state(self.repo)
        self.assertEqual(["deferred", "deferred", "in_progress"],
                         [state["issues"][i]["status"] for i in (self.dead, self.also, third)])

    def test_worktree_boundary_does_not_depend_on_local_state(self):
        tree = self.repo.parent / (self.repo.name + "-lane2")
        self.git("worktree", "add", "-q", "-b", "wt2", str(tree))
        self.addCleanup(lambda: subprocess.run([*GIT, "-C", str(self.repo), "worktree", "remove", "--force", str(tree)]))
        self.assertEqual(0, self.run_main("audit", "--base", "HEAD", repo=tree)[0])
        self.assertTrue((tree / ".hangover").exists())
        for command in (("init",), ("run", "--no-review"), ("scan",), ("fix", self.dead), ("verify", "--no-review")):
            with self.subTest(command=command):
                code, _, err = self.run_main(*command, repo=tree)
                self.assertEqual(2, code)
                self.assertIn("linked worktree", err)
        code, out, _ = self.run_main("list", "--json", repo=tree)
        self.assertIn(self.dead, out)

    def test_packet_out_cannot_reach_state_git_or_an_existing_file(self):
        tree = self.repo.parent / (self.repo.name + "-lane3")
        self.git("worktree", "add", "-q", "-b", "wt3", str(tree))
        self.addCleanup(lambda: subprocess.run([*GIT, "-C", str(self.repo), "worktree", "remove", "--force", str(tree)]))
        state = paths(self.repo)["state"]
        before = state.read_bytes()
        (tree / "link.json").symlink_to(state)
        link_dir = tree / "dirlink"
        link_dir.symlink_to(self.repo / ".hangover")
        existing = tree / "taken.json"
        existing.write_text("keep")
        for destination in (state, tree / "link.json", link_dir / "new.json", self.repo / ".hangover" / "fixes" / "x.json",
                            self.repo / ".git" / "hooks" / "pre-commit", tree / ".hangover" / "x.json"):
            with self.subTest(destination=str(destination)):
                code, _, err = self.run_main("packet", self.dead, "--out", str(destination), repo=tree)
                self.assertEqual(2, code)
                self.assertIn("refusing to write a packet inside", err)
        self.assertEqual(before, state.read_bytes())
        code, _, err = self.run_main("packet", self.dead, "--out", str(existing), repo=tree)
        self.assertEqual((2, "keep"), (code, existing.read_text()))
        self.assertIn("--force", err)
        self.assertEqual(0, self.run_main("packet", self.dead, "--out", str(existing), "--force", repo=tree)[0])
        self.assertEqual(self.dead, json.loads(existing.read_text())["issues"][0]["id"])

    def test_fallow_allows_analysis_and_refuses_mutating_commands_and_write_flags(self):
        real, seen = subprocess.run, []

        def spy(command, *args, **kwargs):
            if command[0] == str(self.case.fake_fallow) and "--version" not in command:
                seen.append(command)
                return subprocess.CompletedProcess(command, 0)
            return real(command, *args, **kwargs)

        with patch("hangover.cli.subprocess.run", side_effect=spy):
            for allowed in (("dupes",), ("dead-code", "--trace", "src/a.ts:x"), ("--format", "json"), ("health", "--score"), ()):
                with self.subTest(allowed=allowed):
                    self.assertEqual(0, self.run_main("fallow", "--", *allowed)[0])
            self.assertEqual(5, len(seen))
            for refused in (("fix", "--yes"), ("init",), ("migrate",), ("hooks", "install"), ("watch",), ("--fix",),
                            ("dead-code", "--yes"), ("dupes", "--save-baseline", "b.json"), ("health", "--save-snapshot"),
                            ("dead-code", "--save-regression-baseline"), ("dead-code", "-o", "out.json"),
                            ("dead-code", "--output-file=out.json"), ("dead-code", "--sarif-file", "s.sarif"),
                            ("agent", "install"), ("ci-template",), ("frobnicate",), ("--quiet", "fix"),
                            ("--format", "json", "unknown-command")):
                with self.subTest(refused=refused):
                    code, _, err = self.run_main("fallow", "--", *refused)
                    self.assertEqual(2, code)
                    self.assertIn("read-only", err)
            self.assertEqual(5, len(seen))

    def test_bare_main_checkout_fails_closed_for_writes_and_unflagged_reads(self):
        bare = self.repo.parent / (self.repo.name + "-bare.git")
        subprocess.run(["git", "clone", "-q", "--bare", str(self.repo), str(bare)], check=True)
        tree = self.repo.parent / (self.repo.name + "-barelane")
        subprocess.run([*GIT, "-C", str(bare), "worktree", "add", "-q", "-b", "lane", str(tree)], check=True)
        for command in (("init",), ("scan",), ("fix", self.dead), ("verify", "--no-review")):
            with self.subTest(command=command):
                code, _, err = self.run_main(*command, repo=tree)
                self.assertEqual(2, code)
                self.assertIn("cannot be determined", err)
        code, _, err = self.run_main("list", repo=tree)
        self.assertEqual(2, code)
        self.assertIn("--state-from", err)
        code, out, _ = self.run_main("list", "--json", "--state-from", str(self.repo), repo=tree)
        self.assertEqual(0, code)
        self.assertIn(self.dead, out)
        self.assertFalse((tree / ".hangover").exists())

    def test_fallow_refuses_every_root_override(self):
        for arguments in (("--root", "/tmp"), ("--root=/tmp",), ("-r", "/tmp"), ("-r/tmp",), ("-r=/tmp",)):
            with self.subTest(arguments=arguments):
                code, _, err = self.run_main("fallow", "--", "config", *arguments)
                self.assertEqual(2, code)
                self.assertIn("fixes --root", err)

    def test_status_lists_every_open_batch_with_its_branch(self):
        self.two_branched_batches()
        code, out, _ = self.run_main("status", "--json")
        batches = json.loads(out)["open_batches"]
        self.assertEqual([(self.also, "lane-b"), (self.dead, "lane-a")], [(b["primary"], b["branch"]) for b in batches])
        self.assertIn("open batch: " + self.dead + " (1 card(s)) on branch lane-a", self.run_main("status")[1])

    def test_worktree_reads_main_state_and_cannot_write_it(self):
        tree = self.repo.parent / (self.repo.name + "-lane")
        self.git("worktree", "add", "-q", "-b", "wt", str(tree))
        self.addCleanup(lambda: subprocess.run([*GIT, "-C", str(self.repo), "worktree", "remove", "--force", str(tree)]))
        code, out, _ = self.run_main("list", "--json", repo=tree)
        self.assertEqual(0, code)
        self.assertIn(self.dead, out)
        code, out, _ = self.run_main("packet", self.dead, repo=tree)
        self.assertEqual(0, code)
        self.assertEqual(str(self.repo), json.loads(out)["repo"])
        before = paths(self.repo)["state"].read_bytes()
        for command in (("fix", self.dead), ("scan",), ("verify", "--no-review")):
            with self.subTest(command=command):
                code, _, err = self.run_main(*command, repo=tree)
                self.assertEqual(2, code)
                self.assertIn("linked worktree", err)
        self.assertFalse((tree / ".hangover").exists())
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        code, out, _ = self.run_main("list", "--json", "--state-from", str(self.repo), repo=self.repo.parent)
        self.assertEqual(0, code)

    def test_fallow_passes_arguments_to_the_pinned_binary_in_this_checkout(self):
        real, seen = subprocess.run, []

        def spy(command, *args, **kwargs):
            if command[0] == str(self.case.fake_fallow) and "--version" not in command:
                seen.append((command, kwargs.get("cwd")))
                return subprocess.CompletedProcess(command, 7)
            return real(command, *args, **kwargs)

        with patch("hangover.cli.subprocess.run", side_effect=spy):
            code, _, _ = self.run_main("fallow", "--", "dupes", "--mode", "strict")
        self.assertEqual(7, code)
        self.assertEqual([([str(self.case.fake_fallow), "--root", str(self.repo), "dupes", "--mode", "strict"],
                           self.repo)], seen)


if __name__ == "__main__":
    unittest.main()
