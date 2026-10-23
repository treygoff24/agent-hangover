import json
import os
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

from hangover.cli import (
    RUN_RETENTION,
    _config,
    _fallow_comparison,
    _print_scan,
    _review_settings,
    _scan,
    _resolve_superseded_post_review_findings,
    _verification_blockers,
    main,
    parser,
)
from hangover.model import (
    write_json as hangover_write_json,
    defer_issue,
    load_state,
    merge_findings,
    mutate_state,
    new_state,
    next_issue,
    ordered_issues,
    paths,
    save_state,
)

FAKE_FALLOW = r'''#!/usr/bin/env python3
import json
from pathlib import Path
import sys

if "--version" in sys.argv:
    print("fallow 3.31.0")
    raise SystemExit(0)
root = Path(sys.argv[sys.argv.index("--root") + 1])
command = next(value for value in sys.argv if value in {"config", "dead-code", "dupes", "health", "flags", "audit"})
if command == "config":
    config_path = root / ".fallowrc.json"
    value = json.loads(config_path.read_text()) if config_path.exists() else {"plugins": []}
elif command == "dead-code":
    package = json.loads((root / "package.json").read_text())
    config_path = root / ".fallowrc.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    declared = package.get("devDependencies", {})
    ignored = config.get("ignoreDependencies", [])
    unused_dependencies = []
    if "chrome-launcher" in declared and "chrome-launcher" not in ignored:
        unused_dependencies.append({
            "package_name": "chrome-launcher",
            "actions": [{
                "type": "add-to-config",
                "config_key": "ignoreDependencies",
                "value": "chrome-launcher",
            }],
        })
    dead_paths = [
        path
        for path in ("src/dead.ts", "src/new-dead.ts", "src/also-dead.ts", "src/side-effect.ts")
        if (root / path).exists()
    ]
    private_type_leaks = (
        [{"path": "src/leak.ts", "exported_name": "leaky"}]
        if (root / "src" / "leak.ts").exists()
        else []
    )
    value = {
        "schema_version": 9,
        "version": "3.31.0",
        "total_issues": len(dead_paths) + len(unused_dependencies) + len(private_type_leaks),
        "summary": {
            "total_issues": len(dead_paths) + len(unused_dependencies) + len(private_type_leaks),
            "unused_files": len(dead_paths),
            "unused_dependencies": len(unused_dependencies),
            "private_type_leaks": len(private_type_leaks),
        },
        "unused_files": [{"path": path} for path in dead_paths],
        "unused_dependencies": unused_dependencies,
        "private_type_leaks": private_type_leaks,
    }
elif command == "dupes":
    value = {"schema_version": 10, "stats": {"clone_groups": 0}, "clone_groups": []}
elif command == "health":
    value = {"schema_version": 11, "health_score": {"score": 90, "grade": "A"}, "vital_signs": {}}
    # Fallow runs in a scrubbed environment, so a test sets the reported count in a file.
    reported = root / ".fake-fallow-files-analyzed"
    if reported.is_file():
        value["summary"] = {"files_analyzed": int(reported.read_text())}
elif command == "flags":
    value = {"schema_version": 8, "total_flags": 0, "feature_flags": []}
else:
    value = {"schema_version": 7, "verdict": "pass", "summary": {}, "attribution": {}}
print(json.dumps(value))
'''


def packet_token_runner(result: dict):
    """Stub an automated review runner that returns `result`, echoing its packet's token.

    A post-fix review must carry the verification_token of the packet it was
    given (a reviewer that omits it cannot close a remediation), so a stub
    standing in for a well-behaved reviewer echoes it unless `result` sets one.
    """
    def run(repo, review_dir, packet, *_, **__):
        value = json.loads(json.dumps(result))
        review = value.get("review")
        if isinstance(review, dict) and "verification_token" not in review:
            review["verification_token"] = json.loads(Path(packet).read_text()).get("verification_token")
        return value
    return run


class CliTests(unittest.TestCase):
    def test_cross_version_scan_explicitly_reports_unchanged_ledger(self):
        self.assertEqual(0, self.invoke('scan'))
        state = load_state(self.repo)
        baseline_path = paths(self.repo)['runs'] / state['baseline_run'] / 'snapshot.json'
        baseline = json.loads(baseline_path.read_text())
        baseline['fallow']['version'] = 'fallow 3.14.0'
        baseline_path.write_text(json.dumps(baseline))
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            result = main(['--repo', str(self.repo), 'scan'])
        self.assertEqual(0, result)
        self.assertEqual(state['issues'], load_state(self.repo)['issues'])
        self.assertIn('ledger unchanged: Fallow version changed (fallow 3.14.0 -> fallow 3.31.0); run hangover scan --rebaseline', stdout.getvalue())
        self.assertNotIn('baseline reset:', stdout.getvalue())

    def test_rebaseline_refuses_a_run_that_analyzed_nothing(self):
        self.assertEqual(0, self.invoke('scan'))
        state = load_state(self.repo)
        cards_before = state['issues']
        self.assertTrue(any(card['status'] == 'open' for card in cards_before.values()))
        baseline = json.loads((paths(self.repo)['runs'] / state['baseline_run'] / 'snapshot.json').read_text())
        empty = json.loads(json.dumps(baseline['fallow']))
        empty['commands']['dead_code']['data'] = {'summary': {'total_issues': 0}, 'workspace_diagnostics': [
            {'kind': 'no-source-files-analyzed', 'path': '.', 'degrades_analysis': True}]}
        with patch('hangover.cli.run_fallow_scan', return_value=empty):
            snapshot, state, _ = _scan(self.repo, no_checks=True, quiet=True, rebaseline=True)
        self.assertFalse(snapshot['rebaseline_evidence_accepted'])
        held = [card for card in state['issues'].values() if card['status'] == 'open']
        self.assertTrue(held and all(card['history'][-1]['event'] == 'unverifiable' for card in held))
        self.assertEqual({k: c['status'] for k, c in cards_before.items()},
                         {k: c['status'] for k, c in state['issues'].items()})
        self.assertEqual(state['baseline_run'], load_state(self.repo)['baseline_run'])

    def test_analyzer_upgrade_and_identity_migration_share_one_revision(self):
        from hangover.oracles import extract_fallow_findings
        self.assertEqual(0, self.invoke('scan'))
        state = load_state(self.repo)
        baseline_path = paths(self.repo)['runs'] / state['baseline_run'] / 'snapshot.json'
        baseline = json.loads(baseline_path.read_text())
        baseline['fallow']['version'] = 'fallow 3.14.0'
        baseline_path.write_text(json.dumps(baseline))
        group = {'fingerprint': 'dup:12345678', 'instances': [
            {'file': 'src/index.ts', 'start_line': 1, 'end_line': 8},
            {'file': 'src/dead.ts', 'start_line': 1, 'end_line': 8}]}
        old = extract_fallow_findings({'commands': {'dupes': {'data': {'clone_groups': [group]}}}})
        old_id = mutate_state(self.repo, lambda state: merge_findings(state, old, 'legacy')['ids'][0])
        mutate_state(self.repo, lambda state: defer_issue(state, old_id, 'Intentional skeleton'))
        current = json.loads(json.dumps(baseline['fallow']))
        current['version'] = 'fallow 3.31.0'
        group['fingerprint'] = 'dup:abcdef12'
        current['commands']['dupes']['data'] = {'clone_groups': [group]}
        current['commands']['health']['data']['hotspot_summary'] = {'clock': {
            'epoch_secs': 12345, 'source': 'head_commit', 'reproducible': True}}
        cards_before = load_state(self.repo)['issues']
        with patch('hangover.cli.run_fallow_scan', return_value=current):
            held, state, _ = _scan(self.repo, no_checks=True, quiet=True)
        self.assertEqual(cards_before, state['issues'])
        self.assertFalse(held['fallow_comparison']['comparable'])
        revision = load_state(self.repo)['revision']
        before_failure = load_state(self.repo)
        with patch('hangover.cli.run_fallow_scan', return_value=current), patch(
                'hangover.cli.write_json', side_effect=OSError('snapshot unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'could not save the scan snapshot'):
                _scan(self.repo, no_checks=True, quiet=True, rebaseline=True)
        self.assertEqual(before_failure, load_state(self.repo))
        with patch('hangover.cli.run_fallow_scan', return_value=current):
            snapshot, state, seen = _scan(self.repo, no_checks=True, quiet=True, rebaseline=True)
        self.assertEqual(revision + 1, state['revision'])
        events = [e for e in state['history'] if e['event'] == 'analyzer_upgraded']
        self.assertEqual(1, len(events))
        self.assertEqual('fallow 3.14.0', events[0]['from'])
        self.assertEqual('fallow 3.31.0', events[0]['to'])
        self.assertEqual(12345, events[0]['clock_epoch'])
        self.assertIn('before_counts', events[0])
        self.assertIn('after_counts', events[0])
        self.assertEqual('obsolete', state['issues'][old_id]['status'])
        replacement = snapshot['identity_migrations'][0]['replacements'][0]
        self.assertEqual('deferred', state['issues'][replacement]['status'])
        self.assertEqual(snapshot['id'], state['baseline_run'])
        with patch('hangover.cli.run_fallow_scan', return_value=current):
            _scan(self.repo, no_checks=True, quiet=True, rebaseline=True)
        self.assertEqual(1, len([e for e in load_state(self.repo)['history'] if e['event'] == 'analyzer_upgraded']))

    def test_failed_upgrade_cannot_rebaseline_or_migrate(self):
        self.assertEqual(0, self.invoke('scan'))
        before = load_state(self.repo)
        with patch('hangover.cli.run_fallow_scan', return_value={'status': 'partial', 'version': 'fallow 3.26.0', 'commands': {}}):
            snapshot, after, _ = _scan(self.repo, no_checks=True, quiet=True, rebaseline=True)
        self.assertEqual(before['baseline_run'], after['baseline_run'])
        self.assertIn('baseline_reset_blocked_reason', snapshot)
        self.assertFalse(any(e['event'] == 'analyzer_upgraded' for e in after['history']))

    def test_duplication_suppression_writes_nested_key_and_reopens_on_sight(self):
        from hangover.oracles import extract_fallow_findings
        self.assertEqual(0, self.invoke('scan'))
        group = {'fingerprint': 'dup:55572694', 'instances': [
            {'file': 'src/index.ts', 'start_line': 1, 'end_line': 8},
            {'file': 'src/dead.ts', 'start_line': 1, 'end_line': 8}]}
        findings = extract_fallow_findings({'commands': {'dupes': {'data': {'clone_groups': [group]}}}})
        identifier = mutate_state(self.repo, lambda state: merge_findings(state, findings, 'fixture')['ids'][0])
        (self.repo / '.fallowrc.json').write_text(json.dumps({'duplicates': {'minTokens': 50}, 'ignoreDependencies': ['kept']}))
        self.assertEqual(0, self.invoke('suppress', identifier, '--reason', 'Intentional parallel policy'))
        config = json.loads((self.repo / '.fallowrc.json').read_text())
        self.assertEqual({'minTokens': 50, 'ignoredClones': ['dup:55572694:2']}, config['duplicates'])
        self.assertEqual(['kept'], config['ignoreDependencies'])
        state = load_state(self.repo)
        self.assertEqual('suppressed', state['issues'][identifier]['status'])
        snapshot = json.loads((paths(self.repo)['runs'] / state['baseline_run'] / 'snapshot.json').read_text())
        self.assertIn('checks_inherited_from', snapshot)
        mutate_state(self.repo, lambda state: merge_findings(state, findings, 'sighted'))
        self.assertEqual('reopened', load_state(self.repo)['issues'][identifier]['status'])

    def test_health_clock_is_pinned_after_first_scan_and_refreshed_on_rebaseline(self):
        self.fake_fallow.write_text(FAKE_FALLOW.replace('import sys', 'import sys\nimport os').replace(
            'print(json.dumps(value))', '''
if command == "health":
    epoch = os.environ.get("FALLOW_CLOCK_EPOCH")
    value["observed_clock_env"] = epoch
    value["hotspot_summary"] = {"clock": {"epoch_secs": int(epoch or 12345),
        "source": "environment" if epoch else "head_commit", "reproducible": True}}
print(json.dumps(value))'''))
        self.assertEqual(0, self.invoke('scan'))
        first = json.loads((paths(self.repo)['runs'] / load_state(self.repo)['latest_run'] / 'snapshot.json').read_text())
        self.assertIsNone(first['fallow']['commands']['health']['data']['observed_clock_env'])
        self.assertEqual(0, self.invoke('scan'))
        second = json.loads((paths(self.repo)['runs'] / load_state(self.repo)['latest_run'] / 'snapshot.json').read_text())
        self.assertEqual('12345', second['fallow']['commands']['health']['data']['observed_clock_env'])
        self.assertEqual(0, self.invoke('scan', '--rebaseline'))
        third = json.loads((paths(self.repo)['runs'] / load_state(self.repo)['latest_run'] / 'snapshot.json').read_text())
        self.assertIsNone(third['fallow']['commands']['health']['data']['observed_clock_env'])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", "-b", "main", self.repo], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "index.ts").write_text("export const live = 1;\n")
        (self.repo / "src" / "dead.ts").write_text("export const dead = 2;\n")
        (self.repo / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {"check": "node -e \"process.exit(0)\""},
                    "exports": "./src/index.ts",
                }
            )
        )
        self.fake_fallow = self.repo / "fake-fallow"
        self.fake_fallow.write_text(FAKE_FALLOW)
        self.fake_fallow.chmod(0o755)
        self.fixture_reviewer = self.repo / "fixture-reviewer"
        self.fixture_reviewer.write_text('''#!/usr/bin/env python3
import json, sys
if "dry-run" in sys.argv:
    lane = sys.argv[sys.argv.index("dry-run") + 1]
    model = sys.argv[sys.argv.index("--model") + 1] if "--model" in sys.argv else None
    effort = sys.argv[sys.argv.index("--reasoning-effort") + 1] if "--reasoning-effort" in sys.argv else None
    print(json.dumps({"ok": True, "dryRun": True, "mode": "safe", "engine": "omp" if lane == "glm" else lane,
                      "modelResolved": model, "resolvedReasoningEffort": effort}))
elif sys.argv[1:] == ["login", "status"]:
    print("Logged in using a synthetic fixture")
elif "--version" in sys.argv:
    print("fixture-reviewer 1")
elif sys.argv[1] == "sandbox":
    print("--permission-profile" if "--help" in sys.argv else "hangover-runner-probe", end="")
else:
    print("Fixture review execution must be stubbed", file=sys.stderr)
    raise SystemExit(2)
''')
        self.fixture_reviewer.chmod(0o755)
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                self.repo,
                "-c",
                "user.name=Hangover Test",
                "-c",
                "user.email=hangover@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            check=True,
        )
        self.environment = patch.dict(os.environ, {
            "HANGOVER_FALLOW_BIN": str(self.fake_fallow),
            "HANGOVER_CODEX_BIN": str(self.fixture_reviewer),
            "HANGOVER_DELEGATE_BIN": str(self.fixture_reviewer),
        })
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def invoke(self, *arguments: str) -> int:
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            return main(["--repo", str(self.repo), *arguments])

    def action(self, *parts: str) -> str:
        """A next_action names this repository, so it works from any cwd."""
        return shlex.join(["hangover", "--repo", str(self.repo), *parts])

    def test_init_force_rebinds_a_copied_campaign(self) -> None:
        self.assertEqual(0, self.invoke("scan"))
        copy = Path(self.temp.name + "-copy")
        subprocess.run(["git", "clone", "-q", str(self.repo), str(copy)], check=True)
        self.addCleanup(shutil.rmtree, copy, True)
        shutil.copytree(self.repo / ".hangover", copy / ".hangover")
        issues = load_state(self.repo)["issues"]
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
            self.assertEqual(2, main(["--repo", str(copy), "status"]))
        self.assertIn("state belongs to", err.getvalue())
        with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(copy), "init", "--force"]))
        self.assertIn("campaign state rebound", out.getvalue())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(copy), "status"]))
        state = load_state(copy)
        self.assertEqual(issues.keys(), state["issues"].keys())
        self.assertEqual("state_rebound", state["history"][-1]["event"])
        self.assertEqual(str(self.repo.resolve()), state["history"][-1]["from"])

    def test_scan_reports_fallow_progress_to_stderr(self) -> None:
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "scan"])

        self.assertEqual(0, rc)
        self.assertIn("baseline:", stdout.getvalue())
        self.assertIn("fallow: running\n", stderr.getvalue())
        self.assertRegex(stderr.getvalue(), r"fallow: done in \d+\.\ds\n")

    def test_review_reports_runner_progress_to_stderr(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 12.34,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []},
        }
        stderr = StringIO()

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake_result)), redirect_stdout(
            StringIO()
        ), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "review"])

        self.assertEqual(0, rc)
        self.assertIn("review: running (codex)\n", stderr.getvalue())
        self.assertIn("review: done in 12.3s\n", stderr.getvalue())

    def test_quiet_global_flag_suppresses_phase_progress(self) -> None:
        self.assertIn("--quiet", parser().format_help())
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(
                ["--repo", str(self.repo), "--quiet", "run", "--no-review"]
            )

        self.assertEqual(0, rc)
        self.assertIn("baseline:", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_rehabilitation_state_survives_fix_and_fresh_review(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        issue = next_issue(state)
        self.assertIsNotNone(issue)
        self.assertEqual("fallow", issue["source"])
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        review = {"reviewed_files": ["src/index.ts"], 
            "verdict": "pass",
            "summary": "The deletion is behavior-preserving.",
            "findings": [],
        }
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": review,
        }
        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake_result)):
            self.assertEqual(0, self.invoke("verify", "--issue", issue["id"]))

        state = load_state(self.repo)
        self.assertEqual("resolved", state["issues"][issue["id"]]["status"])
        self.assertIsNone(state["active_issue"])
        self.assertTrue(paths(self.repo)["state"].is_file())
        self.assertGreaterEqual(len(list(paths(self.repo)["runs"].iterdir())), 3)

    def test_verify_blocks_a_native_gate_removed_from_config(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["checks"] = []
        config_path.write_text(json.dumps(config))

        # With no checks left, verify first refuses to resolve on the model alone (M5) ...
        self.assertEqual(2, self.invoke("verify", "--no-review"))
        # ... and an explicit --model-only still cannot drop the gate the baseline recorded.
        self.assertEqual(1, self.invoke("verify", "--no-review", "--model-only"))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][issue["id"]]["status"])

    def test_verify_refuses_to_resolve_an_issue_changed_during_review(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], 
                "verdict": "pass",
                "summary": "The deletion is behavior-preserving.",
                "findings": [],
            },
        }

        def finish_review(*args, **kwargs):
            mutate_state(
                self.repo,
                lambda state: defer_issue(state, issue["id"], "concurrent command"),
            )
            return fake_result

        stdout = StringIO()
        stderr = StringIO()
        with patch("hangover.cli.run_codex_review", side_effect=finish_review), redirect_stdout(
            stdout
        ), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "verify", "--issue", issue["id"]])

        state = load_state(self.repo)
        self.assertEqual(2, rc)
        self.assertEqual("deferred", state["issues"][issue["id"]]["status"])
        self.assertIsNone(state["active_issue"])
        self.assertNotIn(
            "resolved",
            [event["event"] for event in state["issues"][issue["id"]]["history"]],
        )
        self.assertIn("changed during review", stderr.getvalue())
        self.assertIn("refusing to resolve", stderr.getvalue())

    def _prepare_manual_proof_review(self):
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src" / "dead.ts").unlink()
        self.assertEqual(0, self.invoke("verify", "--runner", "none"))
        state = load_state(self.repo)
        record = state["remediations"][state["active_remediation"]]
        review = {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic proof review", "findings": []}
        if record.get("pending_review"):
            review["verification_token"] = record["pending_review"]["token"]
        output = paths(self.repo)["root"] / "manual-review.json"
        output.write_text(json.dumps(review))
        prepared = next(event["run"] for event in reversed(state["history"]) if event["event"] == "review_prepared")
        packet = json.loads((paths(self.repo)["runs"] / prepared / "review-packet.json").read_text())
        return identifier, record["id"], output, packet

    def test_manual_review_requires_a_bound_single_use_token(self) -> None:
        identifier, attempt_id, output, packet = self._prepare_manual_proof_review()
        review = json.loads(output.read_text())
        self.assertIn("verification_token", review)
        self.assertEqual(review["verification_token"], packet["verification_token"])
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))
        state = load_state(self.repo)
        self.assertEqual("resolved", state["issues"][identifier]["status"])
        self.assertTrue(state["remediations"][attempt_id]["pending_review"]["consumed"])
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_stale_manual_review_cannot_recapture_or_close_changed_code(self) -> None:
        identifier, _, output, packet = self._prepare_manual_proof_review()
        after = Path(packet["after_patch"])
        original_patch = after.read_bytes()
        (self.repo / "src" / "index.ts").write_text("export const live = 'changed after verification';\n")

        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])
        self.assertEqual(original_patch, after.read_bytes())

    def test_untracked_edit_invalidates_a_prepared_review(self) -> None:
        identifier, _, output, _ = self._prepare_manual_proof_review()
        (self.repo / "new-source.ts").write_text("export const introduced = 1;\n")

        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_check_config_drift_invalidates_a_prepared_review(self) -> None:
        identifier, _, output, _ = self._prepare_manual_proof_review()
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["checks"] = []
        config_path.write_text(json.dumps(config))

        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_review_cannot_close_code_changed_during_the_runner(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src" / "dead.ts").unlink()

        def late_writer(*args, **kwargs):
            (self.repo / "src" / "index.ts").write_text("export const live = 'late edit';\n")
            return {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic review", "findings": []}}

        with patch("hangover.cli.run_codex_review", side_effect=late_writer):
            self.assertEqual(2, self.invoke("verify"))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_old_review_cannot_resolve_a_restarted_attempt_with_same_issue_id(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src" / "dead.ts").unlink()

        def restart(*args, **kwargs):
            self.assertEqual(0, self.invoke("fix", "--release", identifier))
            self.assertEqual(0, self.invoke("fix", identifier))
            return {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Old attempt review", "findings": []}}

        with patch("hangover.cli.run_codex_review", side_effect=restart):
            self.assertEqual(2, self.invoke("verify"))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_native_check_source_mutation_blocks_before_review(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["checks"] = [{
            "name": "gate", "command": [sys.executable, "-c",
                "from pathlib import Path; p=Path('.hangover/mutate-during-check'); "
                "p.exists() and Path('src/index.ts').write_text('export const live = 99;\\n')"],
        }]
        config_path.write_text(json.dumps(config))
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src" / "dead.ts").unlink()
        (paths(self.repo)["root"] / "mutate-during-check").touch()
        result = {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic review", "findings": []}}

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(result)) as reviewer:
            self.assertEqual(1, self.invoke("verify"))
        reviewer.assert_not_called()

    def test_manual_import_uses_its_proof_not_the_latest_scan(self) -> None:
        identifier, attempt, output, packet = self._prepare_manual_proof_review()
        proof_run = load_state(self.repo)["remediations"][attempt]["verification"]["run"]
        self.assertEqual(0, self.invoke("scan"))
        self.assertNotEqual(proof_run, load_state(self.repo)["latest_run"])
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))
        self.assertEqual(proof_run, load_state(self.repo)["issues"][identifier]["verified_run"])

    def test_new_failed_verification_invalidates_the_older_token(self) -> None:
        identifier, attempt, output, packet = self._prepare_manual_proof_review()
        (self.repo / "src/dead.ts").write_text("export const dead = 2;\n")
        self.assertEqual(1, self.invoke("verify", "--no-review"))
        (self.repo / "src/dead.ts").unlink()
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_manual_import_rejects_missing_and_wrong_tokens(self) -> None:
        identifier, _, output, packet = self._prepare_manual_proof_review()
        review = json.loads(output.read_text())
        for token in (None, "wrong-token"):
            with self.subTest(token=token):
                review["verification_token"] = token
                output.write_text(json.dumps(review))
                self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
        review["verification_token"] = packet["verification_token"]
        output.write_text(json.dumps(review))
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_prepared_review_rejects_analyzer_and_artifact_drift(self) -> None:
        identifier, _, output, packet = self._prepare_manual_proof_review()
        raw = next(iter(packet["fallow"]["raw_artifacts"].values()))
        for target in (Path(os.environ["HANGOVER_FALLOW_BIN"]), Path(packet["after_patch"]), Path(raw)):
            with self.subTest(target=target.name):
                original = target.read_bytes()
                target.write_bytes(original + b"\n# changed\n")
                self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
                target.write_bytes(original)
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_retained_review_context_cannot_change_after_preparation(self) -> None:
        identifier, attempt_id, output, _ = self._prepare_manual_proof_review()
        state = load_state(self.repo)
        pending = state["remediations"][attempt_id]["pending_review"]
        context = paths(self.repo)["runs"] / pending["id"] / "review-context.json"
        record = json.loads(context.read_text())
        record["issue"]["harm"] = "Altered audit record after preparation"
        context.write_text(json.dumps(record))
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_unchanged_commit_does_not_invalidate_working_tree_proof(self) -> None:
        identifier, _, output, packet = self._prepare_manual_proof_review()
        subprocess.run(["git", "-C", self.repo, "add", "src/dead.ts"], check=True)
        subprocess.run(["git", "-C", self.repo, "-c", "user.name=Hangover Test", "-c",
                        "user.email=hangover@example.invalid", "commit", "-qm", "reviewed deletion"], check=True)
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_ignored_analyzer_configuration_is_still_a_proof_input(self) -> None:
        (self.repo / ".gitignore").write_text(".fallowrc.json\n")
        identifier, _, output, _ = self._prepare_manual_proof_review()
        (self.repo / ".fallowrc.json").write_text('{"ignoreDependencies": ["new-policy"]}\n')
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_legacy_attachment_refuses_a_concurrent_restart(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        state = load_state(self.repo)
        state.pop("active_remediation")
        state.pop("open_remediations")
        state.pop("remediations")
        state["issues"][identifier].pop("remediation")
        old_dir = Path(state["issues"][identifier]["fix_dir"])
        save_state(self.repo, state)

        def restart(*args):
            self.assertEqual(0, self.invoke("fix", "--release", identifier))
            self.assertEqual(0, self.invoke("fix", identifier))
            return old_dir

        with patch("hangover.cli._fix_directory", side_effect=restart), patch("hangover.cli._scan", wraps=_scan) as scanner:
            self.assertEqual(2, self.invoke("verify", "--no-review"))
        scanner.assert_not_called()
        current = load_state(self.repo)
        self.assertNotEqual(str(old_dir), current["issues"][identifier]["fix_dir"])
        self.assertNotIn("verification", current["remediations"][current["active_remediation"]])

    def test_malformed_proof_and_pending_token_are_controlled_errors(self) -> None:
        identifier, attempt, output, _ = self._prepare_manual_proof_review()
        original = paths(self.repo)["state"].read_text()
        for field, value in (("inputs", None), ("artifacts", []), ("token", None)):
            with self.subTest(field=field):
                state = json.loads(original)
                record = state["remediations"][attempt]
                if field == "token":
                    record["pending_review"].pop("token")
                else:
                    record["verification"][field] = value
                save_state(self.repo, state)
                self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_reported_analyzer_version_is_a_proof_input(self) -> None:
        identifier, _, output, _ = self._prepare_manual_proof_review()
        with patch("hangover.evidence.fallow_version", return_value="changed-version", create=True):
            self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_verifier_source_update_invalidates_a_prepared_proof(self) -> None:
        from hangover.evidence import TOOL_ROOT

        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory)
            for name in ("src/hangover/cli.py", "schemas/review.schema.json", "prompts/post-fix-review.md"):
                target = tool / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((TOOL_ROOT / name).read_bytes())
            with patch("hangover.evidence.TOOL_ROOT", tool):
                identifier, _, output, _ = self._prepare_manual_proof_review()
                source = tool / "src/hangover/cli.py"
                source.write_text(source.read_text() + "\n# verifier source update\n")
                self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_changed_issue_contract_invalidates_a_prepared_review(self) -> None:
        identifier, _, output, _ = self._prepare_manual_proof_review()
        mutate_state(self.repo, lambda state: state["issues"][identifier]["invariants"].append(
            "A newly discovered public caller must retain its error behavior."
        ))
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_ambiguous_family_blocks_verify_even_when_new_ids_are_waived(self) -> None:
        from test_complexity_identity import SOURCE

        source = self.repo / "src/handlers.ts"
        source.write_text(SOURCE.replace("value - 1", "value + 1"))
        original = '    value = {"schema_version": 11, "health_score": {"score": 90, "grade": "A"}, "vital_signs": {}}'
        replacement = '''    functions = [
        {"path": "src/handlers.ts", "name": "handler", "line": line, "col": 2,
         "line_count": 3, "param_count": 1, "cyclomatic": 28, "cognitive": 22,
         "exceeded": "both", "severity": "high"}
        for line, text in enumerate((root / "src/handlers.ts").read_text().splitlines(), 1)
        if text.strip().startswith("handler(")
    ]
    value = {"schema_version": 11, "health_score": {"score": 90, "grade": "A"},
             "vital_signs": {}, "findings": functions}'''
        fake = self.fake_fallow.read_text()
        self.assertEqual(1, fake.count(original))
        self.fake_fallow.write_text(fake.replace(original, replacement))
        self.assertEqual(0, self.invoke("run", "--no-review"))
        members = [item for item in load_state(self.repo)["issues"].values() if item.get("category") == "complexity"]
        self.assertEqual(2, len(members))
        self.assertTrue(all(item["complexity_identity"]["ambiguous"] for item in members))
        self.assertEqual(0, self.invoke("fix", members[0]["id"]))
        source.write_text("// prefix moves identical methods\n" + source.read_text())
        self.assertEqual(1, self.invoke("verify", "--no-review"))
        state = load_state(self.repo)
        current_ids = [item["id"] for item in state["issues"].values()
                       if item.get("category") == "complexity" and item.get("last_seen_run") == state["latest_run"]]
        self.assertEqual(2, len(current_ids))
        arguments = ["--repo", str(self.repo), "verify", "--accept-reason", "identity moved; keep replacement work tracked"]
        for identifier in current_ids:
            arguments.extend(["--accept", identifier])
        stderr = StringIO()
        fake_review = {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic pass", "findings": []}}
        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake_review)) as reviewer, redirect_stdout(StringIO()), redirect_stderr(stderr):
            self.assertEqual(1, main(arguments))
        reviewer.assert_not_called()
        blockers = [line for line in stderr.getvalue().splitlines() if line.startswith("blocker:")]
        self.assertEqual(1, len(blockers))
        self.assertIn("ambiguous complexity identity", blockers[0])
        self.assertIn(members[0]["id"], blockers[0])

    def _ready_fix_for_preflight(self):
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src/dead.ts").unlink()
        return identifier

    def test_verify_rejects_incompatible_review_flags_before_checks_or_state_changes(self) -> None:
        self._ready_fix_for_preflight()
        before = paths(self.repo)["state"].read_bytes()
        with patch("hangover.cli._scan", wraps=_scan) as scanner:
            self.assertEqual(2, self.invoke("verify", "--runner", "codex", "--lane", "glm"))
        scanner.assert_not_called()
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())

    def test_verify_rejects_a_missing_command_reviewer_before_checks(self) -> None:
        self._ready_fix_for_preflight()
        config = json.loads(paths(self.repo)["config"].read_text())
        config["review"].update(runner="command", command=["./missing-reviewer", "{prompt}"])
        paths(self.repo)["config"].write_text(json.dumps(config))
        with patch("hangover.cli._scan", wraps=_scan) as scanner:
            self.assertEqual(2, self.invoke("verify"))
        scanner.assert_not_called()

    def test_verify_rejects_known_logged_out_codex_before_checks(self) -> None:
        self._ready_fix_for_preflight()
        self.fixture_reviewer.write_text('#!/usr/bin/env python3\nprint("Not logged in")\nraise SystemExit(1)\n')
        review = {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic pass", "findings": []}}
        with patch("hangover.cli._scan", wraps=_scan) as scanner, patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            self.assertEqual(2, self.invoke("verify"))
        scanner.assert_not_called()

    def test_run_rejects_bad_review_timeout_before_the_baseline_gate(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config = json.loads(paths(self.repo)["config"].read_text())
        config["review"]["timeout_seconds"] = "not an integer"
        paths(self.repo)["config"].write_text(json.dumps(config))
        with patch("hangover.cli._scan", wraps=_scan) as scanner:
            self.assertEqual(2, self.invoke("run"))
        scanner.assert_not_called()

    def test_delegate_readiness_failure_is_detected_before_checks(self) -> None:
        self._ready_fix_for_preflight()
        delegate = self.repo / "preflight-delegate"
        delegate.write_text('#!/usr/bin/env python3\nimport json\nprint(json.dumps({"ok": False, "error": {"message": "profile is required"}}))\nraise SystemExit(2)\n')
        delegate.chmod(0o755)
        with patch.dict(os.environ, {"HANGOVER_DELEGATE_BIN": str(delegate)}), patch("hangover.cli._scan", wraps=_scan) as scanner:
            self.assertEqual(2, self.invoke("verify", "--runner", "delegate"))
        scanner.assert_not_called()

    def test_verify_keeps_its_selected_review_route_when_config_changes_during_checks(self) -> None:
        identifier = self._ready_fix_for_preflight()

        def change_route(*args, **kwargs):
            result = _scan(*args, **kwargs)
            config = json.loads(paths(self.repo)["config"].read_text())
            config["review"]["runner"] = "none"
            paths(self.repo)["config"].write_text(json.dumps(config))
            return result

        review = {"status": "completed", "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic approval", "findings": []}}
        with patch("hangover.cli._scan", side_effect=change_route), patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)) as runner:
            self.assertEqual(0, self.invoke("verify"))
        runner.assert_called_once()
        self.assertEqual("resolved", load_state(self.repo)["issues"][identifier]["status"])

    def test_scan_rebaseline_replaces_the_baseline_and_records_the_reset(self) -> None:
        self.assertEqual(0, self.invoke("scan"))
        previous_run = load_state(self.repo)["baseline_run"]
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "scan", "--rebaseline"])

        self.assertEqual(0, rc)
        state = load_state(self.repo)
        current_run = state["baseline_run"]
        self.assertNotEqual(previous_run, current_run)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / current_run / "snapshot.json").read_text()
        )
        self.assertTrue(snapshot["is_baseline"])
        self.assertEqual(
            {
                "event": "baseline_reset",
                "run": current_run,
                "previous_run": previous_run,
                "reason": "explicit",
            },
            {key: state["history"][-2][key] for key in ("event", "run", "previous_run", "reason")},
        )
        self.assertIn(
            f"baseline reset: {current_run} (previous {previous_run})\n",
            stdout.getvalue(),
        )

    def test_fallow_comparison_rejects_dead_code_mode_changes(self) -> None:
        baseline = {
            "fallow": {
                "version": "fallow 3.31.0",
                "dead_code_mode": "syntactic",
                "summary": {"resolved_config_sha256": "same"},
            }
        }
        current = {
            "fallow": {
                "version": "fallow 3.31.0",
                "dead_code_mode": "type-aware",
                "summary": {"resolved_config_sha256": "same"},
            }
        }

        self.assertEqual(
            {
                "comparable": False,
                "kind": "mode_changed",
                "reason": "dead-code analysis mode changed (baseline syntactic, current type-aware)",
            },
            _fallow_comparison(baseline, current),
        )

    def test_fallow_comparison_keeps_equal_modes_comparable(self) -> None:
        baseline = {
            "fallow": {
                "version": "fallow 3.31.0",
                "dead_code_mode": "syntactic",
                "summary": {
                    "resolved_config_sha256": "same",
                    "total_dead_code_issues": 27,
                },
            }
        }
        current = {
            "fallow": {
                "version": "fallow 3.31.0",
                "dead_code_mode": "syntactic",
                "summary": {
                    "resolved_config_sha256": "same",
                    "total_dead_code_issues": 12,
                },
            }
        }

        comparison = _fallow_comparison(baseline, current)

        self.assertTrue(comparison["comparable"])
        self.assertEqual(-15, comparison["changes"]["dead_code_issues"]["delta"])

    def test_plain_scan_keeps_the_recorded_baseline(self) -> None:
        self.assertEqual(0, self.invoke("scan"))
        previous_run = load_state(self.repo)["baseline_run"]

        self.assertEqual(0, self.invoke("scan"))

        state = load_state(self.repo)
        self.assertEqual(previous_run, state["baseline_run"])
        latest = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        self.assertFalse(latest["is_baseline"])

    def test_plain_scan_inherits_mode_from_legacy_baseline_artifacts(self) -> None:
        self.assertEqual(0, self.invoke("scan"))
        state = load_state(self.repo)
        baseline_path = paths(self.repo)["runs"] / state["baseline_run"] / "snapshot.json"
        baseline = json.loads(baseline_path.read_text())
        baseline["fallow"].pop("dead_code_mode")
        baseline["fallow"]["summary"].pop("dead_code_mode")
        baseline["fallow"]["commands"]["dead_code"]["fallback"] = "type_aware_failed"
        baseline_path.write_text(json.dumps(baseline))

        self.assertEqual(0, self.invoke("scan"))
        state = load_state(self.repo)
        syntactic = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        syntactic_command = syntactic["fallow"]["commands"]["dead_code"]["command"]
        self.assertIn("--no-type-aware", syntactic_command)
        self.assertNotIn("--type-aware", syntactic_command)

        baseline["fallow"]["dead_code_mode"] = "type-aware"
        baseline_path.write_text(json.dumps(baseline))
        self.assertEqual(0, self.invoke("scan"))
        state = load_state(self.repo)
        type_aware = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        type_aware_command = type_aware["fallow"]["commands"]["dead_code"]["command"]
        self.assertIn("--type-aware", type_aware_command)
        self.assertNotIn("--no-type-aware", type_aware_command)

    def test_plain_scan_prints_why_fallow_is_not_comparable(self) -> None:
        self.assertEqual(0, self.invoke("scan"))
        (self.repo / ".fallowrc.json").write_text('{"entry": ["src/index.ts"]}\n')
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "scan"])

        self.assertEqual(0, rc)
        self.assertIn(
            "  fallow baseline: not comparable — resolved Fallow config changed; "
            "run hangover scan --rebaseline\n",
            stdout.getvalue(),
        )

    def test_scan_filters_a_resolved_off_rule_and_warns_without_rewriting_raw_evidence(self) -> None:
        (self.repo / "src" / "leak.ts").write_text(
            "type Private = string; export const leaky = (value: Private) => value;\n"
        )
        (self.repo / ".fallowrc.json").write_text(
            json.dumps({"rules": {"private-type-leaks": "off"}})
        )
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "scan"])

        self.assertEqual(0, rc)
        state = load_state(self.repo)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        raw = json.loads(
            Path(snapshot["fallow"]["commands"]["dead_code"]["raw"]).read_text()
        )
        self.assertNotIn(
            "private_type_leaks",
            {state["issues"][identifier]["category"] for identifier in snapshot["finding_ids_seen"]},
        )
        self.assertEqual(1, snapshot["fallow"]["summary"]["total_dead_code_issues"])
        self.assertEqual(1, len(raw["private_type_leaks"]))
        self.assertIn(
            "warning: Fallow reported 1 finding(s) for disabled rule private-type-leaks; excluded from hangover",
            stdout.getvalue(),
        )

    def test_scan_obsoletes_and_then_reopens_a_rule_governed_issue(self) -> None:
        (self.repo / "src" / "leak.ts").write_text(
            "type Private = string; export const leaky = (value: Private) => value;\n"
        )
        config_path = self.repo / ".fallowrc.json"
        config_path.write_text(json.dumps({"rules": {"private-type-leaks": "warn"}}))
        self.assertEqual(0, self.invoke("scan"))
        state = load_state(self.repo)
        identifier = next(
            issue["id"]
            for issue in state["issues"].values()
            if issue.get("category") == "private_type_leaks"
        )

        config_path.write_text(json.dumps({"rules": {"private-type-leaks": "off"}}))
        self.assertEqual(0, self.invoke("scan"))
        obsolete = load_state(self.repo)["issues"][identifier]
        self.assertEqual("obsolete", obsolete["status"])
        self.assertEqual(
            "rule private-type-leaks is off in the resolved Fallow config",
            obsolete["history"][-1]["reason"],
        )

        config_path.write_text(json.dumps({"rules": {"private-type-leaks": "warn"}}))
        self.assertEqual(0, self.invoke("scan"))
        self.assertEqual("reopened", load_state(self.repo)["issues"][identifier]["status"])

    def test_verify_patch_and_packet_survive_a_remediation_commit(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        base = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        state = load_state(self.repo)
        fix_dir = Path(state["issues"][issue["id"]]["fix_dir"])
        fix_packet = json.loads((fix_dir / "fix-packet.json").read_text())
        self.assertEqual(base, state["issues"][issue["id"]]["fix_base_commit"])
        self.assertEqual(base, fix_packet["fix_base_commit"])

        (self.repo / "src" / "dead.ts").unlink()
        subprocess.run(["git", "-C", self.repo, "add", "src/dead.ts"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                self.repo,
                "-c",
                "user.name=Hangover Test",
                "-c",
                "user.email=hangover@example.invalid",
                "commit",
                "-qm",
                "remove dead file",
            ],
            check=True,
        )
        current_head = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()

        self.assertEqual(
            0,
            self.invoke("verify", "--issue", issue["id"], "--runner", "none"),
        )

        state = load_state(self.repo)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        self.assertEqual(base, snapshot["fix_base_commit"])
        self.assertEqual(current_head, snapshot["current_head"])
        self.assertEqual(current_head, snapshot["git"]["commit"])
        review_run = state["history"][-1]["run"]
        review_packet = json.loads(
            (paths(self.repo)["runs"] / review_run / "review-packet.json").read_text()
        )
        self.assertIn("-export const dead = 2;", Path(review_packet["after_patch"]).read_text())
        self.assertEqual(base, review_packet["issue"]["fix_base_commit"])
        self.assertEqual(current_head, review_packet["git"]["commit"])

    def test_verify_blocks_when_the_fix_base_commit_is_missing(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        missing = "0" * 40
        state = load_state(self.repo)
        state["issues"][issue["id"]]["fix_base_commit"] = missing
        state["remediations"][state["active_remediation"]]["fix_base_commit"] = missing
        save_state(self.repo, state)
        (self.repo / "src" / "dead.ts").unlink()
        stderr = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "verify",
                    "--issue",
                    issue["id"],
                    "--no-review",
                ]
            )

        self.assertEqual(1, rc)
        self.assertIn(f"blocker: fix base commit {missing} no longer exists", stderr.getvalue())

    def test_post_fix_review_uses_the_base_and_current_head(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        state = load_state(self.repo)
        base = state["issues"][issue["id"]]["fix_base_commit"]
        fix_dir = Path(state["issues"][issue["id"]]["fix_dir"])
        (self.repo / "src" / "dead.ts").unlink()
        subprocess.run(["git", "-C", self.repo, "add", "src/dead.ts"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                self.repo,
                "-c",
                "user.name=Hangover Test",
                "-c",
                "user.email=hangover@example.invalid",
                "commit",
                "-qm",
                "review checkpoint",
            ],
            check=True,
        )
        current_head = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()

        self.assertEqual(0, self.invoke("verify", "--no-review"))
        self.assertEqual(0, self.invoke("review", "--issue", issue["id"], "--prepare"))

        state = load_state(self.repo)
        review_run = state["history"][-1]["run"]
        packet = json.loads(
            (paths(self.repo)["runs"] / review_run / "review-packet.json").read_text()
        )
        self.assertIn("-export const dead = 2;", Path(packet["after_patch"]).read_text())
        self.assertEqual(base, packet["issue"]["fix_base_commit"])
        self.assertEqual(current_head, packet["git"]["commit"])

    def test_init_writes_all_review_runner_defaults(self) -> None:
        self.assertEqual(0, self.invoke("init"))

        review = json.loads((paths(self.repo)["config"]).read_text())["review"]

        self.assertEqual("codex", review["runner"])
        self.assertEqual(1200, review["timeout_seconds"])
        self.assertEqual(
            {"lane": "codex", "model": None, "reasoning_effort": None},
            review["delegate"],
        )
        # No environment names are forwarded until the operator lists them.
        self.assertEqual([], review["env"])
        self.assertIsNone(review["command"])

    def test_init_prints_discovered_check_commands_and_edit_hint(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "init"])

        self.assertIn(
            "checks: verify (npm run check)\nedit .hangover/config.json to change the gate\n",
            stdout.getvalue(),
        )

    def test_old_style_review_config_defaults_missing_runner_keys(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"] = {"runner": "codex", "timeout_seconds": 17}
        config_path.write_text(json.dumps(config))

        settings = _config(self.repo)["review"]
        self.assertEqual("codex", settings["runner"])
        self.assertEqual({"runner": "codex", "timeout_seconds": 17}, settings)
        self.assertEqual([], _review_settings(_config(self.repo))["env"])

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner({
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []},
        })):
            self.assertEqual(0, self.invoke("run", "--no-checks"))

    def test_delegate_only_cli_overrides_are_rejected_for_codex(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))

        self.assertEqual(2, self.invoke("review", "--runner", "codex", "--lane", "glm"))

    def test_delegate_cli_overrides_are_forwarded(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []},
        }
        with patch("hangover.cli.run_delegate_review", side_effect=packet_token_runner(fake_result)) as runner:
            self.assertEqual(
                0,
                self.invoke(
                    "review",
                    "--runner",
                    "delegate",
                    "--lane",
                    "glm",
                    "--model",
                    "deepseek-v4-pro",
                    "--reasoning-effort",
                    "high",
                ),
            )

        kwargs = runner.call_args.kwargs
        self.assertEqual("glm", kwargs["lane"])
        self.assertEqual("deepseek-v4-pro", kwargs["model"])
        self.assertEqual("high", kwargs["reasoning_effort"])

        state = load_state(self.repo)
        review_id = state["history"][-1]["run"]
        record = json.loads(
            (paths(self.repo)["runs"] / review_id / "review-run.json").read_text()
        )
        self.assertEqual("glm", record["lane"])
        self.assertEqual("deepseek-v4-pro", record["model"])
        self.assertEqual("high", record["reasoning_effort"])

    def test_command_runner_uses_configured_template(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"] = {
            "runner": "command",
            "timeout_seconds": 23,
            "command": ["reviewer", "{prompt}", "{output}", "{repo}", "{schema}"],
        }
        config_path.write_text(json.dumps(config))
        self.assertEqual(0, self.invoke("scan"))
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []},
        }
        with patch("hangover.cli.run_command_review", side_effect=packet_token_runner(fake_result)) as runner, patch(
            "hangover.readiness.command_binary", return_value=Path(sys.executable)
        ):
            self.assertEqual(0, self.invoke("review"))

        args = runner.call_args.args
        self.assertEqual(
            ["reviewer", "{prompt}", "{output}", "{repo}", "{schema}"], args[4]
        )
        self.assertEqual(23, args[5])

    def test_review_env_forwards_names_only_to_delegate_and_command(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"]["env"] = ["REVIEW_PROFILE", "REVIEW_PROXY"]
        config_path.write_text(json.dumps(config))
        with patch.dict(
            os.environ,
            {"REVIEW_PROFILE": "selected", "REVIEW_PROXY": "http://proxy.invalid"},
            clear=False,
        ):
            self.assertEqual(0, self.invoke("run", "--no-review"))
            fake_result = {
                "status": "completed",
                "exit_code": 0,
                "duration_seconds": 0.01,
                "packet": "packet.json",
                "output": "review.json",
                "stdout": "review.stdout",
                "stderr": "review.stderr",
                "review": {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "done", "findings": []},
            }
            with patch("hangover.cli.run_delegate_review", side_effect=packet_token_runner(fake_result)) as delegate:
                self.assertEqual(0, self.invoke("review", "--runner", "delegate"))
            with patch("hangover.cli.run_command_review", side_effect=packet_token_runner(fake_result)) as command, patch(
                "hangover.readiness.command_binary", return_value=Path(sys.executable)
            ):
                config["review"]["runner"] = "command"
                config["review"]["command"] = ["reviewer"]
                config_path.write_text(json.dumps(config))
                self.assertEqual(0, self.invoke("review"))

        self.assertEqual(["REVIEW_PROFILE", "REVIEW_PROXY"], delegate.call_args.kwargs["env"])
        self.assertEqual(["REVIEW_PROFILE", "REVIEW_PROXY"], command.call_args.kwargs["env"])

    def test_review_env_rejects_malformed_names(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        for invalid in ("REVIEW_PROFILE", [""], ["bad-name"], ["1PROFILE"], [1]):
            with self.subTest(invalid=invalid):
                config["review"]["env"] = invalid
                config_path.write_text(json.dumps(config))
                with self.assertRaisesRegex(
                    RuntimeError, r"review\.env.*environment variable name"
                ):
                    _review_settings(_config(self.repo))

    def test_review_env_rejects_names_that_shadow_the_hardened_base(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        for invalid in ("PATH", "HOME", "SHELL", "GIT_CONFIG_COUNT", "GIT_DIR"):
            with self.subTest(invalid=invalid):
                config["review"]["env"] = ["REVIEW_PROFILE", invalid]
                config_path.write_text(json.dumps(config))
                with self.assertRaisesRegex(RuntimeError, "cannot forward"):
                    _review_settings(_config(self.repo))

    def test_verify_without_a_runner_explains_the_manual_import(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(
                ["--repo", str(self.repo), "verify", "--issue", issue["id"], "--runner", "none"]
            )

        self.assertEqual(0, rc)
        self.assertNotIn("--import <file>", stdout.getvalue())
        state = load_state(self.repo)
        pending = state["remediations"][state["active_remediation"]]["pending_review"]
        directory = paths(self.repo)["runs"] / pending["id"]
        self.assertIn(f"review packet: {directory / 'review-packet.json'}", stdout.getvalue())
        self.assertIn(f"review schema: {directory / 'review-schema.json'}", stdout.getvalue())
        self.assertIn(f"verification_token: {pending['token']}", stdout.getvalue())
        self.assertIn(self.action("review", "--issue", issue["id"], "--import", str(directory / "review.json")), stdout.getvalue())
        self.assertEqual("in_progress", state["issues"][issue["id"]]["status"])
        self.assertEqual(
            "deterministic_verification_passed",
            state["issues"][issue["id"]]["history"][-1]["event"],
        )

    def test_rejected_review_flag_combination_leaves_no_orphan_run_directory(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        before = sorted(path.name for path in paths(self.repo)["runs"].iterdir())

        self.assertEqual(2, self.invoke("review", "--runner", "codex", "--lane", "glm"))

        self.assertEqual(before, sorted(path.name for path in paths(self.repo)["runs"].iterdir()))

    def test_verify_accepts_delegate_cli_overrides(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        self.assertIsNotNone(issue)
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "done", "findings": []},
        }
        with patch("hangover.cli.run_delegate_review", side_effect=packet_token_runner(fake_result)) as runner:
            self.assertEqual(
                0,
                self.invoke(
                    "verify",
                    "--issue",
                    issue["id"],
                    "--runner",
                    "delegate",
                    "--lane",
                    "glm",
                    "--model",
                    "deepseek-v4-pro",
                    "--reasoning-effort",
                    "medium",
                ),
            )

        kwargs = runner.call_args.kwargs
        self.assertEqual("glm", kwargs["lane"])
        self.assertEqual("deepseek-v4-pro", kwargs["model"])
        self.assertEqual("medium", kwargs["reasoning_effort"])

    def test_doctor_requires_configured_delegate_and_reports_its_version(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"] = {
            "runner": "delegate",
            "timeout_seconds": 1200,
            "delegate": {"lane": "glm", "model": None, "reasoning_effort": None},
            "command": None,
        }
        config_path.write_text(json.dumps(config))
        fake_delegate = self.repo / "fake-delegate"
        fake_delegate.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('delegate 0.30.0')\n"
            "    raise SystemExit(0)\n"
            "print(json.dumps({'ok': True, 'dryRun': True, 'mode': 'safe', 'engine': 'glm'}))\n"
        )
        fake_delegate.chmod(0o755)
        with patch.dict(
            os.environ,
            {
                "HANGOVER_DELEGATE_BIN": str(fake_delegate),
                "HANGOVER_CODEX_BIN": str(self.repo / "missing-codex"),
            },
        ):
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = main(["--repo", str(self.repo), "doctor", "--json"])

        self.assertEqual(0, rc)
        output = json.loads(stdout.getvalue())
        self.assertEqual("delegate", output["review_runner"])
        self.assertEqual("delegate 0.30.0", output["tools"]["delegate"])
        self.assertEqual("ready", output["delegate_preflight"])
        self.assertIsNone(output["tools"]["codex"])
        self.assertNotIn("codex", stderr.getvalue())

    def test_doctor_reports_a_delegate_preflight_refusal_as_missing(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"] = {
            "runner": "delegate",
            "timeout_seconds": 1200,
            "delegate": {"lane": "codex", "model": None, "reasoning_effort": None},
            "env": ["AI_PROFILE"],
            "command": None,
        }
        config_path.write_text(json.dumps(config))
        fake_delegate = self.repo / "fake-delegate"
        fake_delegate.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('delegate 0.30.0')\n"
            "    raise SystemExit(0)\n"
            "print(json.dumps({'ok': False, 'dryRun': True, 'mode': 'safe', 'error': {\n"
            "    'message': 'no profile selected for AI_PROFILE=' + os.environ.get('AI_PROFILE', 'unset')\n"
            "    + '; refusing an account-bearing launch or mutation'}}))\n"
            "raise SystemExit(2)\n"
        )
        fake_delegate.chmod(0o755)
        with patch.dict(
            os.environ,
            {
                "AI_PROFILE": "hangover-preflight-test-profile",
                "HANGOVER_DELEGATE_BIN": str(fake_delegate),
                "HANGOVER_CODEX_BIN": str(self.repo / "missing-codex"),
            },
        ):
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = main(["--repo", str(self.repo), "doctor", "--json"])

        self.assertEqual(1, rc)
        output = json.loads(stdout.getvalue())
        self.assertEqual("failed", output["delegate_preflight"])
        self.assertIn("refusing an account-bearing launch or mutation", stderr.getvalue())
        self.assertIn("<AI_PROFILE>", stderr.getvalue())
        self.assertNotIn("hangover-preflight-test-profile", stderr.getvalue())

    def test_doctor_accepts_command_runner_path_name_and_absolute_argv(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        fake_reviewer = self.repo / "fake-reviewer"
        fake_reviewer.write_text("#!/bin/sh\necho 'reviewer 1.0'\n")
        fake_reviewer.chmod(0o755)

        for first_arg in ("fake-reviewer", str(fake_reviewer)):
            with self.subTest(first_arg=first_arg):
                config["review"] = {
                    "runner": "command",
                    "timeout_seconds": 1200,
                    "command": [first_arg, "--version"],
                }
                config_path.write_text(json.dumps(config))
                path = os.environ["PATH"]
                with patch.dict(os.environ, {"PATH": str(self.repo) + os.pathsep + path}):
                    stdout = StringIO()
                    stderr = StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = main(["--repo", str(self.repo), "doctor", "--json"])

                self.assertEqual(0, rc)
                output = json.loads(stdout.getvalue())
                self.assertEqual("command", output["review_runner"])
                self.assertEqual(
                    str(fake_reviewer.resolve()), output["tools"]["command"]
                )
                self.assertNotIn("missing:", stderr.getvalue())

    def test_doctor_reports_the_configured_reviewer_without_running_it(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        marker = self.repo / "doctor-executed-the-reviewer"
        reviewer = self.repo / "repo-supplied-reviewer.sh"
        reviewer.write_text(f"#!/bin/sh\ntouch {marker}\necho 'reviewer 9.9'\n")
        reviewer.chmod(0o755)
        config["review"] = {
            "runner": "command",
            "timeout_seconds": 1200,
            "command": ["./repo-supplied-reviewer.sh", "--version"],
        }
        config_path.write_text(json.dumps(config))

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "doctor", "--json"])

        self.assertEqual(0, rc)
        output = json.loads(stdout.getvalue())
        self.assertEqual(str(reviewer.resolve()), output["tools"]["command"])
        self.assertFalse(marker.exists())

    def test_doctor_reports_null_for_an_unresolvable_reviewer(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"] = {
            "runner": "command",
            "timeout_seconds": 1200,
            "command": ["./missing-reviewer.sh"],
        }
        config_path.write_text(json.dumps(config))

        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "doctor", "--json"])

        self.assertEqual(1, rc)
        self.assertIsNone(json.loads(stdout.getvalue())["tools"]["command"])
        self.assertIn("command", stderr.getvalue())

    def test_doctor_survives_a_malformed_review_env(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config_path = paths(self.repo)["config"]
        config = json.loads(config_path.read_text())
        config["review"]["env"] = ["PATH"]
        config_path.write_text(json.dumps(config))

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            main(["--repo", str(self.repo), "doctor", "--json"])

        self.assertEqual("codex", json.loads(stdout.getvalue())["review_runner"])

    def test_doctor_reports_codex_login_status(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        fake_codex = self.repo / "fake-codex"
        codex_home = self.repo / "codex-home"

        for login_output, login_rc, expected_auth, expected_rc in (
            ("Not logged in", 1, "not_logged_in", 1),
            ("Logged in using ChatGPT", 0, "logged_in", 0),
        ):
            with self.subTest(login_output=login_output):
                fake_codex.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, sys\n"
                    f"if 'sandbox' not in sys.argv and os.environ.get('CODEX_HOME') != {str(codex_home)!r}:\n"
                    "    print('CODEX_HOME missing')\n"
                    "    raise SystemExit(2)\n"
                    "if '--version' in sys.argv:\n"
                    "    print('codex-cli 0.153.4')\n"
                    "    raise SystemExit(0)\n"
                    "if 'sandbox' in sys.argv:\n"
                    "    print('--permission-profile' if '--help' in sys.argv else 'hangover-runner-probe', end='')\n"
                    "    raise SystemExit(0)\n"
                    f"print({login_output!r})\n"
                    f"raise SystemExit({login_rc})\n"
                )
                fake_codex.chmod(0o755)
                stdout = StringIO()
                stderr = StringIO()
                with patch.dict(
                    os.environ,
                    {
                        "CODEX_HOME": str(codex_home),
                        "HANGOVER_CODEX_BIN": str(fake_codex),
                    },
                ):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = main(["--repo", str(self.repo), "doctor", "--json"])

                output = json.loads(stdout.getvalue())
                self.assertEqual(expected_rc, rc)
                self.assertEqual(expected_auth, output["codex_auth"])
                if expected_auth == "not_logged_in":
                    self.assertIn("codex (not logged in)", stderr.getvalue())
                    # The advice names the public options first, not one private tool.
                    self.assertIn("hint: run `codex login`, or set review.runner", stderr.getvalue())
                    self.assertIn("hangover review --prepare", stderr.getvalue())
                else:
                    self.assertNotIn("missing:", stderr.getvalue())

    def test_print_scan_reports_fallow_failures_fallback_and_unavailable_dead_count(self) -> None:
        snapshot = {
            "id": "scan-1",
            "kind": "scan",
            "is_baseline": False,
            "checks": [],
            "git": {"changes": []},
            "git_after_commands": {"changes": []},
            "stale_count": 2,
            "fallow": {
                "status": "partial",
                "summary": {
                    "health_score": 64.3,
                    "total_dead_code_issues": None,
                    "duplication": {"clone_groups": 61},
                },
                "commands": {
                    "dead_code": {
                        "status": "completed",
                        "fallback": "type_aware_failed",
                        "fallback_reason": "sidecar panic",
                    },
                    "flags": {
                        "status": "timeout",
                        "data": {"message": "flags crashed\nstack trace"},
                    },
                },
            },
        }

        stdout = StringIO()
        with redirect_stdout(stdout):
            _print_scan(snapshot)

        output = stdout.getvalue()
        self.assertIn(
            "fallow: partial | mode syntactic | health 64.3 | dead unavailable | clones 61",
            output,
        )
        self.assertIn("fallow flags: timeout — flags crashed", output)
        self.assertIn(
            "fallow dead-code: type-aware sidecar failed (sidecar panic); "
            "findings come from the non-type-aware scan",
            output,
        )
        self.assertIn(
            "stale: 2 issue(s) no longer reported (hangover status --stale to list)",
            output,
        )

    def _mark_first_issue_stale(self) -> dict:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        issue = next_issue(state)
        (self.repo / "src" / "dead.ts").unlink()
        self.assertEqual(0, self.invoke("scan"))
        return load_state(self.repo)["issues"][issue["id"]]

    def test_status_reports_stale_count(self) -> None:
        self._mark_first_issue_stale()
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "status"])

        self.assertEqual(0, rc)
        self.assertIn("stale=1", stdout.getvalue())
        self.assertIn("fallow mode: baseline syntactic | latest syntactic", stdout.getvalue())

    def test_status_stale_lists_stale_issues(self) -> None:
        issue = self._mark_first_issue_stale()
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "status", "--stale"])

        self.assertEqual(0, rc)
        self.assertIn(issue["id"], stdout.getvalue())
        self.assertIn(issue["category"], stdout.getvalue())
        self.assertIn(issue["title"], stdout.getvalue())

    def test_fix_refuses_a_stale_issue(self) -> None:
        issue = self._mark_first_issue_stale()
        stderr = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "fix", issue["id"]])

        self.assertEqual(2, rc)
        self.assertIn(
            f"issue {issue['id']} is stale; rescan to confirm it before fixing",
            stderr.getvalue(),
        )

    def test_status_stale_lists_obsolete_issues_with_a_label(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        review = {
            "source": "subjective-review",
            "category": "dead_code",
            "title": "Remove the deleted subsystem",
            "files": ["src/already-gone.ts"],
            "symbols": [],
            "evidence": ["review evidence"],
            "harm": "dead concept",
            "proposed_change": "remove it",
            "invariants": ["behavior stays the same"],
            "risk": "low",
            "priority": "P2",
            "confidence": "high",
            "verification": ["check"],
            "chesterton": "gone",
        }
        identifier = merge_findings(state, [review], "review-1")["ids"][0]
        save_state(self.repo, state)
        self.assertEqual(0, self.invoke("scan"))
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "status", "--stale"])

        self.assertEqual(0, rc)
        self.assertIn("obsolete=1", stdout.getvalue())
        self.assertIn(f"[obsolete] {identifier}", stdout.getvalue())

    def test_fix_obsolete_refuses_fallow_issue(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))
        stderr = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "fix",
                    issue["id"],
                    "--obsolete",
                    "removed with its subsystem",
                ]
            )

        self.assertEqual(2, rc)
        self.assertIn("Fallow issues are governed by `hangover scan`", stderr.getvalue())

    def test_fix_obsolete_marks_review_issue_with_operator_reason(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        review = {
            "source": "subjective-review",
            "category": "dead_code",
            "title": "Partially removed subsystem",
            "files": ["src/index.ts", "src/removed.ts"],
            "symbols": [],
            "evidence": ["review evidence"],
            "harm": "dead concept",
            "proposed_change": "remove it",
            "invariants": ["behavior stays the same"],
            "risk": "low",
            "priority": "P2",
            "confidence": "high",
            "verification": ["check"],
            "chesterton": "partial removal",
        }
        identifier = merge_findings(state, [review], "review-1")["ids"][0]
        save_state(self.repo, state)

        self.assertEqual(
            0,
            self.invoke(
                "fix", identifier, "--obsolete", "remaining reference is incidental"
            ),
        )

        issue = load_state(self.repo)["issues"][identifier]
        self.assertEqual("obsolete", issue["status"])
        self.assertEqual("remaining reference is incidental", issue["history"][-1]["reason"])

    def test_one_remediation_record_owns_shared_batch_evidence(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const other = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifiers = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", *identifiers))
        state = load_state(self.repo)
        self.assertIn("active_remediation", state)
        attempt = state["remediations"][state["active_remediation"]]
        self.assertEqual(identifiers, attempt["members"])
        self.assertEqual(identifiers[0], attempt["owner"])
        original_findings = list(attempt["fix_finding_ids"])

        (self.repo / "src" / "new-dead.ts").write_text("export const introduced = 4;\n")
        self.assertEqual(0, self.invoke("scan"))
        introduced = next(key for key in load_state(self.repo)["issues"] if key not in identifiers)
        self.assertEqual(1, self.invoke(
            "verify", "--no-review", "--note", "Preserve behavior",
            "--accept", introduced, "--accept-reason", "tracked follow-up",
        ))
        state = load_state(self.repo)
        attempt = state["remediations"][state["active_remediation"]]
        self.assertEqual(original_findings, attempt["fix_finding_ids"])
        self.assertEqual(["Preserve behavior"], [note["text"] for note in attempt["fix_notes"]])
        self.assertEqual([introduced], [waiver["id"] for waiver in attempt["waivers"]])
        for identifier in identifiers:
            issue = state["issues"][identifier]
            self.assertEqual(attempt["id"], issue["remediation"])
            for field in ("fix_dir", "fix_base_commit", "fix_finding_ids", "fix_notes", "waivers"):
                self.assertEqual(attempt[field], issue[field])

    def test_legacy_active_fix_attaches_shared_record_without_reset(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        legacy = load_state(self.repo)
        legacy.pop("remediations", None)
        legacy.pop("active_remediation", None)
        legacy.pop("open_remediations", None)
        issue = legacy["issues"][identifier]
        issue.pop("remediation", None)
        issue["fix_notes"] = [{"at": "2026-01-01T00:00:00Z", "text": "Legacy declaration"}]
        original_dir, original_base = issue["fix_dir"], issue["fix_base_commit"]
        save_state(self.repo, legacy)

        self.assertEqual(1, self.invoke("verify", "--no-review"))
        state = load_state(self.repo)
        self.assertIn("active_remediation", state)
        attempt = state["remediations"][state["active_remediation"]]
        self.assertEqual(original_dir, attempt["fix_dir"])
        self.assertEqual(original_base, attempt["fix_base_commit"])
        self.assertEqual("Legacy declaration", attempt["fix_notes"][0]["text"])
        self.assertEqual("in_progress", state["issues"][identifier]["status"])

    def test_repeating_fix_resumes_without_resetting_the_active_batch(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const other = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifiers = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", *identifiers))
        original = load_state(self.repo)

        self.assertEqual(0, self.invoke("fix", identifiers[0]))
        self.assertEqual(original, load_state(self.repo))

    def test_deferring_companion_detaches_it_from_active_batch(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const other = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        primary, companion = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", primary, companion))

        self.assertEqual(0, self.invoke("fix", companion, "--defer", "later"))
        state = load_state(self.repo)
        self.assertEqual([primary], state["active_batch"])
        self.assertEqual(primary, state["active_issue"])
        self.assertEqual("deferred", state["issues"][companion]["status"])

    def test_obsoleting_primary_promotes_the_surviving_companion(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        mutate_state(self.repo, lambda state: state["issues"].update(_duplicate_backlog()))
        primary, companion = sorted(_duplicate_backlog())
        self.assertEqual(0, self.invoke("fix", primary, companion))

        self.assertEqual(0, self.invoke("fix", primary, "--obsolete", "purpose removed"))
        state = load_state(self.repo)
        self.assertEqual([companion], state["active_batch"])
        self.assertEqual(companion, state["active_issue"])
        self.assertEqual(0, self.invoke("verify", "--no-review"))

    def test_dedupe_detaches_a_closed_active_member(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        mutate_state(self.repo, lambda state: state["issues"].update(_duplicate_backlog()))
        later = sorted(_duplicate_backlog())[-1]
        self.assertEqual(0, self.invoke("fix", later))

        self.assertEqual(0, self.invoke("dedupe", "--apply"))
        state = load_state(self.repo)
        self.assertEqual([], state["active_batch"])
        self.assertIsNone(state["active_issue"])

    def test_two_issue_batch_shares_fix_metadata_and_resolves_together(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        issues = [
            issue
            for issue in state["issues"].values()
            if issue.get("source") == "fallow"
        ]
        issues.sort(key=lambda issue: issue["files"])
        primary, companion = issues

        self.assertEqual(0, self.invoke("fix", primary["id"], companion["id"]))

        state = load_state(self.repo)
        primary_state = state["issues"][primary["id"]]
        companion_state = state["issues"][companion["id"]]
        self.assertEqual([primary["id"], companion["id"]], state["active_batch"])
        self.assertNotIn(
            primary["id"],
            [issue["id"] for issue in ordered_issues(state, open_only=True)],
        )
        self.assertNotIn(
            companion["id"],
            [issue["id"] for issue in ordered_issues(state, open_only=True)],
        )
        self.assertEqual(primary_state["fix_dir"], companion_state["fix_dir"])
        self.assertEqual(primary_state["fix_base_commit"], companion_state["fix_base_commit"])
        self.assertEqual(
            primary["id"], companion_state["history"][-1]["batch_primary"]
        )
        packet = json.loads((Path(primary_state["fix_dir"]) / "fix-packet.json").read_text())
        self.assertEqual(
            [primary["id"], companion["id"]],
            [issue["id"] for issue in packet["issues"]],
        )
        for issue in (primary, companion):
            (self.repo / issue["files"][0]).unlink()
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], 
                "verdict": "pass",
                "summary": "The batch is behavior-preserving.",
                "findings": [],
            },
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake_result)):
            self.assertEqual(0, self.invoke("verify", "--issue", primary["id"]))

        state = load_state(self.repo)
        self.assertEqual(
            ["resolved", "resolved"],
            [state["issues"][issue["id"]]["status"] for issue in (primary, companion)],
        )
        self.assertEqual(
            state["issues"][primary["id"]]["verified_run"],
            state["issues"][companion["id"]]["verified_run"],
        )
        self.assertEqual(
            state["issues"][primary["id"]]["review_run"],
            state["issues"][companion["id"]]["review_run"],
        )
        self.assertIsNone(state["active_issue"])
        self.assertEqual([], state["active_batch"])

    def test_contradictory_import_cannot_close_a_remediation(self) -> None:
        identifier, _, review = self._prepare_noted_review()
        review["declared_changes_assessed"][0]["verdict"] = "rejected"
        output = paths(self.repo)["root"] / "contradictory.json"
        output.write_text(json.dumps(review))
        stderr = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            self.assertEqual(2, main(["--repo", str(self.repo), "review", "--issue", identifier, "--import", str(output)]))
        self.assertIn("passing post-fix review cannot contain a rejected", stderr.getvalue())
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def _prepare_noted_review(self):
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src/dead.ts").unlink()
        self.assertEqual(0, self.invoke("verify", "--runner", "none", "--note", "Preserve output",
                                       "--note", "Delete only the unreachable export"))
        state = load_state(self.repo)
        record = state["remediations"][state["active_remediation"]]
        assessments = []
        for note in record["fix_notes"]:
            assessment = {"note": note["text"], "verdict": "accepted", "evidence": ["Synthetic cited evidence"]}
            # Preserve the pre-ID shape when replaying these RED regressions.
            if note.get("id"):
                assessment["note_id"] = note["id"]
            assessments.append(assessment)
        review = {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic note review", "findings": [],
                  "verification_token": record["pending_review"]["token"], "declared_changes_assessed": assessments}
        return identifier, record, review

    def test_fix_notes_have_stable_distinct_ids(self) -> None:
        identifier, record, _ = self._prepare_noted_review()
        ids = [note.get("id") for note in record["fix_notes"]]
        self.assertTrue(all(ids))
        self.assertEqual(2, len(set(ids)))
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        self.assertEqual(ids, [note["id"] for note in load_state(self.repo)["issues"][identifier]["fix_notes"]])

    def test_missing_required_note_assessment_cannot_close(self) -> None:
        identifier, _, review = self._prepare_noted_review()
        review["declared_changes_assessed"] = review["declared_changes_assessed"][:1]
        output = paths(self.repo)["root"] / "missing-note.json"
        output.write_text(json.dumps(review))
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_duplicate_note_assessment_cannot_close(self) -> None:
        identifier, _, review = self._prepare_noted_review()
        review["declared_changes_assessed"].append(dict(review["declared_changes_assessed"][0]))
        output = paths(self.repo)["root"] / "duplicate-note.json"
        output.write_text(json.dumps(review))
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_unrelated_note_assessment_cannot_close(self) -> None:
        identifier, _, review = self._prepare_noted_review()
        assessment = dict(review["declared_changes_assessed"][0])
        assessment["note"] = "Unrelated claim"
        if "note_id" in assessment:
            assessment["note_id"] = "unknown-note"
        review["declared_changes_assessed"].append(assessment)
        output = paths(self.repo)["root"] / "unrelated-note.json"
        output.write_text(json.dumps(review))
        self.assertEqual(2, self.invoke("review", "--issue", identifier, "--import", str(output)))

    def test_complete_note_assessment_closes_and_retains_its_evidence(self) -> None:
        identifier, _, review = self._prepare_noted_review()
        output = paths(self.repo)["root"] / "complete-notes.json"
        output.write_text(json.dumps(review))
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(output)))
        issue = load_state(self.repo)["issues"][identifier]
        self.assertEqual("resolved", issue["status"])
        resolved = next(event for event in issue["history"] if event["event"] == "resolved")
        self.assertEqual(review["declared_changes_assessed"], resolved["declared_changes_assessed"])

    def test_legacy_note_ids_are_assigned_once_on_explicit_verification(self) -> None:
        identifier, record, _ = self._prepare_noted_review()
        state = load_state(self.repo)
        state["remediations"][record["id"]]["fix_notes"][0].pop("id")
        retained = record["fix_notes"][1]["id"]
        save_state(self.repo, state)
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        notes = load_state(self.repo)["issues"][identifier]["fix_notes"]
        self.assertTrue(notes[0]["id"])
        self.assertEqual(retained, notes[1]["id"])
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        self.assertEqual(notes, load_state(self.repo)["issues"][identifier]["fix_notes"])

    def test_verify_notes_persist_then_new_fix_resets_them(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next(iter(load_state(self.repo)["issues"]))
        self.assertEqual(0, self.invoke("fix", identifier))

        self.assertEqual(1, self.invoke("verify", "--issue", identifier, "--note", "first"))
        note_file = self.repo / "note.txt"
        note_file.write_text("second\n")
        self.assertEqual(
            1,
            self.invoke("verify", "--issue", identifier, "--note-file", str(note_file)),
        )
        issue = load_state(self.repo)["issues"][identifier]
        self.assertEqual(["first", "second"], [note["text"] for note in issue["fix_notes"]])
        notes_md = (Path(issue["fix_dir"]) / "notes.md").read_text()
        self.assertIn("first", notes_md)
        self.assertIn("second", notes_md)

        def reopen(state: dict) -> None:
            state["issues"][identifier]["status"] = "reopened"
            state["active_issue"] = None
            state["active_batch"] = []

        mutate_state(self.repo, reopen)
        self.assertEqual(0, self.invoke("fix", identifier))
        self.assertEqual([], load_state(self.repo)["issues"][identifier]["fix_notes"])

    def test_multi_defer_is_atomic_and_refuses_named_in_progress_issue(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifiers = sorted(load_state(self.repo)["issues"])
        before_revision = load_state(self.repo)["revision"]
        self.assertEqual(0, self.invoke("fix", *identifiers, "--defer", "same reason"))
        state = load_state(self.repo)
        self.assertEqual(before_revision + 1, state["revision"])
        self.assertTrue(all(state["issues"][item]["status"] == "deferred" for item in identifiers))

        for item in identifiers:
            state["issues"][item]["status"] = "reopened"
        save_state(self.repo, state)
        self.assertEqual(0, self.invoke("fix", identifiers[0]))
        stderr = StringIO()
        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main([
                "--repo", str(self.repo), "fix", *identifiers,
                "--defer", "must refuse",
            ])
        self.assertEqual(2, rc)
        self.assertIn(f"issue {identifiers[0]} is in_progress", stderr.getvalue())
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifiers[0]]["status"])

    def test_multi_obsolete_applies_every_subjective_issue_in_one_revision(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        findings = []
        for number in (1, 2):
            findings.append({
                "fingerprint": ["review", number], "source": "subjective-review",
                "category": "duplication", "title": f"duplicate {number}",
                "evidence": ["evidence"], "files": [f"src/{number}.ts"], "symbols": [],
                "harm": "harm", "proposed_change": "consolidate",
                "invariants": ["behavior"], "risk": "low", "priority": "P2",
                "confidence": "high", "verification": ["check"], "chesterton": "known",
            })
        identifiers = merge_findings(state, findings, "review-1")["ids"]
        save_state(self.repo, state)
        before_revision = load_state(self.repo)["revision"]
        self.assertEqual(0, self.invoke("fix", *identifiers, "--obsolete", "same reason"))
        state = load_state(self.repo)
        self.assertEqual(before_revision + 1, state["revision"])
        self.assertTrue(all(state["issues"][item]["status"] == "obsolete" for item in identifiers))

    def test_release_primary_preserves_surviving_batch_evidence(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const companion = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        primary, survivor = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", primary, survivor))
        before = load_state(self.repo)
        fix_dir = Path(before["issues"][survivor]["fix_dir"])
        packet_before = (fix_dir / "fix-packet.json").read_bytes()
        self.assertEqual(0, self.invoke("fix", "--release", primary))
        state = load_state(self.repo)
        self.assertEqual(before["revision"] + 1, state["revision"])
        self.assertEqual("open", state["issues"][primary]["status"])
        self.assertEqual("released", state["issues"][primary]["history"][-1]["event"])
        self.assertEqual([survivor], state["active_batch"])
        self.assertEqual(survivor, state["active_issue"])
        for key in ("fix_base_commit", "fix_finding_ids", "fix_dir"):
            self.assertEqual(before["issues"][survivor][key], state["issues"][survivor][key])
        self.assertEqual(packet_before, (fix_dir / "fix-packet.json").read_bytes())
        (self.repo / state["issues"][survivor]["files"][0]).unlink()
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        self.assertEqual("open", load_state(self.repo)["issues"][primary]["status"])

    def test_release_companion_then_last_member_clears_batch_and_old_waivers(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const companion = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        primary, companion = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", primary, companion))
        mutate_state(self.repo, lambda state: state["issues"][primary].update(
            waivers=[{"id": "hang-aaaaaaaaaa", "reason": "old remediation", "at": "then"}]
        ))
        self.assertEqual(0, self.invoke("fix", companion, "--release"))
        state = load_state(self.repo)
        self.assertEqual([primary], state["active_batch"])
        self.assertEqual(primary, state["active_issue"])
        self.assertEqual(0, self.invoke("fix", primary, "--release"))
        state = load_state(self.repo)
        self.assertEqual([], state["active_batch"])
        self.assertIsNone(state["active_issue"])
        self.assertEqual(0, self.invoke("fix", primary))
        self.assertEqual([], load_state(self.repo)["issues"][primary].get("waivers", []))

    def test_release_requires_explicit_members_and_is_atomic(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const companion = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        primary, companion = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", primary, companion))
        before = paths(self.repo)["state"].read_bytes()
        for arguments in (("--release",), ("--release", primary, "hang-aaaaaaaaaa")):
            self.assertEqual(2, self.invoke("fix", *arguments))
            self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        self.assertEqual(0, self.invoke("fix", "--release", primary, companion))
        self.assertEqual([], load_state(self.repo)["active_batch"])

    def test_release_settled_member_does_not_reopen_it(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const companion = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        primary, settled = sorted(load_state(self.repo)["issues"])
        self.assertEqual(0, self.invoke("fix", primary, settled))
        mutate_state(self.repo, lambda state: state["issues"][settled].update(status="stale"))
        self.assertEqual(0, self.invoke("fix", "--release", primary, settled))
        state = load_state(self.repo)
        self.assertEqual("stale", state["issues"][settled]["status"])
        self.assertEqual("open", state["issues"][primary]["status"])
        self.assertEqual([], state["active_batch"])
        self.assertIsNone(state["active_issue"])

    def test_defer_primary_defers_the_whole_active_batch(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issues = sorted(
            load_state(self.repo)["issues"].values(), key=lambda issue: issue["files"]
        )
        primary, companion = issues
        self.assertEqual(0, self.invoke("fix", primary["id"], companion["id"]))

        self.assertEqual(
            0,
            self.invoke("fix", primary["id"], "--defer", "one batch-level risk"),
        )

        state = load_state(self.repo)
        self.assertEqual(
            ["deferred", "deferred"],
            [state["issues"][issue["id"]]["status"] for issue in (primary, companion)],
        )
        self.assertIsNone(state["active_issue"])
        self.assertEqual([], state["active_batch"])

    def test_batch_verify_names_companion_whose_finding_remains(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issues = sorted(
            load_state(self.repo)["issues"].values(), key=lambda issue: issue["files"]
        )
        primary, companion = issues
        self.assertEqual(0, self.invoke("fix", primary["id"], companion["id"]))
        (self.repo / primary["files"][0]).unlink()
        stderr = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "verify",
                    "--issue",
                    primary["id"],
                    "--no-review",
                ]
            )

        self.assertEqual(1, rc)
        self.assertIn(companion["id"], stderr.getvalue())
        self.assertIn("original Fallow finding is still present", stderr.getvalue())

    def test_fix_refuses_stale_batch_companion_by_id(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issues = sorted(
            load_state(self.repo)["issues"].values(), key=lambda issue: issue["files"]
        )
        primary, companion = issues
        (self.repo / companion["files"][0]).unlink()
        self.assertEqual(0, self.invoke("scan"))
        stderr = StringIO()

        with redirect_stdout(StringIO()), redirect_stderr(stderr):
            rc = main(
                ["--repo", str(self.repo), "fix", primary["id"], companion["id"]]
            )

        self.assertEqual(2, rc)
        self.assertIn(companion["id"], stderr.getvalue())
        self.assertIn("stale", stderr.getvalue())

    def test_passing_verify_attributes_unrelated_vanished_fallow_issue_only(self) -> None:
        (self.repo / "src" / "side-effect.ts").write_text("export const sideEffect = 3;\n")
        (self.repo / "src" / "review.ts").write_text("export const reviewed = 4;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        fallow_issues = [
            issue
            for issue in state["issues"].values()
            if issue.get("source") == "fallow"
        ]
        primary = next(issue for issue in fallow_issues if issue["files"] == ["src/dead.ts"])
        side_effect = next(
            issue for issue in fallow_issues if issue["files"] == ["src/side-effect.ts"]
        )
        review = {
            "source": "subjective-review",
            "category": "dead_code",
            "title": "Review-only concern",
            "files": ["src/review.ts"],
            "symbols": [],
            "evidence": ["review evidence"],
            "harm": "review concern",
            "proposed_change": "inspect it",
            "invariants": ["behavior stays the same"],
            "risk": "low",
            "priority": "P3",
            "confidence": "high",
            "verification": ["check"],
            "chesterton": "review required",
        }
        review_id = merge_findings(state, [review], "review-1")["ids"][0]
        save_state(self.repo, state)
        self.assertEqual(0, self.invoke("fix", primary["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        (self.repo / "src" / "side-effect.ts").unlink()
        fake_result = {
            "status": "completed",
            "exit_code": 0,
            "duration_seconds": 0.01,
            "packet": "packet.json",
            "output": "review.json",
            "stdout": "review.stdout",
            "stderr": "review.stderr",
            "review": {"reviewed_files": ["src/index.ts"], 
                "verdict": "pass",
                "summary": "The remediation is behavior-preserving.",
                "findings": [],
            },
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake_result)):
            self.assertEqual(0, self.invoke("verify", "--issue", primary["id"]))

        state = load_state(self.repo)
        resolved_by = state["issues"][side_effect["id"]]["history"][-1]
        self.assertEqual("resolved", state["issues"][side_effect["id"]]["status"])
        self.assertEqual("resolved_by", resolved_by["event"])
        self.assertEqual(primary["id"], resolved_by["issue"])
        self.assertNotIn(
            "stale",
            [event["event"] for event in state["issues"][side_effect["id"]]["history"]],
        )
        self.assertEqual("open", state["issues"][review_id]["status"])

    def test_audit_is_changed_code_only_and_persists_result(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        (self.repo / "src" / "new.ts").write_text("export const newValue = 3;\n")
        self.assertEqual(0, self.invoke("audit"))
        state = load_state(self.repo)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / state["latest_audit"] / "snapshot.json").read_text()
        )
        self.assertIn("src/new.ts", snapshot["changed_files"])
        self.assertEqual("pass", snapshot["fallow"]["verdict"])

    def test_audit_error_envelope_cannot_pass(self) -> None:
        self.fake_fallow.write_text(FAKE_FALLOW.replace(
            '{"schema_version": 7, "verdict": "pass", "summary": {}, "attribution": {}}',
            '{"error": True, "message": "synthetic analyzer failure"}',
        ))

        # An analyzer that did not complete is a tool error (exit 2), never a pass.
        self.assertEqual(2, self.invoke("audit"))

    def test_subjective_verify_requires_applicable_fallow_evidence(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))

        def add_subjective(state):
            issue = dict(next_issue(state))
            issue.pop("id")
            issue.update(source="subjective-review", category="architecture", title="Simplify source")
            return merge_findings(state, [issue], "subjective-fixture")["ids"][0]

        identifier = mutate_state(self.repo, add_subjective)
        self.assertEqual(0, self.invoke("fix", identifier))
        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(self.repo / "missing-fallow")}):
            self.assertEqual(1, self.invoke("verify", "--no-review"))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_typescript_audit_fails_closed_when_fallow_cannot_run(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        (self.repo / "src" / "new.ts").write_text("export const newValue = 3;\n")
        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(self.repo / "missing-fallow")}):
            self.assertEqual(2, self.invoke("audit"))

    def test_verify_rejects_a_replacement_deterministic_finding(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        original = next_issue(state)
        self.assertEqual(0, self.invoke("fix", original["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        (self.repo / "src" / "new-dead.ts").write_text("export const replacement = 3;\n")

        self.assertEqual(1, self.invoke("verify", "--issue", original["id"]))

        state = load_state(self.repo)
        self.assertEqual("in_progress", state["issues"][original["id"]]["status"])
        self.assertIn(
            "the fix introduced new deterministic finding(s)",
            state["issues"][original["id"]]["history"][-1]["reasons"][0],
        )

    def test_verify_blocker_explains_an_incomparable_fallow_baseline(self) -> None:
        blockers = _verification_blockers(
            {
                "check_comparison": [],
                "fallow": {"status": "completed"},
                "fallow_comparison": {
                    "comparable": False,
                    "reason": "resolved Fallow config changed",
                },
            },
            {"id": "hang-aaaaaaaaaa", "source": "fallow"},
            [],
        )

        self.assertEqual(
            [
                "Fallow evidence is not comparable with the recorded baseline "
                "(resolved Fallow config changed); run hangover scan --rebaseline"
            ],
            blockers,
        )

    def test_verify_blocker_names_a_dead_code_mode_change(self) -> None:
        blockers = _verification_blockers(
            {
                "check_comparison": [],
                "fallow": {"status": "completed"},
                "fallow_comparison": {
                    "comparable": False,
                    "reason": (
                        "dead-code analysis mode changed "
                        "(baseline syntactic, current type-aware)"
                    ),
                },
            },
            {"id": "hang-aaaaaaaaaa", "source": "fallow"},
            [],
        )

        self.assertEqual(
            [
                "Fallow evidence is not comparable with the recorded baseline "
                "(dead-code analysis mode changed (baseline syntactic, current type-aware)); "
                "run hangover scan --rebaseline"
            ],
            blockers,
        )

    def _issue_with_suppression_recipe(self) -> str:
        package = json.loads((self.repo / "package.json").read_text())
        package["devDependencies"] = {"chrome-launcher": "1.0.0"}
        (self.repo / "package.json").write_text(json.dumps(package))
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        return next(
            issue["id"]
            for issue in state["issues"].values()
            if issue.get("suppression")
            == {"config_key": "ignoreDependencies", "value": "chrome-launcher"}
        )

    def test_suppress_applies_the_fallow_config_remedy_and_marks_the_issue(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        prior_state = load_state(self.repo)
        previous_run = prior_state["baseline_run"]
        previous_snapshot = json.loads(
            (paths(self.repo)["runs"] / previous_run / "snapshot.json").read_text()
        )

        with patch("hangover.cli.run_checks") as run_checks:
            self.assertEqual(0, self.invoke("suppress", identifier, "--reason", "dev tooling"))
        run_checks.assert_not_called()

        config = json.loads((self.repo / ".fallowrc.json").read_text())
        self.assertEqual(["chrome-launcher"], config["ignoreDependencies"])
        state = load_state(self.repo)
        current_run = state["baseline_run"]
        self.assertNotEqual(previous_run, current_run)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / current_run / "snapshot.json").read_text()
        )
        self.assertTrue(snapshot["is_baseline"])
        self.assertNotIn(identifier, snapshot["finding_ids_seen"])
        self.assertEqual(previous_snapshot["checks"], snapshot["checks"])
        self.assertEqual(previous_run, snapshot["checks_inherited_from"])
        reset = next(
            event
            for event in reversed(state["history"])
            if event["event"] == "baseline_reset"
        )
        self.assertEqual("suppression", reset["reason"])
        self.assertEqual(previous_run, reset["previous_run"])
        issue = state["issues"][identifier]
        self.assertEqual("suppressed", issue["status"])
        self.assertEqual("dev tooling", issue["history"][-1]["reason"])
        self.assertIsNone(state["active_issue"])

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(self.repo), "status"]))
        self.assertIn(
            f"baseline checks: inherited from {previous_run}\n", stdout.getvalue()
        )

    def test_suppress_refuses_symlinked_config_without_mutating_state(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        original_state = load_state(self.repo)
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "external.json"
            external.write_text('{"keep": true}\n')
            (self.repo / ".fallowrc.json").symlink_to(external)

            self.assertEqual(2, self.invoke(
                "suppress", identifier, "--reason", "synthetic", "--no-rebaseline"
            ))
            self.assertEqual('{"keep": true}\n', external.read_text())
            self.assertEqual(original_state, load_state(self.repo))

    def test_suppress_failed_atomic_write_preserves_config_and_disposition(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        config_path = self.repo / ".fallowrc.json"
        config_path.write_text('{"keep": true}\n')
        original_state = load_state(self.repo)
        real_replace = os.replace

        def reject_config(source, target):
            if Path(target) == config_path:
                raise OSError("synthetic replace failure")
            return real_replace(source, target)

        with patch("hangover.model.os.replace", side_effect=reject_config):
            self.assertEqual(2, self.invoke(
                "suppress", identifier, "--reason", "synthetic", "--no-rebaseline"
            ))
        self.assertEqual('{"keep": true}\n', config_path.read_text())
        self.assertEqual(original_state, load_state(self.repo))

    def test_ineffective_suppression_leaves_the_baseline_untouched(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        state = load_state(self.repo)
        previous_run = state["baseline_run"]
        state["issues"][identifier]["suppression"]["value"] = "not-the-package"
        save_state(self.repo, state)
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "suppress",
                    identifier,
                    "--reason",
                    "dev tooling",
                ]
            )

        self.assertEqual(1, rc)
        state = load_state(self.repo)
        self.assertEqual(previous_run, state["baseline_run"])
        self.assertIn("still reports", stdout.getvalue())

    def test_suppress_appends_without_clobbering_an_existing_config(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        (self.repo / ".fallowrc.json").write_text(
            json.dumps({"entry": ["src/index.ts"], "ignoreDependencies": ["lighthouse"]})
        )

        self.assertEqual(0, self.invoke("suppress", identifier, "--reason", "dev tooling"))

        config = json.loads((self.repo / ".fallowrc.json").read_text())
        self.assertEqual(["src/index.ts"], config["entry"])
        self.assertEqual(["lighthouse", "chrome-launcher"], config["ignoreDependencies"])

    def test_suppress_no_rebaseline_prints_the_rebaseline_hint(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "suppress",
                    identifier,
                    "--reason",
                    "dev tooling",
                    "--no-rebaseline",
                ]
            )

        self.assertEqual(0, rc)
        self.assertIn(
            "Fallow config changed; run hangover scan --rebaseline before the next verify\n",
            stdout.getvalue(),
        )

    def test_verify_after_suppression_has_comparable_fallow_evidence(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        self.assertEqual(0, self.invoke("suppress", identifier, "--reason", "dev tooling"))
        state = load_state(self.repo)
        dead_issue = next(
            issue
            for issue in state["issues"].values()
            if issue.get("category") == "unused_files"
        )
        self.assertEqual(0, self.invoke("fix", dead_issue["id"]))
        (self.repo / "src" / "dead.ts").unlink()

        self.assertEqual(0, self.invoke("verify", "--issue", dead_issue["id"], "--no-review"))

        state = load_state(self.repo)
        snapshot = json.loads(
            (paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text()
        )
        self.assertTrue(snapshot["fallow_comparison"]["comparable"])

    def test_suppress_detaches_active_member_and_keeps_survivor_verifiable(self) -> None:
        suppressed = self._issue_with_suppression_recipe()
        survivor = next(
            issue["id"] for issue in load_state(self.repo)["issues"].values()
            if issue["category"] == "unused_files"
        )
        self.assertEqual(0, self.invoke("fix", suppressed, survivor))
        before = load_state(self.repo)["issues"][survivor]
        self.assertEqual(0, self.invoke("suppress", suppressed, "--reason", "dev tooling"))
        state = load_state(self.repo)
        self.assertEqual([survivor], state["active_batch"])
        self.assertEqual(survivor, state["active_issue"])
        self.assertEqual("suppressed", state["issues"][suppressed]["status"])
        self.assertEqual(before["fix_dir"], state["issues"][survivor]["fix_dir"])
        self.assertEqual(before["fix_base_commit"], state["issues"][survivor]["fix_base_commit"])
        (self.repo / "src" / "dead.ts").unlink()
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        self.assertEqual("in_progress", load_state(self.repo)["issues"][survivor]["status"])

    def test_suppress_refuses_to_rewrite_a_jsonc_config(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        jsonc = self.repo / ".fallowrc.jsonc"
        jsonc.write_text('{\n  // comment\n  "ignoreDependencies": []\n}\n')

        self.assertEqual(2, self.invoke("suppress", identifier, "--reason", "dev tooling"))

        self.assertEqual(
            '{\n  // comment\n  "ignoreDependencies": []\n}\n', jsonc.read_text()
        )
        self.assertFalse((self.repo / ".fallowrc.json").exists())
        self.assertNotEqual("suppressed", load_state(self.repo)["issues"][identifier]["status"])

    def test_suppress_without_a_recipe_fails_with_guidance(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        identifier = next_issue(state)["id"]

        self.assertEqual(2, self.invoke("suppress", identifier, "--reason", "dev tooling"))

        self.assertNotEqual("suppressed", load_state(self.repo)["issues"][identifier]["status"])

    def test_a_suppressed_finding_seen_again_reopens(self) -> None:
        identifier = self._issue_with_suppression_recipe()
        self.assertEqual(0, self.invoke("suppress", identifier, "--reason", "dev tooling"))
        (self.repo / ".fallowrc.json").unlink()

        self.assertEqual(0, self.invoke("scan"))

        state = load_state(self.repo)
        self.assertEqual("reopened", state["issues"][identifier]["status"])

    def test_verify_accept_waives_an_introduced_finding(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        original = next_issue(state)
        self.assertEqual(0, self.invoke("fix", original["id"]))
        (self.repo / "src" / "dead.ts").unlink()
        (self.repo / "src" / "new-dead.ts").write_text("export const replacement = 3;\n")

        self.assertEqual(1, self.invoke("verify", "--issue", original["id"]))
        state = load_state(self.repo)
        reason = state["issues"][original["id"]]["history"][-1]["reasons"][0]
        introduced = reason.rsplit(": ", 1)[1]

        self.assertEqual(
            2, self.invoke("verify", "--issue", original["id"], "--accept", introduced)
        )
        self.assertEqual(
            0,
            self.invoke(
                "verify",
                "--issue",
                original["id"],
                "--no-review",
                "--accept",
                introduced,
                "--accept-reason",
                "tracked as its own open issue",
            ),
        )
        state = load_state(self.repo)
        waivers = state["issues"][original["id"]]["waivers"]
        self.assertEqual([introduced], [waiver["id"] for waiver in waivers])
        self.assertEqual("tracked as its own open issue", waivers[0]["reason"])

    def test_verify_accept_applies_once_to_every_batch_member_only(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const companion = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        members = sorted(load_state(self.repo)["issues"])
        self.assertEqual(2, len(members))
        self.assertEqual(0, self.invoke("fix", *members))
        (self.repo / "src" / "dead.ts").unlink()
        (self.repo / "src" / "also-dead.ts").unlink()
        (self.repo / "src" / "new-dead.ts").write_text("export const replacement = 3;\n")
        self.assertEqual(1, self.invoke("verify", "--no-review"))
        introduced = next(iter(set(load_state(self.repo)["issues"]) - set(members)))

        for _ in range(2):
            self.assertEqual(0, self.invoke(
                "verify", "--no-review", "--accept", introduced, "--accept", introduced,
                "--accept-reason", "tracked separately",
            ))
        state = load_state(self.repo)
        for identifier in members:
            waivers = state["issues"][identifier]["waivers"]
            self.assertEqual([introduced], [item["id"] for item in waivers])
            self.assertEqual("tracked separately", waivers[0]["reason"])
            self.assertEqual(1, sum(
                item["event"] == "finding_waived"
                for item in state["issues"][identifier]["history"]
            ))
            self.assertEqual("in_progress", state["issues"][identifier]["status"])
        self.assertNotIn("waivers", state["issues"][introduced])
        self.assertEqual("open", state["issues"][introduced]["status"])

    def test_tampered_fix_directory_cannot_redirect_patch_writes(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        issue = next_issue(state)
        self.assertEqual(0, self.invoke("fix", issue["id"]))
        with tempfile.TemporaryDirectory() as outside:
            state = load_state(self.repo)
            state["issues"][issue["id"]]["fix_dir"] = outside
            state["remediations"][state["active_remediation"]]["fix_dir"] = outside
            save_state(self.repo, state)

            self.assertEqual(2, self.invoke("verify", "--issue", issue["id"]))

            self.assertFalse((Path(outside) / "after.patch").exists())

    def test_non_git_audit_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(2, main(["--repo", str(other), "audit"]))

    def test_invalid_audit_base_fails_before_persisting_a_run(self) -> None:
        self.assertEqual(0, self.invoke("init"))

        self.assertEqual(2, self.invoke("audit", "--base", "does-not-exist"))

        self.assertIsNone(load_state(self.repo).get("latest_audit"))

    def test_init_recreates_missing_state(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        paths(self.repo)["state"].unlink()

        self.assertEqual(0, self.invoke("init"))

        self.assertIsNotNone(load_state(self.repo))

    def test_tampered_run_id_cannot_read_outside_state_directory(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        state["latest_run"] = "../../outside"
        save_state(self.repo, state)

        self.assertEqual(2, self.invoke("status"))

    def test_invalid_review_import_returns_a_controlled_error(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        bad_review = self.repo / "bad-review.json"
        bad_review.write_text(
            '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"done","findings":[{}]}\n'
        )

        self.assertEqual(2, self.invoke("review", "--import", str(bad_review)))

        self.assertIsNone(load_state(self.repo).get("latest_review"))

    def test_review_prepare_writes_a_runnable_prompt_next_to_packet(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        self.assertEqual(0, self.invoke("review", "--prepare"))
        review_dirs = [
            directory
            for directory in paths(self.repo)["runs"].iterdir()
            if (directory / "review-packet.json").is_file()
        ]
        self.assertEqual(1, len(review_dirs))
        self.assertIn("Review packet:", (review_dirs[0] / "review-prompt.md").read_text())
        review_run = json.loads((review_dirs[0] / "review-run.json").read_text())
        self.assertEqual("codex", review_run["runner"])

    def test_passing_rereview_closes_only_prior_failed_review_blockers(self) -> None:
        state = new_state(self.repo)
        blocker = {
            "fingerprint": ["post-review", "blocker"],
            "source": "post-review",
            "source_version": None,
            "parent_issue": "parent",
            "category": "test_regression",
            "title": "Stale output remains",
            "evidence": ["evidence"],
            "files": ["dist/stale.js"],
            "symbols": [],
            "harm": "harm",
            "proposed_change": "fix",
            "invariants": ["behavior"],
            "risk": "medium",
            "priority": "P1",
            "confidence": "high",
            "verification": ["verify"],
            "chesterton": "reason",
        }
        follow_up = {
            **blocker,
            "fingerprint": ["post-review", "follow-up"],
            "title": "Follow-up",
            "files": ["src/other.ts"],
        }
        blocker_id = merge_findings(state, [blocker], "failed-review")["ids"][0]
        follow_up_id = merge_findings(state, [follow_up], "passing-review")["ids"][0]
        state["history"].append(
            {
                "event": "review_completed",
                "issue": "parent",
                "run": "failed-review",
                "verdict": "fail",
            }
        )

        _resolve_superseded_post_review_findings(
            state, "parent", [follow_up_id], "verify-2", "passing-review"
        )

        self.assertEqual("resolved", state["issues"][blocker_id]["status"])
        self.assertEqual("open", state["issues"][follow_up_id]["status"])

    def test_review_import_links_expanded_scope_without_collapsing_it(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        first = self.repo / "review-1.json"
        second = self.repo / "review-2.json"
        first.write_text(
            json.dumps(
                {"reviewed_files": ["src/index.ts"], 
                    "verdict": "reviewed",
                    "summary": "Team and authors content is duplicated.",
                    "findings": [
                        {
                            "category": "duplication",
                            "title": "Consolidate team.ts and authors.ts",
                            "evidence": ["both modules export overlapping people"],
                            "files": ["src/content/team.ts", "src/content/authors.ts"],
                            "symbols": ["team", "authors"],
                            "harm": "two sources of truth",
                            "proposed_change": "keep one module",
                            "invariants": ["rendered people stay the same"],
                            "risk": "low",
                            "priority": "P2",
                            "confidence": "high",
                            "verification": ["compare people pages"],
                            "chesterton": "authors was added later",
                        }
                    ],
                }
            )
        )
        second.write_text(
            json.dumps(
                {"reviewed_files": ["src/index.ts"], 
                    "verdict": "reviewed",
                    "summary": "The people lists are still duplicated.",
                    "findings": [
                        {
                            "category": "duplication",
                            "title": "team.ts and authors.ts are the same people list",
                            "evidence": ["seo helper also reads both lists"],
                            "files": [
                                "src/content/team.ts",
                                "src/content/authors.ts",
                                "src/lib/seo.ts",
                            ],
                            "symbols": ["team", "authors", "getTeamMember"],
                            "harm": "two sources of truth",
                            "proposed_change": "consolidate the content modules",
                            "invariants": ["rendered people stay the same"],
                            "risk": "low",
                            "priority": "P2",
                            "confidence": "high",
                            "verification": ["compare people pages"],
                            "chesterton": "authors was added later",
                        }
                    ],
                }
            )
        )

        first_out = StringIO()
        with redirect_stdout(first_out), redirect_stderr(StringIO()):
            self.assertEqual(
                0, main(["--repo", str(self.repo), "review", "--import", str(first)])
            )
        second_out = StringIO()
        with redirect_stdout(second_out), redirect_stderr(StringIO()):
            self.assertEqual(
                0, main(["--repo", str(self.repo), "review", "--import", str(second)])
            )

        self.assertIn("1 new, 0 already tracked", first_out.getvalue())
        self.assertIn("1 new, 0 already tracked", second_out.getvalue())
        state = load_state(self.repo)
        subjective = [
            issue
            for issue in state["issues"].values()
            if issue.get("source") == "subjective-review"
        ]
        self.assertEqual(2, len(subjective))
        self.assertEqual("Consolidate team.ts and authors.ts", subjective[0]["title"])
        self.assertEqual(3, len(subjective[1]["files"]))
        self.assertIn(subjective[0]["id"], subjective[1]["possible_duplicates"])

    def test_dedupe_dry_run_does_not_close_issues(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        state = load_state(self.repo)
        state["issues"] = _duplicate_backlog()
        save_state(self.repo, state)

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "dedupe", "--json"])

        self.assertEqual(0, rc)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["dry_run"])
        self.assertEqual(1, payload["count"])
        self.assertEqual("hang-bbbbbbbbbb", payload["pairs"][0]["duplicate"])
        self.assertEqual("hang-aaaaaaaaaa", payload["pairs"][0]["canonical"])
        state = load_state(self.repo)
        self.assertEqual("open", state["issues"]["hang-aaaaaaaaaa"]["status"])
        self.assertEqual("open", state["issues"]["hang-bbbbbbbbbb"]["status"])

    def test_dedupe_apply_reports_overlap_without_claiming_a_close(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        state = load_state(self.repo)
        state["issues"] = _duplicate_backlog()
        state["issues"]["hang-bbbbbbbbbb"]["files"].append("src/extra.ts")
        save_state(self.repo, state)
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.assertEqual(0, main(["--repo", str(self.repo), "dedupe", "--apply"]))
        self.assertIn("closed 0 duplicate issue(s); 1 overlap suggestion(s) kept open", stdout.getvalue())
        self.assertEqual("open", load_state(self.repo)["issues"]["hang-bbbbbbbbbb"]["status"])

    def test_dedupe_apply_closes_later_issue_as_duplicate_of_earlier(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        state = load_state(self.repo)
        state["issues"] = _duplicate_backlog()
        save_state(self.repo, state)

        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "dedupe", "--apply", "--json"])

        self.assertEqual(0, rc)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["dry_run"])
        state = load_state(self.repo)
        self.assertEqual("open", state["issues"]["hang-aaaaaaaaaa"]["status"])
        self.assertEqual("closed", state["issues"]["hang-bbbbbbbbbb"]["status"])
        self.assertEqual(
            "closed_duplicate",
            state["issues"]["hang-bbbbbbbbbb"]["history"][-1]["event"],
        )
        self.assertEqual(
            "hang-aaaaaaaaaa",
            state["issues"]["hang-bbbbbbbbbb"]["history"][-1]["of"],
        )

    def json_invoke(self, *arguments: str) -> dict:
        """Machine stdout must be exactly one JSON value."""
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            self.rc = main(["--repo", str(self.repo), *arguments])
        return json.loads(stdout.getvalue())

    def test_next_json_reports_ready_work_with_a_concrete_next_action(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        issue = next_issue(load_state(self.repo))

        payload = self.json_invoke("next", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("next", payload["command"])
        self.assertEqual("ready", payload["state"])
        self.assertEqual(issue["id"], payload["issue_id"])
        self.assertEqual(issue["last_seen_run"], payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertEqual(self.action("fix", issue["id"]), payload["next_action"])
        self.assertEqual(issue["id"], payload["data"]["issue"]["id"])
        self.assertEqual([], payload["blockers"])

    def test_next_json_reports_an_in_progress_batch_and_its_recorded_proof(self) -> None:
        identifier = self._ready_fix_for_preflight()
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        state = load_state(self.repo)
        proof = state["remediations"][state["active_remediation"]]["verification"]

        payload = self.json_invoke("next", "--json")

        self.assertEqual("in_progress", payload["state"])
        self.assertEqual(identifier, payload["issue_id"])
        self.assertEqual([identifier], payload["batch"])
        self.assertEqual(proof["id"], payload["proof"])
        self.assertEqual(proof["run"], payload["run"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertEqual(self.action("verify", "--issue", identifier, "--retry-review"), payload["next_action"])

    def test_next_json_reports_no_open_work(self) -> None:
        self._mark_first_issue_stale()

        payload = self.json_invoke("next", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("no_open_work", payload["state"])
        self.assertIsNone(payload["issue_id"])
        self.assertIsNone(payload["data"]["issue"])
        self.assertEqual(self.action("scan"), payload["next_action"])

    def test_next_json_keeps_progress_off_machine_stdout(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "next", "--json"])

        self.assertEqual(0, rc)
        json.loads(stdout.getvalue())
        self.assertNotIn("{", stderr.getvalue())


    def _filter_backlog(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        state = load_state(self.repo)
        state["issues"] = _mixed_backlog()
        save_state(self.repo, state)

    def test_list_json_filters_by_source(self) -> None:
        self._filter_backlog()

        payload = self.json_invoke("list", "--json", "--source", "fallow")

        self.assertEqual(0, self.rc)
        self.assertEqual("list", payload["command"])
        self.assertEqual("ready", payload["state"])
        self.assertEqual(
            ["hang-1111111111"], [item["id"] for item in payload["data"]["issues"]]
        )
        self.assertEqual(1, payload["data"]["count"])
        self.assertEqual(3, payload["data"]["total"])
        self.assertEqual({"source": ["fallow"]}, payload["data"]["filters"])
        self.assertEqual(self.action("fix", "hang-1111111111"), payload["next_action"])

    def test_list_json_filters_by_category_and_status_together(self) -> None:
        self._filter_backlog()

        payload = self.json_invoke(
            "list", "--json", "--category", "duplication", "--status", "open"
        )

        self.assertEqual(
            ["hang-2222222222"], [item["id"] for item in payload["data"]["issues"]]
        )

    def test_list_json_filters_by_file_path_and_directory_prefix(self) -> None:
        self._filter_backlog()

        exact = self.json_invoke("list", "--json", "--file", "src/a.ts")
        self.assertEqual(
            ["hang-2222222222", "hang-3333333333"],
            sorted(item["id"] for item in exact["data"]["issues"]),
        )

        directory = self.json_invoke("list", "--json", "--file", "src")
        self.assertEqual(3, directory["data"]["count"])

    def test_list_json_reports_no_open_work_when_nothing_selectable_matches(
        self,
    ) -> None:
        self._filter_backlog()

        payload = self.json_invoke("list", "--json", "--status", "resolved")

        self.assertEqual(0, self.rc)
        self.assertEqual("no_open_work", payload["state"])
        self.assertEqual(
            ["hang-3333333333"], [item["id"] for item in payload["data"]["issues"]]
        )
        self.assertIsNone(payload["issue_id"])

    def test_list_projects_issues_without_replaying_their_history(self) -> None:
        self._filter_backlog()

        payload = self.json_invoke("list", "--json")

        self.assertEqual(3, payload["data"]["count"])
        for item in payload["data"]["issues"]:
            self.assertNotIn("history", item)
            self.assertEqual(
                {
                    "id",
                    "status",
                    "source",
                    "category",
                    "priority",
                    "title",
                    "files",
                    "last_seen_run",
                },
                set(item),
            )

    def test_list_text_output_names_the_matching_issues(self) -> None:
        self._filter_backlog()
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), "list", "--source", "fallow"])

        self.assertEqual(0, rc)
        self.assertIn("hang-1111111111", stdout.getvalue())
        self.assertNotIn("hang-2222222222", stdout.getvalue())

    def test_list_never_writes_campaign_state(self) -> None:
        self._filter_backlog()
        before = paths(self.repo)["state"].read_bytes()

        self.json_invoke("list", "--json", "--source", "fallow")

        self.assertEqual(before, paths(self.repo)["state"].read_bytes())


    def test_review_json_reports_a_prepared_packet_without_a_proof_claim(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))

        payload = self.json_invoke("review", "--json", "--prepare")

        self.assertEqual(0, self.rc)
        self.assertEqual("review", payload["command"])
        self.assertEqual("review_pending", payload["state"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertTrue(Path(payload["data"]["review"]["packet"]).is_file())
        self.assertEqual("prepared", payload["data"]["review"]["status"])
        route = payload["data"]["review"]
        self.assertTrue(Path(route["schema"]).is_file())
        self.assertTrue(Path(route["prompt"]).is_file())
        self.assertIsNone(route["verification_token"])
        self.assertEqual(self.action("review", "--import", payload["data"]["import"]["path"]), payload["next_action"])

    def test_review_json_reports_a_completed_initial_review(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        fake = {
            "status": "completed",
            "review": {"reviewed_files": ["src/index.ts"], 
                "verdict": "reviewed",
                "summary": "done",
                "findings": [],
            },
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake)):
            payload = self.json_invoke("review", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("passed", payload["state"])
        self.assertEqual("reviewed", payload["data"]["verdict"])
        self.assertEqual(0, payload["data"]["new_findings"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertEqual("codex", payload["data"]["review"]["runner"])
        self.assertIsNotNone(payload["review_run"])

    def test_review_and_run_refuse_failed_or_unperformed_verdicts(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        config = _config(self.repo)
        for exit_code, changes in (
            (7, {"reviewed_files": ["src/index.ts"]}),
            (0, {"reviewed_files": []}),
            (0, {"reviewed_files": None}),
        ):
            verdict = {"reviewed_files": ["src/index.ts"], "verdict": "reviewed", "summary": "Reviewed code", "findings": [], **changes}
            if verdict["reviewed_files"] is None:
                verdict.pop("reviewed_files")
            config["review"]["runner"] = "command"
            config["review"]["command"] = [sys.executable, "-c", f"import sys;print({json.dumps(verdict)!r});sys.exit({exit_code})"]
            paths(self.repo)["config"].write_text(json.dumps(config))
            for arguments in (("review", "--json"), ("run", "--no-checks")):
                with self.subTest(exit_code=exit_code, changes=changes, arguments=arguments):
                    stdout, stderr = StringIO(), StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = main(["--repo", str(self.repo), *arguments])
                    self.assertEqual(2, rc)
                    self.assertIn("tool_error/unverifiable", stderr.getvalue())
                    self.assertNotIn("review: reviewed |", stdout.getvalue())
                    state = load_state(self.repo)
                    self.assertIsNone(state.get("latest_review"))
                    self.assertFalse(any(entry["event"] == "review_completed" for entry in state["history"]))
                    failed = next(entry for entry in reversed(state["history"]) if entry["event"] == "review_failed")
                    record = json.loads((paths(self.repo)["runs"] / failed["run"] / "review-run.json").read_text())
                    self.assertEqual("failed" if exit_code else "unverifiable", record["status"])
                    if arguments[0] == "review":
                        self.assertEqual("tool_error", json.loads(stdout.getvalue())["state"])

    def test_verify_does_not_consume_a_token_for_an_empty_review(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))
        (self.repo / "src" / "dead.ts").unlink()
        config = _config(self.repo)
        config["review"]["runner"] = "command"
        config["review"]["command"] = [sys.executable, "-c", "print('{\"verdict\":\"pass\",\"summary\":\"done\",\"reviewed_files\":[],\"findings\":[]}')"]
        paths(self.repo)["config"].write_text(json.dumps(config))
        payload = self.json_invoke("verify", "--issue", identifier, "--json")
        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        state = load_state(self.repo)
        self.assertEqual("in_progress", state["issues"][identifier]["status"])
        self.assertIsNone(state.get("latest_review"))
        self.assertFalse(state["remediations"][state["active_remediation"]]["pending_review"]["consumed"])

    def test_failed_runner_artifact_and_its_alias_cannot_be_imported(self):
        identifier = self._ready_fix_for_preflight()
        config = _config(self.repo)
        config["review"]["runner"] = "command"
        writer = (
            "import json,sys;from pathlib import Path;"
            "output=Path(sys.argv[1]);packet=json.loads((output.parent/'review-packet.json').read_text());"
            "output.write_text(json.dumps({'verdict':'pass','summary':'failed transport','findings':[],"
            "'reviewed_files':['src/index.ts'],'verification_token':packet['verification_token']}));sys.exit(7)"
        )
        config["review"]["command"] = [sys.executable, "-c", writer, "{output}"]
        paths(self.repo)["config"].write_text(json.dumps(config))
        self.assertEqual(2, self.invoke("verify", "--issue", identifier))
        state = load_state(self.repo)
        pending = state["remediations"][state["active_remediation"]]["pending_review"]
        output = paths(self.repo)["runs"] / pending["id"] / "review.json"
        self.assertTrue(output.is_file())
        alias = output.with_name("alias.json")
        alias.symlink_to(output)
        hardlink = output.with_name("hardlink.json")
        os.link(output, hardlink)
        for artifact in (output, alias, hardlink):
            with self.subTest(artifact=artifact.name):
                payload = self.json_invoke("review", "--issue", identifier, "--import", str(artifact), "--json")
                self.assertEqual(2, self.rc)
                self.assertEqual("tool_error", payload["state"])
                self.assertIn("failed runner output", " ".join(payload["blockers"]))
                self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])
        copied = output.with_name("copied-review.json")
        copied.write_bytes(output.read_bytes())
        reformatted = output.with_name("reformatted-review.json")
        reformatted.write_text(json.dumps(json.loads(output.read_text()), indent=2))
        for artifact in (copied, reformatted):
            with self.subTest(copy=artifact.name):
                payload = self.json_invoke("review", "--issue", identifier, "--import", str(artifact), "--json")
                self.assertEqual(2, self.rc)
                self.assertIn("failed runner output", " ".join(payload["blockers"]))
                self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])
        fresh = output.with_name("manual-review.json")
        verdict = json.loads(output.read_text())
        verdict["summary"] = "fresh manual review of the change"
        fresh.write_text(json.dumps(verdict))
        # This checks the artifact boundary, not reviewer authenticity.
        self.assertEqual(0, self.invoke("review", "--issue", identifier, "--import", str(fresh)))
        self.assertEqual("resolved", load_state(self.repo)["issues"][identifier]["status"])

    def test_missing_inspection_evidence_cannot_be_manually_imported(self):
        identifier, _, output, _ = self._prepare_manual_proof_review()
        value = json.loads(output.read_text())
        value.pop("reviewed_files")
        output.write_text(json.dumps(value))
        for arguments in (("review",), ("review", "--issue", identifier)):
            with self.subTest(arguments=arguments):
                value["verdict"] = "reviewed" if len(arguments) == 1 else "pass"
                output.write_text(json.dumps(value))
                payload = self.json_invoke(*arguments, "--import", str(output), "--json")
                self.assertEqual(2, self.rc)
                self.assertEqual("tool_error", payload["state"])
                self.assertIn("reviewed_files", " ".join(payload["blockers"]))
                self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])
                self.assertIsNone(load_state(self.repo).get("latest_review"))

    def test_doctor_reports_logged_in_codex_that_cannot_start(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        binary = self.repo / "broken-codex"
        binary.write_text("#!/usr/bin/env python3\nimport sys\n"
                          "if '--version' in sys.argv: print('codex-cli 0.160.0'); sys.exit(0)\n"
                          "if sys.argv[1:] == ['login', 'status']: print('Logged in'); sys.exit(0)\n"
                          "if '--help' in sys.argv: print('--permission-profile'); sys.exit(0)\n"
                          "print('bwrap: setting up uid map: Permission denied', file=sys.stderr); sys.exit(1)\n")
        binary.chmod(0o755)
        stdout, stderr = StringIO(), StringIO()
        with patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(binary)}), redirect_stdout(stdout), redirect_stderr(stderr):
            rc = main(["--repo", str(self.repo), "doctor", "--json"])
        self.assertEqual(1, rc)
        payload = json.loads(stdout.getvalue())
        self.assertEqual("logged_in", payload["codex_auth"])
        self.assertEqual("failed", payload["codex_startup"]["status"])
        self.assertIn("runner environment failure", stderr.getvalue())
        self.assertIn("--runner delegate --lane claude", stderr.getvalue())

    def test_doctor_probes_local_codex_only_for_delegate_codex(self):
        self.assertEqual(0, self.invoke("init"))
        binary = self.repo / "broken-codex"
        binary.write_text("#!/usr/bin/env python3\nimport sys\n"
                          "if '--version' in sys.argv: print('codex-cli 0.160.0'); sys.exit(0)\n"
                          "if '--help' in sys.argv: print('--permission-profile'); sys.exit(0)\n"
                          "print('bwrap: setting up uid map: Permission denied', file=sys.stderr); sys.exit(1)\n")
        binary.chmod(0o755)
        config = _config(self.repo)
        config["review"]["runner"] = "delegate"
        for lane in ("codex", "claude"):
            with self.subTest(lane=lane):
                config["review"]["delegate"]["lane"] = lane
                paths(self.repo)["config"].write_text(json.dumps(config))
                stdout, stderr = StringIO(), StringIO()
                with patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(binary)}), redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = main(["--repo", str(self.repo), "doctor", "--json"])
                self.assertEqual(1 if lane == "codex" else 0, rc)
                self.assertEqual("failed" if lane == "codex" else "not_invoked", json.loads(stdout.getvalue())["codex_startup"]["status"])

    def test_review_json_surfaces_the_adapter_error_in_route_and_blockers(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        fake = {
            "status": "error",
            "error": "delegate exited 3: lane refused the model alias",
            "review": None,
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake)):
            payload = self.json_invoke("review", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual(
            "delegate exited 3: lane refused the model alias",
            payload["data"]["review"]["error"],
        )
        self.assertEqual(
            [
                "the review did not complete (status=error): "
                "delegate exited 3: lane refused the model alias; its packet is retained"
            ],
            payload["blockers"],
        )

    def test_review_json_reports_an_imported_review_that_checked_a_proof(self) -> None:
        identifier, _, output, _ = self._prepare_manual_proof_review()

        payload = self.json_invoke(
            "review", "--json", "--issue", identifier, "--import", str(output)
        )

        self.assertEqual(0, self.rc)
        self.assertEqual("resolved", payload["state"])
        self.assertEqual("checked", payload["proof_freshness"])
        self.assertEqual(identifier, payload["issue_id"])
        self.assertEqual("pass", payload["data"]["verdict"])
        self.assertEqual("import", payload["data"]["review"]["runner"])
        self.assertEqual(self.action("next"), payload["next_action"])

    def test_review_json_reports_a_runner_failure_as_a_tool_error(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        fake = {"status": "timeout", "review": None}

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake)):
            payload = self.json_invoke("review", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual("timeout", payload["data"]["review"]["status"])
        self.assertIn("timeout", " ".join(payload["blockers"]))

    def test_verify_json_preflight_error_is_one_tool_error_on_stdout(self) -> None:
        self._ready_fix_for_preflight()

        payload = self.json_invoke("verify", "--json", "--runner", "codex", "--lane", "glm")

        self.assertEqual(2, self.rc)
        self.assertEqual("verify", payload["command"])
        self.assertEqual("tool_error", payload["state"])
        self.assertIsNone(payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertIn("lane", " ".join(payload["blockers"]))

    def test_json_parser_error_still_emits_one_tool_error(self) -> None:
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["--repo", str(self.repo), "verify", "--json", "--no-such-flag"])

        self.assertEqual(2, raised.exception.code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual("verify", payload["command"])
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual(str(self.repo), payload["repo"])

    def test_json_parser_error_origin_comes_from_the_parsed_namespace(self) -> None:
        rows = (
            (["--repo=/an-explicit-target", "verify", "--unknown", "--json"], "verify", "/an-explicit-target"),
            (["--repo", "fix", "verify", "--unknown", "--json"], "verify", "fix"),
            (["--json"], "hangover", str(Path.cwd())),
        )
        for arguments, command, repo in rows:
            with self.subTest(arguments=arguments):
                stdout = StringIO()
                with redirect_stdout(stdout), redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main(arguments)

                self.assertEqual(2, raised.exception.code)
                payload = json.loads(stdout.getvalue())
                self.assertEqual("tool_error", payload["state"])
                self.assertEqual(command, payload["command"])
                self.assertEqual(repo, payload["repo"])

    def test_verify_json_late_error_reports_the_failing_invocations_own_run(self) -> None:
        self._ready_fix_for_preflight()
        runs = []

        def interleaved_verify(*args, **kwargs):
            result = _scan(*args, **kwargs)
            runs.append(result[0]["id"])
            if len(runs) == 1:
                self.assertEqual(0, self.invoke("verify", "--no-review"))
            return result

        with patch("hangover.cli._scan", side_effect=interleaved_verify):
            payload = self.json_invoke("verify", "--json", "--no-review")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertIn("superseded", " ".join(payload["blockers"]))
        self.assertEqual(runs[0], payload["run"])
        self.assertNotEqual(load_state(self.repo)["latest_run"], payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertTrue(Path(payload["artifacts"]["snapshot"]).is_file())

    def test_read_only_json_commands_never_initialize_a_campaign(self) -> None:
        for command in ("preview", "list", "next", "status"):
            with self.subTest(command=command):
                payload = self.json_invoke(command, "--json")

                self.assertEqual(2, self.rc)
                self.assertEqual(command, payload["command"])
                self.assertEqual("tool_error", payload["state"])
                self.assertEqual(self.action("init"), payload["next_action"])
                self.assertFalse(paths(self.repo)["root"].exists())

    def test_next_action_keeps_the_explicit_repository(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))

        payload = self.json_invoke("next", "--json")

        action = shlex.split(payload["next_action"])
        self.assertEqual(str(self.repo), action[action.index("--repo") + 1])
        self.assertEqual(["hangover", "--repo", str(self.repo), "fix", payload["issue_id"]], action)

    def test_imported_batch_review_reports_every_member(self) -> None:
        (self.repo / "src" / "also-dead.ts").write_text("export const alsoDead = 3;\n")
        self.assertEqual(0, self.invoke("run", "--no-review"))
        ids = sorted(load_state(self.repo)["issues"])
        self.assertEqual(2, len(ids))
        self.assertEqual(0, self.invoke("fix", *ids))
        (self.repo / "src" / "dead.ts").unlink()
        (self.repo / "src" / "also-dead.ts").unlink()
        self.assertEqual(0, self.invoke("verify", "--runner", "none"))
        state = load_state(self.repo)
        record = state["remediations"][state["active_remediation"]]
        output = paths(self.repo)["root"] / "manual.json"
        output.write_text(json.dumps({"reviewed_files": ["src/index.ts"], 
            "verdict": "pass", "summary": "Synthetic pass", "findings": [],
            "verification_token": record["pending_review"]["token"],
        }))

        payload = self.json_invoke("review", "--json", "--issue", ids[0], "--import", str(output))

        self.assertEqual(0, self.rc)
        self.assertEqual("resolved", payload["state"])
        self.assertEqual(ids, sorted(payload["batch"]))

    def test_review_json_runner_failure_does_not_claim_a_checked_proof(self) -> None:
        identifier, _, _, _ = self._prepare_manual_proof_review()
        fake = {"status": "timeout", "review": None}

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(fake)):
            payload = self.json_invoke("review", "--json", "--issue", identifier)

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertIsNotNone(payload["proof"])
        self.assertEqual([identifier], payload["batch"])
        self.assertEqual("not_checked", payload["proof_freshness"])

    def test_fix_json_origin_is_not_replaced_by_a_concurrent_verification(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        baseline = state["latest_run"]
        identifier = next_issue(state)["id"]
        (self.repo / "src" / "dead.ts").unlink()
        real_write = hangover_write_json

        def verify_while_the_packet_lands(path, value):
            real_write(path, value)
            if Path(path).name == "fix-packet.json":
                self.assertEqual(0, self.invoke("verify", "--no-review"))

        with patch("hangover.cli.write_json", side_effect=verify_while_the_packet_lands):
            payload = self.json_invoke("fix", "--json", identifier)

        self.assertEqual(0, self.rc)
        self.assertEqual(baseline, payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertNotEqual(baseline, load_state(self.repo)["latest_run"])

    def test_ambiguous_identity_blocker_names_the_batch_member(self) -> None:
        blockers = _verification_blockers(
            {
                "check_comparison": [],
                "fallow": {"status": "completed"},
                "fallow_comparison": {"comparable": True},
                "complexity_families_seen": [["src/handlers.ts", "handler"]],
            },
            {
                "id": "hang-aaaaaaaaaa",
                "source": "fallow",
                "complexity_identity": {
                    "ambiguous": True,
                    "family": ["src/handlers.ts", "handler"],
                },
            },
            [],
        )

        self.assertEqual(
            [
                "hang-aaaaaaaaaa has an ambiguous complexity identity and its family "
                "still has same-name findings; release/reselect it or address the "
                "whole family"
            ],
            blockers,
        )

    def test_scan_names_retained_artifacts_when_it_cannot_save_a_snapshot(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        latest = load_state(self.repo)["latest_run"]
        real_write_json = hangover_write_json

        def refuse_the_snapshot(path, value):
            if Path(path).name == "snapshot.json":
                raise OSError("No space left on device")
            return real_write_json(path, value)

        stderr = StringIO()
        with patch("hangover.cli.write_json", side_effect=refuse_the_snapshot):
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                rc = main(["--repo", str(self.repo), "scan"])

        self.assertEqual(2, rc)
        message = stderr.getvalue()
        self.assertIn("could not save the scan snapshot", message)
        self.assertIn("No space left on device", message)
        self.assertIn("fallow/dead-code.json", message)
        self.assertEqual(latest, load_state(self.repo)["latest_run"])

    def test_next_and_resume_do_not_reset_active_evidence(self) -> None:
        identifier, attempt_id, output, _ = self._prepare_manual_proof_review()
        before = load_state(self.repo)["remediations"][attempt_id]

        self.assertEqual(0, self.invoke("next", "--json"))
        self.assertEqual(0, self.invoke("next"))
        self.assertEqual(0, self.invoke("list", "--json"))
        self.assertEqual(0, self.invoke("fix", "--json", identifier))
        self.assertEqual(0, self.invoke("fix", identifier))

        after = load_state(self.repo)["remediations"][attempt_id]
        self.assertEqual(before["verification"], after["verification"])
        self.assertEqual(before["pending_review"], after["pending_review"])
        self.assertEqual(before["fix_notes"], after["fix_notes"])
        self.assertEqual(before["waivers"], after["waivers"])
        self.assertFalse(after["pending_review"]["consumed"])

        # The evidence chain still closes: the prepared token is unspent.
        self.assertEqual(
            0, self.invoke("review", "--issue", identifier, "--import", str(output))
        )
        self.assertEqual(
            "resolved", load_state(self.repo)["issues"][identifier]["status"]
        )

    def test_audit_json_reports_a_passing_changed_code_gate(self) -> None:
        self.assertEqual(0, self.invoke("init"))

        payload = self.json_invoke("audit", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("audit", payload["command"])
        self.assertEqual("passed", payload["state"])
        self.assertEqual([], payload["blockers"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertEqual(self.action("next"), payload["next_action"])
        self.assertEqual("HEAD", payload["data"]["requested_base"])
        self.assertEqual("passed", payload["data"]["diff_check"])
        self.assertEqual("pass", payload["data"]["fallow"]["verdict"])
        self.assertTrue(Path(payload["artifacts"]["snapshot"]).is_file())
        self.assertEqual(
            payload["run"], json.loads(Path(payload["artifacts"]["snapshot"]).read_text())["id"]
        )

    def test_audit_json_names_a_failing_check_as_a_blocker(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config = json.loads(paths(self.repo)["config"].read_text())
        config["checks"] = [
            {"name": "lint", "command": ["node", "-e", "process.exit(1)"]}
        ]
        paths(self.repo)["config"].write_text(json.dumps(config))

        payload = self.json_invoke("audit", "--json")

        self.assertEqual(1, self.rc)
        self.assertEqual("blocked", payload["state"])
        self.assertIn("native check lint failed", payload["blockers"])
        self.assertEqual(self.action("audit", "--base", "HEAD"), payload["next_action"])

    def test_audit_runs_a_combined_gate_when_no_quick_check_is_configured(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config = json.loads(paths(self.repo)["config"].read_text())
        config["checks"] = [
            {"name": "verify", "command": ["node", "-e", "process.exit(1)"]}
        ]
        paths(self.repo)["config"].write_text(json.dumps(config))

        payload = self.json_invoke("audit", "--json")

        self.assertEqual(1, self.rc)
        self.assertEqual("blocked", payload["state"])
        self.assertIn("native check verify failed", payload["blockers"])
        self.assertEqual("all_no_quick_checks", payload["data"]["check_selection"])
        self.assertEqual(["verify"], [check["name"] for check in payload["data"]["checks"]])

    def test_audit_quick_selection_skips_non_quick_checks(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        config = json.loads(paths(self.repo)["config"].read_text())
        config["checks"] = [
            {"name": "lint", "command": ["node", "-e", "process.exit(0)"]},
            {"name": "test", "command": ["node", "-e", "process.exit(1)"]},
        ]
        paths(self.repo)["config"].write_text(json.dumps(config))

        payload = self.json_invoke("audit", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("quick", payload["data"]["check_selection"])
        self.assertEqual(["lint"], [check["name"] for check in payload["data"]["checks"]])

    def test_audit_json_reports_an_analyzer_that_did_not_complete_as_a_tool_error(
        self,
    ) -> None:
        self.assertEqual(0, self.invoke("init"))
        broken = self.repo / "broken-fallow"
        broken.write_text("#!/usr/bin/env python3\nraise SystemExit(3)\n")
        broken.chmod(0o755)

        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(broken)}):
            payload = self.json_invoke("audit", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertIn(
            "Fallow did not complete, so the changed-code verdict is unverified",
            payload["blockers"],
        )

    def test_verify_json_reports_a_deterministic_pass_awaiting_review(self) -> None:
        identifier = self._ready_fix_for_preflight()

        payload = self.json_invoke("verify", "--json", "--no-review")

        self.assertEqual(0, self.rc)
        self.assertEqual("verify", payload["command"])
        self.assertEqual("review_pending", payload["state"])
        self.assertEqual("passed", payload["data"]["deterministic"])
        self.assertEqual(identifier, payload["issue_id"])
        self.assertEqual([identifier], payload["batch"])
        self.assertEqual("checked", payload["proof_freshness"])
        state = load_state(self.repo)
        proof = state["remediations"][state["active_remediation"]]["verification"]
        self.assertEqual(proof["id"], payload["proof"])
        self.assertEqual(proof["run"], payload["run"])
        self.assertEqual(
            self.action("review", "--issue", identifier), payload["next_action"]
        )
        self.assertIsNone(payload["data"]["review"])
        self.assertTrue(Path(payload["artifacts"]["snapshot"]).is_file())

    def test_verify_json_reports_blockers_it_actually_checked(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.invoke("fix", identifier))

        payload = self.json_invoke("verify", "--json", "--no-review")

        self.assertEqual(1, self.rc)
        self.assertEqual("blocked", payload["state"])
        # The gate ran, but no proof exists whose binding could have been checked.
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertIn(
            "the original Fallow finding is still present",
            " ".join(payload["blockers"]),
        )
        self.assertIsNone(payload["proof"])
        self.assertEqual(
            self.action("verify", "--issue", identifier), payload["next_action"]
        )

    def test_verify_json_resolves_and_reports_the_review_route(self) -> None:
        identifier = self._ready_fix_for_preflight()
        review = {
            "status": "completed",
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic pass", "findings": []},
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("resolved", payload["state"])
        self.assertEqual("checked", payload["proof_freshness"])
        self.assertEqual([identifier], payload["batch"])
        self.assertIsNotNone(payload["review_run"])
        self.assertEqual("pass", payload["data"]["verdict"])
        self.assertEqual(self.action("next"), payload["next_action"])
        route = payload["data"]["review"]
        self.assertEqual({"runner": "codex"}, route["requested_review"])
        self.assertEqual("ready", route["preflight"]["status"])
        self.assertEqual("not_probed", route["preflight"]["credential_validity"])
        self.assertEqual("completed", route["status"])
        self.assertNotIn("reported_route", route)
        self.assertEqual(
            "resolved", load_state(self.repo)["issues"][identifier]["status"]
        )

    def test_verify_json_passes_through_a_reported_route_without_inventing_one(
        self,
    ) -> None:
        self._ready_fix_for_preflight()
        review = {
            "status": "completed",
            "reported_route": {"model": "a-model-the-adapter-reported"},
            "review": {"reviewed_files": ["src/index.ts"], "verdict": "pass", "summary": "Synthetic pass", "findings": []},
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual(
            {"model": "a-model-the-adapter-reported"},
            payload["data"]["review"]["reported_route"],
        )

    def test_verify_json_reports_a_review_that_did_not_complete_as_a_tool_error(
        self,
    ) -> None:
        identifier = self._ready_fix_for_preflight()
        review = {"status": "timeout", "review": None}

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual("timeout", payload["data"]["review"]["status"])
        self.assertIn("timeout", " ".join(payload["blockers"]))
        self.assertEqual(
            self.action("verify", "--issue", identifier, "--retry-review", "--runner", "codex"), payload["next_action"]
        )
        self.assertNotEqual(
            "resolved", load_state(self.repo)["issues"][identifier]["status"]
        )

    def test_verify_json_surfaces_the_adapter_error_in_route_and_blockers(
        self,
    ) -> None:
        self._ready_fix_for_preflight()
        review = {
            "status": "error",
            "error": "delegate exited 3: lane refused the model alias",
            "review": None,
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("tool_error", payload["state"])
        route = payload["data"]["review"]
        self.assertEqual("error", route["status"])
        self.assertEqual("delegate exited 3: lane refused the model alias", route["error"])
        self.assertEqual(
            [
                "the fresh review did not complete (status=error): "
                "delegate exited 3: lane refused the model alias; its packet is retained"
            ],
            payload["blockers"],
        )

    def test_verify_json_omits_error_when_the_adapter_reports_none(self) -> None:
        self._ready_fix_for_preflight()
        review = {"status": "timeout", "error": None, "review": None}

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual("tool_error", payload["state"])
        self.assertIsNone(payload["data"]["review"]["error"])
        self.assertEqual(
            ["the fresh review did not complete (status=timeout); its packet is retained"],
            payload["blockers"],
        )

    def test_verify_json_reports_a_failed_verdict_as_blocked(self) -> None:
        self._ready_fix_for_preflight()
        review = {
            "status": "completed",
            "review": {"reviewed_files": ["src/index.ts"], 
                "verdict": "fail",
                "summary": "Synthetic rejection",
                "findings": [],
            },
        }

        with patch("hangover.cli.run_codex_review", side_effect=packet_token_runner(review)):
            payload = self.json_invoke("verify", "--json")

        self.assertEqual(1, self.rc)
        self.assertEqual("blocked", payload["state"])
        self.assertEqual("fail", payload["data"]["verdict"])
        self.assertIn("did not approve", " ".join(payload["blockers"]))

    def test_verify_json_reports_a_prepared_packet_as_review_pending(self) -> None:
        identifier = self._ready_fix_for_preflight()

        payload = self.json_invoke("verify", "--json", "--runner", "none")

        self.assertEqual(0, self.rc)
        self.assertEqual("review_pending", payload["state"])
        self.assertIsNotNone(payload["review_run"])
        self.assertEqual("checked", payload["proof_freshness"])
        expected = paths(self.repo)["runs"] / payload["review_run"] / "review.json"
        self.assertEqual(
            self.action("review", "--issue", identifier, "--import", str(expected)),
            payload["next_action"],
        )
        self.assertEqual(str(expected), payload["data"]["import"]["path"])
        self.assertIn("fresh reviewer", payload["data"]["import"]["prerequisite"])
        self.assertFalse(expected.exists())
        self.assertTrue(Path(payload["data"]["review"]["packet"]).is_file())
        route = payload["data"]["review"]
        self.assertTrue(Path(route["schema"]).is_file())
        self.assertTrue(Path(route["prompt"]).is_file())
        packet = json.loads(Path(route["packet"]).read_text())
        self.assertEqual(packet["verification_token"], route["verification_token"])
        self.assertTrue(route["verification_token"])

    def test_fix_json_reports_the_started_batch_and_its_packet(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        state = load_state(self.repo)
        identifier = next_issue(state)["id"]
        started_from = state["latest_run"]

        payload = self.json_invoke("fix", "--json", identifier)

        self.assertEqual(0, self.rc)
        self.assertEqual("fix", payload["command"])
        self.assertEqual("in_progress", payload["state"])
        self.assertEqual(identifier, payload["issue_id"])
        self.assertEqual([identifier], payload["batch"])
        self.assertEqual(started_from, payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertEqual(self.action("verify", "--issue", identifier), payload["next_action"])
        self.assertEqual(identifier, payload["data"]["packet"]["issue"]["id"])
        self.assertFalse(payload["data"]["resumed"])
        self.assertTrue(Path(payload["artifacts"]["fix_dir"]).is_dir())
        self.assertTrue(Path(payload["artifacts"]["before_patch"]).is_file())

    def test_fix_json_resume_reports_the_recorded_proof(self) -> None:
        identifier = self._ready_fix_for_preflight()
        self.assertEqual(0, self.invoke("verify", "--no-review"))
        state = load_state(self.repo)
        proof = state["remediations"][state["active_remediation"]]["verification"]

        payload = self.json_invoke("fix", "--json", identifier)

        self.assertEqual(0, self.rc)
        self.assertEqual("in_progress", payload["state"])
        self.assertTrue(payload["data"]["resumed"])
        self.assertTrue(payload["data"]["packet"]["resumed"])
        self.assertEqual(proof["id"], payload["proof"])
        self.assertEqual(proof["run"], payload["run"])
        self.assertEqual("not_checked", payload["proof_freshness"])

    def test_fix_json_reports_no_open_work(self) -> None:
        self._mark_first_issue_stale()

        payload = self.json_invoke("fix", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("no_open_work", payload["state"])
        self.assertIsNone(payload["issue_id"])
        self.assertEqual(self.action("scan"), payload["next_action"])

    def _json_invoke_on_a_new_campaign(self, *arguments: str) -> tuple[dict, str]:
        """A mutating command that initializes on the way keeps stdout machine-only."""
        self.assertFalse(paths(self.repo)["root"].exists())
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.rc = main(["--repo", str(self.repo), *arguments])
        self.assertTrue(paths(self.repo)["config"].is_file())
        self.assertIn("initialized ", stderr.getvalue())
        return json.loads(stdout.getvalue()), stderr.getvalue()

    def test_fix_json_on_a_new_campaign_keeps_initialization_prose_off_stdout(self) -> None:
        payload, _ = self._json_invoke_on_a_new_campaign("fix", "--json")

        self.assertEqual(0, self.rc)
        self.assertEqual("fix", payload["command"])
        self.assertEqual("no_open_work", payload["state"])
        self.assertEqual(self.action("scan"), payload["next_action"])

    def test_verify_json_on_a_new_campaign_is_one_tool_error_on_stdout(self) -> None:
        payload, stderr = self._json_invoke_on_a_new_campaign("verify", "--json")

        self.assertEqual(2, self.rc)
        self.assertEqual("verify", payload["command"])
        self.assertEqual("tool_error", payload["state"])
        self.assertIsNone(payload["run"])
        self.assertIsNone(payload["proof"])
        self.assertEqual("not_checked", payload["proof_freshness"])
        self.assertIn("no active issue", " ".join(payload["blockers"]))
        self.assertEqual(self.action("fix"), payload["next_action"])
        self.assertIn("hangover: no active issue", stderr)

    def test_fix_json_reports_a_deferral_and_what_remains(self) -> None:
        self.assertEqual(0, self.invoke("run", "--no-review"))
        identifier = next_issue(load_state(self.repo))["id"]

        payload = self.json_invoke("fix", "--json", "--defer", "not now", identifier)

        self.assertEqual(0, self.rc)
        self.assertEqual("no_open_work", payload["state"])
        self.assertEqual("deferred", payload["data"]["action"])
        self.assertEqual([identifier], payload["data"]["issues"])
        self.assertEqual("not now", payload["data"]["reason"])
        self.assertEqual("deferred", load_state(self.repo)["issues"][identifier]["status"])

    def test_fix_json_reports_a_release(self) -> None:
        identifier = self._ready_fix_for_preflight()

        payload = self.json_invoke("fix", "--json", "--release", identifier)

        self.assertEqual(0, self.rc)
        self.assertEqual("released", payload["data"]["action"])
        self.assertEqual([identifier], payload["data"]["issues"])
        self.assertEqual("ready", payload["state"])
        self.assertEqual(self.action("fix", identifier), payload["next_action"])

    def _preview_backlog(self) -> None:
        self.assertEqual(0, self.invoke("init"))
        state = load_state(self.repo)
        state["issues"] = _overlap_backlog()
        save_state(self.repo, state)

    def test_preview_reports_selected_members_their_files_and_overlap(self) -> None:
        self._preview_backlog()

        payload = self.json_invoke(
            "preview", "--json", "hang-aaaa000001", "hang-aaaa000002"
        )

        self.assertEqual(0, self.rc)
        self.assertEqual("preview", payload["command"])
        self.assertEqual("ready", payload["state"])
        self.assertEqual(["hang-aaaa000001", "hang-aaaa000002"], payload["batch"])
        self.assertEqual(
            ["hang-aaaa000001", "hang-aaaa000002"],
            [member["id"] for member in payload["data"]["members"]],
        )
        self.assertEqual(
            ["src/a.ts", "src/b.ts"], payload["data"]["members"][0]["files"]
        )
        self.assertEqual(["src/a.ts"], payload["data"]["overlap"]["shared_files"])
        self.assertEqual("partial", payload["data"]["overlap"]["file_overlap"])
        self.assertEqual(
            ["src/a.ts", "src/b.ts", "src/c.ts"], payload["data"]["files"]
        )
        self.assertEqual(
            self.action("fix", "hang-aaaa000001", "hang-aaaa000002"), payload["next_action"]
        )

    def test_preview_names_outliers_that_share_no_file_with_the_batch(self) -> None:
        self._preview_backlog()

        payload = self.json_invoke(
            "preview", "--json", "hang-aaaa000001", "hang-aaaa000002", "hang-aaaa000003"
        )

        self.assertEqual(
            [
                {
                    "id": "hang-aaaa000003",
                    "reason": "shares no file with another selected member",
                }
            ],
            payload["data"]["outliers"],
        )

    def test_preview_does_not_claim_semantic_coherence_from_overlap(self) -> None:
        self._preview_backlog()

        payload = self.json_invoke(
            "preview", "--json", "hang-aaaa000001", "hang-aaaa000002"
        )

        overlap = payload["data"]["overlap"]
        self.assertNotIn("coherent", overlap)
        self.assertEqual(
            "file overlap is not semantic coherence; confirm the remediation "
            "unit before activating this batch",
            overlap["caveat"],
        )

    def test_preview_reports_no_file_overlap_honestly(self) -> None:
        self._preview_backlog()

        payload = self.json_invoke(
            "preview", "--json", "hang-aaaa000001", "hang-aaaa000003"
        )

        self.assertEqual([], payload["data"]["overlap"]["shared_files"])
        self.assertEqual("none", payload["data"]["overlap"]["file_overlap"])

    def test_preview_defaults_to_the_highest_priority_open_issues(self) -> None:
        self._preview_backlog()

        payload = self.json_invoke("preview", "--json", "--limit", "2")

        self.assertEqual(["hang-aaaa000001", "hang-aaaa000002"], payload["batch"])

    def test_preview_refuses_a_settled_member_without_activating_anything(self) -> None:
        self._preview_backlog()
        before = paths(self.repo)["state"].read_bytes()

        payload = self.json_invoke(
            "preview", "--json", "hang-aaaa000001", "hang-aaaa000004"
        )

        self.assertEqual(1, self.rc)
        self.assertEqual("blocked", payload["state"])
        self.assertEqual(
            ["hang-aaaa000004 is resolved; only open or reopened issues are selectable"],
            payload["blockers"],
        )
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())

    def test_preview_never_mutates_state_or_writes_a_run(self) -> None:
        self._preview_backlog()
        before = paths(self.repo)["state"].read_bytes()
        runs_before = sorted(path.name for path in paths(self.repo)["runs"].glob("*"))

        self.json_invoke("preview", "--json", "hang-aaaa000001", "hang-aaaa000002")

        state = load_state(self.repo)
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        self.assertIsNone(state.get("active_issue"))
        self.assertIsNone(state.get("active_remediation"))
        self.assertEqual(
            runs_before, sorted(path.name for path in paths(self.repo)["runs"].glob("*"))
        )

    def test_preview_rejects_an_unknown_issue(self) -> None:
        self._preview_backlog()

        self.assertEqual(2, self.invoke("preview", "hang-0000000000"))

    def test_preview_text_output_names_members_and_shared_files(self) -> None:
        self._preview_backlog()
        stdout = StringIO()

        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(
                [
                    "--repo",
                    str(self.repo),
                    "preview",
                    "hang-aaaa000001",
                    "hang-aaaa000002",
                ]
            )

        output = stdout.getvalue()
        self.assertEqual(0, rc)
        self.assertIn("hang-aaaa000001", output)
        self.assertIn("shared files: src/a.ts", output)
        self.assertIn("file overlap is not semantic coherence", output)


def _overlap_backlog() -> dict:
    common = {
        "harm": "carries unused surface",
        "proposed_change": "delete it",
        "confidence": "high",
        "risk": "low",
        "invariants": [],
        "symbols": [],
        "source": "subjective-review",
        "category": "duplication",
        "first_seen": "2026-09-01T00:00:00+00:00",
        "last_seen": "2026-09-01T00:00:00+00:00",
        "last_seen_run": "run-1",
        "history": [],
    }
    members = (
        ("hang-aaaa000001", "P1", "open", ["src/a.ts", "src/b.ts"]),
        ("hang-aaaa000002", "P2", "open", ["src/a.ts", "src/c.ts"]),
        ("hang-aaaa000003", "P3", "open", ["src/z.ts"]),
        ("hang-aaaa000004", "P1", "resolved", ["src/a.ts"]),
    )
    return {
        identifier: {
            **common,
            "id": identifier,
            "priority": priority,
            "status": status,
            "title": f"{identifier} touches {', '.join(files)}",
            "files": files,
        }
        for identifier, priority, status, files in members
    }


def _mixed_backlog() -> dict:
    common = {
        "harm": "carries unused surface",
        "proposed_change": "delete it",
        "confidence": "high",
        "risk": "low",
        "invariants": [],
        "symbols": [],
        "first_seen": "2026-09-01T00:00:00+00:00",
        "last_seen": "2026-09-01T00:00:00+00:00",
        "history": [],
    }
    return {
        "hang-1111111111": {
            **common,
            "id": "hang-1111111111",
            "source": "fallow",
            "category": "unused_files",
            "status": "open",
            "priority": "P1",
            "title": "src/dead.ts is unreferenced",
            "files": ["src/dead.ts"],
            "last_seen_run": "run-1",
        },
        "hang-2222222222": {
            **common,
            "id": "hang-2222222222",
            "source": "subjective-review",
            "category": "duplication",
            "status": "open",
            "priority": "P2",
            "title": "a.ts and b.ts repeat the same parser",
            "files": ["src/a.ts", "src/b.ts"],
            "last_seen_run": "run-2",
        },
        "hang-3333333333": {
            **common,
            "id": "hang-3333333333",
            "source": "post-review",
            "category": "complexity",
            "status": "resolved",
            "priority": "P3",
            "title": "a.ts nests four levels deep",
            "files": ["src/a.ts"],
            "last_seen_run": "run-3",
        },
    }


def _duplicate_backlog() -> dict:
    earlier = {
        "id": "hang-aaaaaaaaaa",
        "source": "subjective-review",
        "source_version": None,
        "category": "duplication",
        "title": "Consolidate team.ts and authors.ts",
        "evidence": ["overlap"],
        "files": ["src/content/team.ts", "src/content/authors.ts"],
        "symbols": ["team", "authors"],
        "harm": "two sources of truth",
        "proposed_change": "consolidate",
        "invariants": ["behavior"],
        "risk": "low",
        "priority": "P2",
        "confidence": "high",
        "verification": ["check pages"],
        "chesterton": "authors added later",
        "status": "open",
        "first_seen": "2026-08-26T17:33:00+00:00",
        "last_seen": "2026-08-26T17:33:00+00:00",
        "last_seen_run": "review-1",
        "history": [{"at": "2026-08-26T17:33:00+00:00", "event": "opened", "run": "review-1"}],
    }
    later = {
        **earlier,
        "id": "hang-bbbbbbbbbb",
        "title": "team.ts and authors.ts are the same people list",
        "files": list(earlier["files"]),
        "symbols": list(earlier["symbols"]),
        "first_seen": "2026-08-26T18:00:00+00:00",
        "last_seen": "2026-08-26T18:00:00+00:00",
        "last_seen_run": "review-2",
        "history": [{"at": "2026-08-26T18:00:00+00:00", "event": "opened", "run": "review-2"}],
    }
    return {earlier["id"]: earlier, later["id"]: later}


def _echo_token_review(verdict: str = "pass", token: object = "echo"):
    """An automated-runner stub that answers like a reviewer which read its packet.

    token "echo" returns the packet's verification_token; anything else is
    returned as the token (None for a reviewer that omits it).
    """
    def run(repo, review_dir, packet, mode, timeout, **_):
        value = json.loads(Path(packet).read_text())["verification_token"] if token == "echo" else token
        return {"status": "completed", "review": {
            "reviewed_files": ["src/index.ts"], "verdict": verdict, "summary": "Synthetic review",
            "findings": [], "declared_changes_assessed": [], "verification_token": value}}
    return run


class CliContractTests(unittest.TestCase):
    """The command contracts a stranger or an agent driving --json relies on."""

    def setUp(self) -> None:
        self.case = CliTests()
        self.case.setUp()
        self.addCleanup(self.case.tearDown)
        self.repo = self.case.repo

    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--repo", str(self.repo), *arguments])
        return code, out.getvalue(), err.getvalue()

    def set_config(self, **changes) -> None:
        config = json.loads(paths(self.repo)["config"].read_text())
        config.update(changes)
        paths(self.repo)["config"].write_text(json.dumps(config))

    def ready_fix(self) -> str:
        self.assertEqual(0, self.run_main("run", "--no-review")[0])
        identifier = next_issue(load_state(self.repo))["id"]
        self.assertEqual(0, self.run_main("fix", identifier)[0])
        (self.repo / "src/dead.ts").unlink()
        return identifier

    # M5: no discoverable gate
    def test_verify_with_no_checks_refuses_to_resolve_on_the_model_alone(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[])
        identifier = self.ready_fix()
        before = paths(self.repo)["state"].read_bytes()
        with patch("hangover.cli._scan", wraps=_scan) as scanner, \
                patch("hangover.cli.run_codex_review", side_effect=_echo_token_review()):
            code, out, err = self.run_main("verify", "--json")
        self.assertEqual(2, code)
        payload = json.loads(out)
        self.assertEqual("tool_error", payload["state"])
        self.assertIn("--model-only", payload["blockers"][0])
        self.assertEqual(self.case.action("verify", "--issue", identifier, "--model-only"), payload["next_action"])
        scanner.assert_not_called()
        self.assertEqual(before, paths(self.repo)["state"].read_bytes())
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_model_only_verify_resolves_and_says_so_everywhere(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[])
        identifier = self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review()):
            code, out, _ = self.run_main("verify", "--model-only")
        self.assertEqual(0, code)
        self.assertIn("gate: NONE, model-only proof", out)
        self.assertIn(f"resolved {identifier} on a MODEL-ONLY proof", out)
        state = load_state(self.repo)
        self.assertEqual("resolved", state["issues"][identifier]["status"])
        events = [event for event in state["issues"][identifier]["history"]
                  if event["event"] == "deterministic_verification_passed"]
        self.assertTrue(events and events[-1].get("model_only") is True)
        code, out, _ = self.run_main("status")
        self.assertIn("latest gate: NONE, model-only proof", out)
        self.assertNotIn("latest gate: ran", out)
        self.assertIn("checks: none configured", out)

    def test_model_only_json_labels_the_proof(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[])
        self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review()):
            code, out, _ = self.run_main("verify", "--model-only", "--json")
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual("resolved", payload["state"])
        self.assertIs(True, payload["data"]["model_only"])
        self.assertEqual("model_only", payload["data"]["gate"]["mode"])

    def test_model_only_is_refused_when_checks_exist(self) -> None:
        self.ready_fix()
        with patch("hangover.cli._scan", wraps=_scan) as scanner:
            code, _, err = self.run_main("verify", "--model-only")
        self.assertEqual(2, code)
        self.assertIn("--model-only applies only when no checks are configured", err)
        scanner.assert_not_called()

    # M7: analyzer coverage
    def python_only_repo(self) -> None:
        for path in self.repo.glob("src/*.ts"):
            path.unlink()
        (self.repo / "package.json").unlink()
        (self.repo / "app.py").write_text("def main():\n    return 1\n")
        (self.repo / "lib.py").write_text("VALUE = 2\n")
        subprocess.run(["git", "-C", self.repo, "add", "-A"], check=True)
        subprocess.run(["git", "-C", self.repo, "-c", "user.name=Hangover Test", "-c",
                        "user.email=hangover@example.invalid", "commit", "-qm", "python"], check=True)

    def test_python_only_repo_is_not_reported_as_clean(self) -> None:
        self.python_only_repo()
        code, out, _ = self.run_main("run", "--no-review")
        self.assertEqual(0, code)
        self.assertIn("no deterministic analyzer covers 2 of 2 source files (.py 2)", out)
        self.assertIn("analyzed: nothing", out)
        code, out, _ = self.run_main("next")
        self.assertEqual(0, code)
        self.assertIn("no open issues", out)
        self.assertIn("no deterministic analyzer covers 2 of 2 source files", out)
        code, out, _ = self.run_main("next", "--json")
        self.assertEqual(2, json.loads(out)["data"]["analyzer_coverage"]["uncovered_files"])
        code, out, _ = self.run_main("status", "--json")
        coverage = json.loads(out)["analyzer_coverage"]
        self.assertEqual({".py": 2}, coverage["uncovered_by_suffix"])

    def test_scan_names_the_languages_fallow_covered(self) -> None:
        (self.repo / "tool.py").write_text("print(1)\n")
        reported = self.repo / ".fake-fallow-files-analyzed"
        reported.write_text("2")
        code, out, _ = self.run_main("scan")
        self.assertEqual(0, code)
        self.assertIn("analyzed: TypeScript/JavaScript 2 file(s) (fallow)", out)
        self.assertIn("no deterministic analyzer covers 1 of 3 source files (.py 1)", out)
        snapshot = json.loads((paths(self.repo)["runs"] / load_state(self.repo)["latest_run"] / "snapshot.json").read_text())
        self.assertEqual(2, snapshot["analyzer_coverage"]["analyzers"]["fallow"]["files"])
        # A Fallow that reports no count: only its language support is known, and the scan says so.
        reported.unlink()
        code, out, _ = self.run_main("scan")
        self.assertEqual(0, code)
        self.assertIn("analyzed: TypeScript/JavaScript (fallow ran; it reported no file count, "
                      "2 file(s) in languages it supports)", out)
        self.assertIn("coverage: unknown for 2 of 3 source files", out)

    def test_coverage_counts_what_fallow_reports_it_analyzed(self) -> None:
        from hangover.cli import _analyzer_coverage, _coverage_lines
        files = {".ts": 4, ".json": 2}
        rust = {"status": "not_applicable"}
        # Fallow's .fallowrc.json ignorePatterns excluded 3 of the 4: its health summary says 1.
        scan = {"status": "completed", "commands": {"health": {"data": {"summary": {"files_analyzed": 1}}}}}
        audit = {"status": "completed", "command": {"data": {"complexity": {"summary": {"files_analyzed": 1}}}}}
        for fallow in (scan, audit):
            with self.subTest(shape="scan" if "commands" in fallow else "audit"):
                coverage = _analyzer_coverage(files, fallow, rust)
                item = coverage["analyzers"]["fallow"]
                self.assertEqual((1, 4, 3, "reported"),
                                 (item["files"], item["language_files"], item["not_analyzed"], item["files_basis"]))
                self.assertEqual(3, coverage["uncovered_files"])
                lines = _coverage_lines(coverage)
                self.assertIn("analyzed: TypeScript/JavaScript 1 of 4 file(s) (fallow)", lines)
                self.assertTrue(any("covers 3 of 4 source files" in line and "fallow did not analyze 3" in line
                                    for line in lines), lines)
                self.assertFalse(any("cover all" in line for line in lines), lines)
        # No count reported: only language support is known, and the output says so.
        coverage = _analyzer_coverage(files, {"status": "completed", "commands": {}}, rust)
        item = coverage["analyzers"]["fallow"]
        self.assertEqual((None, "unreported", None), (item["files"], item["files_basis"], item["not_analyzed"]))
        self.assertEqual(4, coverage["unknown_files"])
        lines = _coverage_lines(coverage)
        self.assertIn("analyzed: TypeScript/JavaScript (fallow ran; it reported no file count, "
                      "4 file(s) in languages it supports)", lines)
        self.assertTrue(any(line.startswith("coverage: unknown for 4 of 4 source files") for line in lines), lines)
        self.assertFalse(any("cover all" in line for line in lines), lines)

    def test_audit_of_a_python_change_says_no_analyzer_read_it(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[])
        (self.repo / "tool.py").write_text("print(1)\n")
        code, out, _ = self.run_main("audit")
        self.assertEqual(0, code)
        self.assertIn("no deterministic analyzer covers 1 of 1 changed source files (.py 1)", out)

    # m3: one analyzer policy
    def test_audit_honours_a_disabled_fallow(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[], fallow={"enabled": False})
        marker = Path(self.case.temp.name + "-fallow-ran")
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        loud = self.repo / "loud-fallow"
        # The version probe is identity, not analysis; any analysis call leaves the marker.
        loud.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "fallow 3.31.0"; exit 0; fi\n'
                        f"echo \"$*\" >> '{marker}'\nexit 3\n")
        loud.chmod(0o755)
        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(loud)}):
            code, out, _ = self.run_main("audit", "--json")
        self.assertEqual(0, code, out)
        payload = json.loads(out)
        self.assertEqual("passed", payload["state"])
        self.assertEqual("disabled", payload["data"]["fallow"]["status"])
        self.assertFalse(marker.exists(), "audit invoked a disabled Fallow")

    # m2: one mapping from state to exit code and envelope
    def test_audit_tool_error_exits_2(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        self.set_config(checks=[])
        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(self.repo / "missing-fallow")}):
            code, out, err = self.run_main("audit", "--json")
        payload = json.loads(out)
        self.assertEqual("tool_error", payload["state"])
        self.assertEqual(2, code)
        with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(self.repo / "missing-fallow")}):
            code, out, err = self.run_main("audit")
        self.assertEqual(2, code)
        self.assertIn("audit: tool_error", out)
        self.assertIn("Fallow did not complete", err)

    def test_occupied_state_path_gives_a_json_error_not_a_traceback(self) -> None:
        (self.repo / ".hangover").write_text("not a directory\n")
        code, out, err = self.run_main("review", "--prepare", "--json")
        self.assertEqual(2, code)
        payload = json.loads(out)
        self.assertEqual("tool_error", payload["state"])
        self.assertIn("is not a directory", payload["blockers"][0])
        self.assertNotIn("Traceback", err)

    # m10: readable output and real errors
    def test_fix_of_an_unknown_id_is_an_error(self) -> None:
        self.assertEqual(0, self.run_main("run", "--no-review")[0])
        code, out, err = self.run_main("fix", "hang-0000000000")
        self.assertEqual(2, code)
        self.assertIn("unknown issue hang-0000000000", err)
        self.assertNotIn("no open issues", out)
        code, out, _ = self.run_main("fix", "hang-0000000000", "--json")
        self.assertEqual(2, code)
        self.assertEqual("tool_error", json.loads(out)["state"])

    def test_next_prints_text_and_doctor_prints_json_only_on_request(self) -> None:
        self.assertEqual(0, self.run_main("run", "--no-review")[0])
        issue = next_issue(load_state(self.repo))
        code, out, _ = self.run_main("next")
        self.assertEqual(0, code)
        self.assertTrue(out.startswith(f"{issue['id']} [{issue['priority']}] {issue['title']}"), out)
        with self.assertRaises(ValueError):
            json.loads(out.split("\n\nStart:")[0])
        self.assertIn("Start: " + self.case.action("fix", issue["id"]), out)
        code, out, _ = self.run_main("doctor")
        with self.assertRaises(ValueError):
            json.loads(out)
        self.assertIn("review runner: codex", out)
        code, out, _ = self.run_main("doctor", "--json")
        self.assertEqual("codex", json.loads(out)["review_runner"])

    # M10: first-run reviewer advice
    def test_logged_out_codex_advice_names_options_run_accepts(self) -> None:
        self.case.fixture_reviewer.write_text('#!/usr/bin/env python3\nprint("Not logged in")\nraise SystemExit(1)\n')
        code, _, err = self.run_main("run")
        self.assertEqual(2, code)
        self.assertIn("--runner command", err)
        self.assertIn("--no-review", err)
        self.assertNotIn("explicit reviewer", err)
        code, out, err = self.run_main("run", "--runner", "none")
        self.assertEqual(0, code, err)
        self.assertIn("review packet:", out)
        code, _, _ = self.run_main("run", "--no-review")
        self.assertEqual(0, code)

    # M6 call site: a Cargo.toml hangover was not pointed at is said, not silently skipped
    def test_a_nested_cargo_manifest_is_named_even_under_quiet(self) -> None:
        shutil.copytree(NO_CHECKS_FIXTURE, self.repo / "skill")
        code, _, err = self.run_main("--quiet", "scan")
        self.assertEqual(0, code)
        self.assertIn("Rust: no root Cargo.toml; found skill/Cargo.toml", err)
        snapshot = json.loads((paths(self.repo)["runs"] / load_state(self.repo)["latest_run"] / "snapshot.json").read_text())
        self.assertEqual("not_applicable", snapshot["rust"]["status"])
        self.assertIn("skill/Cargo.toml", snapshot["rust"]["notice"])
        self.set_config(checks=[])
        code, out, err = self.run_main("audit", "--json")
        self.assertIn("skill/Cargo.toml", err)
        self.assertEqual(0, code, out)
        self.assertFalse((self.repo / "skill" / "build-script-ran").exists())

    # H8: run retention
    def test_runs_are_pruned_to_references_and_the_newest_ten(self) -> None:
        from datetime import datetime, timedelta, timezone
        from hangover.gates import record_gate_proof
        identifier = self.ready_fix()
        self.assertEqual(0, self.run_main("verify", "--no-review")[0])
        state = load_state(self.repo)
        proof_run = state["remediations"][state["active_remediation"]]["verification"]["run"]
        runs = paths(self.repo)["runs"]

        def fabricate(when, kind="scan", index=0):
            name = f"{when.strftime('%Y%m%dT%H%M%SZ')}-{kind}-{index:06x}"
            (runs / name).mkdir()
            (runs / name / "snapshot.json").write_text("{}")
            return name

        ancient = datetime(2020, 1, 1, tzinfo=timezone.utc)
        old = [fabricate(ancient + timedelta(minutes=index), index=index) for index in range(12)]
        now = datetime.now(timezone.utc)
        # Age protects nothing: a run a live process is writing holds a lease
        # (test_a_live_run_is_not_pruned_however_old); an hour-old unleased one is history.
        recent_outside_ten = fabricate(now - timedelta(hours=1), index=99)
        newest = [fabricate(now + timedelta(days=1, minutes=index), index=200 + index) for index in range(10)]
        baseline, audit_run, gate_run, inherited, old_proof, old_packet = old[:6]
        (runs / baseline / "snapshot.json").write_text(json.dumps({"checks_inherited_from": inherited}))

        def reference(current):
            current["baseline_run"] = baseline
            current.setdefault("audit_reviews", {})["a1"] = {"id": "a1", "run": audit_run, "consumed": False}
            # An open batch's proof and prepared review can be older than the grace period.
            record = current["remediations"][current["active_remediation"]]
            record["verification"] = {**record["verification"], "run": old_proof}
            record["pending_review"] = {"id": old_packet, "token": "t", "proof": record["verification"]["id"], "consumed": False}
        mutate_state(self.repo, reference)
        record_gate_proof(self.repo, "key", gate_run, [{"name": "check", "status": "passed"}])

        self.assertEqual(0, self.run_main("scan")[0])
        remaining = {entry.name for entry in runs.iterdir()}
        for kept in (baseline, audit_run, gate_run, inherited, old_proof, old_packet,
                     proof_run, *newest):
            self.assertIn(kept, remaining)
        removed = [*old[6:], recent_outside_ten]
        self.assertTrue(removed)
        for name in removed:
            self.assertNotIn(name, remaining)
        self.assertEqual(0, self.run_main("status")[0])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def crowd_runs(self, count: int = RUN_RETENTION + 1) -> list[str]:
        """Fabricate `count` runs newer than anything real, so every real run is a prune candidate."""
        runs = paths(self.repo)["runs"]
        names = [f"20990101T0000{index:02d}Z-scan-{index:06x}" for index in range(count)]
        for name in names:
            (runs / name).mkdir(parents=True, exist_ok=True)
            (runs / name / "snapshot.json").write_text("{}")
        return names

    def test_a_prepared_initial_review_survives_pruning_until_imported(self) -> None:
        self.assertEqual(0, self.run_main("run", "--no-review")[0])
        code, out, _ = self.run_main("review", "--prepare", "--json")
        self.assertEqual(0, code)
        import_path = Path(json.loads(out)["data"]["import"]["path"])
        prepared = import_path.parent
        self.crowd_runs()
        # Older than any age-based grace period the retention once used.
        with patch("hangover.cli.RUN_RETENTION_GRACE_SECONDS", 0, create=True):
            self.assertEqual(0, self.run_main("scan")[0])
        self.assertTrue((prepared / "review-prompt.md").is_file(), "pruning deleted a prepared review packet")
        import_path.write_text(json.dumps({"reviewed_files": ["src/index.ts"], "verdict": "reviewed",
                                           "summary": "done", "findings": []}))
        self.assertEqual(0, self.run_main("review", "--import", str(import_path))[0])
        state = load_state(self.repo)
        self.assertNotIn(prepared.name, (state.get("prepared_reviews") or {}).values())
        # Imported, the packet is no longer referenced and is pruned like any run.
        self.crowd_runs()
        self.assertEqual(0, self.run_main("scan")[0])
        self.assertFalse(prepared.exists(), "an imported initial review packet is retained forever")

    def test_a_newer_prepared_initial_review_supersedes_the_older(self) -> None:
        self.assertEqual(0, self.run_main("run", "--no-review")[0])
        first = Path(json.loads(self.run_main("review", "--prepare", "--json")[1])["data"]["import"]["path"]).parent
        second = Path(json.loads(self.run_main("review", "--prepare", "--json")[1])["data"]["import"]["path"]).parent
        self.crowd_runs()
        self.assertEqual(0, self.run_main("scan")[0])
        self.assertFalse(first.exists())
        self.assertTrue(second.is_dir())

    def test_a_live_run_is_not_pruned_however_old(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        runs = paths(self.repo)["runs"]
        name = "20200101T000000Z-verify-abcdef"
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; from pathlib import Path; from hangover.cli import _run_dir; "
             f"_run_dir(Path(sys.argv[1]), {name!r}); print('ready', flush=True); sys.stdin.read()",
             str(self.repo)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
        )
        self.addCleanup(holder.wait)
        self.addCleanup(lambda: holder.stdin.close() if not holder.stdin.closed else None)
        self.assertEqual("ready\n", holder.stdout.readline())
        self.crowd_runs()
        self.assertEqual(0, self.run_main("scan")[0])
        self.assertTrue((runs / name).is_dir(), "pruning deleted a run its process is still writing")
        # The process ends; the OS releases its lease and the run is ordinary history.
        holder.stdin.close()
        self.assertEqual(0, holder.wait(timeout=30))
        self.assertEqual(0, self.run_main("scan")[0])
        self.assertFalse((runs / name).exists(), "a dead process's run is retained forever")

    def test_checks_inherited_across_rebaselines_keep_the_run_with_the_logs(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        runs = paths(self.repo)["runs"]
        original, middle, baseline = (f"20200101T00000{index}Z-scan-00000{index}" for index in range(3))
        for name, inherited in ((original, None), (middle, original), (baseline, middle)):
            (runs / name).mkdir(parents=True)
            (runs / name / "snapshot.json").write_text(
                json.dumps({"checks_inherited_from": inherited} if inherited else {}))
        mutate_state(self.repo, lambda current: current.update(baseline_run=baseline))
        self.crowd_runs()
        self.assertEqual(0, self.run_main("scan")[0])
        for name in (original, middle, baseline):
            self.assertTrue((runs / name).is_dir(), f"{name} was pruned")

    def test_pruning_decides_and_removes_under_the_state_lock(self) -> None:
        import fcntl
        from hangover.cli import _prune_runs
        self.assertEqual(0, self.run_main("init")[0])
        doomed = "20200101T000000Z-scan-000000"
        (paths(self.repo)["runs"] / doomed).mkdir(parents=True)
        self.crowd_runs(RUN_RETENTION)
        observed = []
        original_rename = os.rename

        def rename(source, target):
            with paths(self.repo)["state_lock"].open("a+") as other:
                try:
                    fcntl.flock(other.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    observed.append("unlocked")
                    fcntl.flock(other.fileno(), fcntl.LOCK_UN)
                except BlockingIOError:
                    observed.append("locked")
            return original_rename(source, target)

        with patch("hangover.cli.os.rename", side_effect=rename):
            removed = _prune_runs(self.repo)
        self.assertEqual([doomed], removed)
        self.assertEqual(["locked"], observed)

    # New configs do not inherit operator-specific environment variable names.
    def test_init_seeds_no_review_environment_names(self) -> None:
        self.assertEqual(0, self.run_main("init")[0])
        config = json.loads(paths(self.repo)["config"].read_text())
        self.assertEqual([], config["review"]["env"])

    # m5: automated runner tokens
    def test_automated_runner_with_a_wrong_token_cannot_resolve(self) -> None:
        identifier = self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review(token="0" * 32)):
            code, out, err = self.run_main("verify", "--json")
        self.assertEqual(2, code)
        self.assertIn("different verification_token", json.loads(out)["blockers"][0])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_automated_runner_without_a_token_cannot_resolve(self) -> None:
        identifier = self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review(token=None)):
            code, out, err = self.run_main("verify", "--json")
        self.assertEqual(2, code)
        self.assertIn("no verification_token", json.loads(out)["blockers"][0])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    # Review verdicts: only a pass approves a remediation
    def test_a_partial_verdict_does_not_resolve(self) -> None:
        identifier = self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review(verdict="partial")):
            code, out, _ = self.run_main("verify", "--json")
        self.assertEqual(1, code)
        payload = json.loads(out)
        self.assertEqual("blocked", payload["state"])
        self.assertEqual("partial", payload["data"]["verdict"])
        self.assertIn("verdict partial", payload["blockers"][0])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_an_imported_partial_is_blocked_and_says_why(self) -> None:
        identifier = self.ready_fix()
        code, out, _ = self.run_main("verify", "--runner", "none", "--json")
        self.assertEqual(0, code)
        prepared = json.loads(out)
        verdict = Path(prepared["data"]["import"]["path"])
        verdict.write_text(json.dumps({
            "verdict": "partial", "summary": "Two of five call sites remain.", "declared_changes_assessed": [],
            "findings": [], "reviewed_files": ["src/index.ts"],
            "verification_token": prepared["data"]["review"]["verification_token"]}))
        code, out, _ = self.run_main("review", "--issue", identifier, "--import", str(verdict), "--json")
        payload = json.loads(out)
        self.assertEqual("blocked", payload["state"])
        self.assertEqual(1, code)
        self.assertIn("verdict partial: Two of five call sites remain.", payload["blockers"][0])
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_an_imported_refusal_exits_as_blocked(self) -> None:
        identifier = self.ready_fix()
        code, out, _ = self.run_main("verify", "--runner", "none", "--json")
        self.assertEqual(0, code)
        prepared = json.loads(out)
        verdict = Path(prepared["data"]["import"]["path"])
        verdict.write_text(json.dumps({
            "verdict": "fail", "summary": "Synthetic refusal.", "declared_changes_assessed": [],
            "findings": [{"category": "behavior_regression", "title": "The deletion drops a caller", "evidence": ["src/index.ts"],
                          "files": ["src/index.ts"], "symbols": ["live"], "harm": "a caller breaks",
                          "proposed_change": "restore the export", "invariants": ["exports stay"], "risk": "low",
                          "priority": "P1", "confidence": "high", "verification": ["run the gate"],
                          "chesterton": "none"}],
            "reviewed_files": ["src/index.ts"], "verification_token": prepared["data"]["review"]["verification_token"]}))
        code, out, _ = self.run_main("review", "--issue", identifier, "--import", str(verdict), "--json")
        self.assertEqual("blocked", json.loads(out)["state"])
        self.assertEqual(1, code)
        self.assertEqual("in_progress", load_state(self.repo)["issues"][identifier]["status"])

    def test_automated_runner_echoing_its_token_resolves(self) -> None:
        identifier = self.ready_fix()
        with patch("hangover.cli.run_codex_review", side_effect=_echo_token_review()):
            code, out, err = self.run_main("verify", "--json")
        self.assertEqual(0, code, err)
        self.assertEqual("resolved", json.loads(out)["state"])
        self.assertEqual("resolved", load_state(self.repo)["issues"][identifier]["status"])


FAKE_CARGO = '''#!/bin/sh
# Any cargo invocation can run repository code (build scripts, proc macros, a
# rust-toolchain.toml path toolchain), so the fake only records that it ran.
printf '%s\\n' "$*" >> "$CARGO_HANGOVER_TEST_MARKER"
exit 1
'''

NO_CHECKS_FIXTURE = Path(__file__).parent / "fixtures" / "rust" / "build-marker"


class NoChecksFixture(unittest.TestCase):
    """A committed Rust checkout whose build script leaves a marker, and a fake Fallow."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.repo = root / "repo"
        shutil.copytree(NO_CHECKS_FIXTURE, self.repo)
        subprocess.run(["git", "init", "-q", "-b", "main", self.repo], check=True)
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.repo, "-c", "user.name=Hangover Test", "-c",
                        "user.email=hangover@example.invalid", "commit", "-qm", "fixture"], check=True)
        fake_fallow = root / "fake-fallow"
        fake_fallow.write_text(FAKE_FALLOW)
        fake_fallow.chmod(0o755)
        self.environment = patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(fake_fallow)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.temp.cleanup)

    def invoke(self, *arguments: str) -> tuple[int, str]:
        stdout = StringIO()
        with redirect_stdout(stdout), redirect_stderr(StringIO()):
            rc = main(["--repo", str(self.repo), *arguments])
        return rc, stdout.getvalue()

    def latest_rust(self) -> dict:
        state = load_state(self.repo)
        return json.loads((paths(self.repo)["runs"] / state["latest_run"] / "snapshot.json").read_text())["rust"]

    def fake_cargo_on_path(self) -> Path:
        bin_dir = Path(self.temp.name) / "bin"
        bin_dir.mkdir()
        cargo = bin_dir / "cargo"
        cargo.write_text(FAKE_CARGO)
        cargo.chmod(0o755)
        marker = Path(self.temp.name) / "cargo-ran"
        path = patch.dict(os.environ, {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                                       "CARGO_HANGOVER_TEST_MARKER": str(marker)})
        path.start()
        self.addCleanup(path.stop)
        return marker


class NoChecksExecutesNoRepositoryCodeTests(NoChecksFixture):
    """`--no-checks` is the documented inspection mode for an untrusted checkout."""

    def test_no_checks_never_invokes_cargo(self) -> None:
        marker = self.fake_cargo_on_path()
        rc, stdout = self.invoke("run", "--no-checks", "--no-review")
        self.assertEqual(0, rc)
        self.assertFalse(marker.exists(), "run --no-checks invoked cargo: " + (marker.read_text() if marker.exists() else ""))
        rust = self.latest_rust()
        # Static analysis only: manifests and sources read, cargo never started.
        self.assertIs(False, rust["repository_code_executed"])
        self.assertEqual("skipped", rust["sections"]["clippy"])
        self.assertEqual("completed", rust["sections"]["items"])
        self.assertIn("rust: static analysis only (--no-checks: cargo was not run", stdout)
        rc, _ = self.invoke("scan", "--no-checks")
        self.assertEqual(0, rc)
        self.assertFalse(marker.exists(), "scan --no-checks invoked cargo")
        # Preparing a review packet records no analyzer identity, so it probes no cargo either.
        rc, _ = self.invoke("run", "--no-checks", "--runner", "none")
        self.assertEqual(0, rc)
        self.assertFalse(marker.exists(), "run --no-checks --runner none invoked cargo")
        # The control: without --no-checks the same checkout does reach cargo,
        # so the absence above is the flag's doing and not a missing fixture.
        rc, _ = self.invoke("scan")
        self.assertEqual(0, rc)
        self.assertTrue(marker.exists(), "the fixture never reached cargo; the assertions above prove nothing")

    @unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
    def test_no_checks_does_not_run_a_real_build_script(self) -> None:
        marker = self.repo / "build-script-ran"
        rc, _ = self.invoke("run", "--no-checks", "--no-review")
        self.assertEqual(0, rc)
        self.assertFalse(marker.exists(), "run --no-checks executed the checkout's build.rs")
        rc, _ = self.invoke("scan")
        self.assertEqual(0, rc)
        self.assertEqual("completed", self.latest_rust()["sections"]["clippy"])
        self.assertTrue(marker.exists(), "a trusted scan never compiled the fixture; the assertion above proves nothing")


GIT_DRIVER = '''#!/bin/sh
# A git filter/diff driver the checkout's config names: records that git ran it.
printf '%s\\n' "$DRIVER_KIND" >> "$(dirname "$0")/git-driver-ran"
if [ "$#" -gt 0 ] && [ -f "$1" ]; then cat "$1"; else cat; fi
'''


class NoChecksRunsNoGitDriverTests(NoChecksFixture):
    """git status runs a clean filter on a modified tracked file; --no-checks must not let it."""

    def plant_driver(self, attributes: Path) -> Path:
        root = Path(self.temp.name)
        driver = root / "driver"
        driver.write_text(GIT_DRIVER)
        driver.chmod(0o755)
        # In the repository's own config: one that includes another file is refused under --no-checks
        # (test_containment.GitConfigIncludeTests), so the drivers to disarm are the config's own.
        with (self.repo / ".git" / "config").open("a") as config:
            config.write(
                "[filter \"evil\"]\n"
                f"\tclean = DRIVER_KIND=clean {driver}\n"
                f"\tsmudge = DRIVER_KIND=smudge {driver}\n"
                "[diff \"evil\"]\n"
                f"\ttextconv = DRIVER_KIND=textconv {driver}\n"
            )
        attributes.parent.mkdir(parents=True, exist_ok=True)
        attributes.write_text("* filter=evil diff=evil\n")
        # Same size, new content: git can only tell it changed by hashing it
        # through the clean filter (a size change would skip the filter).
        source = self.repo / "src" / "lib.rs"
        original = source.read_text()
        source.write_text(original.replace("pub", "PUB", 1))
        self.assertEqual(len(original), len(source.read_text()))
        return root / "git-driver-ran"

    def assert_no_driver_runs(self, marker: Path) -> None:
        for arguments in (("run", "--no-checks", "--no-review"), ("scan", "--no-checks")):
            rc, _ = self.invoke(*arguments)
            self.assertEqual(0, rc, arguments)
            self.assertFalse(marker.exists(), " ".join(arguments) + " ran a git driver: "
                             + (marker.read_text() if marker.exists() else ""))
            snapshot = json.loads((paths(self.repo)["runs"] / load_state(self.repo)["latest_run"]
                                   / "snapshot.json").read_text())
            self.assertIs(False, snapshot["repository_code_executed"])
            # The safe path still sees the modified file.
            self.assertIn(" M src/lib.rs", snapshot["git"]["changes"])
        # The control: plain git status on the same checkout runs the planted filter.
        os.utime(self.repo / "src" / "lib.rs")
        subprocess.run(["git", "-C", self.repo, "status", "--short"], check=True, capture_output=True)
        self.assertTrue(marker.exists(), "the planted filter never runs; the assertions above prove nothing")

    def test_worktree_gitattributes_filter_is_not_run(self) -> None:
        self.assert_no_driver_runs(self.plant_driver(self.repo / ".gitattributes"))

    def test_info_attributes_filter_is_not_run(self) -> None:
        # .git/info/attributes is read whatever the attribute source; the
        # driver itself must be overridden.
        self.assert_no_driver_runs(self.plant_driver(self.repo / ".git" / "info" / "attributes"))

    def test_git_too_old_for_attribute_isolation_is_refused(self) -> None:
        self.assertEqual(0, self.invoke("init")[0])
        for arguments in (("scan", "--no-checks"), ("run", "--no-checks", "--no-review")):
            stderr = StringIO()
            with patch("hangover.repository._git_version", return_value=(2, 39, 0)), \
                    redirect_stdout(StringIO()), redirect_stderr(stderr):
                rc = main(["--repo", str(self.repo), *arguments])
            self.assertNotEqual(0, rc, arguments)
            self.assertIn("needs git 2.42 or newer", stderr.getvalue())
            self.assertIsNone(load_state(self.repo)["latest_run"], arguments)
            self.assertFalse(paths(self.repo)["runs"].is_dir() and any(paths(self.repo)["runs"].iterdir()))


if __name__ == "__main__":
    unittest.main()
