import json
from hashlib import sha256
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.oracles import _run_fallow, run_codex_review, run_command_review, run_delegate_review
from hangover.repository import run_command, run_checks
from hangover.process import RunResult
if __package__:
    from .process_support import _after_ready
else:  # unittest discovery and direct file execution
    from process_support import _after_ready


class ProcessAdapterTests(unittest.TestCase):
    def test_codex_diagnostics_explain_failures_without_vetoing_valid_reviews(self):
        diagnostics = (
            "bwrap: setting up uid map: Permission denied",
            "bwrap: setting up uid map: Invalid argument",
            "Permission denied creating ~/.codex/tmp/arg0",
            "warning: Codex's Linux sandbox uses bubblewrap and needs access to create user namespaces.",
        )
        for diagnostic in diagnostics:
            for valid, exit_code in ((True, 0), (True, 1), (False, 0)):
                with self.subTest(diagnostic=diagnostic, valid=valid, exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "review-prompt.md").write_text("Synthetic prompt")
                    verdict = {"verdict": "reviewed", "summary": "Inspected source", "findings": [],
                               "reviewed_files": ["file.py"] if valid else [],
                               "verification_token": None, "declared_changes_assessed": []}
                    binary = root / "codex"
                    binary.write_text("#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\n"
                                      "Path(sys.argv[sys.argv.index('-o')+1]).write_text(" + repr(json.dumps(verdict)) + ")\n"
                                      f"print({diagnostic!r},file=sys.stderr)\nprint('noise'*1000,file=sys.stderr)\nsys.exit({exit_code})\n")
                    binary.chmod(0o755)
                    with patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(binary)}):
                        result = run_codex_review(root, root, root / "packet.json", "initial")
                    if valid and not exit_code:
                        self.assertEqual("completed", result["status"])
                        self.assertEqual(verdict, result["review"])
                    else:
                        self.assertEqual("environment_failure", result["status"])
                        self.assertIsNone(result["review"])
                        self.assertIn("runner environment failure", result["error"])
                        self.assertIn("--runner delegate --lane claude", result["error"])

    def test_codex_ignores_environment_words_in_prompt_and_model_output(self):
        prompt = "error: Permission denied writing ~/.codex/tmp/arg0\n"
        finding = {"category": "other", "title": "Handle permission failures", "evidence": ["Permission denied under .codex"],
                   "files": ["file.py"], "symbols": [], "harm": "A command fails", "proposed_change": "Report errors",
                   "invariants": ["Errors remain visible"], "risk": "low", "priority": "P2", "confidence": "high",
                   "verification": ["Run focused checks"], "chesterton": "Keep the error boundary"}
        for valid, echoed in ((False, "prompt"), (False, "model"), (False, "split"), (True, "json")):
            with self.subTest(valid=valid, echoed=echoed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "review-prompt.md").write_text(prompt)
                verdict = {"verdict": "reviewed", "summary": "Inspected source", "reviewed_files": ["file.py"] if valid else [],
                           "findings": [finding] if valid else []}
                model = "bwrap: setting up uid map: Permission denied\n" if echoed == "model" else json.dumps(verdict)
                stderr = ("user\n" + prompt if echoed == "prompt" else "") + "codex\n" + model + "\nhook: Stop\n"
                if echoed == "split":
                    stderr = "error: Permission denied reading another directory\nerror: unrelated ~/.codex note\n"
                binary = root / "codex"
                binary.write_text("#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
                                  "Path(sys.argv[sys.argv.index('-o')+1]).write_text(" + repr(json.dumps(verdict)) + ")\n"
                                  f"print({stderr!r},file=sys.stderr)\n")
                binary.chmod(0o755)
                with patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(binary)}):
                    result = run_codex_review(root, root, root / "packet.json", "initial")
                self.assertEqual("completed" if valid else "unverifiable", result["status"], repr(result))
                if valid:
                    self.assertEqual(verdict, result["review"])
                else:
                    self.assertNotIn("runner environment failure", result["error"])

    def test_command_and_delegate_reject_missing_inspection_evidence(self):
        verdict = {"verdict": "reviewed", "summary": "No inspected-file evidence", "findings": []}
        for runner in ("command", "delegate"):
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "review-prompt.md").write_text("Synthetic prompt")
                (root / "packet.json").write_text("{}")
                binary = root / "runner"
                value = verdict if runner == "command" else {"exitCode": 0, "assistantText": json.dumps(verdict)}
                binary.write_text("#!/usr/bin/env python3\nprint(" + repr(json.dumps(value)) + ")\n")
                binary.chmod(0o755)
                if runner == "command":
                    result = run_command_review(root, root, root / "packet.json", "initial", [str(binary)])
                else:
                    with patch.dict(os.environ, {"HANGOVER_DELEGATE_BIN": str(binary)}):
                        result = run_delegate_review(root, root, root / "packet.json", "initial", lane="glm")
                self.assertEqual("unverifiable", result["status"])
                self.assertIsNone(result["review"])
                self.assertIn("coverage is zero", result["error"])

    def test_native_failure_fingerprint_keeps_legacy_text_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import sys;sys.stdout.buffer.write(b'a\\r\\nb\\r\\x1b[31mred\\x1b[0m');sys.stderr.buffer.write(b'e\\r\\n');sys.exit(1)"
            result = run_command([sys.executable, "-c", code], root, 5, root / "check.log", quiet=True)
            self.assertEqual("failed", result["status"])
            self.assertEqual(sha256(b"a\nb\nred\ne\n").hexdigest(), result["output_sha256"])

    def test_native_gates_keep_their_repository_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"REPOSITORY_GATE_FIXTURE": "kept"}):
                result = run_command([sys.executable, "-c", "import os;print(os.environ['REPOSITORY_GATE_FIXTURE'])"],
                                     root, 5, root / "check.log", quiet=True)
            self.assertEqual("passed", result["status"])
            self.assertIn("kept", result["stdout_tail"])

    def test_signal_termination_is_not_a_comparable_test_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_command([sys.executable, "-c", "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"],
                                 root, 5, root / "check.log", quiet=True)
            self.assertEqual("error", result["status"])
            self.assertIsNone(result["output_sha256"])

    def test_incomplete_capture_cannot_supply_a_passing_review_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review-prompt.md").write_text("Synthetic prompt")
            passing = '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"partial prefix","findings":[]}'
            def incomplete(_command, **kwargs):
                Path(kwargs["stdout_path"]).write_text(passing)
                Path(kwargs["stderr_path"]).write_text("")
                return RunResult("incomplete", None, 0.1, str(kwargs["stdout_path"]), str(kwargs["stderr_path"]),
                                 len(passing), 0, passing, "", False)
            with patch("hangover.oracles.run_logged", side_effect=incomplete):
                result = run_command_review(root, root, root / "packet.json", "initial", ["fixture"])
            self.assertEqual("incomplete", result["status"])
            self.assertIsNone(result["review"])

    def test_delegate_route_metadata_is_reported_only_when_present(self):
        for reported in ({}, {"model": "not a resolved route"}, {"engine": "codex", "modelResolved": "reported-model", "resolvedReasoningEffort": "high"}):
            with self.subTest(reported=reported), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "review-prompt.md").write_text("Synthetic prompt")
                packet = root / "packet.json"
                packet.write_text("{}")
                envelope = {"exitCode": 0, "assistantText": '{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"synthetic","findings":[]}',
                            "modelRequested": "not evidence of the resolved model", **reported}
                text = json.dumps(envelope)
                def captured(_command, **kwargs):
                    Path(kwargs["stdout_path"]).write_text(text)
                    Path(kwargs["stderr_path"]).write_text("")
                    return RunResult("exited", 0, 0.1, str(kwargs["stdout_path"]), str(kwargs["stderr_path"]),
                                     len(text), 0, text, "", False)
                with patch("hangover.oracles.delegate_binary", return_value=Path(sys.executable)), patch("hangover.oracles.run_logged", side_effect=captured):
                    result = run_delegate_review(root, root, packet, "initial")
                self.assertEqual("completed", result["status"])
                self.assertEqual(reported.get("modelResolved"), result["reported_route"]["model"])

    def test_reviewer_failure_reason_redacts_forwarded_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review-prompt.md").write_text("Synthetic prompt")
            code = "import os,sys;print('authentication failed: '+os.environ['REVIEW_SECRET'],file=sys.stderr);sys.exit(1)"
            with patch.dict(os.environ, {"REVIEW_SECRET": "synthetic-sensitive-value"}):
                result = run_command_review(root, root, root / "packet.json", "initial",
                                            [sys.executable, "-c", code], env=["REVIEW_SECRET"])
            self.assertEqual("failed", result["status"])
            self.assertIn("authentication failed", result["error"])
            self.assertNotIn("synthetic-sensitive-value", result["error"])

    def test_invalid_review_diagnostics_are_bounded_redacted_and_terminal_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review-prompt.md").write_text("Synthetic prompt")
            code = "import os,json;print(json.dumps({'verdict':'reviewed','summary':'fixture','findings':[], '\\x1b[31m'+os.environ['REVIEW_SECRET']+'x'*2000:0}))"
            with patch.dict(os.environ, {"REVIEW_SECRET": "synthetic-sensitive-value"}):
                result = run_command_review(root, root, root / "packet.json", "initial",
                                            [sys.executable, "-c", code], env=["REVIEW_SECRET"])
            self.assertEqual("invalid_output", result["status"])
            self.assertNotIn("synthetic-sensitive-value", result["error"])
            self.assertNotIn("\x1b", result["error"])
            self.assertLessEqual(len(result["error"]), 600)

    def test_automatic_review_does_not_follow_a_symlinked_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "review-prompt.md").write_text("Synthetic prompt")
            outside = root / "other-result.json"
            outside.write_text('{"reviewed_files":["src/index.ts"],"verdict":"reviewed","summary":"synthetic","findings":[]}')
            output = root / "review.json"
            output.symlink_to(outside)
            result = run_command_review(root, root, root / "packet.json", "initial",
                                        [sys.executable, "-c", "pass", "{output}"])
            self.assertEqual("invalid_output", result["status"])
            self.assertIsNone(result["review"])

    def test_duplicate_check_names_cannot_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checks = [{"name": "same", "command": ["first"]}, {"name": "same", "command": ["second"]}]
            with patch("hangover.repository.run_command", side_effect=AssertionError("executed before validation")):
                with self.assertRaisesRegex(RuntimeError, "unique"):
                    run_checks(root, checks, root)

    def test_all_check_timeouts_are_validated_before_any_check_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for timeout in (0, -1, True, None, "invalid"):
                with self.subTest(timeout=timeout):
                    checks = [{"name": "first", "command": ["first"]},
                              {"name": "bad", "command": ["second"], "timeout_seconds": timeout}]
                    with patch("hangover.repository.run_command", side_effect=AssertionError("executed before validation")):
                        with self.assertRaisesRegex(RuntimeError, "positive integer"):
                            run_checks(root, checks, root)

    def test_every_execution_adapter_stops_its_timed_out_descendant(self):
        for adapter in ("check", "fallow", "codex", "command", "delegate"):
            # The platform tempdir is exec-capable here; these Python scripts
            # need no special /var/tmp mount (and should honor caller TMPDIR).
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory(prefix="hangover-adapter-") as directory:
                root = Path(directory)
                marker = root / "late-write"
                trigger = root / "returned"
                pidfile = root / "child.pid"
                ready = root / "ready"
                child = ("import time\nfrom pathlib import Path\n"
                         f"Path({str(ready)!r}).write_text('ready')\n"
                         f"while not Path({str(trigger)!r}).exists(): time.sleep(.01)\n"
                         f"Path({str(marker)!r}).write_text('late')\ntime.sleep(30)")
                code = ("import subprocess,sys,time;from pathlib import Path;"
                        f"p=subprocess.Popen([sys.executable,'-c',{child!r}]);"
                        f"Path({str(pidfile)!r}).write_text(str(p.pid));time.sleep(30)")
                binary = root / "fixture-runner"
                binary.write_text("#!/usr/bin/env python3\nimport sys\nif '--version' in sys.argv:\n print('fallow 3.31.0');raise SystemExit(0)\n" + code + "\n")
                binary.chmod(0o755)
                run = root / "run"
                run.mkdir()
                packet = run / "review-packet.json"
                packet.write_text("{}\n")
                (run / "review-prompt.md").write_text("Synthetic adapter test\n")
                try:
                    with patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(binary), "HANGOVER_CODEX_BIN": str(binary),
                                                 "HANGOVER_DELEGATE_BIN": str(binary)}), patch(
                        "hangover.oracles.DELEGATE_TIMEOUT_GRACE", 0.05
                    ), _after_ready(ready):
                        if adapter == "check":
                            result = run_command([str(binary)], root, 1, run / "check.log", quiet=True)
                        elif adapter == "fallow":
                            result = _run_fallow(root, run, "health", ["health"], timeout=1)
                        elif adapter == "codex":
                            result = run_codex_review(root, run, packet, "initial", timeout=1)
                        elif adapter == "command":
                            result = run_command_review(root, run, packet, "initial", [str(binary)], timeout=1)
                        else:
                            result = run_delegate_review(root, run, packet, "initial", timeout=1)
                    self.assertEqual("timeout", result["status"])
                    self.assertTrue(pidfile.exists(), "the descendant was never launched")
                    trigger.write_text("the adapter returned")
                    # Absence of a write after a short sleep is not enough on
                    # a busy host. Inspect the launched PID too; zombies have
                    # stopped executing even if an init/subreaper has yet to
                    # collect them (particularly on Linux).
                    deadline = time.monotonic() + 15
                    while True:
                        state = subprocess.run(
                            ["ps", "-p", pidfile.read_text(), "-o", "stat="],
                            capture_output=True, text=True, timeout=15, check=False,
                        )
                        self.assertIn(state.returncode, (0, 1), state.stderr)
                        live = bool(state.stdout.strip()) and not state.stdout.strip().startswith("Z")
                        if not live or time.monotonic() >= deadline:
                            break
                        time.sleep(0.05)
                    self.assertFalse(live, f"{adapter} left a live descendant after timeout")
                    self.assertFalse(marker.exists(), f"{adapter} left a descendant running after timeout")
                finally:
                    if pidfile.exists():
                        try:
                            os.kill(int(pidfile.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_native_check_output_limit_cannot_be_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_command([sys.executable, "-c", "print('x'*10000)"], root, 5, root / "check.log",
                                 max_output_bytes=100, quiet=True)
            self.assertEqual("output_limit", result["status"])
            self.assertIsNone(result["exit_code"])

    def test_separate_review_output_file_is_size_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet = root / "review-packet.json"
            packet.write_text("{}\n")
            prompt = root / "review-prompt.md"
            prompt.write_text("Synthetic review\n")
            output = root / "huge.json"
            writer = "import json,sys;from pathlib import Path;Path(sys.argv[1]).write_text(json.dumps({'verdict':'reviewed','summary':'x'*(9*1024*1024),'findings':[]}))"
            result = run_command_review(root, root, packet, "initial", [sys.executable, "-c", writer, "{output}"],
                                        output_path=output)
            self.assertEqual("invalid_output", result["status"])
            self.assertIsNone(result["review"])


if __name__ == "__main__":
    unittest.main()
