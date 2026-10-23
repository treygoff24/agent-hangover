import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.readiness import resolve_review, codex_startup_probe


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        (self.repo / ".hangover").mkdir()
        self.settings = {"runner": "none", "timeout_seconds": 1200, "env": [], "command": None,
                         "delegate": {"lane": "codex", "model": None, "reasoning_effort": None}}
        # Hermetic: never resolve the host's real codex (it cannot start a sandbox under Landlock).
        # Tests that need a Codex binary set HANGOVER_CODEX_BIN themselves.
        environment = patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(self.repo / "no-codex")})
        environment.start()
        self.addCleanup(environment.stop)

    def tearDown(self):
        self.temp.cleanup()

    def test_invalid_timeouts_are_rejected_before_any_process(self):
        for value in (True, 0, -1, 1.5, None, "invalid"):
            with self.subTest(value=value), patch("hangover.readiness.run_logged", side_effect=AssertionError("spawned")):
                with self.assertRaisesRegex(RuntimeError, "positive integer"):
                    resolve_review(self.repo, {**self.settings, "timeout_seconds": value})

    def test_command_readiness_does_not_execute_repository_code(self):
        marker = self.repo / "executed"
        reviewer = self.repo / "reviewer"
        reviewer.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        reviewer.chmod(0o755)
        settings = {**self.settings, "runner": "command", "command": ["./reviewer", "{prompt}"]}
        plan = resolve_review(self.repo, settings)
        self.assertEqual("ready", plan["preflight"]["status"])
        self.assertFalse(marker.exists())

    def test_manual_preparation_does_not_require_an_installed_reviewer(self):
        with patch("hangover.readiness.command_binary", side_effect=AssertionError("looked up binary")):
            plan = resolve_review(self.repo, {**self.settings, "runner": "command"}, execute=False)
        self.assertEqual("not_invoked", plan["preflight"]["status"])

    def test_codex_path_alias_warning_is_not_a_startup_failure(self):
        from hangover.readiness import codex_auth_state
        binary = self.repo / "codex"
        binary.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "print('WARNING: proceeding, even though we could not create PATH aliases: Permission denied "
            "(os error 13) at path \"/home/user/.codex/tmp/arg0/codex-arg0abc\"', file=sys.stderr)\n"
            "print('Logged in using ChatGPT')\n")
        binary.chmod(0o755)
        self.assertEqual("logged_in", codex_auth_state(binary))

    def test_codex_login_does_not_hide_a_broken_sandbox(self):
        binary = self.repo / "codex"
        for stderr, exit_code, stdout in (
            ("bwrap: setting up uid map: Permission denied", 1, ""),
            ("Permission denied creating ~/.codex/tmp/arg0", 1, ""),
            ("", 0, "not the probe receipt"),
            ("", 0, "hangover-runner-probe"),
        ):
            with self.subTest(stderr=stderr, stdout=stdout):
                binary.write_text("#!/usr/bin/env python3\nimport sys\n"
                                  "if sys.argv[1:] == ['login', 'status']: print('Logged in'); sys.exit(0)\n"
                                  "if '--help' in sys.argv: print('--permission-profile'); sys.exit(0)\n"
                                  f"print({stdout!r}, end=''); print({stderr!r}, file=sys.stderr); sys.exit({exit_code})\n")
                binary.chmod(0o755)
                with patch.dict(os.environ, {"HANGOVER_CODEX_BIN": str(binary)}):
                    if stdout == "hangover-runner-probe":
                        plan = resolve_review(self.repo, self.settings, runner="codex")
                        self.assertEqual("ready", plan["preflight"]["startup"]["status"])
                        self.assertFalse(plan["preflight"]["startup"]["model_invoked"])
                    else:
                        with self.assertRaises(RuntimeError) as raised:
                            resolve_review(self.repo, self.settings, runner="codex")
                        if stderr:
                            self.assertIn("runner environment failure", str(raised.exception))
                            self.assertIn("--runner delegate --lane claude", str(raised.exception))
                            self.assertIn("host write policies and container sandboxes", str(raised.exception))
                            self.assertNotRegex(str(raised.exception), r"(?i)\b(?:Landlock|AppArmor|SELinux)\b")
                        else:
                            self.assertIn("cannot execute here", str(raised.exception))

    def test_resolved_plan_is_not_mutated_through_the_original_config(self):
        settings = copy.deepcopy(self.settings)
        settings["command"] = ["original"]
        plan = resolve_review(self.repo, settings, execute=False)
        settings["command"][0] = "changed"
        settings["delegate"]["lane"] = "changed"
        self.assertEqual(["original"], plan["command"])
        self.assertEqual("codex", plan["delegate"]["lane"])

    def test_probe_ignores_user_config_and_allows_benign_stdout(self):
        binary = self.repo / "codex"
        home = self.repo / "configured-home"
        home.mkdir()
        (home / "config.toml").write_text('sandbox_mode="danger-full-access"')
        binary.write_text("#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
                          "if (Path(os.environ['CODEX_HOME'])/'config.toml').exists(): sys.exit(3)\n"
                          "print('--permission-profile' if '--help' in sys.argv else 'startup banner\\nhangover-runner-probe\\n')\n")
        binary.chmod(0o755)
        with patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            self.assertEqual("ready", codex_startup_probe(binary)["status"])

    def test_delegate_codex_checks_a_local_sandbox_when_available(self):
        with patch("hangover.readiness.delegate_preflight", return_value={"status": "ready"}), patch(
            "hangover.readiness.codex_binary", return_value=Path("/local/codex")
        ), patch("hangover.readiness.codex_startup_probe", side_effect=RuntimeError("runner environment failure")):
            with self.assertRaisesRegex(RuntimeError, "runner environment failure"):
                resolve_review(self.repo, self.settings, runner="delegate")

    def test_delegate_dry_run_pins_and_records_requested_and_resolved_selection(self):
        binary = self.repo / "delegate"
        payload = {"ok": True, "dryRun": True, "mode": "safe", "engine": "codex",
                   "modelResolved": "resolved-model", "resolvedReasoningEffort": "high", "promptTransport": "stdin"}
        binary.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps(" + repr(payload) + "))\n")
        binary.chmod(0o755)
        with patch.dict(os.environ, {"HANGOVER_DELEGATE_BIN": str(binary)}):
            plan = resolve_review(self.repo, self.settings, runner="delegate", model="requested-alias", reasoning_effort="high")
        self.assertEqual("resolved-model", plan["delegate"]["model"])
        self.assertEqual("requested-alias", plan["requested"]["model"])
        self.assertEqual("not_probed", plan["preflight"]["credential_validity"])

    def test_delegate_error_diagnostic_redacts_forwarded_values(self):
        binary = self.repo / "delegate"
        binary.write_text('#!/usr/bin/env python3\nimport os,sys\nprint("profile failure: " + os.environ["REVIEW_SECRET"],file=sys.stderr)\nraise SystemExit(2)\n')
        binary.chmod(0o755)
        with patch.dict(os.environ, {"HANGOVER_DELEGATE_BIN": str(binary), "REVIEW_SECRET": "sentinel-secret-value"}):
            with self.assertRaises(RuntimeError) as raised:
                resolve_review(self.repo, {**self.settings, "env": ["REVIEW_SECRET"]}, runner="delegate")
        self.assertNotIn("sentinel-secret-value", str(raised.exception))
        self.assertIn("<REVIEW_SECRET>", str(raised.exception))

    def test_delegate_must_confirm_safe_mode_and_requested_selection(self):
        binary = self.repo / "delegate"
        good = {"ok": True, "dryRun": True, "mode": "safe", "engine": "codex",
                "modelResolved": "resolved-model", "resolvedReasoningEffort": "high"}
        for changes in ({"mode": "work"}, {"dryRun": False}, {"engine": None}, {"engine": "claude"},
                        {"modelResolved": None}, {"resolvedReasoningEffort": None}, {"resolvedReasoningEffort": "low"}):
            with self.subTest(changes=changes):
                payload = {**good, **changes}
                binary.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps(" + repr(payload) + "))\n")
                binary.chmod(0o755)
                with patch.dict(os.environ, {"HANGOVER_DELEGATE_BIN": str(binary)}), self.assertRaises(RuntimeError):
                    resolve_review(self.repo, self.settings, runner="delegate", model="alias", reasoning_effort="high")


if __name__ == "__main__":
    unittest.main()
