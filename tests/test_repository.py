import json
import os
import shlex
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

from hangover import repository
from hangover.repository import (
    RepositoryRefusal,
    _line_count,
    capture_patch,
    compare_checks,
    diff_check,
    adopted_drift,
    discover_checks,
    failure_excerpt,
    git,
    git_info,
    git_safe_environment,
    inventory,
    no_execute_git,
    no_execute_git_env,
    propose_gate_stages,
    run_checks,
    stage_drift,
    update_local_exclude,
)


class RepositoryTests(unittest.TestCase):
    def test_commonjs_source_is_counted_and_selects_its_analyzer(self) -> None:
        for suffix, language in ((".cts", "typescript"), (".cjs", "javascript")):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                repo = Path(directory)
                (repo / f"source{suffix}").write_text("const value = 1;\n")
                result = inventory(repo)
                self.assertTrue(result[language])
                self.assertEqual({suffix: 1}, result["source_lines_by_suffix"])

    def test_inventory_does_not_open_non_source_assets_for_line_counting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            asset = repo / "image.bin"
            asset.write_bytes(b"\0" * (4 * 1024 * 1024))
            (repo / "source.ts").write_text("export const value = 1;\n")
            original_open = repository.open_repo_file

            def guarded_open(repo, relative, **kwargs):
                self.assertNotEqual("image.bin", relative, "non-source asset opened for line counting")
                return original_open(repo, relative, **kwargs)

            with patch.object(repository, "open_repo_file", guarded_open):
                result = inventory(repo)
            self.assertEqual(2, result["file_count"])
            self.assertEqual({".ts": 1}, result["source_lines_by_suffix"])

    def test_large_source_line_count_uses_bounded_reads(self) -> None:
        payload = b"x" * (4 * 1024 * 1024) + b"\nlast line"
        testcase = self

        class BoundedReader(BytesIO):
            def read(self, size=-1):
                testcase.assertGreater(size, 0)
                testcase.assertLessEqual(size, 128 * 1024)
                return super().read(size)

        with patch.object(repository, "open_repo_file", return_value=BoundedReader(payload)):
            self.assertEqual(2, _line_count(Path("."), Path("large.ts")))

    def test_source_line_count_preserves_empty_newline_and_binary_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.ts"
            for payload, expected in ((b"", 0), (b"one", 1), (b"one\n", 1),
                                      (b"one\r\ntwo", 2), (b"\n\n", 2), (b"one\0\n", None)):
                with self.subTest(payload=payload):
                    source.write_bytes(payload)
                    self.assertEqual(expected, _line_count(Path(directory), source))

    def git_repo(self, directory: str) -> Path:
        repo = Path(directory)
        subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True)
        (repo / "tracked.txt").write_text("tracked\n")
        subprocess.run(["git", "-C", repo, "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                repo,
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
        return repo

    def test_splits_a_readable_combined_gate_into_ordered_stages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "packageManager": "pnpm@11.18.0",
                        "scripts": {
                            "verify": "npm test && npm run build",
                            "test": "node --test",
                            "build": "tsc",
                        },
                    }
                )
            )
            (repo / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")

            self.assertEqual(
                ["test", "build"],
                [check["name"] for check in discover_checks(repo)],
            )
            # The gate's own runner and tokens survive: `npm test` is not rewritten to pnpm.
            self.assertEqual(
                [["npm", "test"], ["npm", "run", "build"]],
                [check["command"] for check in discover_checks(repo)],
            )

    def test_prefers_one_repo_native_combined_gate_when_stages_are_opaque(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "verify": "npm test && tsc --noEmit",
                            "test": "node --test",
                        }
                    }
                )
            )

            self.assertEqual(
                [
                    {
                        "name": "verify",
                        "command": ["npm", "run", "verify"],
                        "timeout_seconds": 1800,
                    }
                ],
                discover_checks(repo),
            )

    def test_a_simple_gate_script_is_only_proposed_in_declared_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "gate": "bash scripts/gate.sh",
                            "typecheck": "tsc",
                            "lint": "eslint .",
                            "format:check": "prettier --check .",
                            "test:unit": "vitest run",
                            "test:e2e": "playwright test",
                        }
                    }
                )
            )
            (repo / "scripts" / "gate.sh").write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'cd "$(dirname "$0")/.."\n'
                'echo "== start =="\n'
                "npm run test:unit\n"
                "npm run typecheck && npm run lint\n"
                "npm run format:check\n"
                "node scripts/budget.mjs\n"
                "npm run test:e2e\n"
            )

            # A gate shell script is never split automatically: it stays one check.
            self.assertEqual([["npm", "run", "gate"]], [c["command"] for c in discover_checks(repo)])
            proposal = propose_gate_stages(repo)
            checks = proposal["checks"]
            self.assertEqual("gate", proposal["script"])

            # Declared order is preserved; nothing is reordered.
            self.assertEqual(
                ["test", "typecheck", "lint", "format", "budget", "test-e2e"],
                [check["name"] for check in checks],
            )
            self.assertEqual(
                [None, True, True, True, None, None],
                [check.get("narrow") for check in checks],
            )
            self.assertEqual(["node", "scripts/budget.mjs"], checks[4]["command"])
            self.assertTrue(all(check["stage_of"] == "gate" for check in checks))
            self.assertTrue(all(check["adopted_from"]["script"] == "gate" for check in checks))
            self.assertEqual(1, len({check["adopted_from"]["sha256"] for check in checks}))

    def test_gate_script_with_control_flow_is_not_split(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "gate": "bash scripts/gate.sh",
                            "lint": "eslint .",
                            "test": "vitest run",
                        }
                    }
                )
            )
            (repo / "scripts" / "gate.sh").write_text(
                "set -e\nif [ -n \"$CI\" ]; then npm run lint; fi\nnpm test\n"
            )

            self.assertIsNone(propose_gate_stages(repo))
            self.assertEqual(
                [["npm", "run", "gate"]],
                [check["command"] for check in discover_checks(repo)],
            )

            (repo / "scripts" / "gate.sh").write_text(
                "node scripts/budget.mjs | tee budget.log\nnpm test\nnpm run lint\n"
            )

            # Not a plain command list, so only the weaker reference proposal is offered, and it
            # names the pipeline line it does not cover. Automatic discovery still never splits it.
            proposal = propose_gate_stages(repo)
            self.assertEqual("references", proposal["kind"])
            self.assertEqual([["npm", "test"], ["npm", "run", "lint"]], [c["command"] for c in proposal["checks"]])
            self.assertEqual(["node scripts/budget.mjs | tee budget.log"], proposal["uncovered"])
            self.assertEqual(
                [["npm", "run", "gate"]],
                [check["command"] for check in discover_checks(repo)],
            )

    def test_wrapped_gate_script_proposes_its_package_calls_and_lists_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            scripts = {"gate": "bash scripts/gate.sh", "typecheck": "tsc", "lint": "oxlint",
                       "format:check": "oxfmt --check", "test:core": "vitest", "build": "next build"}
            (repo / "package.json").write_text(json.dumps({"scripts": scripts}))
            (repo / "apps" / "web").mkdir(parents=True)
            (repo / "apps" / "web" / "package.json").write_text(json.dumps({"scripts": {"build:web": "next build"}}))
            # A wrapped gate: pins and prerequisite checks, a wrapper function, wrapped stages.
            (repo / "scripts" / "gate.sh").write_text(
                "#!/usr/bin/env bash\nset -uo pipefail\n"
                "[[ \"$(npm --version)\" == 11.19.0 ]] || { echo \"GATE FAILED npm pin\"; exit 1; }\n"
                "run_stage() {\n  local stage=\"$1\"\n  shift\n  if ! \"$@\"; then\n    exit 1\n  fi\n}\n"
                "run_stage typecheck npm run typecheck\n"
                "run_stage lint npm run lint\n"
                "run_stage format:check npm run format:check\n"
                "run_stage test:core npm run test:core -- --maxWorkers=8\n"
                "if [ -n \"$CI\" ]; then npm run build; fi\n"
                "echo done && npm run build\n"
                "run_stage build:web npm run build:web --workspace apps/web\n"
                "run_stage missing npm run nowhere --workspace apps/web\n"
            )
            proposal = propose_gate_stages(repo)
            self.assertEqual("references", proposal["kind"])
            self.assertEqual(
                [["npm", "run", "typecheck"], ["npm", "run", "lint"], ["npm", "run", "format:check"],
                 ["npm", "run", "test:core", "--", "--maxWorkers=8"],
                 ["npm", "run", "build:web", "--workspace", "apps/web"]],
                [c["command"] for c in proposal["checks"]],
            )
            uncovered = proposal["uncovered"]
            self.assertIn("if [ -n \"$CI\" ]; then npm run build; fi", uncovered)
            self.assertIn("echo done && npm run build", uncovered)
            self.assertIn("run_stage missing npm run nowhere --workspace apps/web", uncovered)
            self.assertTrue(any("11.19.0" in line for line in uncovered))
            self.assertTrue(all(c["adopted_from"]["script"] == "gate" for c in proposal["checks"]))
            self.assertEqual([["npm", "run", "gate"]], [c["command"] for c in discover_checks(repo)])

    def test_prefers_ci_quality_over_individual_package_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "packageManager": "pnpm@11.18.0",
                        "scripts": {
                            "ci:quality": "pnpm fmt:check && pnpm lint && pnpm test && pnpm build",
                            "test": "node --test",
                            "lint": "eslint .",
                            "build": "tsc",
                        },
                    }
                )
            )

            self.assertEqual(
                [
                    {
                        "name": "verify",
                        "command": ["pnpm", "run", "ci:quality"],
                        "timeout_seconds": 1800,
                    }
                ],
                discover_checks(repo),
            )

    def test_discovers_non_mutating_format_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {
                            "test": "node --test",
                            "fmt:check": "prettier --check .",
                        }
                    }
                )
            )

            self.assertEqual(
                [
                    {
                        "name": "test",
                        "command": ["npm", "run", "test"],
                        "timeout_seconds": 900,
                    },
                    {
                        "name": "format",
                        "command": ["npm", "run", "fmt:check"],
                        "timeout_seconds": 900,
                        "narrow": True,
                    },
                ],
                discover_checks(repo),
            )

    def test_does_not_treat_prefixed_check_script_as_combined_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps({"scripts": {"check-bundle-isolation": "node check-bundle.js"}})
            )

            self.assertEqual([], discover_checks(repo))

    def _gate_repo(self, directory, scripts, gate=None):
        repo = Path(directory)
        (repo / "scripts").mkdir(exist_ok=True)
        (repo / "package.json").write_text(json.dumps({"scripts": scripts}))
        if gate is not None:
            (repo / "scripts" / "gate.sh").write_text(gate)
        return repo

    def test_gate_with_npm_lifecycle_hooks_is_not_split(self) -> None:
        for hook in ("precheck", "postcheck"):
            with self.subTest(hook=hook), tempfile.TemporaryDirectory() as directory:
                repo = self._gate_repo(directory, {
                    "check": "npm run lint && npm test", "lint": "eslint .", "test": "vitest",
                    hook: "echo hook",
                })
                self.assertEqual([["npm", "run", "check"]], [c["command"] for c in discover_checks(repo)])

    def test_gate_with_shell_expansion_is_not_split(self) -> None:
        for line in ("node scripts/check.mjs src/*.ts", "node scripts/check.mjs ~/x", "node scripts/c.mjs $FILES"):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as directory:
                repo = self._gate_repo(directory, {
                    "gate": "bash scripts/gate.sh", "test": "vitest",
                }, f"{line}\nnpm test\n")
                self.assertIsNone(propose_gate_stages(repo))
                self.assertEqual([["npm", "run", "gate"]], [c["command"] for c in discover_checks(repo)])

    def test_stage_drift_detects_a_gate_that_changed_after_init(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self._gate_repo(directory, {
                "gate": "npm run lint && npm test", "lint": "eslint .", "test": "vitest",
                "security": "audit",
            })
            saved = discover_checks(repo)
            self.assertEqual(["lint", "test"], [c["name"] for c in saved])
            self.assertIsNone(stage_drift(repo, saved))

            (repo / "package.json").write_text(json.dumps({"scripts": {
                "gate": "npm run lint && npm test && npm run security", "lint": "eslint .",
                "test": "vitest", "security": "audit"}}))
            fresh = stage_drift(repo, saved)

            self.assertEqual(["lint", "test", "security"], [c["name"] for c in fresh])
            # A user-added check with no stage_of is never treated as drift.
            self.assertIsNone(stage_drift(repo, [{"name": "x", "command": ["x"]}]))

    def test_only_a_pure_package_script_chain_is_split_automatically(self) -> None:
        opaque = (
            "npm test && node scripts/check.js",
            "npm test && tsc --noEmit",
            "CI=1 npm test && npm run lint",
            "npm test && npx tsc",
            "npm test",
        )
        for gate in opaque:
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as directory:
                repo = self._gate_repo(directory, {"gate": gate, "test": "vitest", "lint": "eslint ."})
                self.assertEqual([["npm", "run", "gate"]], [c["command"] for c in discover_checks(repo)])
        for gate, commands in (
            ("npm run lint && pnpm test", [["npm", "run", "lint"], ["pnpm", "test"]]),
            ("yarn lint && yarn run test", [["yarn", "lint"], ["yarn", "run", "test"]]),
            ("bun run lint && bun run test", [["bun", "run", "lint"], ["bun", "run", "test"]]),
        ):
            with self.subTest(gate=gate), tempfile.TemporaryDirectory() as directory:
                repo = self._gate_repo(directory, {"gate": gate, "test": "vitest", "lint": "eslint ."})
                self.assertEqual(commands, [c["command"] for c in discover_checks(repo)])

    def test_adopted_stages_report_drift_when_the_gate_script_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self._gate_repo(directory, {
                "gate": "bash scripts/gate.sh", "lint": "eslint .", "test": "vitest",
            }, "npm run lint\nnpm test\n")
            adopted = propose_gate_stages(repo)["checks"]
            self.assertEqual([], adopted_drift(repo, adopted))
            # Adopted stages are the operator's assertion: never auto-rediscovered.
            self.assertIsNone(stage_drift(repo, adopted))

            (repo / "scripts" / "gate.sh").write_text("npm run lint\nnpm test\nnpm run lint\n")

            self.assertEqual(["gate"], adopted_drift(repo, adopted))

    def test_inventory_records_public_surface_and_risky_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "package.json").write_text(
                json.dumps({"exports": "./src/index.ts", "dependencies": {"next": "16.3.0"}})
            )
            (repo / "src").mkdir()
            (repo / "src" / "index.ts").write_text("export const value = 1;\n")
            (repo / "migrations").mkdir()
            (repo / "migrations" / "001.sql").write_text("select 1;\n")

            result = inventory(repo)

            self.assertTrue(result["typescript"])
            self.assertEqual({"exports": "./src/index.ts"}, result["public_surface"])
            self.assertIn("next", result["frameworks"])
            self.assertIn("migrations", result["risk_paths"])

    def test_inventory_does_not_follow_source_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            repo = Path(directory)
            (Path(outside) / "secret.ts").write_text("export const secret = 1;\n")
            (repo / "linked.ts").symlink_to(Path(outside) / "secret.ts")

            result = inventory(repo)

            self.assertFalse(result["typescript"])
            self.assertEqual(0, result["file_count"])

    def test_git_metadata_reads_disable_repo_fsmonitor_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            sentinel = repo / "hook-ran"
            hook = repo / "fsmonitor-hook"
            hook.write_text(
                "#!/bin/sh\n"
                f"printf hit > {shlex.quote(str(sentinel))}\n"
                "printf '%s\\n' \"$2\"\n"
            )
            hook.chmod(0o755)
            subprocess.run(
                ["git", "-C", repo, "config", "core.fsmonitor", str(hook)], check=True
            )
            subprocess.run(
                ["git", "-C", repo, "status", "--short"],
                capture_output=True,
                check=False,
            )
            self.assertTrue(sentinel.exists())
            sentinel.unlink()

            git_info(repo)
            inventory(repo)

            self.assertFalse(sentinel.exists())

    def test_tool_environment_does_not_inherit_parent_secrets(self) -> None:
        with patch.dict("os.environ", {"SECRET_TOKEN_DUMMY": "must-not-leak"}):
            environment = git_safe_environment()

        self.assertNotIn("SECRET_TOKEN_DUMMY", environment)
        self.assertIn("PATH", environment)

    def test_existing_failure_is_not_reported_as_a_regression(self) -> None:
        failure = {
            "name": "test", "command": ["npm", "test"], "status": "failed",
            "exit_code": 1, "output_sha256": "same-failure", "output_bytes": 400,
        }
        baseline = [dict(failure)]
        current = [dict(failure)]
        self.assertEqual(
            "pre_existing_failure", compare_checks(baseline, current)[0]["classification"]
        )

    def test_identical_trivial_failure_output_is_not_proof_of_the_same_debt(self) -> None:
        for size in (None, 0, 12, 39):
            failure = {
                "name": "test", "command": ["npm", "test"], "status": "failed",
                "exit_code": 1, "output_sha256": "same-failure",
                **({} if size is None else {"output_bytes": size}),
            }
            with self.subTest(size=size):
                self.assertEqual(
                    "incomparable", compare_checks([failure], [dict(failure)])[0]["classification"]
                )

    def test_removed_native_check_is_incomparable(self) -> None:
        baseline = [{"name": "gate", "command": ["check"], "status": "passed"}]

        self.assertEqual(
            [{"name": "gate", "classification": "incomparable", "reason": "check removed"}],
            compare_checks(baseline, []),
        )

    def test_changed_or_unknown_failure_is_not_pre_existing(self) -> None:
        baseline = {
            "name": "test", "command": ["check"], "status": "failed",
            "exit_code": 1, "output_sha256": "original-failure", "output_bytes": 400,
        }
        for delta in (
            {"output_sha256": "new-failure"}, {"output_sha256": None},
            {"exit_code": 2}, {"status": "timeout"},
        ):
            with self.subTest(delta=delta):
                result = compare_checks([baseline], [{**baseline, **delta}])
                self.assertEqual("incomparable", result[0]["classification"])

    def test_legacy_failure_without_fingerprint_is_unknown(self) -> None:
        failure = {"name": "test", "command": ["check"], "status": "failed"}

        self.assertEqual(
            "incomparable", compare_checks([failure], [failure])[0]["classification"]
        )

    def test_new_green_check_does_not_block_an_existing_campaign(self) -> None:
        current = [{"name": "lint", "command": ["npm", "run", "lint"], "status": "passed"}]
        self.assertEqual("new_pass", compare_checks([], current)[0]["classification"])

    def test_changed_check_command_is_incomparable_even_when_it_passes(self) -> None:
        baseline = [{"name": "test", "command": ["npm", "test"], "status": "passed"}]
        current = [{"name": "test", "command": ["true"], "status": "passed"}]
        self.assertEqual(
            "incomparable", compare_checks(baseline, current)[0]["classification"]
        )

    def test_diff_check_catches_untracked_trailing_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            (repo / "new.txt").write_text("bad   \n")

            result = diff_check(repo, "HEAD", repo / "diff-check.log")

            self.assertEqual("failed", result["status"])
            self.assertIn("new.txt:1", (repo / "diff-check.log").read_text())

    def test_capture_patch_includes_untracked_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            (repo / "new.txt").write_text("new content\n")

            capture_patch(repo, repo / "review.patch")

            patch = (repo / "review.patch").read_text()
            self.assertIn("+++ b/new.txt", patch)
            self.assertIn("+new content", patch)

    def test_capture_patch_from_base_includes_a_committed_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            (repo / "staged.txt").write_text("old staged\n")
            (repo / "unstaged.txt").write_text("old unstaged\n")
            subprocess.run(
                ["git", "-C", repo, "add", "staged.txt", "unstaged.txt"], check=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    repo,
                    "-c",
                    "user.name=Hangover Test",
                    "-c",
                    "user.email=hangover@example.invalid",
                    "commit",
                    "-qm",
                    "more fixtures",
                ],
                check=True,
            )
            base = subprocess.run(
                ["git", "-C", repo, "rev-parse", "HEAD"],
                capture_output=True,
                check=True,
                text=True,
            ).stdout.strip()
            (repo / "tracked.txt").write_text("committed remediation\n")
            subprocess.run(["git", "-C", repo, "add", "tracked.txt"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    repo,
                    "-c",
                    "user.name=Hangover Test",
                    "-c",
                    "user.email=hangover@example.invalid",
                    "commit",
                    "-qm",
                    "remediation",
                ],
                check=True,
            )
            (repo / "staged.txt").write_text("new staged\n")
            subprocess.run(["git", "-C", repo, "add", "staged.txt"], check=True)
            (repo / "unstaged.txt").write_text("new unstaged\n")
            (repo / "untracked.txt").write_text("new untracked\n")

            capture_patch(repo, repo / "review.patch", base=base)

            patch = (repo / "review.patch").read_text()
            self.assertIn("-tracked", patch)
            self.assertIn("+committed remediation", patch)
            self.assertIn("+new staged", patch)
            self.assertIn("+new unstaged", patch)
            self.assertIn("+new untracked", patch)

    def test_capture_patch_without_base_remains_head_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            (repo / "tracked.txt").write_text("already committed\n")
            subprocess.run(["git", "-C", repo, "add", "tracked.txt"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    repo,
                    "-c",
                    "user.name=Hangover Test",
                    "-c",
                    "user.email=hangover@example.invalid",
                    "commit",
                    "-qm",
                    "checkpoint",
                ],
                check=True,
            )

            capture_patch(repo, repo / "review.patch")

            self.assertNotIn("already committed", (repo / "review.patch").read_text())

    def test_capture_patch_omits_state_and_sensitive_untracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = self.git_repo(directory)
            (repo / ".hangover").mkdir()
            (repo / ".hangover" / "state.json").write_text("private-state\n")
            (repo / ".env.local").write_text("TOKEN=private-token\n")
            (repo / "credentials.json").write_text('{"private_key":"json-secret"}\n')
            (repo / "secrets.yml").write_text("client_secret: yaml-secret\n")

            capture_patch(repo, repo / "review.patch")

            patch = (repo / "review.patch").read_text()
            self.assertNotIn("private-state", patch)
            self.assertNotIn("private-token", patch)
            self.assertNotIn("json-secret", patch)
            self.assertNotIn("yaml-secret", patch)
            self.assertIn("Sensitive untracked file omitted", patch)

    def test_check_name_cannot_escape_log_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "check name"):
                run_checks(
                    repo,
                    [{"name": "../escape", "command": ["true"]}],
                    repo / "runs",
                )

    def test_run_checks_reports_start_and_pass_to_stderr_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stdout = StringIO()
            stderr = StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                results = run_checks(
                    repo,
                    [{"name": "test", "command": ["python3", "-c", "pass"]}],
                    repo / "runs",
                )

            self.assertEqual("passed", results[0]["status"])
            self.assertEqual("", stdout.getvalue())
            self.assertIn("check test: running (python3 -c pass)\n", stderr.getvalue())
            self.assertRegex(stderr.getvalue(), r"check test: passed in \d+\.\ds\n")

    def test_run_checks_reports_failed_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stderr = StringIO()

            with redirect_stderr(stderr):
                results = run_checks(
                    repo,
                    [
                        {
                            "name": "test",
                            "command": ["python3", "-c", "raise SystemExit(7)"],
                        }
                    ],
                    repo / "runs",
                )

            self.assertEqual("failed", results[0]["status"])
            self.assertRegex(
                stderr.getvalue(), r"check test: failed \(exit 7\) in \d+\.\ds\n"
            )

    def test_run_checks_names_the_log_and_the_failing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stderr = StringIO()
            script = "import sys; print('noise'); print('lint: 3 errors', file=sys.stderr); sys.exit(2)"

            with redirect_stderr(stderr):
                results = run_checks(repo, [{"name": "lint", "command": ["python3", "-c", script]}], repo / "runs")

            self.assertIn(f"check lint: log {repo / 'runs' / 'checks' / 'lint.log'}\n", stderr.getvalue())
            self.assertIn("check lint:   | lint: 3 errors\n", stderr.getvalue())
            self.assertIn("lint: 3 errors", "\n".join(failure_excerpt(results[0])))

    def test_run_checks_stops_at_the_first_stage_the_caller_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stderr = StringIO()
            checks = [
                {"name": "lint", "command": ["python3", "-c", "raise SystemExit(1)"]},
                {"name": "test", "command": ["python3", "-c", "open('ran', 'w')"]},
            ]

            with redirect_stderr(stderr):
                results = run_checks(
                    repo, checks, repo / "runs", stop_when=lambda result: result["status"] != "passed"
                )

            self.assertEqual(["failed", "not_run"], [item["status"] for item in results])
            self.assertEqual("lint", results[1]["skipped_after"])
            self.assertFalse((repo / "ran").exists())
            self.assertIn("not run: test", stderr.getvalue())
            self.assertEqual("not_run", compare_checks([], results)[1]["classification"])

    def test_run_checks_without_a_stop_rule_runs_every_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            checks = [
                {"name": "lint", "command": ["python3", "-c", "raise SystemExit(1)"]},
                {"name": "test", "command": ["python3", "-c", "pass"]},
            ]

            with redirect_stderr(StringIO()):
                results = run_checks(repo, checks, repo / "runs")

            self.assertEqual(["failed", "passed"], [item["status"] for item in results])

    def test_run_checks_quiet_suppresses_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stderr = StringIO()

            with redirect_stderr(stderr):
                run_checks(
                    repo,
                    [{"name": "test", "command": ["python3", "-c", "pass"]}],
                    repo / "runs",
                    quiet=True,
                )

            self.assertEqual("", stderr.getvalue())

    def test_local_exclude_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            repo = self.git_repo(directory)
            target = Path(outside) / "target"
            target.write_text("keep\n")
            exclude = repo / ".git" / "info" / "exclude"
            exclude.unlink()
            exclude.symlink_to(target)

            with self.assertRaisesRegex(RuntimeError, "outside the Git directory"):
                update_local_exclude(repo)

            self.assertEqual("keep\n", target.read_text())


DRIVERS = ("[filter \"evil\"]\n\tclean = touch marker\n\tprocess = touch marker\n"
           "[diff \"evil\"]\n\ttextconv = touch marker\n[core]\n\tpager = touch marker\n")


class NoExecuteGitTests(unittest.TestCase):
    """Each layer of no_execute_git_env, checked on its own with git's own readers."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = RepositoryTests.git_repo(self, self.temp.name + "/repo")
        # The drivers sit in the repository's own config: static mode refuses a config that includes
        # another file (test_includes_are_refused_when_strict), so a strict environment never sees one.
        with (self.repo / ".git" / "config").open("a") as config:
            config.write(DRIVERS)

    def include_drivers(self) -> Path:
        """Move the drivers into a file the repository's config includes."""
        included = Path(self.temp.name) / "drivers.gitconfig"
        included.write_text(DRIVERS)
        config = self.repo / ".git" / "config"
        config.write_text(config.read_text().replace(DRIVERS, ""))
        subprocess.run(["git", "-C", self.repo, "config", "include.path", str(included)], check=True)
        return included

    def read(self, environment: dict, *arguments: str) -> str:
        return subprocess.run(["git", "-C", self.repo, *arguments], capture_output=True, text=True,
                              check=False, env=environment).stdout.strip()

    def test_worktree_attributes_select_no_driver(self) -> None:
        (self.repo / ".gitattributes").write_text("* filter=evil diff=evil\n")
        attribute = ("check-attr", "filter", "--", "tracked.txt")
        self.assertEqual("tracked.txt: filter: evil", self.read(git_safe_environment(), *attribute))
        self.assertEqual("tracked.txt: filter: unspecified", self.read(no_execute_git_env(self.repo), *attribute))

    def test_command_keys_are_emptied(self) -> None:
        trusted = git_safe_environment()
        safe = no_execute_git_env(self.repo)
        for key in ("filter.evil.clean", "filter.evil.process", "diff.evil.textconv", "core.pager"):
            with self.subTest(key=key):
                self.assertEqual("touch marker", self.read(trusted, "config", key))
                self.assertEqual("", self.read(safe, "config", key))
        self.assertEqual("false", self.read(safe, "config", "filter.evil.required"))
        self.assertEqual("/dev/null", self.read(safe, "config", "core.hooksPath"))

    def test_includes_are_refused_when_strict(self) -> None:
        self.include_drivers()
        with self.assertRaisesRegex(RepositoryRefusal, "includes another file"):
            no_execute_git_env(self.repo)
        subprocess.run(["git", "-C", self.repo, "config", "--unset", "include.path"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "includeIf.gitdir:/.path", "/dev/null"], check=True)
        with self.assertRaisesRegex(RepositoryRefusal, r"includeif\.gitdir:/\.path"):
            no_execute_git_env(self.repo)

    def test_included_command_keys_are_emptied_when_not_strict(self) -> None:
        """A trusted checkout's includes are followed to find the keys to override."""
        self.include_drivers()
        safe = no_execute_git_env(self.repo, strict=False)
        for key in ("filter.evil.clean", "diff.evil.textconv", "core.pager"):
            with self.subTest(key=key):
                self.assertEqual("touch marker", self.read(git_safe_environment(), "config", "--includes", key))
                self.assertEqual("", self.read(safe, "config", "--includes", key))

    def test_a_sha256_repository_gets_its_own_empty_tree(self) -> None:
        repo = Path(self.temp.name) / "sha256"
        subprocess.run(["git", "init", "-q", "--object-format=sha256", repo], check=True)
        tree = no_execute_git_env(repo)["GIT_ATTR_SOURCE"]
        self.assertEqual(tree, subprocess.run(["git", "-C", repo, "hash-object", "-t", "tree", "--stdin"], input="",
                                              capture_output=True, text=True, check=True).stdout.strip())
        self.assertEqual(64, len(tree))
        self.assertEqual(subprocess.run(["git", "-C", self.repo, "hash-object", "-t", "tree", "--stdin"], input="",
                                        capture_output=True, text=True, check=True).stdout.strip(),
                         no_execute_git_env(self.repo)["GIT_ATTR_SOURCE"])

    def test_global_config_is_not_read(self) -> None:
        home = Path(self.temp.name) / "home"
        home.mkdir()
        # Any global key: a command-valued one would also be emptied by name.
        (home / ".gitconfig").write_text("[hangover]\n\tprobe = global\n")
        with patch.dict(os.environ, {"HOME": str(home), "XDG_CONFIG_HOME": str(home)}):
            self.assertEqual("global", self.read(git_safe_environment(), "config", "hangover.probe"))
            self.assertEqual("", self.read(no_execute_git_env(self.repo), "config", "hangover.probe"))

    def test_mode_covers_git_and_tool_environments_then_ends(self) -> None:
        (self.repo / ".gitattributes").write_text("* filter=evil\n")
        with no_execute_git(self.repo):
            self.assertIn("unspecified", git(self.repo, "check-attr", "filter", "--", "tracked.txt").stdout)
            self.assertIn("GIT_ATTR_SOURCE", git_safe_environment())
        self.assertIn(": evil", git(self.repo, "check-attr", "filter", "--", "tracked.txt").stdout)
        self.assertNotIn("GIT_ATTR_SOURCE", git_safe_environment())

    def test_old_git_is_refused(self) -> None:
        with patch("hangover.repository._git_version", return_value=(2, 41, 9)):
            with self.assertRaisesRegex(RuntimeError, "needs git 2.42 or newer"):
                no_execute_git_env(self.repo)

    def test_old_git_is_accepted_when_not_strict_and_keeps_the_overrides(self) -> None:
        """strict=False: git hangover runs on a checkout it trusts to execute still gets layers 2 and 3."""
        self.include_drivers()
        with patch("hangover.repository._git_version", return_value=(2, 39, 5)):
            safe = no_execute_git_env(self.repo, strict=False)
        self.assertEqual("", self.read(safe, "config", "--includes", "filter.evil.clean"))
        self.assertEqual("/dev/null", self.read(safe, "config", "core.hooksPath"))

    def test_no_transport_is_allowed_whatever_the_repository_allows(self) -> None:
        """A repository's protocol.<name>.allow=always outranks protocol.allow=never: each one it sets is
        overridden by name, and the environment allows no transport and no lazy fetch at all."""
        for key in ("protocol.ext.allow", "protocol.Custom.allow"):
            subprocess.run(["git", "-C", self.repo, "config", key, "always"], check=True)
        for strict in (True, False):
            with self.subTest(strict=strict):
                safe = no_execute_git_env(self.repo, strict=strict)
                for key in ("protocol.ext.allow", "protocol.Custom.allow", "protocol.allow", "protocol.file.allow"):
                    self.assertEqual("never", self.read(safe, "config", key), key)
                self.assertEqual(("1", "", "0"), (safe["GIT_NO_LAZY_FETCH"], safe["GIT_ALLOW_PROTOCOL"],
                                                  safe["GIT_PROTOCOL_FROM_USER"]))
        self.assertEqual("always", self.read(git_safe_environment(), "config", "protocol.ext.allow"))

    def test_config_defined_hooks_are_disabled(self) -> None:
        """`hook.<name>.command` runs whatever core.hooksPath says; each hook the config names is disabled."""
        marker = Path(self.temp.name) / "HOOK_RAN"
        for key, value in (("hook.planted.command", f"echo ran >> '{marker}'"), ("hook.planted.event", "pre-commit")):
            subprocess.run(["git", "-C", self.repo, "config", key, value], check=True)
        commit = ["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                  "commit", "-q", "--allow-empty", "-m", "probe"]
        safe = no_execute_git_env(self.repo)
        self.assertEqual(("false", ""), (self.read(safe, "config", "hook.planted.enabled"),
                                         self.read(safe, "config", "hook.planted.command")))
        subprocess.run(commit, capture_output=True, env=safe, check=False)
        self.assertFalse(marker.exists(), "a config-defined hook ran under the no-execute environment")
        # Positive control: the same commit under the repository's own config runs the hook.
        subprocess.run(commit, capture_output=True, env={**git_safe_environment(), "GIT_CONFIG_COUNT": "1",
                                                         "GIT_CONFIG_KEY_0": "core.hooksPath",
                                                         "GIT_CONFIG_VALUE_0": "/dev/null"}, check=False)
        self.assertTrue(marker.is_file(), "the planted hook did not bind (core.hooksPath=/dev/null does not stop it)")

    def test_no_file_the_config_names_is_opened(self) -> None:
        """status, ls-files, diff and log open the exclude, order, attributes and mailmap files config names;
        under the no-execute environment each is /dev/null, so a FIFO there (or anywhere) stalls nothing."""
        fifo = Path(self.temp.name) / "pipe"
        os.mkfifo(fifo)
        self.addCleanup(lambda: _release_fifo(fifo))
        (self.repo / "tracked.txt").write_text("changed\n")
        (self.repo / "untracked.txt").write_text("new\n")
        probes = {"core.excludesFile": ["status", "--short", "--untracked-files=all"],
                  "diff.orderFile": ["status", "--short"],
                  "core.attributesFile": ["diff", "--no-ext-diff", "--no-textconv"],
                  "mailmap.file": ["log", "-1", "--format=%ct"]}
        for key, command in probes.items():
            with self.subTest(key=key):
                subprocess.run(["git", "-C", self.repo, "config", key, str(fifo)], check=True)
                safe = no_execute_git_env(self.repo)
                result = subprocess.run(["git", "-C", self.repo, *command], capture_output=True, text=True,
                                        env=safe, timeout=20, check=False)
                self.assertEqual(0, result.returncode, result.stderr)
                # Positive control: under the repository's own config the same command blocks on the FIFO.
                with self.assertRaises(subprocess.TimeoutExpired, msg=f"{key} did not bind"):
                    subprocess.run(["git", "-C", self.repo, *command], capture_output=True,
                                   env=git_safe_environment(), timeout=2, check=False)
                _release_fifo(fifo)
                subprocess.run(["git", "-C", self.repo, "config", "--unset", key], check=True)

    def test_an_outside_exclude_file_hides_nothing(self) -> None:
        outside = Path(self.temp.name) / "outside-ignore"
        outside.write_text("hidden.txt\n")
        subprocess.run(["git", "-C", self.repo, "config", "core.excludesFile", str(outside)], check=True)
        (self.repo / "hidden.txt").write_text("x\n")
        status = ["status", "--short", "--untracked-files=all"]
        self.assertNotIn("hidden.txt", self.read(git_safe_environment(), *status))
        self.assertIn("?? hidden.txt", self.read(no_execute_git_env(self.repo), *status))


def _release_fifo(fifo: Path) -> None:
    """Give a reader still blocked on `fifo` its end of file."""
    try:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass  # ENXIO: nobody is reading it.


OUTSIDE_SOURCE = b"export const outsideSecretMarker = 7;\n"


class InventoryFileListTests(unittest.TestCase):
    """inventory (every scan, static ones included) lists files from the index, which the repository
    controls: a crafted name never makes it open a file outside the repository, and the refusal is a
    RuntimeError the CLI reports as a tool error, never a traceback."""

    def crafted(self, kind: str) -> Path:
        from test_rust import run_git, write_index

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name).resolve() / "repo"
        (repo / "src").mkdir(parents=True)
        inside = {"src/index.ts": b"export const inside = 1;\n"}
        for name, data in inside.items():
            (repo / name).write_bytes(data)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "first")
        outside = repo.parent / "outside"
        outside.mkdir()
        (outside / "secret.ts").write_bytes(OUTSIDE_SOURCE)
        (repo.parent / "sibling-secret.ts").write_bytes(OUTSIDE_SOURCE)
        if kind == "dot-dot":
            name = "../sibling-secret.ts"
        elif kind == "absolute":
            name = str(outside / "secret.ts")
        elif kind == "symlinked parent":
            (repo / "link").symlink_to(outside, target_is_directory=True)
            name = "link/secret.ts"
        else:
            raise AssertionError(kind)
        write_index(repo, {**inside, name: OUTSIDE_SOURCE})
        listed = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, text=True).stdout
        self.assertIn(name, listed.split("\0"), "precondition: git lists the crafted name")
        return repo

    def test_inventory_refuses_a_crafted_index_name_without_opening_it(self) -> None:
        for kind in ("dot-dot", "absolute", "symlinked parent"):
            with self.subTest(kind):
                repo = self.crafted(kind)
                with patch("hangover.repository._line_count", side_effect=AssertionError("opened a listed file")):
                    with self.assertRaisesRegex(RuntimeError, "refusing the repository's file list"):
                        inventory(repo)

    def test_an_ordinary_index_still_inventories(self) -> None:
        from test_rust import run_git

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            (repo / "src").mkdir()
            (repo / "src" / "index.ts").write_text("export const value = 1;\n")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            run_git(repo, "add", "-A")
            self.assertEqual(1, inventory(repo)["file_count"])
            self.assertEqual({".ts": 1}, inventory(repo)["source_lines_by_suffix"])


if __name__ == "__main__":
    unittest.main()
