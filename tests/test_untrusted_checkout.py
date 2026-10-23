"""What a checkout can make hangover do: `--no-checks` (static mode) is for untrusted checkouts, so
nothing the repository ships (a crafted index, a `.hangover/` directory, a policy file reaching outside)
may execute, choose a command, or read outside the repository; a refusal is a tool error (exit 2)."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from hangover.cli import main
from test_rust import run_git, write_index

TOOL_ERROR = 2


def scratch_repo(case: unittest.TestCase) -> Path:
    """A committed Git repository with no JavaScript or Rust, so no analyzer needs a real toolchain."""
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    repo = Path(directory.name).resolve() / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "README.md").write_text("hello\n")
    (repo / "app" / "main.py").write_text("print('hi')\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "first")
    return repo


def invoke(repo: Path, *arguments: str) -> tuple[int, str, str]:
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = main(["--repo", str(repo), *arguments])
    return rc, stdout.getvalue(), stderr.getvalue()


def shipped_state(repo: Path, sentinel: Path) -> None:
    """A `.hangover/config.json` as a hostile checkout would ship it: its review command writes `sentinel`.
    It names this very repository path (an attacker can guess a CI path), so only provenance stops it."""
    root = repo / ".hangover"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({
        "schema_version": 1,
        "repo": str(repo),
        "checks": [],
        "fallow": {"enabled": True},
        "rust": {"enabled": True},
        "review": {
            "runner": "command",
            "timeout_seconds": 60,
            "delegate": {"lane": "codex", "model": None, "reasoning_effort": None},
            "env": [],
            "command": [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').write('ran')"],
        },
    }))


class ShippedStateTests(unittest.TestCase):
    """`.hangover/` that came with the checkout chooses nothing."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.sentinel = self.repo.parent / "review-command-ran"

    def test_tracked_state_is_refused_in_every_mode_and_its_review_command_never_runs(self) -> None:
        shipped_state(self.repo, self.sentinel)
        run_git(self.repo, "add", "-f", ".hangover/config.json")
        run_git(self.repo, "commit", "-q", "-m", "ship hangover state")
        for arguments in (("run", "--no-checks"), ("scan", "--no-checks"), ("scan",), ("run", "--no-review"),
                          ("init",), ("status",), ("review",), ("doctor",)):
            with self.subTest(arguments=arguments):
                rc, _, stderr = invoke(self.repo, *arguments)
                self.assertEqual(TOOL_ERROR, rc, stderr)
                self.assertIn("the repository tracks files there (.hangover/config.json)", stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertFalse(self.sentinel.exists(), f"{arguments} ran the repository's review command")

    def test_untracked_state_without_this_directorys_marker_is_refused_under_no_checks(self) -> None:
        # The shape of an archive (or a copied checkout) that carries `.hangover/`.
        shipped_state(self.repo, self.sentinel)
        rc, _, stderr = invoke(self.repo, "run", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stderr)
        self.assertIn("hangover did not create it in this directory", stderr)
        self.assertFalse(self.sentinel.exists(), "run --no-checks ran a review command from shipped state")
        rc, _, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stderr)
        self.assertFalse((self.repo / ".hangover" / "state.json").exists(), "static mode wrote into foreign state")
        # `hangover init` is the operator adopting it: then static mode uses it.
        self.assertEqual(0, invoke(self.repo, "init")[0])
        self.assertEqual(0, invoke(self.repo, "run", "--no-checks", "--no-review")[0])

    def test_a_campaign_copied_from_another_checkout_is_not_trusted_under_no_checks(self) -> None:
        other = scratch_repo(self)
        self.assertEqual(0, invoke(other, "init")[0])
        self.assertTrue((other / ".hangover" / "owner").is_file(), "precondition: init marks its directory")
        shutil.copytree(other / ".hangover", self.repo / ".hangover")
        config = json.loads((self.repo / ".hangover" / "config.json").read_text())
        config["repo"] = str(self.repo)
        (self.repo / ".hangover" / "config.json").write_text(json.dumps(config))
        rc, _, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stderr)
        self.assertIn("no owner marker for it", stderr)

    def test_hangovers_own_state_keeps_working_in_both_modes(self) -> None:
        self.assertEqual(0, invoke(self.repo, "run", "--no-checks", "--no-review")[0])
        self.assertTrue((self.repo / ".hangover" / "owner").is_file())
        self.assertEqual(0, invoke(self.repo, "scan", "--no-checks")[0])
        self.assertEqual(0, invoke(self.repo, "scan")[0])

    def test_executing_mode_accepts_an_unmarked_campaign_from_an_older_hangover(self) -> None:
        self.assertEqual(0, invoke(self.repo, "init")[0])
        (self.repo / ".hangover" / "owner").unlink()
        self.assertEqual(0, invoke(self.repo, "scan")[0])
        self.assertEqual(TOOL_ERROR, invoke(self.repo, "scan", "--no-checks")[0])


class CraftedIndexTests(unittest.TestCase):
    """A hand-built index naming a path outside the repository fails the scan as a tool error."""

    def test_scan_and_run_refuse_with_a_tool_error_not_a_traceback(self) -> None:
        repo = scratch_repo(self)
        outside = repo.parent / "outside"
        outside.mkdir()
        (outside / "secret.py").write_text("SECRET = 'outside_secret_marker'\n")
        names = {"README.md": b"hello\n", "app/main.py": b"print('hi')\n"}
        for name in ("../outside/secret.py", str(outside / "secret.py")):
            with self.subTest(name=name):
                write_index(repo, {**names, name: b"SECRET = 'outside_secret_marker'\n"})
                for arguments in (("scan", "--no-checks"), ("run", "--no-checks", "--no-review"), ("scan",)):
                    rc, stdout, stderr = invoke(repo, *arguments)
                    self.assertEqual(TOOL_ERROR, rc, stderr)
                    self.assertIn("refusing the repository's file list", stderr)
                    self.assertNotIn("outside_secret_marker", stdout + stderr)


class RustRefusalExitTests(unittest.TestCase):
    """A Rust analysis that refused repository content is a tool error for scan and run, as for audit;
    any other Rust failure keeps the scan's exit (the failure is recorded in the snapshot)."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        outside = self.repo.parent / "outside-policy.json"
        outside.write_text("{}\n")
        self.policy = self.repo / ".hangover-rust.json"

    def test_a_refused_policy_file_makes_scan_and_run_exit_2(self) -> None:
        self.policy.symlink_to(self.repo.parent / "outside-policy.json")
        for arguments in (("scan", "--no-checks"), ("run", "--no-checks", "--no-review"), ("scan",)):
            with self.subTest(arguments=arguments):
                rc, stdout, stderr = invoke(self.repo, *arguments)
                self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
                self.assertIn("refusing symlinked or external .hangover-rust.json", stderr)

    def test_an_invalid_policy_file_keeps_the_scan_exit(self) -> None:
        self.policy.write_text("{not json")
        for arguments in (("scan", "--no-checks"), ("run", "--no-checks", "--no-review")):
            with self.subTest(arguments=arguments):
                rc, stdout, stderr = invoke(self.repo, *arguments)
                self.assertEqual(0, rc, stdout + stderr)
                self.assertIn("rust: failed", stdout)


if __name__ == "__main__":
    unittest.main()
