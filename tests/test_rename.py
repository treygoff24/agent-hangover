"""Public-name migration and first-run messages; all repositories are disposable fixtures."""

import json
import os
import unittest
from unittest.mock import patch

from hangover.oracles import FALLOW_VERSION
from hangover.repository import state_owned
from test_untrusted_checkout import invoke, scratch_repo


class RenameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = scratch_repo(self)

    def test_legacy_init_stops_before_creating_new_state(self) -> None:
        legacy = self.repo / ".deslop"
        legacy.mkdir()
        (legacy / "config.json").write_text("not configuration to import")
        # Tracked legacy state is foreign data, not the new tool's campaign state.
        from test_rust import run_git
        run_git(self.repo, "add", ".deslop/config.json")
        for args in (("init",), ("init", "--force"), ("scan",), ("scan", "--no-checks"),
                     ("run", "--no-checks", "--no-review")):
            with self.subTest(args=args):
                rc, out, err = invoke(self.repo, *args)
                self.assertEqual(1, rc, out + err)
                hints = [line for line in out.splitlines() if "mv .deslop .hangover" in line]
                self.assertEqual(1, len(hints), out)
                self.assertTrue(hints[0].startswith("info: "))
                self.assertEqual("not configuration to import", (legacy / "config.json").read_text())
                self.assertFalse((self.repo / ".hangover").exists())
        rc, out, err = invoke(self.repo, "audit", "--base", "HEAD", "--json")
        self.assertEqual(1, rc, out + err)
        self.assertEqual("blocked", json.loads(out)["state"])
        self.assertIn("--ignore-legacy", json.loads(out)["next_action"])
        self.assertEqual(1, err.count("mv .deslop .hangover"))
        self.assertFalse((self.repo / ".hangover").exists())
        clean = scratch_repo(self)
        self.assertNotIn("mv .deslop .hangover", invoke(clean, "init")[1])

    def test_init_can_explicitly_ignore_legacy_state(self) -> None:
        legacy = self.repo / ".deslop"
        legacy.mkdir()
        (legacy / "config.json").write_text("not configuration to import")
        rc, out, err = invoke(self.repo, "init", "--ignore-legacy")
        self.assertEqual(0, rc, out + err)
        self.assertTrue((self.repo / ".hangover" / "config.json").is_file())
        self.assertTrue(state_owned(self.repo))
        exclude = (self.repo / ".git" / "info" / "exclude").read_text().splitlines()
        self.assertEqual({"/.hangover/", "/.fallow/"},
                         {line for line in exclude if line and not line.startswith("#")})
        self.assertEqual("not configuration to import", (legacy / "config.json").read_text())
        self.assertNotIn("mv .deslop .hangover", invoke(self.repo, "init")[1])

    def test_doctor_legacy_hint_keeps_json_stdout_machine_readable(self) -> None:
        (self.repo / ".deslop").mkdir()
        with patch("hangover.cli.codex_binary", return_value=None), patch(
            "hangover.cli.delegate_binary", return_value=None
        ), patch("hangover.cli.fallow_version", return_value=f"fallow {FALLOW_VERSION}"):
            rc, out, err = invoke(self.repo, "doctor", "--json")
            self.assertEqual(1, rc)  # This fixture intentionally has no Codex runner.
            self.assertEqual(str(self.repo), json.loads(out)["repo"])
            self.assertEqual(1, err.count("mv .deslop .hangover"), err)
            _, out, err = invoke(self.repo, "doctor")
            self.assertIn("mv .deslop .hangover", out)
            self.assertNotIn("mv .deslop .hangover", err)
            (self.repo / ".hangover").mkdir()
            self.assertNotIn("mv .deslop .hangover", invoke(self.repo, "doctor")[1])
        self.assertFalse((self.repo / ".hangover" / "config.json").exists())

    def test_same_filesystem_legacy_state_move_keeps_owner_binding(self) -> None:
        # Reconstruct the old marker, rather than asking the renamed init to make it.
        legacy = self.repo / ".deslop"
        legacy.mkdir()
        before = os.lstat(legacy)
        marker = {"tool": "deslop", "repo": str(self.repo),
                  "device": before.st_dev, "inode": before.st_ino}
        (legacy / "owner").write_text(json.dumps(marker))
        new = self.repo / ".hangover"
        legacy.rename(new)
        after = os.lstat(new)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertTrue(state_owned(self.repo), "same-filesystem rename must retain the owner binding")
        # The tool label still matters; only the exact old and new labels are accepted.
        for label, expected in (("hangover", True), ("foreign-tool", False), (None, False)):
            with self.subTest(label=label):
                (new / "owner").write_text(json.dumps({**marker, "tool": label}))
                self.assertEqual(expected, state_owned(self.repo))
        (new / "owner").write_text(json.dumps({**marker, "repo": str(self.repo.parent)}))
        self.assertFalse(state_owned(self.repo), "the parent-path binding must still be enforced")

    def test_static_first_scan_does_not_warn_to_use_static_mode(self) -> None:
        self.assertFalse((self.repo / ".hangover").exists(), "precondition: first scan initializes")
        rc, out, err = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(0, rc, out + err)
        self.assertIn("initialized ", out)
        self.assertNotIn("warning: configured checks execute repository code", out + err)
        # A normal init still warns about executing configured checks.
        other = scratch_repo(self)
        rc, out, err = invoke(other, "init")
        self.assertEqual(0, rc, err)
        self.assertIn("warning: configured checks execute repository code", out)


if __name__ == "__main__":
    unittest.main()
