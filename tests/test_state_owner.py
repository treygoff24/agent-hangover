"""The state owner marker and first-run messages; all repositories are disposable fixtures."""

import json
import os
import unittest

from hangover.repository import state_owned
from test_untrusted_checkout import invoke, scratch_repo


class StateOwnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = scratch_repo(self)

    def test_owner_marker_binds_hangovers_label_and_this_directory(self) -> None:
        state = self.repo / ".hangover"
        state.mkdir()
        info = os.lstat(state)
        marker = {"tool": "hangover", "repo": str(self.repo), "device": info.st_dev, "inode": info.st_ino}
        # Only hangover's own label is accepted.
        for label, expected in (("hangover", True), ("Hangover", False), ("foreign-tool", False), (None, False)):
            with self.subTest(label=label):
                (state / "owner").write_text(json.dumps({**marker, "tool": label}))
                self.assertEqual(expected, state_owned(self.repo))
        (state / "owner").write_text(json.dumps({**marker, "repo": str(self.repo.parent)}))
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
