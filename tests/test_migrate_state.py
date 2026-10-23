"""Explicit upgrade migration preserves decisions and refuses external state paths."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from hangover.repository import state_owned
from test_untrusted_checkout import scratch_repo

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "migrate-state.py"
OLD = "dslp-0123456789"
NEW = "hang-0123456789"


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.repo = scratch_repo(self)
        self.root = self.repo / ".hangover"
        self.root.mkdir()
        (self.root / "runs").mkdir()
        self.marker = {"tool": "deslop", "repo": str(self.repo),
                       "device": self.root.stat().st_dev, "inode": self.root.stat().st_ino}
        (self.root / "owner").write_text(json.dumps(self.marker))
        self.card = {"id": OLD, "status": "deferred", "history": [{"reason": "keep it"}],
                     "fix_dir": str(self.root / "fixes" / OLD)}
        (self.root / "state.json").write_text(json.dumps({"repo": str(self.repo), "issues": {OLD: self.card}}))

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.repo), *args],
                              capture_output=True, text=True, timeout=20)

    def test_dry_run_then_apply_preserves_history_and_owner_binding(self):
        fixes = self.root / "fixes" / OLD
        fixes.mkdir(parents=True)
        (fixes / "notes.md").write_text(f"Keep {OLD}\n")
        # U+2028 is valid in a JSON string; it must not be split as a record delimiter.
        (self.root / "runs" / "events.jsonl").write_text(json.dumps({"id": OLD, "note": "one\u2028two"}, ensure_ascii=False) + "\n")
        before = (self.root / "state.json").read_bytes()
        dry = self.invoke()
        self.assertEqual(0, dry.returncode, dry.stderr)
        self.assertEqual(before, (self.root / "state.json").read_bytes())
        self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))
        self.assertFalse((self.root / "state.json.lock").exists())
        result = self.invoke("--apply")
        self.assertEqual(0, result.returncode, result.stderr)
        state = json.loads((self.root / "state.json").read_text())
        self.assertEqual([NEW], list(state["issues"]))
        self.assertEqual("deferred", state["issues"][NEW]["status"])
        self.assertEqual(self.card["history"], state["issues"][NEW]["history"])
        self.assertEqual(str(self.root / "fixes" / NEW), state["issues"][NEW]["fix_dir"])
        self.assertEqual(f"Keep {NEW}\n", (self.root / "fixes" / NEW / "notes.md").read_text())
        self.assertEqual("one\u2028two", json.loads((self.root / "runs" / "events.jsonl").read_text())["note"])
        self.assertTrue(state_owned(self.repo))
        owner = json.loads((self.root / "owner").read_text())
        self.assertEqual(self.marker["inode"], owner["inode"])
        self.assertEqual(self.marker["device"], owner["device"])
        backups = list(self.repo.glob(".hangover.pre-migrate-*"))
        self.assertEqual(1, len(backups))
        self.assertEqual(before, (backups[0] / "state.json").read_bytes())
        again = self.invoke("--apply")
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertIn("nothing to migrate", again.stdout)
        self.assertEqual(backups, list(self.repo.glob(".hangover.pre-migrate-*")))

    def test_large_raw_log_does_not_block_preview(self):
        runs = self.root / "runs" / "old-run"
        runs.mkdir(parents=True)
        log = runs / "checks.stdout"
        with log.open("wb") as handle:
            handle.write(OLD.encode())
            handle.truncate(64 * 1024 * 1024 + 1)
        result = self.invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(64 * 1024 * 1024 + 1, log.stat().st_size)
        with log.open("rb") as handle:
            self.assertEqual(OLD.encode(), handle.read(len(OLD)))
        self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))

    def test_scratch_checkout_is_untouched_and_not_backed_up(self):
        scratch = self.root / "rust-audit-base"
        scratch.mkdir()
        external = self.repo / "private-canary"
        external.write_text("never change this")
        (scratch / "linked.json").symlink_to(external)
        (scratch / "state.json").write_text("not campaign JSON")
        result = self.invoke("--apply")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("never change this", external.read_text())
        self.assertTrue((scratch / "linked.json").is_symlink())
        self.assertEqual("not campaign JSON", (scratch / "state.json").read_text())
        backup, = self.repo.glob(".hangover.pre-migrate-*")
        self.assertFalse((backup / "rust-audit-base").exists())
        self.assertIn(NEW, (self.root / "state.json").read_text())

    def test_missing_marker_gains_no_trust(self):
        owner = self.root / "owner"
        owner.unlink()
        result = self.invoke("--apply")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(state_owned(self.repo))
        self.assertFalse(owner.exists())

    def test_copied_marker_gains_no_trust(self):
        owner = self.root / "owner"
        owner.write_text(json.dumps({**self.marker, "inode": self.marker["inode"] + 1}))
        result = self.invoke("--apply")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(state_owned(self.repo))
        self.assertTrue(owner.exists())

    def test_rejects_linked_and_special_files_before_writes(self):
        external = self.repo / "canary.json"
        external.write_text(json.dumps({"id": OLD}))
        for kind in ("symlink", "hardlink", "directory", "fifo", "lock"):
            with self.subTest(kind=kind):
                path = self.root / "state.json.lock" if kind == "lock" else self.root / "runs" / "linked.json"
                if kind in ("symlink", "lock"):
                    path.symlink_to(external)
                elif kind == "hardlink":
                    os.link(external, path)
                elif kind == "directory":
                    path.symlink_to(self.repo, target_is_directory=True)
                else:
                    os.mkfifo(path)
                try:
                    result = self.invoke("--apply")
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    self.assertEqual({"id": OLD}, json.loads(external.read_text()))
                    self.assertIn(OLD, (self.root / "state.json").read_text())
                    self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))
                finally:
                    path.unlink()

    def test_rejects_held_lock(self):
        with (self.root / "state.json.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.invoke("--apply")
        self.assertEqual(2, result.returncode)
        self.assertIn("held", result.stderr)
        self.assertIn(OLD, (self.root / "state.json").read_text())

    def test_rejects_invalid_json_and_collisions_before_writes(self):
        for content in ("{", json.dumps({OLD: 1, NEW: 2})):
            with self.subTest(content=content):
                (self.root / "runs" / "extra.json").write_text(content)
                result = self.invoke("--apply")
                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertIn(OLD, (self.root / "state.json").read_text())
                self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))
        (self.root / "runs" / "extra.json").unlink()
        (self.root / "runs" / OLD).mkdir()
        (self.root / "runs" / NEW).mkdir()
        self.assertEqual(2, self.invoke("--apply").returncode)
        self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))

    def test_rejects_tracked_state_and_git_includes(self):
        subprocess.run(["git", "-C", str(self.repo), "add", ".hangover"], check=True, capture_output=True)
        result = self.invoke("--apply")
        self.assertEqual(2, result.returncode)
        self.assertIn("tracks files", result.stderr)
        subprocess.run(["git", "-C", str(self.repo), "reset", "--", ".hangover"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "include.path", str(self.repo / "outside")],
                       check=True, capture_output=True)
        result = self.invoke("--apply")
        self.assertEqual(2, result.returncode)
        self.assertIn("includes another file", result.stderr)
        self.assertFalse(list(self.repo.glob(".hangover.pre-migrate-*")))


if __name__ == "__main__":
    unittest.main()
