import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.evidence import file_digest, run_artifact, tree_identity


class EvidenceTests(unittest.TestCase):
    def test_tracked_vendor_and_untracked_source_are_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "vendor").mkdir()
            source = repo / "vendor/code.ts"
            source.write_text("export const value = 1;\n")
            subprocess.run(["git", "-C", str(repo), "add", "vendor/code.ts"], check=True)
            before = tree_identity(repo)
            source.write_text("export const value = 2;\n")
            self.assertNotEqual(before, tree_identity(repo))
            before = tree_identity(repo)
            (repo / "untracked.ts").write_text("export const another = 1;\n")
            self.assertNotEqual(before, tree_identity(repo))

    def test_symlink_identity_never_reads_the_external_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            target = root / "outside"
            target.write_text("not repository source")
            link = repo / "link"
            link.symlink_to(target)
            with patch.object(Path, "open", side_effect=AssertionError("followed link")):
                before = tree_identity(repo)
            target.write_text("external change")
            self.assertEqual(before, tree_identity(repo))
            link.unlink()
            link.symlink_to(root / "different")
            self.assertNotEqual(before, tree_identity(repo))

    def test_mode_changes_count_but_local_state_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "tool.sh"
            source.write_text("#!/bin/sh\nexit 0\n")
            source.chmod(0o644)
            before = tree_identity(repo)
            source.chmod(0o755)
            self.assertNotEqual(before, tree_identity(repo))
            before = tree_identity(repo)
            (repo / ".hangover").mkdir()
            (repo / ".hangover/state.json").write_text("local state")
            self.assertEqual(before, tree_identity(repo))

    def test_artifact_paths_cannot_escape_or_follow_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            for run, name in (("../outside", "snapshot.json"), ("run", "../outside"), ("run", "/outside")):
                with self.subTest(run=run, name=name), self.assertRaises(RuntimeError):
                    run_artifact(repo, run, name)
            artifacts = repo / ".hangover/runs/run"
            artifacts.mkdir(parents=True)
            (artifacts / "checks").symlink_to(repo, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                run_artifact(repo, "run", "checks/result.log")

    def test_missing_evidence_is_a_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                file_digest(Path(directory) / "missing")


if __name__ == "__main__":
    unittest.main()
