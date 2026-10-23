import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.oracles import TOOL_ROOT, run_command_review


class CommandRecipeTests(unittest.TestCase):
    def run_recipe(self, text, *, child_exit=0, process_exit=0, truncated=False, planted=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if planted is not None:
                planted(root)
            binary = root / "delegate"
            envelope = json.dumps({
                "exitCode": child_exit, "assistantText": text,
                "assistantTextTruncated": truncated,
            })
            binary.write_text(
                "#!/usr/bin/env python3\nimport sys\n"
                f"print({envelope!r})\nsys.exit({process_exit})\n"
            )
            binary.chmod(0o755)
            run = root / "run"
            run.mkdir()
            prompt = run / "review-prompt.md"
            prompt.write_text("Review this test fixture, which has no product code.")
            packet = run / "packet.json"
            packet.write_text('{}')
            with patch.dict(os.environ, {"PATH": str(root) + os.pathsep + os.environ["PATH"]}):
                result = run_command_review(root, run, packet, "post_fix", [
                    "bash", str(TOOL_ROOT / "docs/examples/review-claude.sh"),
                    "{prompt}", "{output}", "{schema}", "{repo}",
                ])
            return result, (run / "review.json").exists()

    def test_recipe_reads_review_after_prose_braces_and_metadata(self):
        result, exists = self.run_recipe(
            'I checked {braces} and {"metadata":true}.\n'
            '{"verdict":"pass","summary":"reviewed","findings":[],"reviewed_files":["src/index.ts"]}'
        )
        self.assertEqual("completed", result["status"])
        self.assertTrue(exists)
        self.assertEqual("reviewed", result["review"]["summary"])

    def test_recipe_uses_final_review_not_planning_object(self):
        result, _ = self.run_recipe(
            '{"verdict":"pass","summary":"planning","findings":[]}\n'
            '{"verdict":"pass","summary":"actual review","findings":[],"reviewed_files":["src/index.ts"]}'
        )
        self.assertEqual("completed", result["status"])
        self.assertEqual("actual review", result["review"]["summary"])

    def test_recipe_rejects_failed_or_truncated_delegate_evidence(self):
        valid = '{"verdict":"pass","summary":"reviewed","findings":[]}'
        for kwargs in ({"process_exit": 1}, {"child_exit": 1}, {"truncated": True}):
            with self.subTest(kwargs=kwargs):
                result, exists = self.run_recipe(valid, **kwargs)
                self.assertNotEqual("completed", result["status"])
                self.assertFalse(exists)

    def test_recipe_rejects_trailing_incomplete_review(self):
        result, exists = self.run_recipe(
            '{"verdict":"pass","summary":"planning","findings":[]}\n'
            '{"verdict":"pass","summary":"unfinished'
        )
        self.assertNotEqual("completed", result["status"])
        self.assertFalse(exists)

    def test_recipe_python_ignores_modules_planted_in_the_repository(self):
        marker = {}

        def plant(root):
            marker["path"] = root / "planted-json-ran"
            (root / "json.py").write_text(
                f"open({str(marker['path'])!r}, 'w').write('ran')\n"
                "raise SystemExit('planted json.py imported')\n"
            )

        result, exists = self.run_recipe(
            '{"verdict":"pass","summary":"reviewed","findings":[],"reviewed_files":["src/index.ts"]}',
            planted=plant,
        )
        self.assertFalse(marker["path"].exists(), "the recipe imported a module from the repository")
        self.assertEqual("completed", result["status"])
        self.assertTrue(exists)
