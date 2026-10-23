import tempfile
import subprocess
import unittest
from pathlib import Path

from hangover.scope import assess_scope, select_scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "src").mkdir()
        (self.repo / "src/a.py").write_text("a = 1\n")
        (self.repo / "src/b.py").write_text("b = 2\n")
        (self.repo / "README.md").write_text("A fixture.\n")

    def test_selection_is_explicit_deduplicated_and_does_not_write(self):
        before = sorted(str(p) for p in self.repo.rglob("*"))
        scope = select_scope(self.repo, ["./src/", "src/a.py"])
        self.assertEqual(["src/a.py", "src/b.py"], scope["files"])
        self.assertEqual(["README.md"], scope["unselected_files"])
        self.assertEqual("selected", scope["kind"])
        self.assertEqual(before, sorted(str(p) for p in self.repo.rglob("*")))

    def test_invalid_scope_refuses_traversal_absolute_empty_and_symlinks(self):
        (self.repo / "link").symlink_to(self.repo / "src", target_is_directory=True)
        for name in ("../src", str(self.repo / "src"), "missing", "", "link", "link/a.py", "src/../README.md"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                select_scope(self.repo, [name])

    def test_symlinked_ancestor_above_repo_does_not_hide_source(self):
        real = self.repo / "real"
        project = real / "project"
        (project / "src").mkdir(parents=True)
        (project / "src/a.py").write_text("a = 1\n")
        alias = self.repo / "linked"
        alias.symlink_to(real, target_is_directory=True)
        for requested in (None, ["src"]):
            with self.subTest(requested=requested):
                self.assertEqual(["src/a.py"], select_scope(alias / "project", requested)["files"])

    def test_tracked_file_cannot_be_read_through_a_replaced_directory_symlink(self):
        subprocess.run(["git", "init", "-q", self.repo], check=True)
        subprocess.run(["git", "-C", self.repo, "add", "src"], check=True)
        outside = self.repo / "outside"
        outside.mkdir()
        (outside / "a.py").write_text("outside = True\n")
        (self.repo / "src/a.py").unlink()
        (self.repo / "src/b.py").unlink()
        (self.repo / "src").rmdir()
        (self.repo / "src").symlink_to(outside, target_is_directory=True)
        # The one file-list validator (repository.checked_files) refuses a listed path that leads
        # through a symlink, rather than skipping it: nothing outside is read either way.
        for requested in (None, ["src"]):
            with self.subTest(requested=requested), self.assertRaisesRegex(RuntimeError, "symlink"):
                select_scope(self.repo, requested)

    def test_coverage_is_reported_not_verified_and_leaves_uninspected_files(self):
        scope = select_scope(self.repo, ["src"])
        coverage = assess_scope(scope, {"reviewed_files": ["src/a.py"], "findings": []})
        self.assertEqual(["src/a.py"], coverage["reported_files"])
        self.assertEqual(["src/b.py"], coverage["remaining_selected_files"])
        self.assertEqual(["README.md"], coverage["unselected_files"])
        self.assertFalse(coverage["exhaustive"])
        self.assertEqual("reviewer_reported", coverage["evidence"])

    def test_scoped_verdict_cannot_claim_or_file_outside_its_selection(self):
        scope = select_scope(self.repo, ["src/a.py"])
        for review in (
            {"reviewed_files": ["README.md"], "findings": []},
            {"reviewed_files": ["src/a.py", "src/a.py"], "findings": []},
            {"reviewed_files": ["src/a.py"], "findings": [{"files": ["src/b.py"]}]},
        ):
            with self.subTest(review=review), self.assertRaises(RuntimeError):
                assess_scope(scope, review)


class ListGroupingTests(unittest.TestCase):
    def issue(self, ident, category, files, spans=()):
        return {"id": ident, "category": category, "files": files, "status": "open",
                "duplication_identity": {"spans": [
                    {"file": f, "start_line": a, "end_line": b} for f, a, b in spans]}}

    def test_exclude_tests_paths(self):
        from hangover.selection import is_non_source_path
        for path in ("tests/a.py", "src/test_a.py", "web/a.test.ts", "docs/x.md", "src/spikes/a.py", "a/fixtures/b.py",
                     "apps/web/e2e/inbox/a.ts", "src/__mocks__/m.ts"):
            self.assertTrue(is_non_source_path(path), path)
        for path in ("src/a.py", "src/testing_utils.py", "contest/a.py"):
            self.assertFalse(is_non_source_path(path), path)

    def make_repo(self):
        repo = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, repo)
        (repo / "src").mkdir()
        (repo / "src/a.py").write_text("a\nb\nc\n")
        return repo

    def issues(self):
        # mixed: 5+5 source lines, 30 test lines; count order conflicts with weight order
        mixed = self.issue("mixed", "duplication", ["src/a.py", "tests/t.py"],
                           [("src/a.py", 1, 5), ("tests/t.py", 1, 30)])
        heavy = self.issue("heavy", "duplication", ["lib/x.py", "lib/y.py"],
                           [("lib/x.py", 1, 8), ("lib/y.py", 1, 8)])
        d1 = self.issue("d1", "dead_code", ["src/b.py"])
        d2 = self.issue("d2", "dead_code", ["src/c.py"])
        return [mixed, heavy, d1, d2]

    def test_weights_units_and_estimates(self):
        from hangover.selection import issue_line_weight
        big = self.issue("i", "duplication", ["a.py", "b.py"], [("a.py", 1, 10), ("b.py", 1, 10)])
        self.assertEqual((20, False), issue_line_weight(big))
        self.assertEqual((10, False), issue_line_weight(big, {"a.py"}))
        est = {"id": "e", "files": ["a.py", "b.py"], "evidence": [
            "Fallow found 10 duplicated lines (5 tokens) across 2 instances in: a.py, b.py."]}
        self.assertEqual((20, True), issue_line_weight(est))
        self.assertEqual((None, False), issue_line_weight({"id": "n", "files": ["a.py"]}))

    def run_list(self, repo, issues, **kwargs):
        import io, json, contextlib
        from unittest import mock
        from hangover import selection
        state = {"issues": {i["id"]: i for i in issues}}
        with mock.patch.object(selection, "load_state", return_value=state), \
             mock.patch.object(selection, "ordered_issues", return_value=issues), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            selection.list_issues(repo, kwargs.pop("as_json", True), {}, **kwargs)
        text = out.getvalue()
        return json.loads(text) if text.lstrip().startswith("{") else text

    def test_json_exclude_tests_sort_and_group_dir(self):
        repo = self.make_repo()
        data = self.run_list(repo, self.issues(), sort="lines", exclude_tests=True, group_by="dir")["data"]
        weights = {i["id"]: i["lines"] for i in data["issues"]}
        self.assertEqual({"heavy": 16, "mixed": 5, "d1": None, "d2": None}, weights)
        self.assertEqual(["heavy", "mixed"], [i["id"] for i in data["issues"]][:2])
        self.assertNotIn("tests/t.py", [f for i in data["issues"] for f in i["files"]])
        groups = {g["group"]: g for g in data["groups"]}
        self.assertEqual(16, groups["lib"]["lines"])
        self.assertEqual(5, groups["src"]["lines"])
        self.assertEqual(3, groups["src"]["source_lines"])
        # by count src (3 findings) would lead; by lines lib leads
        self.assertEqual(["lib", "src"], [g["group"] for g in data["groups"]])
        self.assertEqual(3, groups["src"]["findings"])

    def test_file_grouping_and_category_and_text(self):
        repo = self.make_repo()
        data = self.run_list(repo, self.issues(), group_by="file", sort="lines")["data"]
        self.assertEqual("file", data["group_by"])
        groups = {g["group"]: g for g in data["groups"]}
        self.assertEqual(35, groups["tests/t.py"]["lines"])  # full issue weight in each file group
        self.assertEqual(35, groups["src/a.py"]["lines"])
        self.assertEqual(16, groups["lib/x.py"]["lines"])
        self.assertEqual(["src/a.py", "tests/t.py", "lib/x.py", "lib/y.py"], [g["group"] for g in data["groups"]][:4])
        cats = self.run_list(repo, self.issues(), group_by="category")["data"]["groups"]
        self.assertEqual({"dead_code": 2, "duplication": 2}, {g["group"]: g["findings"] for g in cats})
        text = self.run_list(repo, self.issues(), as_json=False, group_by="dir")
        self.assertIn("src: 3 finding(s)", text)
        self.assertIn("source lines", text)

    def test_status_delta_line(self):
        from hangover.cli import _baseline_delta
        snap = lambda dead, clones, health: {"fallow": {"summary": {
            "total_dead_code_issues": dead, "duplication": {"clone_groups": clones}, "health_score": health}}}
        delta = _baseline_delta(snap(805, 108, 57.2), snap(333, 81, 61.2))
        self.assertIn("dead_code 805 -> 333, clone_groups 108 -> 81, health 57.2 -> 61.2", delta["line"])
        self.assertIsNone(_baseline_delta(None, snap(1, 1, 1)))
