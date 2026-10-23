import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover import rust
from hangover.cli import _verification_blockers
from hangover.model import issue_id, merge_findings, new_state
from hangover.repository import _command_stage, discover_checks

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rust"
MARKER = "build-script-ran"
TOOLS_MISSING = None if shutil.which("cargo") and rust.ast_grep_path() and rust.jscpd_path() else (
    "cargo, ast-grep and jscpd are needed (install a Rust toolchain; npm ci)")


def run_git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=hangover-test", "-c", "user.email=test@example.invalid",
                           "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def scratch_repo(case: unittest.TestCase, fixture: str | None = None, subdir: str = "") -> Path:
    """A committed Git repository in a scratch directory, optionally holding a copy of a fixture."""
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    repo = Path(directory.name).resolve() / "repo"
    if fixture:
        shutil.copytree(FIXTURES / fixture, repo / subdir if subdir else repo)
    else:
        repo.mkdir()
        (repo / "README").write_text("one\n")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    with (repo / ".git" / "info" / "exclude").open("a") as exclude:
        exclude.write(".hangover/\n")  # As `hangover init` does.
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "first")
    return repo


def cargo_isolated(case: unittest.TestCase) -> None:
    """Keep cargo's and hangover's build output inside each scratch repository."""
    patcher = patch.dict(os.environ)
    patcher.start()
    case.addCleanup(patcher.stop)
    for name in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "HANGOVER_CARGO_TARGET_DIR"):
        os.environ.pop(name, None)


def card(category: str, key: str) -> dict:
    return rust._finding(category, [key], title=f"{category} {key}", evidence=["e"], files=["src/lib.rs"],
                         symbols=[], priority="P2", risk="low", confidence="high", chesterton="c")


class RustLexTests(unittest.TestCase):
    def test_comments_go_and_strings_stay(self) -> None:
        source = (
            'let url = "http://x"; keep_me(); // gone_line\n'
            "/* gone /* nested */ still_gone */ after();\n"
            'let raw = r#"a "quoted" // not_a_comment"#; tail();\n'
            "fn f<'a>(c: char) -> bool { c == '\"' || c == '/' } // doc_gone\n"
        )
        names = set(rust.IDENTIFIER.findall(rust.strip_comments(source)))
        self.assertTrue({"keep_me", "after", "not_a_comment", "tail", "url"} <= names)
        self.assertFalse({"gone_line", "gone", "nested", "still_gone", "doc_gone"} & names)
        self.assertEqual(source.count("\n"), rust.strip_comments(source).count("\n"))


class RustFindingTests(unittest.TestCase):
    def test_complexity_lints_merge_into_one_card_per_function(self) -> None:
        functions = [{"path": "src/a.rs", "name": "run", "qualname": "Engine::run", "start": 10, "end": 200,
                      "test": False}]
        messages = [
            {"lint": "clippy::cognitive_complexity", "path": "src/a.rs", "line": 10,
             "message": "the function has a cognitive complexity of (48/15)"},
            {"lint": "clippy::too_many_lines", "path": "src/a.rs", "line": 10,
             "message": "this function has too many lines (190/100)"},
        ]
        churn = {"hotspots": ["src/a.rs"], "commits": {"src/a.rs": 9}, "window_days": 180, "cutoff": 5}
        (finding,) = rust._complexity_findings(messages, functions, rust.DEFAULT_THRESHOLDS, churn)
        self.assertEqual(["rust", "complexity", "src/a.rs", "Engine::run"], finding["fingerprint"])
        self.assertEqual({"cognitive": 48, "line_count": 190}, {
            key: value for key, value in finding["complexity_metrics"].items() if not key.startswith("max_")})
        # 48/15 is past three times the threshold: P1, already the most urgent the hotspot bump allows.
        self.assertEqual("P1", finding["priority"])
        self.assertEqual("complexity:src/a.rs:Engine::run", finding["suppression"]["value"])

    def test_pub_items_unused_anywhere_and_used_only_inside_their_crate(self) -> None:
        def info(package: str, role: str, text: str) -> dict:
            return {"package": package, "role": role, "text": text, "lines": text.splitlines(), "test_ranges": []}

        files = {
            "core/src/lib.rs": info("core", "lib", "pub fn shared() {}\npub fn internal() {}\npub fn orphan() {}\n"
                                    "fn use_it() { internal(); helper(); }\n"),
            "core/src/util.rs": info("core", "lib", "pub fn helper() {}\n"),
            "app/src/main.rs": info("app", "bin", "fn main() { core::shared(); } // orphan\n"),
        }

        def pub_fn(line: int, name: str) -> dict:
            return {"kind": "fn", "name": name, "start": line, "end": line, "visibility": "pub", "test": False,
                    "exported": False, "trait_method": False}

        items = {"core/src/lib.rs": [pub_fn(line, name) for line, name in ((1, "shared"), (2, "internal"), (3, "orphan"))],
                 "core/src/util.rs": [pub_fn(1, "helper")]}
        workspace = {"packages": {
            "core": {"name": "core", "dir": "core", "manifest": "core/Cargo.toml", "lib": True, "proc_macro": False,
                     "publishable": False, "dependents": ["app"], "path_dependencies": []},
            "app": {"name": "app", "dir": "app", "manifest": "app/Cargo.toml", "lib": False, "proc_macro": False,
                    "publishable": False, "dependents": [], "path_dependencies": ["core"]},
        }}
        cards = rust._pub_findings(files, items, workspace, rust.DEFAULT_THRESHOLDS)
        findings = {item["category"]: item for item in cards}
        self.assertEqual(["orphan"], findings["unused_pub_items"]["symbols"])
        # Narrowing is one decision per crate (a pub fn returning another file's pub type cannot be
        # narrowed alone), so the crate-local items of every file share one card.
        self.assertEqual(1, sum(item["category"] == "crate_local_pub" for item in cards))
        local = findings["crate_local_pub"]
        self.assertEqual(["rust", "crate_local_pub", "core"], local["fingerprint"])
        self.assertEqual(["helper", "internal"], local["pub_items"])
        self.assertEqual(["core/src/lib.rs", "core/src/util.rs"], local["files"])

    @unittest.skipUnless(rust.ast_grep_path(), "ast-grep is not installed (npm ci)")
    def test_ast_grep_inventory_names_functions_and_test_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "src").mkdir()
            source = ("pub struct Engine;\n\nimpl Engine {\n    pub fn run(&self) -> u8 {\n        1\n    }\n}\n\n"
                      "#[cfg(test)]\nmod tests {\n    #[test]\n    fn runs() {}\n}\n\n#[cfg(test)]\nmod more;\n")
            (repo / "src/lib.rs").write_text(source)
            (repo / "src/more.rs").write_text("fn helper() {}\n")
            files = {path: {"package": "p", "role": "lib", "text": text, "lines": text.splitlines(), "test_ranges": []}
                     for path, text in (("src/lib.rs", source), ("src/more.rs", "fn helper() {}\n"))}
            workspace = {"packages": {"p": {"dir": ""}}}
            command, items = rust._items(repo, repo / "out", files, workspace, rust.cargo_environment())
            self.assertEqual("completed", command["status"], command)
            functions = {item["qualname"]: item for item in rust._annotate(files, items)}
            self.assertEqual({"Engine::run", "runs", "helper"}, set(functions))
            self.assertFalse(functions["Engine::run"]["test"])
            self.assertTrue(functions["runs"]["test"] and functions["helper"]["test"])
            self.assertEqual([(10, 13)], files["src/lib.rs"]["test_ranges"])
            self.assertEqual("unit_test", files["src/more.rs"]["role"])


class RustClippyTests(unittest.TestCase):
    def clippy_status(self, target_kind: list[str]) -> str:
        record = {"reason": "compiler-message", "target": {"name": "core", "kind": target_kind},
                  "message": {"level": "error", "code": {"code": "clippy::never_loop"}, "message": "never loops",
                              "spans": [{"is_primary": True, "file_name": "src/lib.rs", "line_start": 3}]}}
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            stdout = repo / "clippy.out"
            stdout.write_text(json.dumps(record) + "\n")
            ran = {"status": "completed", "exit_code": 101, "stdout": str(stdout), "stderr_tail": ""}
            with patch.object(rust, "_run", return_value=ran):
                command, _ = rust._clippy(repo, repo / "out", {"root": str(repo)}, rust.load_policy(repo),
                                          {}, repo / "target", conf_root=repo / ".hangover")
        return command["status"]

    def test_an_error_in_a_library_leaves_its_dependents_unlinted(self) -> None:
        self.assertEqual("partial", self.clippy_status(["lib"]))
        # Nothing depends on a test target: its deny-level lint is the gate's concern only.
        self.assertEqual("completed", self.clippy_status(["test"]))

    def test_generated_clippy_config_never_writes_through_a_link(self) -> None:
        """M2: a planted link under the build tree or hangover's own config directory is never written through."""
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            repo, victim = scratch / "repo", scratch / "victim.txt"
            repo.mkdir()
            victim.write_text("USER FILE\n")
            target, conf_root = repo / "target" / "hangover", repo / ".hangover"
            # Where earlier versions wrote the generated config, inside the (repository-controlled) build tree.
            (target / "clippy-conf").mkdir(parents=True)
            (target / "clippy-conf" / "clippy.toml").symlink_to(victim)
            seen: list[str] = []

            def fake_run(name, command, cwd, out_dir, environment, timeout, ok_codes=(0,)):
                seen.append(environment["CLIPPY_CONF_DIR"])
                stdout = out_dir / "clippy.out"
                out_dir.mkdir(parents=True, exist_ok=True)
                stdout.write_text("")
                return {"status": "completed", "exit_code": 0, "stdout": str(stdout), "stderr_tail": ""}

            policy = rust.load_policy(repo)
            with patch.object(rust, "_run", side_effect=fake_run):
                command, _ = rust._clippy(repo, repo / "out", {"root": str(repo)}, policy, {}, target,
                                          conf_root=conf_root)
            self.assertEqual("completed", command["status"], command)
            self.assertEqual("USER FILE\n", victim.read_text())
            (conf_dir,) = seen
            config = Path(conf_dir) / "clippy.toml"
            self.assertTrue(config.is_file() and not config.is_symlink())
            self.assertTrue(Path(conf_dir).resolve().is_relative_to(conf_root.resolve()), conf_dir)
            self.assertIn("cognitive-complexity-threshold = 15", config.read_text())
            # The same policy reuses the same directory (clippy re-lints when CLIPPY_CONF_DIR moves).
            self.assertEqual(Path(conf_dir), rust._clippy_config_dir(repo, conf_root, policy["thresholds"]))

            # A link planted at hangover's own config file, or at a directory above it, is refused.
            config.unlink()
            config.symlink_to(victim)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                rust._clippy_config_dir(repo, conf_root, policy["thresholds"])
            self.assertEqual("USER FILE\n", victim.read_text())
            config.unlink()
            elsewhere = scratch / "elsewhere"
            elsewhere.mkdir()
            shutil.rmtree(conf_dir)
            Path(conf_dir).symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                rust._clippy_config_dir(repo, conf_root, policy["thresholds"])
            self.assertEqual([], list(elsewhere.iterdir()))
            # Through _clippy the refusal is a failed section, not a crash.
            with patch.object(rust, "_run", side_effect=fake_run):
                command, _ = rust._clippy(repo, repo / "out", {"root": str(repo)}, policy, {}, target,
                                          conf_root=conf_root)
            self.assertEqual("failed", command["status"])
            self.assertIn("symlink", command["error"])

    def test_a_symlinked_repository_clippy_toml_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            repo = scratch / "repo"
            repo.mkdir()
            (scratch / "secret").write_text("avoid-lints = []\n")
            (repo / "clippy.toml").symlink_to(scratch / "secret")
            with self.assertRaisesRegex(RuntimeError, "clippy.toml"):
                rust._clippy_config_dir(repo, repo / ".hangover", rust.DEFAULT_THRESHOLDS)


class RustCampaignTests(unittest.TestCase):
    def test_policy_rejects_unknown_thresholds_and_records_suppressions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / rust.POLICY_FILE).write_text(json.dumps({"thresholds": {"cognitive": 20}}))
            self.assertEqual(20, rust.load_policy(repo)["thresholds"]["cognitive"])
            rust.add_suppression(repo, "god_file:src/big.rs")
            rust.add_suppression(repo, "god_file:src/big.rs")
            self.assertEqual(["god_file:src/big.rs"], rust.load_policy(repo)["ignore"])
            (repo / rust.POLICY_FILE).write_text(json.dumps({"thresholds": {"cognitve": 20}}))
            with self.assertRaisesRegex(RuntimeError, "unknown threshold"):
                rust.load_policy(repo)

    def test_rust_cards_go_stale_only_when_their_section_completed(self) -> None:
        state = new_state(Path("/repo"))
        complexity, duplicate = card("complexity", "a"), card("duplication", "b")
        merge_findings(state, [complexity, duplicate], "first")
        scan = {"kind": "scan", "rust": {"commands": {"clippy": {"status": "completed"},
                                                      "dupes": {"status": "failed"}}},
                "rust_comparison": {"comparable": True}}
        merge_findings(state, [], "second", scan_result=scan)
        statuses = {issue["category"]: issue["status"] for issue in state["issues"].values()}
        self.assertEqual({"complexity": "stale", "duplication": "open"}, statuses)
        # An analyzer card is never merged as a subjective claim: no possible_duplicates field.
        self.assertNotIn("possible_duplicates", state["issues"][issue_id(complexity)])

    def test_verify_blocks_a_present_finding_and_incomparable_evidence(self) -> None:
        finding = card("complexity", "a")
        issue = {**finding, "id": issue_id(finding)}
        snapshot = {"fallow": {"status": "not_applicable"}, "rust": {"status": "completed", "sections": {}},
                    "rust_comparison": {"comparable": False, "reason": "Rust tool versions changed"}}
        blockers = _verification_blockers(snapshot, issue, [issue["id"]])
        self.assertIn("the original Rust finding is still present", blockers)
        self.assertTrue(any("not comparable" in blocker for blocker in blockers))
        snapshot["rust_comparison"] = {"comparable": True}
        self.assertEqual([], _verification_blockers(snapshot, issue, []))

    def test_comparison_names_what_changed(self) -> None:
        before = {"rust": {"status": "completed", "version": "hangover-rust 1", "tools": {"clippy": "a"},
                           "policy_sha256": "p", "sections": {"clippy": "completed"}, "summary": {"findings": 3}}}
        after = json.loads(json.dumps(before))
        self.assertTrue(rust.rust_comparison(before, after)["comparable"])
        after["rust"]["tools"] = {"clippy": "b"}
        self.assertEqual("version_changed", rust.rust_comparison(before, after)["kind"])
        # A static scan (cargo never run: clippy skipped, no cargo versions) against a full baseline:
        # the missing evidence is the reason, not the tool versions it could not read.
        after["rust"].update(tools={"clippy": None}, sections={"clippy": "skipped"})
        comparison = rust.rust_comparison(before, after)
        self.assertEqual("sections_changed", comparison["kind"])
        self.assertIn("clippy -> )", comparison["reason"])


COMPLETED_SCAN = {"status": "completed", "findings": [], "summary": {}}


def recorded_audit(repo: Path, base: str, *, execute: bool = True, name: str = "audit") -> tuple[dict, list[Path]]:
    """run_rust_audit with the scans stubbed out (they need cargo): the trees each scan was given, in order."""
    trees: list[Path] = []

    def fake_scan(tree: Path, run_dir: Path, **options) -> dict:
        trees.append(Path(tree))
        return COMPLETED_SCAN

    run_dir = repo / ".hangover" / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    with patch.object(rust, "applicable", return_value=True), \
            patch.object(rust, "run_rust_scan", side_effect=fake_scan):
        return rust.run_rust_audit(repo, run_dir, base, execute=execute), trees


def plant(repo: Path, kind: str, marker: Path) -> None:
    """Repository-controlled git configuration that runs a program when git checks a tree out."""
    hook = f"#!/bin/sh\necho {kind} >> '{marker}'\n"
    git_dir = repo / ".git"
    if kind == "post-checkout hook":
        (git_dir / "hooks" / "post-checkout").write_text(hook)
        (git_dir / "hooks" / "post-checkout").chmod(0o755)
    elif kind == "hooksPath from an included config":
        hooks = repo.parent / "included-hooks"
        hooks.mkdir()
        for name in ("post-checkout", "reference-transaction"):
            (hooks / name).write_text(hook)
            (hooks / name).chmod(0o755)
        (git_dir / "included.cfg").write_text(f"[core]\n\thooksPath = {hooks}\n")
        with (git_dir / "config").open("a") as config:
            config.write("[include]\n\tpath = included.cfg\n")
    elif kind == "smudge filter":
        # .gitattributes is committed in the base (see two_commits); the driver is local config.
        with (git_dir / "config").open("a") as config:
            config.write(f"[filter \"planted\"]\n\tsmudge = \"echo {kind} >> '{marker}'; cat\"\n\tclean = cat\n")
    else:
        raise AssertionError(kind)


PLANTS = ("post-checkout hook", "hooksPath from an included config", "smudge filter")


def two_commits(case: unittest.TestCase) -> tuple[Path, str, str]:
    """A repository whose base commit (README "one", a filter attribute) differs from HEAD (README "two")."""
    repo = scratch_repo(case)
    (repo / ".gitattributes").write_text("README filter=planted\n")
    run_git(repo, "add", ".gitattributes")
    run_git(repo, "commit", "-q", "-m", "attributes")
    first = run_git(repo, "rev-parse", "HEAD")
    (repo / "README").write_text("two\n")
    run_git(repo, "commit", "-q", "-am", "second")
    return repo, first, run_git(repo, "rev-parse", "HEAD")


class RustHermeticGitTests(unittest.TestCase):
    """B2: an audit materializes the base tree without a checkout, so no hook, filter or included
    configuration the repository set up ever runs (static mode promises to run no repository code)."""

    def test_planted_hooks_filters_and_included_config_never_run(self) -> None:
        for kind in PLANTS:
            with self.subTest(kind):
                repo, first, second = two_commits(self)
                marker = repo.parent / "MARKER"
                plant(repo, kind, marker)
                result, trees = recorded_audit(repo, first, execute=False)
                self.assertEqual("completed", result["status"], result)
                self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")
                # The base side read the base commit's bytes, unfiltered.
                self.assertEqual(2, len(trees))
                self.assertEqual("one\n", (trees[1] / "README").read_text())
                self.assertEqual("README filter=planted\n", (trees[1] / ".gitattributes").read_text())
                self.assertEqual("main", run_git(repo, "branch", "--show-current"))
                self.assertEqual(second, run_git(repo, "rev-parse", "HEAD"))
                self.assertEqual("", run_git(repo, "status", "--porcelain"))
                # Positive control: a plain checkout of the same base does run the plant.
                subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", "--detach",
                                str(repo.parent / "control"), first], check=True, capture_output=True)
                self.assertTrue(marker.is_file(), f"{kind} did not bind")

    def test_the_no_execute_recipe_disarms_drivers_even_for_commands_that_apply_them(self) -> None:
        """Defense in depth: under rust's git recipe, even `cat-file --filters` and textconv start no
        driver, whether .gitattributes or .git/info/attributes selects it and an included file defines it."""
        repo, first, second = two_commits(self)
        marker = repo.parent / "MARKER"
        (repo / ".git" / "drivers.cfg").write_text(
            f"[filter \"planted\"]\n\tsmudge = \"echo smudge >> '{marker}'; cat\"\n"
            f"\tprocess = \"sh -c 'echo process >> {marker}'\"\n"
            f"[diff \"planted\"]\n\ttextconv = \"sh -c 'echo textconv >> {marker}'\"\n")
        with (repo / ".git" / "config").open("a") as config:
            config.write("[include]\n\tpath = drivers.cfg\n")
        (repo / ".git" / "info" / "attributes").write_text("* filter=planted diff=planted\n")
        prefix, environment = rust._no_execute_git(repo)
        for args in (["cat-file", "--filters", "HEAD:README"], ["cat-file", "--textconv", "HEAD:README"],
                     ["log", "-p", "--textconv", "-1"]):
            subprocess.run([*prefix, *args], capture_output=True, env=environment, check=False)
            self.assertFalse(marker.exists(), (args, marker.read_text() if marker.exists() else ""))
        # Positive control: the same command under the repository's own config runs the driver.
        subprocess.run(["git", "-C", str(repo), "cat-file", "--filters", "HEAD:README"], capture_output=True)
        self.assertTrue(marker.is_file(), "the planted drivers did not bind")

    def test_a_driver_whose_name_holds_an_equals_sign_is_disarmed(self) -> None:
        """`-c filter.a=b.smudge=cat` would split at the first `=`: the override goes as a key/value pair."""
        repo, first, second = two_commits(self)
        marker = repo.parent / "MARKER"
        with (repo / ".git" / "config").open("a") as config:
            config.write(f"[filter \"a=b\"]\n\tsmudge = \"echo smudge >> '{marker}'; cat\"\n\trequired = true\n"
                         f"[diff \"a=b\"]\n\ttextconv = \"sh -c 'echo textconv >> {marker}'\"\n")
        (repo / ".git" / "info" / "attributes").write_text("* filter=a=b diff=a=b\n")
        prefix, environment = rust._no_execute_git(repo)
        for args in (["cat-file", "--filters", "HEAD:README"], ["cat-file", "--textconv", "HEAD:README"]):
            subprocess.run([*prefix, *args], capture_output=True, env=environment, check=False)
            self.assertFalse(marker.exists(), (args, marker.read_text() if marker.exists() else ""))
        # The guarantees rust's git recipe always gave, now from repository.py's shared helper.
        settings = {environment[f"GIT_CONFIG_KEY_{index}"]: environment[f"GIT_CONFIG_VALUE_{index}"]
                    for index in range(int(environment["GIT_CONFIG_COUNT"]))}
        self.assertEqual(("1", os.devnull), (environment["GIT_CONFIG_NOSYSTEM"], environment["GIT_CONFIG_GLOBAL"]))
        self.assertEqual("4b825dc642cb6eb9a060e54bf8d69288fbee4904", environment["GIT_ATTR_SOURCE"])  # empty tree
        self.assertTrue({"core.hooksPath": "/dev/null", "core.fsmonitor": "false", "filter.a=b.smudge": "",
                         "filter.a=b.required": "false", "diff.a=b.textconv": "", "log.showSignature": "false",
                         "protocol.allow": "never"}.items() <= settings.items(), settings)
        # Positive control: the same command under the repository's own config runs the driver.
        subprocess.run(["git", "-C", str(repo), "cat-file", "--filters", "HEAD:README"], capture_output=True)
        self.assertTrue(marker.is_file(), "the planted driver did not bind")

    def test_churn_opens_no_mailmap_or_order_file_the_config_names(self) -> None:
        """The churn `git log` reads the mailmap (log.mailmap is on by default) and diff order file its
        config names; under static mode both are /dev/null, so a FIFO there stalls nothing."""
        repo = scratch_repo(self)
        (repo / "src").mkdir()
        (repo / "src" / "lib.rs").write_text("pub fn one() {}\n")
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "rust")
        fifo = repo.parent / "pipe"
        os.mkfifo(fifo)
        self.addCleanup(_release_fifo, fifo)
        environment = {key: value for key, value in os.environ.items() if key != "GIT_CONFIG_PARAMETERS"}
        for key in ("mailmap.file", "diff.orderFile"):
            with self.subTest(key=key):
                run_git(repo, "config", key, str(fifo))
                with patch.object(rust._repository, "STATIC_GIT_TIMEOUT_SECONDS", 3), \
                        rust._repository.no_execute_git(repo):
                    churn = rust._churn(repo, {"src/lib.rs": {}})
                self.assertEqual(("completed", {"src/lib.rs": 1}), (churn["status"], churn["commits"]), churn)
                # Positive control: the same log under the repository's own config blocks on the FIFO.
                with self.assertRaises(subprocess.TimeoutExpired, msg=f"{key} did not bind"):
                    subprocess.run(["git", "-C", str(repo), "log", "--no-merges", "--format=%x00", "--name-only",
                                    "HEAD", "--", "*.rs"], capture_output=True, env=environment, timeout=2)
                _release_fifo(fifo)
                run_git(repo, "config", "--unset", key)


def _release_fifo(fifo: Path) -> None:
    """Give a reader still blocked on `fifo` its end of file."""
    try:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass  # ENXIO: nobody is reading it.


class RustArgvTests(unittest.TestCase):
    """B2: repository-controlled names (package directories) never reach a tool as options."""

    CRAFTED = ("--config=sgconfig.yml", "--custom-languages=allow")

    def test_tool_paths_follow_a_double_dash_and_the_config_is_hangovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            out = repo / "out"
            seen: dict[str, list[str]] = {}

            def fake_run(name, command, cwd, out_dir, environment, timeout, ok_codes=(0,)):
                seen[name] = command
                return {"status": "failed", "exit_code": 2, "command": command, "error": "stub"}

            workspace = {"packages": {name: {"dir": name} for name in self.CRAFTED} | {"p": {"dir": ""}}}
            files = {f"{name}/src/lib.rs": {} for name in self.CRAFTED}
            with patch.object(rust, "_run", side_effect=fake_run), \
                    patch.object(rust, "ast_grep_path", return_value=Path("/stub/ast-grep")), \
                    patch.object(rust, "jscpd_path", return_value=Path("/stub/jscpd")):
                rust._items(repo, out, files, workspace, {})
                rust._dupes(repo, out, workspace, files, rust.load_policy(repo), {})
            self.assertEqual({"ast-grep", "jscpd"}, set(seen))
            for name, command in seen.items():
                options = command[:command.index("--")] if name == "ast-grep" else command
                self.assertFalse(any(option.startswith("--config=") for option in options), name)
                config = Path(options[options.index("--config") + 1])
                self.assertTrue(config.is_file() and config.is_relative_to(out), (name, config))
            # ast-grep reads exactly the checked files, after `--` (it walks no directory); jscpd takes no
            # path on its command line at all: hangover's config names each file by absolute path, so none
            # can read as an option.
            split = seen["ast-grep"].index("--")
            self.assertEqual(sorted(files), seen["ast-grep"][split + 1:])
            self.assertIn("--custom-languages=ignore", seen["ast-grep"])
            config = json.loads(Path(seen["jscpd"][seen["jscpd"].index("--config") + 1]).read_text())
            self.assertEqual(sorted(str(repo / name) for name in files), config["path"])
            self.assertFalse({".", *self.CRAFTED, *files} & set(seen["jscpd"]), seen["jscpd"])

    @unittest.skipUnless(rust.ast_grep_path() and shutil.which("cc"), "ast-grep (npm ci) and a C compiler")
    def test_a_repository_sgconfig_never_loads_a_native_language(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            repo, marker = scratch / "repo", scratch / "NATIVE_LIBRARY_LOADED"
            (repo / "src").mkdir(parents=True)
            source = "pub fn one() -> u8 {\n    1\n}\n"
            (repo / "src/lib.rs").write_text(source)
            (scratch / "planted.c").write_text(
                "#include <stdio.h>\n"
                f"__attribute__((constructor)) static void ran(void) {{ FILE *f = fopen(\"{marker}\", \"w\"); "
                "if (f) { fputs(\"loaded\", f); fclose(f); } }\n"
                "void *tree_sitter_planted(void) { return 0; }\n")
            subprocess.run(["cc", "-shared", "-fPIC", "-o", str(repo / "planted.so"), str(scratch / "planted.c")],
                           check=True, capture_output=True)
            (repo / "sgconfig.yml").write_text(
                "ruleDirs: []\ncustomLanguages:\n  planted:\n    libraryPath: planted.so\n    extensions: [planted]\n")
            for name in self.CRAFTED:
                (repo / name).mkdir()
            files = {"src/lib.rs": {"package": "p", "role": "lib", "text": source, "lines": source.splitlines(),
                                    "test_ranges": []}}
            workspace = {"packages": {name: {"dir": name} for name in self.CRAFTED} | {"p": {"dir": ""}}}
            command, items = rust._items(repo, scratch / "out", files, workspace, rust.cargo_environment())
            self.assertFalse(marker.exists(), "ast-grep loaded the repository's native library")
            self.assertEqual("completed", command["status"], command)
            self.assertEqual(["one"], [item["name"] for item in items["src/lib.rs"]])
            # Positive control: ast-grep allowed to load the repository's languages does run the library.
            subprocess.run([str(rust.ast_grep_path()), "scan", "--custom-languages=allow", "--rule",
                            str(scratch / "out" / "ast-grep-rules.yml"), "src"], cwd=repo, capture_output=True)
            self.assertTrue(marker.is_file(), "the planted library did not bind")

    def test_no_files_run_no_ast_grep(self) -> None:
        """A bare `ast-grep scan` walks its working directory: with nothing checked, ast-grep never runs."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            with patch.object(rust, "_run") as run, \
                    patch.object(rust, "ast_grep_path", return_value=Path("/stub/ast-grep")):
                command, items = rust._items(repo, repo / "out", {}, {"packages": {"p": {"dir": ""}}}, {})
            run.assert_not_called()
            self.assertEqual(("completed", 0, {}), (command["status"], command["items"], items))

    def test_argument_chunks_stay_within_the_limit(self) -> None:
        names = [f"src/{index:04}.rs" for index in range(300)]
        chunks = rust._argument_chunks(names, limit=1000)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(names, [name for chunk in chunks for name in chunk])
        self.assertTrue(all(sum(len(name) + 9 for name in chunk) <= 1000 for chunk in chunks))
        self.assertEqual([["x" * 2000]], rust._argument_chunks(["x" * 2000], limit=1000))
        self.assertEqual([], rust._argument_chunks([]))

    @unittest.skipUnless(rust.ast_grep_path(), "ast-grep is not installed (npm ci)")
    def test_many_files_are_scanned_in_chunks_and_only_listed_lines_are_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory).resolve()
            repo = scratch / "repo"
            (repo / "src").mkdir(parents=True)
            files = {}
            for index in range(40):
                source = f"pub fn item_{index}() -> u8 {{\n    1\n}}\n"
                (repo / "src" / f"m{index}.rs").write_text(source)
                files[f"src/m{index}.rs"] = {"package": "p", "role": "lib", "text": source,
                                             "lines": source.splitlines(), "test_ranges": []}
            (repo / "src" / "unlisted.rs").write_text("pub fn unlisted_item() {}\n")
            with patch.object(rust, "AST_GREP_ARGUMENT_BYTES", 200):
                command, items = rust._items(repo, scratch / "out", files, {"packages": {"p": {"dir": ""}}},
                                             rust.cargo_environment())
            self.assertEqual("completed", command["status"], command)
            self.assertGreater(command.get("chunks", 1), 1)
            self.assertEqual(sorted(files), sorted(items))
            stored = Path(command["stdout"]).read_text()
            self.assertEqual(40, len(stored.splitlines()), stored)
            self.assertNotIn("unlisted_item", stored)
            self.assertEqual(scratch / "out", Path(command["stdout"]).parent)

    def test_option_like_member_directories_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            (repo / "Cargo.toml").write_text('[workspace]\nmembers = ["--config=sgconfig.yml"]\n')
            member = repo / "--config=sgconfig.yml"
            (member / "src").mkdir(parents=True)
            (member / "Cargo.toml").write_text('[package]\nname = "crafted"\nversion = "0.1.0"\n')
            (member / "src/lib.rs").write_text("")
            with self.assertRaisesRegex(RuntimeError, "starts with '-'"):
                rust._static_workspace(repo, repo)
            command, workspace = rust._static_metadata(repo, repo)
            self.assertEqual("failed", command["status"])
            self.assertIsNone(workspace)


class RustJscpdConfigTests(unittest.TestCase):
    """M3: jscpd reads hangover's generated configuration, never the repository's own."""

    @unittest.skipUnless(rust.jscpd_path(), "jscpd is not installed (npm ci)")
    def test_a_planted_jscpd_config_is_never_obeyed(self) -> None:
        import http.server
        import threading

        requests: list[str] = []

        class Recorder(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                requests.append(self.path)
                self.send_response(500)
                self.end_headers()

            do_GET = do_POST

            def log_message(self, *args) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_address[1]}/v1"
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            (repo / "src").mkdir()
            body = "\n".join(f"    let v{i} = compute_value({i}, {i + 1}, \"label{i}\");" for i in range(12))
            source = f"pub fn a() {{\n{body}\n}}\n\npub fn b() {{\n{body}\n}}\n"
            (repo / "src/lib.rs").write_text(source)
            files = {"src/lib.rs": {"package": "p", "role": "lib", "text": source, "lines": source.splitlines(),
                                    "test_ranges": []}}
            workspace = {"packages": {"p": {"dir": ""}}}
            policy = rust.load_policy(repo)
            command, expected = rust._dupes(repo, repo.parent / f"{repo.name}-clean", workspace, files, policy,
                                            rust.cargo_environment())
            self.assertEqual("completed", command["status"], command)
            self.assertEqual(1, len(expected))
            planted = {
                ".jscpd.json": json.dumps({"semantic": {"enabled": True, "url": url, "provider": "http"}}),
                "package.json": json.dumps({"name": "x", "jscpd": {"ignore": ["**/*.rs"], "minTokens": 100000}}),
            }
            for number, (name, text) in enumerate(planted.items()):
                with self.subTest(name):
                    (repo / name).write_text(text)
                    command, groups = rust._dupes(repo, repo.parent / f"{repo.name}-{number}", workspace, files,
                                                  policy, rust.cargo_environment())
                    (repo / name).unlink()
                    self.assertEqual([], requests)
                    self.assertEqual("completed", command["status"], command)
                    self.assertEqual(expected, groups)
            # Positive control: jscpd left to discover the repository's config does call the server.
            (repo / ".jscpd.json").write_text(planted[".jscpd.json"])
            subprocess.run([str(rust.jscpd_path()), "--format", "rust", "--silent", "--reporters", "json",
                            "--output", str(repo.parent / f"{repo.name}-control"), "."], cwd=repo,
                           capture_output=True, timeout=120)
            self.assertTrue(requests, "the planted semantic config did not bind")


class RustPolicyTests(unittest.TestCase):
    def test_an_invalid_root_is_a_failed_configuration_not_not_applicable(self) -> None:
        """m: a root outside the repository is reported as the error it is, by the scan and the audit."""
        repo = scratch_repo(self, "build-marker", subdir="skill")
        (repo / rust.POLICY_FILE).write_text(json.dumps({"root": "../skill"}))
        self.assertTrue(rust.applicable(repo))
        self.assertIsNone(rust.manifest_notice(repo))
        run_dir = repo / ".hangover" / "runs" / "scan-1"
        run_dir.mkdir(parents=True)
        result = rust.run_rust_scan(repo, run_dir, execute=False)
        self.assertEqual("failed", result["status"], result)
        self.assertEqual({"policy": "failed"}, result["sections"])
        self.assertIn("root '../skill'", result["error"])
        self.assertTrue(any("root '../skill'" in warning for warning in result["warnings"]))
        self.assertEqual([], result["findings"])
        audit = rust.run_rust_audit(repo, run_dir, "HEAD", execute=False)
        self.assertEqual(("failed", None), (audit["status"], audit["verdict"]), audit)
        self.assertIn("root '../skill'", audit["error"])
        self.assertFalse((repo / ".hangover" / "rust-audit").exists())


class RustAuditBaseTests(unittest.TestCase):
    """M1: the audit's base tree is hangover's own directory, written from git objects; nothing else is
    reused, written through or removed, and git never runs inside it."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        (self.repo / "lib").mkdir()
        (self.repo / "lib" / "keep.txt").write_text("unchanged\n")
        (self.repo / "run.sh").write_text("#!/bin/sh\n")
        (self.repo / "run.sh").chmod(0o755)
        (self.repo / "link").symlink_to("README")
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-q", "-m", "more")
        self.first = run_git(self.repo, "rev-parse", "HEAD")
        (self.repo / "README").write_text("two\n")
        run_git(self.repo, "commit", "-q", "-am", "second")
        self.second = run_git(self.repo, "rev-parse", "HEAD")
        self.holder = self.repo / ".hangover" / "rust-audit"
        self.tree = self.holder / "tree"
        self.audits = 0

    def audit(self, base: str | None = None) -> dict:
        self.audits += 1
        result, self.trees = recorded_audit(self.repo, base or self.first, name=f"audit-{self.audits}")
        return result

    def assert_on_branch(self, repo: Path, commit: str, text: str) -> None:
        self.assertEqual("main", run_git(repo, "branch", "--show-current"))
        self.assertEqual(commit, run_git(repo, "rev-parse", "HEAD"))
        self.assertEqual(text, (repo / "README").read_text())
        self.assertEqual("", run_git(repo, "status", "--porcelain"))

    def test_a_forged_gitfile_never_moves_the_main_checkout(self) -> None:
        self.assertEqual("completed", self.audit()["status"])
        index = run_git(self.repo, "ls-files", "--stage")
        forged = 0
        # Wherever hangover keeps its base tree (this version or the worktree of earlier ones), a `.git`
        # file there naming the main repository's own git directory changes nothing.
        for candidate in (self.repo / ".hangover" / "rust-audit-base", self.tree):
            if candidate.is_dir():
                gitfile = candidate / ".git"
                if gitfile.is_dir():
                    shutil.rmtree(gitfile)
                elif gitfile.exists():
                    gitfile.unlink()
                gitfile.write_text(f"gitdir: {self.repo / '.git'}\n")
                forged += 1
        self.assertGreaterEqual(forged, 1)
        result = self.audit(self.second)
        self.assert_on_branch(self.repo, self.second, "two\n")
        self.assertEqual(index, run_git(self.repo, "ls-files", "--stage"))
        self.assertEqual("unchanged\n", (self.repo / "lib" / "keep.txt").read_text())
        if result["status"] == "completed":
            self.assertEqual("two\n", (self.trees[1] / "README").read_text())

    def test_its_own_tree_is_written_from_git_objects_then_synced(self) -> None:
        self.assertEqual("completed", self.audit()["status"])
        self.assertEqual([self.repo, self.tree], self.trees)
        self.assertEqual("one\n", (self.tree / "README").read_text())
        self.assertTrue(os.access(self.tree / "run.sh", os.X_OK))
        self.assertEqual("README", os.readlink(self.tree / "link"))
        self.assertFalse((self.tree / ".git").exists())
        self.assertEqual(1, run_git(self.repo, "worktree", "list", "--porcelain").count("worktree "))
        self.assert_on_branch(self.repo, self.second, "two\n")
        # Reuse at another base: an edit in hangover's own tree (cargo rewriting Cargo.lock, a build
        # script's output) is discarded, and a file the base did not change keeps its mtime, so cargo
        # stays incremental.
        keep = self.tree / "lib" / "keep.txt"
        os.utime(keep, (1_000_000_000, 1_000_000_000))
        (self.tree / "README").write_text("scribble\n")
        (self.tree / "lib" / "generated.rs").write_text("// build output\n")
        (self.tree / "stray").mkdir()
        self.assertEqual("completed", self.audit(self.second)["status"])
        self.assertEqual("two\n", (self.tree / "README").read_text())
        self.assertFalse((self.tree / "lib" / "generated.rs").exists())
        self.assertFalse((self.tree / "stray").exists())
        self.assertEqual(1_000_000_000, int(keep.stat().st_mtime))

    def test_a_symlink_on_the_way_is_refused_and_left_alone(self) -> None:
        victim = self.repo.parent / "victim"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(victim)], check=True)
        self.assert_on_branch(victim, self.second, "two\n")
        for link, target in ((self.holder, victim), (self.tree, victim)):
            with self.subTest(str(link.relative_to(self.repo))):
                if self.holder.is_symlink():
                    self.holder.unlink()
                elif self.holder.exists():
                    shutil.rmtree(self.holder)
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target, target_is_directory=True)
                result = self.audit()
                self.assertEqual("failed", result["status"], result)
                self.assertIsNone(result["verdict"])
                self.assertIn("symlink", result["error"])
                self.assert_on_branch(victim, self.second, "two\n")
                self.assertTrue(link.is_symlink())

    def test_a_directory_hangover_did_not_create_is_refused_and_kept(self) -> None:
        self.tree.mkdir(parents=True)
        (self.tree / "notes.txt").write_text("mine\n")
        result = self.audit()
        self.assertEqual("failed", result["status"], result)
        self.assertIn("did not create", result["error"])
        self.assertEqual("mine\n", (self.tree / "notes.txt").read_text())
        self.assert_on_branch(self.repo, self.second, "two\n")

    def test_committed_files_under_its_directory_are_refused_and_kept(self) -> None:
        """A clone can bring files to any path, hangover's included: tracked files there are never hangover's."""
        self.tree.mkdir(parents=True)
        (self.holder / "tree.owner").write_text("forged\n")
        (self.tree / "src.rs").write_text("committed\n")
        run_git(self.repo, "add", "-f", ".hangover/rust-audit")
        run_git(self.repo, "commit", "-q", "-m", "plant")
        result = self.audit()
        self.assertEqual("failed", result["status"], result)
        self.assertIn("tracked", result["error"])
        self.assertEqual("committed\n", (self.tree / "src.rs").read_text())
        self.assertEqual("", run_git(self.repo, "status", "--porcelain"))

    def test_an_earlier_versions_worktree_is_left_alone_and_named(self) -> None:
        old = self.repo / ".hangover" / "rust-audit-base"
        run_git(self.repo, "worktree", "add", "-q", "--detach", str(old), self.first)
        result = self.audit()
        self.assertEqual("completed", result["status"], result)
        self.assertTrue(any("rust-audit-base" in warning for warning in result.get("warnings") or []), result)
        self.assertEqual(self.first, run_git(old, "rev-parse", "HEAD"))
        self.assertEqual(2, run_git(self.repo, "worktree", "list", "--porcelain").count("worktree "))


@unittest.skipUnless(rust.ast_grep_path() and rust.jscpd_path(), "ast-grep and jscpd are needed (npm ci)")
class RustStaticAuditTests(unittest.TestCase):
    """B2 end to end: a static audit of a real crate, with every plant in place, runs none of them."""

    def test_a_static_audit_runs_no_repository_code(self) -> None:
        repo = scratch_repo(self, "build-marker")
        (repo / ".gitattributes").write_text("*.rs filter=planted\n")
        run_git(repo, "add", ".gitattributes")
        run_git(repo, "commit", "-q", "-m", "attributes")
        base = run_git(repo, "rev-parse", "HEAD")
        with (repo / "src" / "lib.rs").open("a") as handle:
            handle.write("\npub fn added_and_unnamed() -> u32 {\n    3\n}\n")
        run_git(repo, "commit", "-q", "-am", "add an unnamed pub fn")
        marker = repo.parent / "MARKER"
        for kind in PLANTS:
            if kind == "hooksPath from an included config":
                continue  # One hook route is enough here; both are covered above.
            plant(repo, kind, marker)
        run_dir = repo / ".hangover" / "runs" / "audit-1"
        run_dir.mkdir(parents=True)
        result = rust.run_rust_audit(repo, run_dir, base, execute=False)
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")
        self.assertFalse((repo / MARKER).exists())
        self.assertEqual("partial", result["status"], result)
        for side in ("current", "base"):
            sections = result[side]["sections"]
            self.assertEqual(("completed", "skipped", "completed", "completed"),
                             (sections["items"], sections["clippy"], sections["dupes"], sections["churn"]), side)
        self.assertEqual(2, result["base"]["summary"]["files"])  # build.rs and src/lib.rs
        self.assertEqual(["Unused pub fn added_and_unnamed in src/lib.rs"],
                         [item["title"] for item in result["introduced"]])


@unittest.skipIf(TOOLS_MISSING, TOOLS_MISSING)
class RustCargoFixtureTests(unittest.TestCase):
    """Real Cargo projects through the functions the CLI calls (applicable, run_rust_scan, run_rust_audit)."""

    def setUp(self) -> None:
        cargo_isolated(self)

    def scan(self, repo: Path, **options) -> dict:
        self.scans = getattr(self, "scans", 0) + 1
        run_dir = repo / ".hangover" / "runs" / f"scan-{self.scans}"
        run_dir.mkdir(parents=True)
        return rust.run_rust_scan(repo, run_dir, **options)

    @staticmethod
    def keys(result: dict) -> set[str]:
        return {finding["suppression"]["value"] for finding in rust.extract_rust_findings(result)}

    def test_a_cargo_repository_is_analyzed_end_to_end(self) -> None:
        repo = scratch_repo(self, "build-marker")
        self.assertTrue(rust.applicable(repo))
        self.assertIsNone(rust.manifest_notice(repo))
        result = self.scan(repo)
        self.assertEqual("completed", result["sections"]["clippy"], result["warnings"])
        self.assertEqual("completed", result["sections"]["items"], result["warnings"])
        self.assertTrue({"unused_pub_items:src/lib.rs:fn:exported_but_unnamed",
                         "dead_code:src/lib.rs:function `never_called` is never used"} <= self.keys(result),
                        self.keys(result))
        # clippy compiled the crate, so its build script ran: the positive control for the static test.
        self.assertTrue((repo / MARKER).is_file())
        # hangover's generated clippy configuration lives in its own state, not in the build tree (M2).
        self.assertEqual(1, len(list((repo / ".hangover" / "rust-clippy-conf").glob("*/clippy.toml"))))
        self.assertEqual([], list((repo / "target").rglob("clippy-conf")))
        state = new_state(repo)
        merged = merge_findings(state, rust.extract_rust_findings(result), "scan-1",
                                scan_result={"kind": "scan", "rust": result,
                                             "rust_comparison": rust.rust_comparison(None, {"rust": result})})
        self.assertEqual(len(result["findings"]), len(merged["ids"]))

    def test_static_analysis_never_runs_the_build_script(self) -> None:
        """B2: execute=False reads manifests and source but never starts cargo, so build.rs never runs."""
        repo = scratch_repo(self, "build-marker")
        with patch.object(rust, "_run", wraps=rust._run) as ran:
            result = self.scan(repo, execute=False)
        commands = [call.args[1][0] for call in ran.call_args_list]
        self.assertFalse((repo / MARKER).exists())
        self.assertNotIn("cargo", commands)
        self.assertEqual("partial", result["status"])
        self.assertEqual({"metadata": "completed", "items": "completed", "clippy": "skipped", "dupes": "completed",
                          "machete": "skipped", "churn": "completed"}, result["sections"])
        self.assertIn("unused_pub_items:src/lib.rs:fn:exported_but_unnamed", self.keys(result))
        self.assertFalse(any(key.startswith("dead_code") for key in self.keys(result)))
        self.assertTrue(any("never runs cargo" in warning for warning in result["warnings"]), result["warnings"])
        self.assertTrue(all(result["tools"][name] is None for name in ("cargo", "clippy", "cargo_machete")))
        # The full scan of the same tree compiles it, so the fixture does bind.
        self.scan(repo)
        self.assertTrue((repo / MARKER).is_file())

    def test_a_nested_manifest_is_named_and_analyzed_once_its_root_is_set(self) -> None:
        """M6: a Cargo.toml below the repository root is reported, and `root` in the policy analyzes it."""
        repo = scratch_repo(self, "build-marker", subdir="skill")
        self.assertFalse(rust.applicable(repo))
        notice = rust.manifest_notice(repo)
        self.assertIn("no root Cargo.toml", notice)
        self.assertIn("skill/Cargo.toml", notice)
        self.assertIn(f'"root": "skill"', notice)
        self.assertEqual("not_applicable", self.scan(repo)["status"])
        (repo / rust.POLICY_FILE).write_text(json.dumps({"root": "skill"}))
        self.assertTrue(rust.applicable(repo))
        self.assertIsNone(rust.manifest_notice(repo))
        result = self.scan(repo)
        self.assertEqual("completed", result["status"], result["warnings"])
        self.assertTrue({"unused_pub_items:skill/src/lib.rs:fn:exported_but_unnamed",
                         "dead_code:skill/src/lib.rs:function `never_called` is never used"} <= self.keys(result),
                        self.keys(result))
        (repo / rust.POLICY_FILE).write_text(json.dumps({"root": "elsewhere"}))
        self.assertFalse(rust.applicable(repo))
        self.assertIn("elsewhere", rust.manifest_notice(repo))
        for unsafe in ("../skill", "/tmp", "skill/../.."):
            (repo / rust.POLICY_FILE).write_text(json.dumps({"root": unsafe}))
            with self.assertRaisesRegex(RuntimeError, "root"):
                rust.load_policy(repo)

    def test_the_static_workspace_reader_agrees_with_cargo_metadata(self) -> None:
        repo = scratch_repo(self, "workspace")
        out = repo.parent / "out"
        command, from_cargo = rust._workspace(repo, repo, out, rust.cargo_environment())
        self.assertEqual("completed", command["status"], command)
        from_manifests = rust._static_workspace(repo, repo)
        self.assertEqual(4, len(from_cargo["packages"]))
        self.assertEqual(from_cargo["packages"], from_manifests["packages"])
        self.assertEqual(from_cargo["root"], from_manifests["root"])

    def assert_agrees_with_cargo(self, repo: Path, manifest_dir: Path) -> dict:
        command, from_cargo = rust._workspace(repo, manifest_dir, repo.parent / "out", rust.cargo_environment())
        self.assertEqual("completed", command["status"], command)
        from_manifests = rust._static_workspace(repo, manifest_dir)
        self.assertEqual(from_cargo["packages"], from_manifests["packages"])
        self.assertEqual(from_cargo["root"], from_manifests["root"])
        return from_manifests

    def test_a_member_root_reads_its_enclosing_workspace_like_cargo(self) -> None:
        """M5: `root` naming a member crate analyzes the workspace cargo finds above it, inherited fields too."""
        repo = scratch_repo(self, "workspace")
        workspace = self.assert_agrees_with_cargo(repo, repo / "crates" / "ws_core")
        self.assertEqual(4, len(workspace["packages"]))
        self.assertFalse(workspace["packages"]["ws_core"]["publishable"])
        # An excluded crate is a workspace of its own, for cargo and for hangover.
        self.assertEqual(["ignored"], list(self.assert_agrees_with_cargo(repo, repo / "crates" / "ignored")["packages"]))

    def test_workspace_layouts_cargo_rejects_are_rejected_statically(self) -> None:
        """M5: never a different workspace than cargo's: where cargo fails, the static reader fails too."""
        repo = scratch_repo(self, "workspace")
        out = repo.parent / "out"
        manifest = repo / "crates" / "ws_macros" / "Cargo.toml"
        original = manifest.read_text()
        manifest.write_text(original + "\n[workspace]\n")
        command, _ = rust._workspace(repo, repo, out, rust.cargo_environment())
        self.assertEqual("failed", command["status"])
        self.assertIn("multiple workspace roots", command["error"])
        with self.assertRaisesRegex(RuntimeError, "multiple workspace roots"):
            rust._static_workspace(repo, repo)
        # The nested workspace analyzed as the root is a workspace of its own, for both.
        self.assertEqual(["ws_macros"], list(self.assert_agrees_with_cargo(repo, manifest.parent)["packages"]))
        manifest.write_text(original)
        # A package under a workspace that does not list it: cargo refuses to guess.
        stray = repo / "stray"
        (stray / "src").mkdir(parents=True)
        (stray / "Cargo.toml").write_text('[package]\nname = "stray"\nversion = "0.1.0"\nedition = "2021"\n')
        (stray / "src" / "lib.rs").write_text("")
        command, _ = rust._workspace(repo, stray, out, rust.cargo_environment())
        self.assertEqual("failed", command["status"])
        self.assertIn("believes it's in a workspace", command["error"])
        with self.assertRaisesRegex(RuntimeError, "believes it's in a workspace"):
            rust._static_workspace(repo, stray)

    def test_audit_reports_only_what_the_change_introduced(self) -> None:
        repo = scratch_repo(self, "build-marker")
        base = run_git(repo, "rev-parse", "HEAD")
        with (repo / "src" / "lib.rs").open("a") as handle:
            handle.write("\npub fn added_and_unnamed() -> u32 {\n    3\n}\n")
        run_git(repo, "commit", "-q", "-am", "add an unnamed pub fn")
        run_dir = repo / ".hangover" / "runs" / "audit-1"
        run_dir.mkdir(parents=True)
        result = rust.run_rust_audit(repo, run_dir, base)
        self.assertEqual(("completed", "fail"), (result["status"], result["verdict"]), result)
        self.assertEqual(["Unused pub fn added_and_unnamed in src/lib.rs"],
                         [item["title"] for item in result["introduced"]])
        # The base side analyzed the base commit's tree.
        self.assertEqual(run_git(repo, "show", f"{base}:src/lib.rs") + "\n",
                         (repo / ".hangover" / "rust-audit" / "tree" / "src" / "lib.rs").read_text())
        # Each side keeps what a prevention review packet projects: tool versions, the policy
        # digest and the paths of its own command logs (raw_artifacts, as oracles reads them).
        logs = {}
        for side in ("current", "base"):
            view = result[side]
            self.assertIsNotNone(view["tools"]["cargo"])
            self.assertEqual(rust.digest(rust.load_policy(repo)), view["policy_sha256"])
            self.assertTrue({"metadata", "items", "clippy", "dupes"} <= set(view["raw_artifacts"]), view["raw_artifacts"])
            for paths_of in view["raw_artifacts"].values():
                self.assertEqual({"stdout", "stderr"}, set(paths_of))
                self.assertTrue(all(Path(path).is_file() for path in paths_of.values()))
            logs[side] = view["raw_artifacts"]["clippy"]["stdout"]
        self.assertNotEqual(logs["current"], logs["base"])
        self.assertNotIn("findings", result["current"])


class RustGateTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
    def test_a_cargo_repository_gets_fmt_clippy_and_test(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\n')
            self.assertEqual(["fmt", "clippy", "test"], [check["name"] for check in discover_checks(repo)])

    def test_gate_script_steps_become_named_stages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            (repo / "scripts/gate-rust.sh").write_text("cargo test\n")
            stage = _command_stage(repo, "  run rust bash scripts/gate-rust.sh", "scripts/gate.sh")
            self.assertEqual(("rust", ["bash", "scripts/gate-rust.sh"]), (stage["name"], stage["command"]))
            self.assertEqual("check", _command_stage(repo, "run check pnpm exec biome ci .", "g")["name"])
            # A bare tool exec may sit inside a conditional; only a named wrapper line counts.
            self.assertIsNone(_command_stage(repo, "    pnpm exec vitest run --config x.ts", "g"))
            self.assertIsNone(_command_stage(repo, "run missing bash scripts/absent.sh", "g"))


def blob(repo: Path, data: bytes) -> str:
    return subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=data,
                          check=True, capture_output=True).stdout.decode().strip()


def write_index(repo: Path, names: dict[str, bytes]) -> None:
    """Replace the index with a hand-built one (version 2) listing each name with its bytes' blob.
    Git's own commands refuse names like these; a hostile clone can ship such an index all the same."""
    import hashlib
    import struct
    body = b""
    for name in sorted(names, key=os.fsencode):
        path = os.fsencode(name)
        entry = (struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, len(names[name]))
                 + bytes.fromhex(blob(repo, names[name])) + struct.pack(">H", min(len(path), 0xFFF)) + path)
        body += entry + b"\0" * (8 - len(entry) % 8)
    data = b"DIRC" + struct.pack(">II", 2, len(names)) + body
    (repo / ".git" / "index").write_bytes(data + hashlib.sha1(data).digest())


SECRET = b"pub fn outside_secret_marker() -> u8 {\n    7\n}\n"
CRATE = {"Cargo.toml": b'[package]\nname = "inside"\nversion = "0.1.0"\nedition = "2021"\n',
         "src/lib.rs": b"pub fn inside() -> u8 {\n    1\n}\n"}


class RustFileListTests(unittest.TestCase):
    """The current tree's file list comes from the index, which the repository controls: no name in it
    makes hangover read a file outside the repository, and one that tries fails the scan."""

    def crafted(self, kind: str) -> Path:
        repo = scratch_repo(self)
        for name, data in CRATE.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(data)
        outside = repo.parent / "outside"
        outside.mkdir()
        (outside / "secret.rs").write_bytes(SECRET)
        (repo.parent / "sibling-secret.rs").write_bytes(SECRET)
        if kind == "dot-dot":
            name = "../sibling-secret.rs"
        elif kind == "absolute":
            name = str(outside / "secret.rs")
        elif kind == "symlinked parent":
            (repo / "link").symlink_to(outside, target_is_directory=True)
            name = "link/secret.rs"
        elif kind == "symlinked parent inside":
            (repo / "src" / "inner").mkdir()
            (repo / "src" / "inner" / "secret.rs").write_bytes(SECRET)
            (repo / "alias").symlink_to(repo / "src" / "inner", target_is_directory=True)
            name = "alias/secret.rs"
        elif kind == "dot-git component":
            (repo / ".GIT").mkdir(exist_ok=True)
            name = ".GIT/secret.rs"
        else:
            raise AssertionError(kind)
        write_index(repo, {**CRATE, name: SECRET})
        listed = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, text=True).stdout
        self.assertIn(name, listed.split("\0"), "precondition: git lists the crafted name")
        return repo

    KINDS = ("dot-dot", "absolute", "symlinked parent", "symlinked parent inside", "dot-git component")

    def test_a_name_reaching_outside_the_repository_is_refused(self) -> None:
        for kind in self.KINDS:
            with self.subTest(kind):
                repo = self.crafted(kind)
                with self.assertRaisesRegex(RuntimeError, "refusing the repository's file list"):
                    rust._listed_files(repo)

    def test_the_scan_fails_with_a_status_and_reads_nothing_outside(self) -> None:
        for kind in ("dot-dot", "absolute", "symlinked parent"):
            with self.subTest(kind):
                repo = self.crafted(kind)
                run_dir = repo / ".hangover" / "runs" / "scan"
                run_dir.mkdir(parents=True)
                with patch.object(rust, "_items", side_effect=AssertionError("ran past the file list")):
                    result = rust.run_rust_scan(repo, run_dir, execute=False)
                self.assertEqual("failed", result["status"], result)
                self.assertEqual("failed", result["sections"]["files"])
                self.assertIn("refusing the repository's file list", result["error"])
                # A refusal, not an analyzer hiccup: the CLI's scan and run exit 2 on `refusal`.
                self.assertIn("refusing the repository's file list", result.get("refusal", ""))
                self.assertNotIn("outside_secret_marker", json.dumps(result))

    def test_an_ordinary_index_lists_its_files_and_skips_nested_repositories(self) -> None:
        repo = scratch_repo(self)
        for name, data in CRATE.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(data)
        nested = repo / "nested"
        nested.mkdir()
        subprocess.run(["git", "init", "-q", str(nested)], check=True)
        (nested / "x.rs").write_text("fn x() {}\n")
        run_git(repo, "add", "Cargo.toml", "src/lib.rs")
        self.assertIn("nested/", run_git(repo, "ls-files", "--others", "--exclude-standard").splitlines())
        self.assertEqual([repo / "Cargo.toml", repo / "README", repo / "src/lib.rs"], rust._listed_files(repo))


@unittest.skipUnless(rust.ast_grep_path() and rust.jscpd_path(), "ast-grep and jscpd are needed (npm ci)")
class RustIgnoreFileTests(unittest.TestCase):
    """hangover supplies the analyzers' file set: no ignore file the repository controls hides a tracked file."""

    BODY = "\n".join(f"    let v{i} = compute_value({i}, {i + 1}, \"label{i}\");" for i in range(12))

    def tree(self) -> tuple[Path, dict, dict]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repo = Path(directory.name).resolve() / "repo"
        (repo / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        sources = {"src/lib.rs": f"pub fn a() {{\n{self.BODY}\n}}\n",
                   "src/hidden.rs": f"pub fn hidden() {{\n{self.BODY}\n}}\n"}
        for name, text in sources.items():
            (repo / name).write_text(text)
        # Copies hangover never lists: build output and hangover's own audit tree.
        for copy in ("target/debug/build/out/copy.rs", ".hangover/rust-audit/tree/src/lib.rs"):
            (repo / copy).parent.mkdir(parents=True, exist_ok=True)
            (repo / copy).write_text(sources["src/lib.rs"])
        files = {name: {"package": "p", "role": "lib", "text": text, "lines": text.splitlines(), "test_ranges": []}
                 for name, text in sources.items()}
        return repo, files, {"packages": {"p": {"dir": ""}}}

    PLANTS = {".gitignore": "src/hidden.rs\n", ".git/info/exclude": "*.rs\n", ".ignore": "*.rs\n",
              "src/.gitignore": "hidden.rs\n"}

    def test_ast_grep_sees_every_listed_file(self) -> None:
        for plant, text in self.PLANTS.items():
            with self.subTest(plant):
                repo, files, workspace = self.tree()
                (repo / plant).write_text(text)
                command, items = rust._items(repo, repo.parent / "out", files, workspace, rust.cargo_environment())
                self.assertEqual("completed", command["status"], command)
                self.assertEqual({"src/lib.rs": ["a"], "src/hidden.rs": ["hidden"]},
                                 {path: [item["name"] for item in found] for path, found in items.items()})

    def test_jscpd_compares_exactly_the_listed_files(self) -> None:
        for plant, text in self.PLANTS.items():
            with self.subTest(plant):
                repo, files, workspace = self.tree()
                (repo / plant).write_text(text)
                command, groups = rust._dupes(repo, repo.parent / "out", workspace, files, rust.load_policy(repo),
                                              rust.cargo_environment())
                self.assertEqual("completed", command["status"], command)
                self.assertEqual([["src/hidden.rs", "src/lib.rs"]],
                                 [sorted(span[0] for span in group["spans"]) for group in groups], groups)


class RustTreeCollisionTests(unittest.TestCase):
    """Two names in the base commit that are one directory entry here fail the tree write."""

    def setUp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / "Probe"
            probe.write_text("")
            if not (Path(directory) / "probe").exists():
                self.skipTest("this volume is case-sensitive: two names differing by case are two files")

    def commit(self, repo: Path, names: dict[str, bytes]) -> str:
        write_index(repo, names)
        tree = run_git(repo, "write-tree")
        return run_git(repo, "commit-tree", tree, "-m", "colliding names")

    def test_names_differing_only_by_case_are_refused(self) -> None:
        cases = {"two files": {"A.rs": b"one\n", "a.rs": b"two\n"},
                 "two directories": {"Src/x.rs": b"one\n", "src/y.rs": b"two\n"},
                 "a file and a directory": {"SRC": b"one\n", "src/y.rs": b"two\n"}}
        for label, names in cases.items():
            with self.subTest(label):
                repo = scratch_repo(self)
                commit = self.commit(repo, names)
                tree, found, listed, error = rust._prepare_base_tree(repo, commit)
                self.assertIsNone(tree, listed)
                self.assertRegex(error, "which name one directory entry on this filesystem")

    def test_distinct_names_still_write(self) -> None:
        repo = scratch_repo(self)
        commit = self.commit(repo, {"A.rs": b"one\n", "b.rs": b"two\n", "src/x.rs": b"three\n"})
        tree, found, listed, error = rust._prepare_base_tree(repo, commit)
        self.assertIsNone(error)
        self.assertEqual(b"one\n", (tree / "A.rs").read_bytes())
        self.assertEqual([tree / "A.rs", tree / "b.rs", tree / "src/x.rs"], listed)


class RustBaseTreeGitTests(unittest.TestCase):
    """In an executing audit, git run by a build script in the base tree cannot find the checkout."""

    def test_git_in_the_base_tree_finds_no_repository(self) -> None:
        repo = scratch_repo(self)
        for name, data in CRATE.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(data)
        run_git(repo, "add", "-A")
        run_git(repo, "commit", "-q", "-m", "crate")
        commit = run_git(repo, "rev-parse", "HEAD")
        tree, _, listed, error = rust._prepare_base_tree(repo, commit)
        self.assertIsNone(error)
        seen: list[dict] = []

        def fake_workspace(scanned, manifest_dir, out_dir, environment):
            seen.append(dict(environment))
            return {"status": "failed", "exit_code": 1, "command": None, "error": "stub"}, None

        run_dir = repo / ".hangover" / "runs" / "base"
        with patch.object(rust, "_workspace", side_effect=fake_workspace):
            rust.run_rust_scan(tree, run_dir, name="rust-base", execute=True, listed=listed, history=(repo, commit))
        self.assertEqual(1, len(seen))
        where = tree / "src"
        probe = ["git", "rev-parse", "--show-toplevel"]
        found = subprocess.run(probe, cwd=where, env=seen[0], capture_output=True, text=True)
        self.assertNotEqual(0, found.returncode, found.stdout)
        # Positive control: without the ceiling, the same git finds the checkout around the tree.
        unbounded = {key: value for key, value in seen[0].items() if key != "GIT_CEILING_DIRECTORIES"}
        control = subprocess.run(probe, cwd=where, env=unbounded, capture_output=True, text=True)
        self.assertEqual(str(repo), control.stdout.strip())
        # The current tree's own scan is not bounded: it is the checkout.
        with patch.object(rust, "_workspace", side_effect=fake_workspace):
            rust.run_rust_scan(repo, run_dir, execute=True)
        self.assertNotIn("GIT_CEILING_DIRECTORIES", seen[1])


if __name__ == "__main__":
    unittest.main()
