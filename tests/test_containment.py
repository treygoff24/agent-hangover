"""Containment: hangover never reads, obeys or writes outside the repository because of what the
repository says. Every reader of a repository-controlled path goes through
`repository.contained_path` / `read_repo_file`, which refuses (RepositoryRefusal, exit 2) an absolute
path, a `..` component, a symlink in any component, or anything resolving outside the repository.

Each test plants a repository with a canary outside it and asserts the exit code (2) and that the
canary never appears in stdout, stderr or hangover's stored state."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hangover import oracles, repository, rust
from hangover.cli import _scan
from hangover.evidence import repository_inputs
from hangover.repository import RepositoryRefusal, checked_files, no_execute_git, resolve_repo
from test_rust import run_git
from test_untrusted_checkout import TOOL_ERROR, invoke, scratch_repo

CANARY = "CANARY_outside_7f3a91"


def stored(repo: Path) -> str:
    """Everything hangover stored under the repository's .hangover/ (empty when it stored nothing)."""
    root = repo / ".hangover"
    if not root.is_dir():
        return ""
    return "\n".join(path.read_text(errors="replace") for path in sorted(root.rglob("*"))
                     if path.is_file() and not path.is_symlink())


def commit_all(repo: Path, message: str = "plant") -> None:
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", message)


class ContainedPathTests(unittest.TestCase):
    """The one rule, as a function."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.outside = self.repo.parent / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text(CANARY + "\n")

    def test_in_repository_paths_are_read(self) -> None:
        self.assertEqual("hello\n", repository.read_repo_file(self.repo, "README.md", purpose="test"))
        self.assertEqual("print('hi')\n", repository.read_repo_file(self.repo, "./app/main.py", purpose="test"))
        self.assertIsNone(repository.read_repo_file(self.repo, "missing.txt", purpose="test"))
        self.assertIsNone(repository.read_repo_file(self.repo, "app", purpose="test"), "a directory is not a file")
        self.assertEqual(self.repo / "app" / "main.py", repository.contained_path(self.repo, "app/main.py", purpose="test"))

    def test_absolute_dotdot_and_symlinked_paths_are_refused_unread(self) -> None:
        (self.repo / "link.txt").symlink_to(self.outside / "secret.txt")
        (self.repo / "inner.txt").symlink_to(self.repo / "README.md")  # Inside, but still a link.
        (self.repo / "linkdir").symlink_to(self.outside)
        for name in (str(self.outside / "secret.txt"), "../outside/secret.txt", "app/../../outside/secret.txt",
                     "link.txt", "inner.txt", "linkdir/secret.txt", "linkdir"):
            with self.subTest(name=name):
                with self.assertRaises(RepositoryRefusal) as caught:
                    repository.read_repo_file(self.repo, name, purpose="the test file")
                self.assertIn("the test file", str(caught.exception))
                self.assertNotIn(CANARY, str(caught.exception))
                with self.assertRaises(RepositoryRefusal):
                    repository.contained_path(self.repo, name, purpose="the test file")

    def test_a_fifo_is_not_read(self) -> None:
        os.mkfifo(self.repo / "pipe")
        self.assertIsNone(repository.read_repo_file(self.repo, "pipe", purpose="test"))  # Returns, never blocks.

    def test_a_directory_link_swapped_in_after_the_check_is_not_followed(self) -> None:
        """The open itself refuses a symlink in any component, not only the last (O_NOFOLLOW_ANY on macOS,
        a chain of O_NOFOLLOW directory opens elsewhere): the check-then-open race finds nothing to follow."""
        (self.repo / "linkdir").symlink_to(self.outside)
        self.assertTrue((self.repo / "linkdir" / "secret.txt").is_file(), "precondition: the link reaches the canary")
        unchecked = lambda repo, relative, *, purpose: repo.resolve() / relative  # The check passed, then the swap.
        for name, nofollow_any in (("O_NOFOLLOW_ANY", getattr(os, "O_NOFOLLOW_ANY", 0)), ("openat chain", 0)):
            if name == "O_NOFOLLOW_ANY" and not nofollow_any:
                continue
            with self.subTest(open=name), mock.patch.object(repository, "contained_path", unchecked), \
                    mock.patch.object(repository, "_NOFOLLOW_ANY", nofollow_any, create=True):
                with self.assertRaises(RepositoryRefusal) as caught:
                    repository.read_repo_file(self.repo, "linkdir/secret.txt", purpose="the test file")
                self.assertNotIn(CANARY, str(caught.exception))
                self.assertEqual("hello\n", repository.read_repo_file(self.repo, "README.md", purpose="test"))
                self.assertEqual("print('hi')\n", repository.read_repo_file(self.repo, "app/main.py", purpose="test"))
                self.assertIsNone(repository._line_count(self.repo, self.repo / "linkdir" / "secret.txt"))
                self.assertEqual(1, repository._line_count(self.repo, self.repo / "app" / "main.py"))


class GateScriptTests(unittest.TestCase):
    """A gate script package.json names outside the repository (or through a link) is never read,
    so none of its lines is printed by init, the first `scan --no-checks`, or doctor."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        outside = self.repo.parent / "outside"
        outside.mkdir()
        (outside / "gate.sh").write_text(f"npm run lint\nnpm run test\necho {CANARY} > /dev/null\n")

    def plant(self, gate: str) -> None:
        (self.repo / "package.json").write_text(json.dumps(
            {"name": "x", "scripts": {"gate": gate, "lint": "true", "test": "true"}}))
        commit_all(self.repo)

    def assert_refused(self, *arguments: str) -> None:
        rc, stdout, stderr = invoke(self.repo, *arguments)
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertNotIn(CANARY, stdout + stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn(CANARY, stored(self.repo))
        self.assertIn("gate script", stderr)

    def test_a_dotdot_gate_script_is_refused_and_never_printed(self) -> None:
        self.plant("bash ../outside/gate.sh")
        for arguments in (("scan", "--no-checks"), ("init",), ("doctor",)):
            with self.subTest(arguments=arguments):
                self.assert_refused(*arguments)
        self.assertFalse((self.repo / ".hangover" / "config.json").exists(), "a refused init wrote its config")

    def test_a_symlinked_gate_script_is_refused_and_never_printed(self) -> None:
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts" / "gate.sh").symlink_to(self.repo.parent / "outside" / "gate.sh")
        self.plant("bash scripts/gate.sh")
        self.assert_refused("scan", "--no-checks")

    def test_an_in_repository_gate_script_is_still_proposed(self) -> None:
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts" / "gate.sh").write_text("npm run lint\nnpm run test\necho in-repo-line\n")
        self.plant("bash scripts/gate.sh")
        rc, stdout, stderr = invoke(self.repo, "init")
        self.assertEqual(0, rc, stdout + stderr)
        self.assertIn("proposed stages from the `gate` gate script", stdout)


class ManifestTests(unittest.TestCase):
    """Symlinked or external manifests are refused, not followed and stored."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.outside = self.repo.parent / "outside"
        self.outside.mkdir()

    def assert_refused(self, *arguments: str, says: str) -> None:
        rc, stdout, stderr = invoke(self.repo, *arguments)
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertNotIn(CANARY, stdout + stderr)
        self.assertNotIn(CANARY, stored(self.repo))
        self.assertNotIn("Traceback", stderr)
        self.assertIn(says, stderr)

    def test_a_symlinked_package_json_is_refused(self) -> None:
        (self.outside / "package.json").write_text(json.dumps(
            {"name": CANARY, "bin": {CANARY: "x.js"}, "scripts": {"test": f"echo {CANARY}"}}))
        (self.repo / "package.json").symlink_to(self.outside / "package.json")
        commit_all(self.repo)
        for arguments in (("scan", "--no-checks"), ("scan",)):
            with self.subTest(arguments=arguments):
                self.assert_refused(*arguments, says="package.json")

    @unittest.skipUnless(shutil.which("make"), "the Makefile is read only when make is installed")
    def test_a_symlinked_makefile_is_refused(self) -> None:
        (self.outside / "Makefile").write_text(f"verify:\n\techo {CANARY}\n")
        (self.repo / "Makefile").symlink_to(self.outside / "Makefile")
        commit_all(self.repo)
        self.assert_refused("init", says="Makefile")
        self.assertFalse((self.repo / ".hangover" / "config.json").exists())

    def test_a_symlinked_root_cargo_manifest_is_refused_statically(self) -> None:
        (self.outside / "Cargo.toml").write_text(f'[package]\nname = "{CANARY}"\nversion = "0.1.0"\n')
        (self.repo / "Cargo.toml").symlink_to(self.outside / "Cargo.toml")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "lib.rs").write_text("pub fn f() {}\n")
        commit_all(self.repo)
        self.assert_refused("scan", "--no-checks", says="Cargo.toml")

    def test_a_symlinked_member_manifest_is_refused_statically(self) -> None:
        (self.repo / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\n')
        member = self.repo / "crates" / "a"
        (member / "src").mkdir(parents=True)
        (member / "src" / "lib.rs").write_text("pub fn f() {}\n")
        (self.outside / "Cargo.toml").write_text(f'[package]\nname = "{CANARY}"\nversion = "0.1.0"\n')
        (member / "Cargo.toml").symlink_to(self.outside / "Cargo.toml")
        commit_all(self.repo)
        self.assert_refused("scan", "--no-checks", says="Cargo.toml")

    def test_an_absolute_or_dotdot_member_glob_is_refused_cleanly(self) -> None:
        crate = self.outside / "crate"
        (crate / "src").mkdir(parents=True)
        (crate / "Cargo.toml").write_text(f'[package]\nname = "{CANARY}"\nversion = "0.1.0"\n')
        (crate / "src" / "lib.rs").write_text("pub fn f() {}\n")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "lib.rs").write_text("pub fn g() {}\n")
        for pattern in (str(self.outside) + "/*", "../outside/*"):
            with self.subTest(pattern=pattern):
                (self.repo / "Cargo.toml").write_text(
                    f'[package]\nname = "inside"\nversion = "0.1.0"\n[workspace]\nmembers = ["{pattern}"]\n')
                self.assert_refused("scan", "--no-checks", says="workspace member")


class VerificationInputTests(unittest.TestCase):
    """Verification binds analyzer policy by digest; a symlinked policy file is refused there too,
    as the scan refuses it, instead of being hashed through the link."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.assertEqual(0, invoke(self.repo, "init")[0])
        outside = self.repo.parent / "outside.json"
        outside.write_text("{}\n")
        self.outside = outside

    def test_a_symlinked_rust_policy_is_refused_by_verification_inputs(self) -> None:
        (self.repo / "Cargo.toml").write_text('[package]\nname = "inside"\nversion = "0.1.0"\n')
        (self.repo / ".hangover-rust.json").symlink_to(self.outside)
        with self.assertRaises(RepositoryRefusal):
            rust.analyzer_identity(self.repo)
        with self.assertRaises(RepositoryRefusal):
            repository_inputs(self.repo, None)

    def test_a_symlinked_fallow_config_is_refused_by_verification_inputs(self) -> None:
        (self.repo / ".fallowrc.json").symlink_to(self.outside)
        with self.assertRaises(RepositoryRefusal):
            repository_inputs(self.repo, None)


class HardlinkTests(unittest.TestCase):
    """Git never checks out a hard link; under static mode a listed file with another link is skipped."""

    def test_a_hard_linked_file_is_skipped_in_static_mode_only(self) -> None:
        repo = scratch_repo(self)
        outside = repo.parent / "outside.py"
        outside.write_text(f"SECRET = '{CANARY}'\n")
        os.link(outside, repo / "linked.py")
        listing = run_git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard") + "\0"
        self.assertIn(repo / "linked.py", checked_files(repo, listing), "executing mode keeps it")
        with no_execute_git(repo):
            self.assertNotIn(repo / "linked.py", checked_files(repo, listing))
            self.assertIn(repo / "app" / "main.py", checked_files(repo, listing))

    def test_a_hard_linked_manifest_gate_script_or_policy_is_refused_unread(self) -> None:
        """A same-volume hard link of an outside file passes every path check (no symlink, no '..'); the
        open refuses a file with more than one name before returning a byte, in every mode."""
        repo = scratch_repo(self)
        outside = repo.parent / "outside"
        outside.mkdir()
        (outside / "package.json").write_text(json.dumps(
            {"name": CANARY, "bin": {CANARY: "x.js"}, "scripts": {"verify": f"echo {CANARY}"}}))
        (outside / "gate.sh").write_text(f"npm run lint\nnpm run test\necho {CANARY}\n")
        (outside / "policy.json").write_text(json.dumps({"exclude": [CANARY]}))
        self.assertEqual(os.stat(outside).st_dev, os.stat(repo).st_dev, "precondition: one volume")
        os.link(outside / "package.json", repo / "package.json")
        self.assertEqual(2, os.stat(repo / "package.json").st_nlink, "precondition: a second name")
        for arguments in (("init",), ("scan", "--no-checks")):
            with self.subTest(arguments=arguments):
                rc, stdout, stderr = invoke(repo, *arguments)
                self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
                self.assertNotIn(CANARY, stdout + stderr + stored(repo))
                self.assertIn("hard link", stderr)
        (repo / "scripts").mkdir()
        os.link(outside / "gate.sh", repo / "scripts" / "gate.sh")
        os.link(outside / "policy.json", repo / ".hangover-rust.json")
        for name in ("package.json", "scripts/gate.sh", ".hangover-rust.json"):
            with self.subTest(name=name), self.assertRaises(RepositoryRefusal) as caught:
                repository.read_repo_file(repo, name, purpose=name)
            self.assertNotIn(CANARY, str(caught.exception))

    def test_a_hard_linked_owner_marker_is_refused_unread(self) -> None:
        """`.hangover/owner` is read like any repository file: a hard link to an outside file holding the very
        marker hangover wrote is refused, never trusted."""
        repo = scratch_repo(self)
        rc, stdout, stderr = invoke(repo, "init")
        self.assertEqual(0, rc, stdout + stderr)
        rc, stdout, stderr = invoke(repo, "scan", "--no-checks")
        self.assertEqual(0, rc, "precondition: the owned state is accepted: " + stdout + stderr)
        owner = repo / ".hangover" / "owner"
        outside = repo.parent / "owner-copy"
        outside.write_bytes(owner.read_bytes())
        owner.unlink()
        os.link(outside, owner)
        rc, stdout, stderr = invoke(repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("hard link", stderr)

    @unittest.skipUnless(rust.ast_grep_path() and rust.jscpd_path(), "ast-grep and jscpd are needed (npm ci)")
    def test_a_hard_linked_rust_source_never_reaches_ast_grep(self) -> None:
        """ast-grep is given the checked files, not the package directories: a hard-linked .rs (skipped
        under static mode) is never read, and nothing of it is stored."""
        repo = scratch_repo(self)
        (repo / "Cargo.toml").write_text('[package]\nname = "planted"\nversion = "0.1.0"\nedition = "2021"\n')
        (repo / "src").mkdir()
        (repo / "src" / "lib.rs").write_text("pub fn listed_function() -> u8 {\n    1\n}\n")
        commit_all(repo)
        outside = repo.parent / "outside.rs"
        outside.write_text(f"pub fn {CANARY}() -> u8 {{\n    7\n}}\n")
        os.link(outside, repo / "src" / "linked.rs")
        rc, stdout, stderr = invoke(repo, "scan", "--no-checks")
        self.assertIn(rc, (0, 1), stdout + stderr)
        outputs = sorted((repo / ".hangover").rglob("ast-grep.out"))
        self.assertTrue(outputs, "precondition: ast-grep ran")
        self.assertIn("listed_function", outputs[-1].read_text(), "precondition: ast-grep read the listed file")
        self.assertNotIn(CANARY, stdout + stderr + stored(repo))


class GitLocationTests(unittest.TestCase):
    """Under --no-checks the repository is the directory holding `.git`, and its git data must belong
    to it: a shipped config or gitfile cannot move the scan (or `.hangover/`) somewhere else."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.elsewhere = self.repo.parent / "elsewhere"
        self.elsewhere.mkdir()
        (self.elsewhere / f"{CANARY}.txt").write_text(CANARY + "\n")

    def assert_refused(self, target: Path, *, untouched: list[Path]) -> None:
        rc, stdout, stderr = invoke(target, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertNotIn(CANARY, stdout + stderr)
        self.assertNotIn("Traceback", stderr)
        for path in untouched:
            self.assertFalse((path / ".hangover").exists(), f"hangover created state in {path}")
        self.assertNotIn(CANARY, stored(target))

    def test_core_worktree_elsewhere_is_refused(self) -> None:
        run_git(self.repo, "config", "core.worktree", str(self.elsewhere))
        self.assert_refused(self.repo, untouched=[self.elsewhere, self.repo])

    def test_a_gitfile_naming_another_repository_is_refused(self) -> None:
        victim = scratch_repo(self)
        (victim / f"{CANARY}.txt").write_text(CANARY + "\n")
        commit_all(victim, "victim")
        exclude = (victim / ".git" / "info" / "exclude").read_text()
        attacker = self.repo.parent / "attacker"
        attacker.mkdir()
        (attacker / "main.py").write_text("print('x')\n")
        (attacker / ".git").write_text(f"gitdir: {victim / '.git'}\n")
        self.assert_refused(attacker, untouched=[victim])
        self.assertEqual(exclude, (victim / ".git" / "info" / "exclude").read_text())

    def test_a_gitfile_whose_gitdir_sets_core_worktree_is_refused(self) -> None:
        victim = scratch_repo(self)
        run_git(victim, "config", "core.worktree", str(self.elsewhere))
        attacker = self.repo.parent / "attacker"
        attacker.mkdir()
        (attacker / ".git").write_text(f"gitdir: {victim / '.git'}\n")
        self.assert_refused(attacker, untouched=[victim, self.elsewhere])

    def test_a_commondir_reaching_another_repository_is_refused(self) -> None:
        victim = scratch_repo(self)
        (victim / f"{CANARY}.txt").write_text(CANARY + "\n")
        commit_all(victim, "victim")
        (self.repo / ".git" / "commondir").write_text(str(victim / ".git") + "\n")
        self.assert_refused(self.repo, untouched=[victim])

    def fake_worktree(self, victim: Path) -> Path:
        """A checkout whose gitfile names an admin directory outside it that looks like `git worktree
        add` made it (its `gitdir` names the checkout back) but whose `commondir` is the victim's .git."""
        attacker = self.repo.parent / "attacker"
        admin = self.repo.parent / "admin"
        attacker.mkdir()
        admin.mkdir()
        (attacker / "main.py").write_text("print('x')\n")
        (attacker / ".git").write_text(f"gitdir: {admin}\n")
        (admin / "HEAD").write_text(run_git(victim, "rev-parse", "HEAD") + "\n")
        (admin / "commondir").write_text(str(victim / ".git") + "\n")
        (admin / "gitdir").write_text(str(attacker / ".git") + "\n")
        return attacker

    def test_a_fake_linked_worktree_sharing_a_victims_git_directory_is_refused(self) -> None:
        victim = scratch_repo(self)
        (victim / f"{CANARY}.txt").write_text(CANARY + "\n")
        commit_all(victim, "victim")
        exclude = (victim / ".git" / "info" / "exclude").read_text()
        attacker = self.fake_worktree(victim)
        self.assertEqual(str(victim / ".git"), run_git(attacker, "rev-parse", "--path-format=absolute",
                                                       "--git-common-dir"), "precondition: git takes the bait")
        rc, stdout, stderr = invoke(attacker, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("regular clone", stderr)
        self.assertNotIn(CANARY, stdout + stderr + stored(attacker))
        self.assertEqual(exclude, (victim / ".git" / "info" / "exclude").read_text(), "the victim's exclude changed")
        self.assertFalse((victim / ".hangover").exists())

    def test_an_exclude_is_written_only_into_the_checkouts_own_git_directory(self) -> None:
        """In any mode: a common directory that is not this checkout's own `.git` is never appended to."""
        victim = scratch_repo(self)
        exclude = (victim / ".git" / "info" / "exclude").read_text()
        attacker = self.fake_worktree(victim)
        self.assertIsNone(repository.update_local_exclude(attacker))
        self.assertEqual(exclude, (victim / ".git" / "info" / "exclude").read_text())
        own = repository.update_local_exclude(self.repo)
        self.assertEqual(self.repo / ".git" / "info" / "exclude", own)
        self.assertIn("/.hangover/", own.read_text().splitlines())

    def test_a_linked_worktree_or_a_submodule_is_refused_statically(self) -> None:
        """Static mode reads only a regular clone: its `.git` is a directory inside it, with no commondir
        or alternates. A gitfile (linked worktree, submodule, anything else) is refused, genuine or not."""
        linked = self.repo.parent / "linked"
        run_git(self.repo, "worktree", "add", "-q", str(linked))
        sub = scratch_repo(self)
        run_git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendored-sub")
        commit_all(self.repo, "submodule")
        for target in (linked, self.repo / "vendored-sub"):
            with self.subTest(target=target.name):
                rc, stdout, stderr = invoke(target, "scan", "--no-checks")
                self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
                self.assertIn("regular clone", stderr)
                self.assertFalse((target / ".hangover").exists())
        self.assertEqual(0, invoke(linked, "scan")[0], "executing mode still scans a linked worktree")

    def test_a_symlink_inside_git_is_refused_statically(self) -> None:
        """`git-new-workdir` style: .git/refs (or objects) linked into another repository's .git."""
        victim = scratch_repo(self)
        refs = self.repo / ".git" / "refs"
        own = self.repo.parent / "own-refs"
        refs.rename(own)
        refs.symlink_to(victim / ".git" / "refs")
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn(".git/refs is a symlink", stderr)
        self.assertFalse((self.repo / ".hangover").exists())
        refs.unlink()
        own.rename(refs)
        hook.symlink_to(self.repo / "README.md")  # Hooks never run in static mode: a linked hook is fine.
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(0, rc, stdout + stderr)

    def test_alternates_are_refused_statically(self) -> None:
        victim = scratch_repo(self)
        info = self.repo / ".git" / "objects" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "alternates").write_text(str(victim / ".git" / "objects") + "\n")
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("alternates", stderr)

    def test_static_resolution_unit(self) -> None:
        self.assertEqual(self.repo, resolve_repo(self.repo / "app", static=True))
        run_git(self.repo, "config", "core.worktree", str(self.elsewhere))
        with self.assertRaises(RepositoryRefusal):
            resolve_repo(self.repo, static=True)


SOURCE = Path(__file__).resolve().parents[1] / "src"


def hangover_process(repo: Path, *arguments: str, timeout: float = 30, prelude: str = "") -> tuple[int, str, str]:
    """hangover in its own process group, killed (with any git it started) if it outlives `timeout`: a
    hang is a failure, never a stuck suite. `prelude` runs first (to shorten a timeout constant, say)."""
    script = (f"import sys; sys.path.insert(0, {str(SOURCE)!r}); {prelude}\n"
              f"from hangover.cli import main; sys.exit(main(['--repo', {str(repo)!r}, *{list(arguments)!r}]))")
    environment = {key: value for key, value in os.environ.items() if key != "GIT_CONFIG_PARAMETERS"}
    process = subprocess.Popen([sys.executable, "-I", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=environment, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise AssertionError(f"hangover {' '.join(arguments)} hung for {timeout} s") from None
    return process.returncode, stdout, stderr


def release_fifo(fifo: Path) -> None:
    """Give a reader still blocked on `fifo` its end of file (a git a hung run left behind)."""
    try:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass  # ENXIO: nobody is reading it.


class GitConfigIncludeTests(unittest.TestCase):
    """Under --no-checks the checkout's own git config is read without includes before any git runs in
    it, and a config that includes another file is refused: git would read that file (any file, a FIFO
    that never ends) for every command."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        self.outside = self.repo.parent / "outside"
        self.outside.mkdir()
        self.fifo = self.outside / "pipe"
        os.mkfifo(self.fifo)
        self.addCleanup(release_fifo, self.fifo)
        (self.outside / "secret.gitconfig").write_text(f"{CANARY} is not config\n")

    def test_an_include_is_refused_without_reading_its_target(self) -> None:
        config = self.repo / ".git" / "config"
        original = config.read_text()
        for name, section in (("include.path", f"[include]\n\tpath = {self.fifo}\n"),
                              ("includeIf", f"[includeIf \"gitdir:/\"]\n\tpath = {self.fifo}\n"),
                              ("include of a file", f"[include]\n\tpath = {self.outside / 'secret.gitconfig'}\n")):
            with self.subTest(include=name):
                config.write_text(original + section)
                rc, stdout, stderr = hangover_process(self.repo, "scan", "--no-checks")
                self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
                self.assertIn("include", stderr)
                self.assertNotIn(CANARY, stdout + stderr + stored(self.repo))
                self.assertFalse((self.repo / ".hangover").exists(), "hangover wrote state for a refused checkout")
        config.write_text(original)
        rc, stdout, stderr = hangover_process(self.repo, "scan", "--no-checks")
        self.assertEqual(0, rc, stdout + stderr)

    def test_a_bare_repository_is_never_discovered(self) -> None:
        """A directory that is itself a bare repository (no .git entry) is read as a plain tree: git is
        told not to discover bare repositories, so the bare config's include is never followed."""
        bare = self.repo.parent / "bare"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
        with (bare / "config").open("a") as config:
            config.write(f"[include]\n\tpath = {self.fifo}\n")
        (bare / "main.py").write_text("print('x')\n")
        rc, stdout, stderr = hangover_process(bare, "scan", "--no-checks")
        self.assertEqual(0, rc, stdout + stderr)

    def test_a_git_that_stalls_is_stopped_and_refused(self) -> None:
        """Every git run in static mode has a deadline: a FIFO for HEAD stalls git's own discovery."""
        head = self.repo / ".git" / "HEAD"
        head.unlink()
        os.mkfifo(head)
        self.addCleanup(release_fifo, head)
        rc, stdout, stderr = hangover_process(self.repo, "scan", "--no-checks", timeout=60,
                                            prelude="import hangover.repository as r; r.STATIC_GIT_TIMEOUT_SECONDS = 2")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("did not finish", stderr)
        self.assertNotIn("Traceback", stderr)


class GitTransportTests(unittest.TestCase):
    """Under --no-checks git starts no transport: a promisor remote whose URL is `ext::<command>` (and
    whose protocol the repository's config allows) is lazily fetched from by `git status` when an object
    is missing, which runs the command."""

    def test_a_promisor_ext_remote_never_runs(self) -> None:
        repo = scratch_repo(self)
        marker = repo.parent / "EXT_RAN"
        script = repo.parent / "remote.sh"
        script.write_text(f"#!/bin/sh\necho ran >> '{marker}'\nexit 1\n")
        script.chmod(0o755)
        head = run_git(repo, "rev-parse", "HEAD")
        loose = repo / ".git" / "objects" / head[:2] / head[2:]
        self.assertTrue(loose.is_file(), "precondition: HEAD's commit is a loose object")
        loose.unlink()
        with (repo / ".git" / "config").open("a") as config:
            config.write(f"[extensions]\n\tpartialClone = origin\n[remote \"origin\"]\n\tpromisor = true\n"
                         f"\turl = ext::/bin/sh {script} %S\n[protocol \"ext\"]\n\tallow = always\n")
        hangover_process(repo, "scan", "--no-checks", timeout=60,
                       prelude="import hangover.repository as r; r.STATIC_GIT_TIMEOUT_SECONDS = 10")
        self.assertFalse(marker.exists(), "the promisor remote's ext:: command ran under --no-checks")
        # Positive control: git status under the repository's own config runs it.
        environment = {key: value for key, value in os.environ.items() if key != "GIT_CONFIG_PARAMETERS"}
        subprocess.run(["git", "-C", str(repo), "status", "--short"], capture_output=True, env=environment,
                       timeout=30, check=False)
        self.assertTrue(marker.is_file(), "the planted remote did not bind")


class GitConfigNamedFileTests(unittest.TestCase):
    """Under --no-checks git opens no file the checkout's config names: an exclude or order file outside
    the checkout (a FIFO that never ends) neither hides files from nor stalls the scan's git status."""

    def test_a_named_fifo_stalls_no_static_scan(self) -> None:
        repo = scratch_repo(self)
        fifo = repo.parent / "pipe"
        os.mkfifo(fifo)
        self.addCleanup(release_fifo, fifo)
        (repo / "README.md").write_text("changed\n")  # status diffs (and orders) only a changed file.
        for key in ("core.excludesFile", "diff.orderFile"):
            with self.subTest(key=key):
                run_git(repo, "config", key, str(fifo))
                rc, stdout, stderr = hangover_process(
                    repo, "scan", "--no-checks", timeout=60,
                    prelude="import hangover.repository as r; r.STATIC_GIT_TIMEOUT_SECONDS = 5")
                self.assertEqual(0, rc, stdout + stderr)
                self.assertNotIn("did not finish", stderr)
                release_fifo(fifo)
                run_git(repo, "config", "--unset", key)


class RefusedScanStateTests(unittest.TestCase):
    """A refused scan is never the baseline or the latest run; status and audit carry the refusal
    and exit 2 while it stands."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        outside = self.repo.parent / "outside-policy.json"
        outside.write_text("{}\n")
        self.policy = self.repo / ".hangover-rust.json"
        self.policy.symlink_to(outside)

    def test_a_refused_scan_records_no_baseline_and_status_exits_2(self) -> None:
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        state = json.loads((self.repo / ".hangover" / "state.json").read_text())
        self.assertIsNone(state.get("baseline_run"))
        self.assertIsNone(state.get("latest_run"))
        rc, stdout, stderr = invoke(self.repo, "status", "--json")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("refusing symlinked or external .hangover-rust.json", json.loads(stdout)["refused_scan"]["refusal"])
        rc, stdout, stderr = invoke(self.repo, "status")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("refused", stdout + stderr)
        # Once the content is fixed, the next scan records normally and status is clean.
        self.policy.unlink()
        self.assertEqual(0, invoke(self.repo, "scan", "--no-checks")[0])
        rc, stdout, _ = invoke(self.repo, "status", "--json")
        self.assertEqual(0, rc)
        self.assertIsNone(json.loads(stdout).get("refused_scan"))

    def test_scan_raises_for_every_caller_and_leaves_issues_alone(self) -> None:
        self.assertEqual(0, invoke(self.repo, "init")[0])
        before = (self.repo / ".hangover" / "state.json").read_text()
        for kind in ("scan", "verify"):
            with self.subTest(kind=kind):
                with self.assertRaises(RepositoryRefusal):
                    _scan(self.repo, kind=kind, no_checks=True, no_execute=True, quiet=True)
        after = json.loads((self.repo / ".hangover" / "state.json").read_text())
        self.assertEqual(json.loads(before).get("issues"), after.get("issues"))
        self.assertIsNone(after.get("latest_run"))

    def test_the_rust_audit_carries_the_refusal(self) -> None:
        (self.repo / "Cargo.toml").write_text('[package]\nname = "inside"\nversion = "0.1.0"\n')
        commit_all(self.repo)
        with tempfile.TemporaryDirectory() as directory:
            result = rust.run_rust_audit(self.repo, Path(directory), "HEAD", execute=False)
        self.assertIn("refusing symlinked or external .hangover-rust.json", result.get("refusal") or "")
        self.assertIn("refusing symlinked or external .hangover-rust.json", result["current"].get("refusal") or "")
        rc, stdout, stderr = invoke(self.repo, "audit", "--base", "HEAD")
        self.assertEqual(TOOL_ERROR, rc, stdout + stderr)
        self.assertIn("refusing symlinked or external .hangover-rust.json", stderr)


class FallowNotRunStaticallyTests(unittest.TestCase):
    """Under --no-checks hangover does not run Fallow at all: it reads tsconfig/jsconfig chains, package
    manifests under node_modules and plugin files in ways no precheck can follow exactly.
    The Fallow section is `skipped`, which is no
    failure and no refusal; executing mode runs Fallow as before."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "index.ts").write_text("export const used = 1;\nexport function unused() { return used; }\n")
        (self.repo / "package.json").write_text(json.dumps({"name": "x", "main": "src/index.ts"}))
        self.outside = self.repo.parent / "outside"
        self.outside.mkdir()
        (self.outside / "base.json").write_text(json.dumps({"compilerOptions": {"strict": True}}))
        # Shapes a precheck missed: a bare-package extends, an include glob climbing out.
        (self.repo / "tsconfig.json").write_text(json.dumps(
            {"extends": "some-package/tsconfig.json", "include": ["*/../../outside/*.ts"]}))
        commit_all(self.repo)
        self.marker = self.repo.parent / "fallow-ran"
        fake = self.repo.parent / "fake-fallow"
        fake.write_text(f"#!/bin/sh\necho \"$@\" >> {self.marker}\necho 'fallow 0.0.0'\n")
        fake.chmod(0o755)
        patcher = mock.patch.dict(os.environ, {"HANGOVER_FALLOW_BIN": str(fake)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def latest(self) -> dict:
        state = json.loads((self.repo / ".hangover" / "state.json").read_text())
        return json.loads((self.repo / ".hangover" / "runs" / state["latest_run"] / "snapshot.json").read_text())

    def test_static_scan_and_run_skip_fallow_and_exit_0(self) -> None:
        for arguments in (("scan", "--no-checks"), ("run", "--no-checks", "--no-review")):
            with self.subTest(arguments=arguments):
                rc, stdout, stderr = invoke(self.repo, *arguments)
                self.assertEqual(0, rc, stdout + stderr)
                self.assertFalse(self.marker.exists(), "Fallow ran under --no-checks")
                fallow = self.latest()["fallow"]
                self.assertEqual("skipped", fallow["status"])
                self.assertIn("static mode does not run Fallow", fallow["reason"])
                self.assertIn("fallow: skipped", stdout)
                self.assertTrue(self.latest()["inventory"]["typescript"])
        rc, stdout, stderr = invoke(self.repo, "status", "--json")
        self.assertEqual(0, rc, stdout + stderr)

    def test_executing_mode_still_runs_fallow(self) -> None:
        rc, stdout, stderr = invoke(self.repo, "scan")
        self.assertEqual(0, rc, stdout + stderr)
        self.assertTrue(self.marker.exists(), "executing mode did not run Fallow")
        self.assertNotEqual("skipped", self.latest()["fallow"]["status"])

    def test_a_symlinked_root_tsconfig_does_not_count_as_typescript(self) -> None:
        (self.repo / "src" / "index.ts").rename(self.repo / "src" / "index.js")
        (self.repo / "tsconfig.json").unlink()
        (self.repo / "tsconfig.json").symlink_to(self.outside / "base.json")
        commit_all(self.repo)
        with no_execute_git(self.repo):
            found = repository.inventory(self.repo)
        self.assertFalse(found["typescript"], "a symlinked tsconfig.json made the checkout TypeScript")
        self.assertTrue(found["javascript"])


@unittest.skipUnless(oracles._fallow_path(), "the pinned Fallow is needed (npm ci)")
class FallowSkippedBaselineTests(unittest.TestCase):
    """A skipped Fallow section never reads as a Fallow version change or as the disappearance of
    Fallow findings: cards stay as they were, and a static baseline asks for a rebaseline."""

    def setUp(self) -> None:
        self.repo = scratch_repo(self)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "index.ts").write_text("export const used = 1;\n")
        (self.repo / "src" / "orphan.ts").write_text("export function orphan() { return 2; }\n")
        (self.repo / "package.json").write_text(json.dumps({"name": "x", "main": "src/index.ts"}))
        commit_all(self.repo)

    def snapshot(self) -> dict:
        state = json.loads((self.repo / ".hangover" / "state.json").read_text())
        return json.loads((self.repo / ".hangover" / "runs" / state["latest_run"] / "snapshot.json").read_text())

    def fallow_cards(self) -> dict:
        state = json.loads((self.repo / ".hangover" / "state.json").read_text())
        return {key: (card["status"], len(card.get("history", []))) for key, card in state["issues"].items()
                if card.get("source") == "fallow"}

    def test_a_static_scan_after_an_executing_baseline_leaves_fallow_cards_alone(self) -> None:
        self.assertEqual(0, invoke(self.repo, "scan")[0])
        before = self.fallow_cards()
        self.assertTrue(before, "precondition: the executing scan recorded Fallow cards")
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(0, rc, stdout + stderr)
        self.assertNotIn("Fallow version changed", stdout)
        self.assertEqual("not_run", self.snapshot()["fallow_comparison"]["kind"])
        self.assertEqual(before, self.fallow_cards())
        rc, stdout, stderr = invoke(self.repo, "scan")
        self.assertEqual(0, rc, stdout + stderr)
        self.assertTrue(self.snapshot()["fallow_comparison"]["comparable"])
        self.assertEqual({key: "open" for key in before}, {key: value[0] for key, value in self.fallow_cards().items()})

    def test_a_static_first_baseline_asks_for_a_rebaseline_and_still_records_findings(self) -> None:
        rc, stdout, stderr = invoke(self.repo, "scan", "--no-checks")
        self.assertEqual(0, rc, stdout + stderr)
        self.assertTrue(self.snapshot()["is_baseline"])
        rc, stdout, stderr = invoke(self.repo, "scan", "--rebaseline", "--no-checks")
        self.assertEqual(2, rc, stdout + stderr)
        self.assertIn("Fallow was not run (--no-checks)", stdout)
        rc, stdout, stderr = invoke(self.repo, "scan")
        self.assertEqual(0, rc, stdout + stderr)
        comparison = self.snapshot()["fallow_comparison"]
        self.assertEqual("baseline_not_run", comparison["kind"])
        self.assertIn("rebaseline", comparison["reason"])
        self.assertNotIn("Fallow version changed", stdout)
        self.assertTrue(self.fallow_cards(), "the executing scan's Fallow findings were not recorded")
        self.assertEqual(0, invoke(self.repo, "scan", "--rebaseline")[0])
        self.assertTrue(self.snapshot()["is_baseline"])


class ToolEnvironmentTests(unittest.TestCase):
    def test_relative_path_entries_never_reach_a_tool(self) -> None:
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = os.pathsep.join([".", "node_modules/.bin", "", original])
        try:
            entries = repository.git_safe_environment()["PATH"].split(os.pathsep)
        finally:
            os.environ["PATH"] = original
        self.assertTrue(entries and all(os.path.isabs(entry) for entry in entries), entries)
        self.assertIn(original.split(os.pathsep)[0], entries)


if __name__ == "__main__":
    unittest.main()
