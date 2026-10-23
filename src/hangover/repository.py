from __future__ import annotations

import contextlib
import contextvars
import errno
import functools
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from difflib import unified_diff
from hashlib import sha256
from pathlib import Path
from typing import Any

from .model import STATE_DIR, paths, write_json
from .process import run_logged

IGNORED_DIRS = {
    ".git",
    ".hangover",
    ".fallow",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".venv",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs"}
TYPESCRIPT_SUFFIXES = {".ts", ".tsx", ".mts", ".cts"}
SOURCE_SUFFIXES = JAVASCRIPT_SUFFIXES | TYPESCRIPT_SUFFIXES | {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".svelte",
    ".swift",
    ".vue",
}
DOC_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
}
RISK_PARTS = {
    ".github",
    "api",
    "auth",
    "ci",
    "database",
    "deploy",
    "infra",
    "migration",
    "migrations",
    "plugin",
    "plugins",
    "route",
    "routes",
    "schema",
    "schemas",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MIN_FAILURE_OUTPUT_BYTES = 40
SAFE_CHECK_NAME = re.compile(r"[A-Za-z0-9_.-]+")
MAX_PATCH_FILE_BYTES = 1_000_000
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
SENSITIVE_FILENAMES = {".npmrc", ".pypirc", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}
SENSITIVE_NAME_PARTS = {
    "credential",
    "credentials",
    "privatekey",
    "secret",
    "secrets",
    "serviceaccount",
    "token",
    "tokens",
}
SENSITIVE_CONTENT_MARKERS = (
    b"access_token",
    b"api_key",
    b"aws_secret_access_key",
    b"client_secret",
    b"private_key",
    b"refresh_token",
    b"secret_access_key",
)
SAFE_ENVIRONMENT_NAMES = {
    "CODEX_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NODE_EXTRA_CA_CERTS",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SystemRoot",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "TZ",
    "USER",
}


def _base_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in SAFE_ENVIRONMENT_NAMES
        if os.environ.get(name)
    }
    environment.setdefault("HOME", str(Path.home()))
    environment.setdefault("PATH", os.defpath)
    # Tools run with the repository as their working directory, so a relative PATH entry (`.`,
    # `node_modules/.bin`, an empty one) would let the checkout choose `node` or `git`: drop them.
    environment["PATH"] = os.pathsep.join(
        entry for entry in environment["PATH"].split(os.pathsep) if os.path.isabs(entry)) or os.defpath
    environment["SHELL"] = "/bin/sh"
    environment["GIT_CONFIG_COUNT"] = "1"
    environment["GIT_CONFIG_KEY_0"] = "core.fsmonitor"
    environment["GIT_CONFIG_VALUE_0"] = "false"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def git_safe_environment() -> dict[str, str]:
    """The environment hangover gives git and the tools it starts.

    Inside ``no_execute_git(repo)`` it is that repository's no-execute
    environment, so an analyzer or reviewer that runs git itself inherits the
    same protection as hangover's own git calls.
    """
    active = _NO_EXECUTE_GIT.get()
    if active is not None:
        return dict(active[active["root"]])
    return _base_environment()


# GIT_ATTR_SOURCE, the environment form of --attr-source, is git 2.42.
NO_EXECUTE_GIT_MINIMUM = (2, 42)
# Config keys whose value git runs as a command, or that let a transport run one. In a checkout
# hangover must not execute, each one found is overridden with an empty (or off) value.
_GIT_COMMAND_KEYS = (
    (re.compile(r"filter\..+\.(clean|smudge|process)"), ""),
    (re.compile(r"filter\..+\.required"), "false"),
    (re.compile(r"diff\..+\.(textconv|command)"), ""),
    (re.compile(r"merge\..+\.driver"), ""),
    (re.compile(r"pager\..+"), "false"),
    (re.compile(r"credential(\..+)?\.helper"), ""),
    (re.compile(r"gpg(\..+)?\.program"), ""),
    (re.compile(r"remote\..+\.(uploadpack|receivepack|proxy)"), ""),
    # A repository's `protocol.ext.allow=always` outranks `protocol.allow=never`, and `ext::` runs
    # the remote's URL as a command (a promisor remote's lazy fetch does, under `git status`).
    (re.compile(r"protocol\..+\.allow"), "never"),
    # Config-defined hooks (`hook.<name>.command`) run whatever core.hooksPath says: each hook the
    # config names gets an empty command and is disabled (`no_execute_git_env`).
    (re.compile(r"hook\..+\.(command|event|enabled)"), ""),
)
# Transports git names itself; each is denied by name as well as by `protocol.allow`.
_GIT_PROTOCOLS = ("ext", "file", "ssh", "git", "http", "https")
_GIT_FIXED_OVERRIDES = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.pager", ""),
    ("core.editor", ""),
    ("sequence.editor", ""),
    ("core.sshCommand", ""),
    ("core.askPass", ""),
    ("core.gitProxy", ""),
    ("diff.external", ""),
    ("credential.helper", ""),
    # Files git opens because config names them: anywhere outside the checkout, a FIFO that never
    # ends. status and ls-files read the exclude file, diff and log the attributes and order files,
    # log the mailmap (log.mailmap is on by default); signatures are never verified.
    ("core.attributesFile", "/dev/null"),
    ("core.excludesFile", "/dev/null"),
    ("diff.orderFile", "/dev/null"),
    ("log.mailmap", "false"),
    ("mailmap.file", "/dev/null"),
    ("mailmap.blob", ""),
    ("log.showSignature", "false"),
    # No transport: no lazy fetch from a promisor remote, no remote at all.
    ("protocol.allow", "never"),
    *((f"protocol.{name}.allow", "never") for name in _GIT_PROTOCOLS),
)
_NO_EXECUTE_GIT: contextvars.ContextVar[dict[Any, Any] | None] = contextvars.ContextVar(
    "hangover_no_execute_git", default=None)


# Every git hangover runs in static mode gets this deadline: a FIFO or device where git expects a file
# (HEAD, the index, an exclude file) blocks it forever otherwise. Past it the run is refused.
STATIC_GIT_TIMEOUT_SECONDS = 120
EMPTY_TREE_SHA1 = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
EMPTY_TREE_SHA256 = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"


def _run_git_bounded(arguments: list[str], environment: dict[str, str], *, what: str,
                     input: str | None = None, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    """A git command with the static-mode deadline; RepositoryRefusal when git outlives it."""
    try:
        return subprocess.run(arguments, input=input, capture_output=True, text=True, check=False,
                              env=environment, cwd=cwd, timeout=STATIC_GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RepositoryRefusal(
            f"refusing the checkout under --no-checks: git {what} did not finish within "
            f"{STATIC_GIT_TIMEOUT_SECONDS} s (a FIFO or device where git expects a file stalls it); "
            "inspect the checkout's .git directory") from exc


def _git_holder(repo: Path) -> Path | None:
    """The nearest directory at or above `repo` holding a `.git` entry."""
    return next((directory for directory in (repo, *repo.parents) if os.path.lexists(directory / ".git")), None)


def _static_config_entries(repo: Path, environment: dict[str, str]) -> list[str]:
    """The `key\\nvalue` entries of the repository's own config files, read by git without includes
    and without git looking at the checkout (it runs from /, on the file alone).

    RepositoryRefusal for a config file that is not a regular file, one git cannot parse, or one that
    includes another file. No `.git` at or above `repo`: no entries (git will find no repository)."""
    holder = _git_holder(repo.resolve())
    if holder is None:
        return []
    dot_git = holder / ".git"
    if not stat.S_ISDIR(os.lstat(dot_git).st_mode):
        raise RepositoryRefusal(f"refusing {holder} under --no-checks: {dot_git} is not a directory; "
                                f"{REGULAR_CLONE_HINT}")
    entries: list[str] = []
    for name in ("config", "config.worktree"):
        path = dot_git / name
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RepositoryRefusal(f"refusing {holder} under --no-checks: .git/{name} is not a regular file "
                                    "(a symlink, FIFO or device), and git reads it for every command")
        listing = _run_git_bounded(["git", "config", "--no-includes", "--file", str(path), "--list", "-z"],
                                   environment, what=f"config (.git/{name})", cwd="/")
        if listing.returncode != 0:
            raise RepositoryRefusal(f"refusing {holder} under --no-checks: git cannot read .git/{name} "
                                    f"(git config exited {listing.returncode})")
        for entry in listing.stdout.split("\0"):
            key = entry.split("\n", 1)[0]
            if key == "include.path" or (key.startswith("includeif.") and key.endswith(".path")):
                raise RepositoryRefusal(
                    f"refusing {holder} under --no-checks: .git/{name} includes another file ({key}), which git "
                    "would read for every command, wherever it is; static mode does not follow includes. "
                    "Remove the include, or scan in executing mode once you trust the checkout")
            if entry:
                entries.append(entry)
    return entries


@functools.lru_cache(maxsize=None)
def _git_version() -> tuple[int, ...] | None:
    try:
        result = subprocess.run(["git", "--version"], capture_output=True, text=True, check=False,
                                env=_base_environment(), timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    found = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", result.stdout)
    return tuple(int(part or 0) for part in found.groups()) if result.returncode == 0 and found else None


def no_execute_git_env(repo: Path, *, strict: bool = True) -> dict[str, str]:
    """An environment in which git runs nothing the checkout configures.

    ``git status`` (and ``diff``, ``log -p``, ``checkout``) run the clean,
    smudge and textconv drivers a repository's attributes select, and its
    config can define those drivers (``.git/config``, or a file it includes).
    Three layers keep a checkout hangover must not execute from doing so:

    1. attributes come from the empty tree (``GIT_ATTR_SOURCE``), and no
       system or ``core.attributesFile`` attributes are read, so the
       checkout's ``.gitattributes`` selects no driver;
    2. no system or global config is read; ``core.fsmonitor``,
       ``core.hooksPath`` and the pager, editor, ssh and askpass commands
       are off; no transport is allowed (so no promisor remote is lazily
       fetched from, through ``ext::`` or anything else); and every file a
       config key could name for these commands to open (exclude, attributes,
       order and mailmap files) is ``/dev/null``;
    3. every command-valued key the repository's own config defines is
       overridden with an empty value: ``.git/info/attributes`` is read
       whatever the attribute source, so a driver it selects must have no
       command to run.

    strict=True (static mode) reads the repository's own config files before
    any git runs in the checkout, without includes, and raises
    RepositoryRefusal when one includes another file (`include.path`,
    `includeIf.*.path`): git would read that file, wherever it is (a FIFO
    never ends), for every command. Every git it runs has a deadline.

    Raises RuntimeError when git is too old for layer 1, or its config cannot
    be read: refusing is the only honest answer then. ``strict=False`` (for
    git that hangover runs on a checkout it already trusts to execute) accepts an
    older git, which ignores ``GIT_ATTR_SOURCE`` but keeps layers 2 and 3, and
    follows includes to find the keys to override.
    """
    version = _git_version()
    if strict and (version is None or version < NO_EXECUTE_GIT_MINIMUM):
        found = ".".join(map(str, version)) if version else "unknown"
        minimum = ".".join(map(str, NO_EXECUTE_GIT_MINIMUM))
        raise RuntimeError(
            f"--no-checks needs git {minimum} or newer to read the checkout without running its "
            f"git filters (found {found}); upgrade git, or run without --no-checks on a trusted checkout"
        )
    environment = _base_environment()
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "",
        # No transport, whatever any config says: a promisor remote's lazy fetch never starts, and
        # an empty allow list (set, and naming nothing) outranks every protocol.*.allow.
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_PROTOCOL_FROM_USER": "0",
    })
    for name in [key for key in environment if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_")]:
        del environment[name]
    environment["GIT_CONFIG_COUNT"] = "0"
    overrides = dict(_GIT_FIXED_OVERRIDES)
    if strict:
        # Static mode: no git runs in the checkout before its own config has been read, without
        # includes, and found to include nothing (`_static_config_entries`).
        entries = _static_config_entries(repo, environment)
        sha256_objects = any(entry == "extensions.objectformat\nsha256" for entry in entries)
        tree = EMPTY_TREE_SHA256 if sha256_objects else EMPTY_TREE_SHA1
        # A bare repository is never found by discovery (the checkout itself, or a parent, could be one).
        overrides["safe.bareRepository"] = "explicit"
    else:
        empty_tree = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-t", "tree", "--no-filters", "--stdin"],
            input="", capture_output=True, text=True, check=False, env=environment)
        listing = subprocess.run(["git", "-C", str(repo), "config", "--list", "--includes", "-z"],
                                 capture_output=True, text=True, check=False, env=environment)
        tree = empty_tree.stdout.strip()
        if empty_tree.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", tree):
            raise RuntimeError(f"could not compute git's empty tree (git hash-object exited {empty_tree.returncode})")
        if listing.returncode != 0:
            raise RuntimeError(f"could not read the checkout's git config (git config exited {listing.returncode})")
        entries = listing.stdout.split("\0")
    for entry in entries:
        key = entry.split("\n", 1)[0]
        for pattern, value in _GIT_COMMAND_KEYS:
            if key and pattern.fullmatch(key):
                name = key.rsplit(".", 1)[0]
                if key.startswith("hook."):
                    overrides[name + ".command"], overrides[name + ".enabled"] = "", "false"
                    continue
                overrides[key] = value
                if key.startswith("filter."):
                    overrides[name + ".required"] = "false"
    environment["GIT_ATTR_SOURCE"] = tree
    environment["GIT_CONFIG_COUNT"] = str(len(overrides))
    for index, (key, value) in enumerate(overrides.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


@contextlib.contextmanager
def no_execute_git(repo: Path) -> Iterator[None]:
    """Every git call (and every tool environment) inside runs under ``no_execute_git_env``.

    Entering raises RuntimeError, before anything runs, when that environment
    cannot be built, and RepositoryRefusal when the repository's `.git` is not
    a regular clone's own (`_refuse_shared_git_dir`).
    """
    root = repo.resolve()
    holder = _git_holder(root)
    if holder is not None:
        _refuse_shared_git_dir(holder)
    cache: dict[Any, Any] = {"root": root, root: no_execute_git_env(root)}
    token = _NO_EXECUTE_GIT.set(cache)
    try:
        yield
    finally:
        _NO_EXECUTE_GIT.reset(token)


def no_execute_git_active() -> bool:
    return _NO_EXECUTE_GIT.get() is not None


def _git_environment(repo: Path) -> dict[str, str]:
    active = _NO_EXECUTE_GIT.get()
    if active is None:
        return _base_environment()
    key = repo.resolve()
    if key not in active:
        active[key] = no_execute_git_env(key)
    return dict(active[key])


def resolve_repo(start: Path, *, static: bool = False) -> Path:
    """The repository hangover works on for `start`: git's top-level directory, or `start` outside git.

    static=True (--no-checks) does not let the checkout's git data choose it: the repository is the
    nearest directory at or above `start` holding a `.git` entry, which must be a regular clone's
    (`_refuse_shared_git_dir`: a directory, no gitfile, commondir, alternates or symlink in it), git
    runs under the no-execute environment (whose config may include nothing), and RepositoryRefusal
    is raised when git's work tree or git directory is anywhere else (a shipped `core.worktree`).
    GIT_DIR, GIT_WORK_TREE and the like never reach git from hangover's environment.
    """
    start = start.expanduser().resolve()
    if static:
        return _static_repo(start)
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(start),
            "rev-parse",
            "--show-toplevel",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=git_safe_environment(),
    )
    if result.returncode == 0:
        return Path(result.stdout.strip()).resolve()
    return start


REGULAR_CLONE_HINT = ("static mode reads only a regular clone, whose .git is a directory inside it that shares "
                      "nothing with another repository; run static mode on a regular clone (`git clone`) of the checkout")


def _refuse_shared_git_dir(holder: Path) -> None:
    """RepositoryRefusal unless `holder/.git` is a directory of this checkout's own: not a symlink or a
    gitfile (a linked worktree, a submodule, or a pointer anywhere), no `commondir` or
    `objects/info/alternates` file, and no symlink inside it (as `git-new-workdir` makes) outside hooks/,
    which static mode never runs. Each of those would let git read another repository's objects, refs
    or exclude file and present them as this checkout's."""
    dot_git = holder / ".git"

    def refuse(reason: str) -> RepositoryRefusal:
        return RepositoryRefusal(f"refusing {holder} under --no-checks: {reason}; {REGULAR_CLONE_HINT}")

    mode = os.lstat(dot_git).st_mode
    if stat.S_ISLNK(mode):
        raise refuse(f"{dot_git} is a symlink")
    if not stat.S_ISDIR(mode):
        raise refuse(f"{dot_git} is a gitfile (a linked worktree, a submodule, or a pointer to another git "
                     "directory), not a directory")
    for name in ("commondir", "objects/info/alternates"):
        if os.path.lexists(dot_git / name):
            raise refuse(f".git/{name} exists, so its git directory shares another repository's "
                         + ("objects and refs" if name == "commondir" else "objects (alternates)"))
    pending = [dot_git]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise refuse(f"{Path(entry.path).relative_to(holder).as_posix()} is a symlink inside .git")
                    if entry.is_dir(follow_symlinks=False) and not (directory == dot_git and entry.name == "hooks"):
                        pending.append(Path(entry.path))
        except (FileNotFoundError, NotADirectoryError):
            continue


def _static_repo(start: Path) -> Path:
    holder = _git_holder(start)
    if holder is not None:
        holder = holder.resolve()
        _refuse_shared_git_dir(holder)
    environment = no_execute_git_env(holder or start)  # Refuses a config that includes another file.
    result = _run_git_bounded(
        ["git", "-C", str(start), "rev-parse", "--path-format=absolute", "--show-toplevel",
         "--absolute-git-dir", "--git-common-dir"], environment, what="rev-parse")
    lines = result.stdout.splitlines() if result.returncode == 0 else []

    def refuse(reason: str) -> RepositoryRefusal:
        return RepositoryRefusal(
            f"refusing {start} under --no-checks: {reason}. A checkout's git data (.git/config, a "
            "gitfile) cannot point hangover at another directory or repository; inspect the checkout")

    if holder is None:
        if len(lines) == 3:
            raise refuse(f"git finds a work tree at {lines[0]}, but no directory at or above it holds .git")
        return start
    if len(lines) != 3:
        return start  # git cannot use this .git: hangover reads the directory as a plain tree.
    toplevel, git_dir, common_dir = (Path(line).resolve() for line in lines)
    dot_git = holder / ".git"
    if toplevel != holder:
        raise refuse(f"git's work tree is {toplevel}, not {holder} (which holds .git): core.worktree moves it")
    if git_dir != dot_git or common_dir != dot_git:
        raise refuse(f"git uses the git directory {git_dir} (common directory {common_dir}), not {dot_git}")
    return holder


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """git in `repo`; in static mode under the no-execute environment and the static-mode deadline."""
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args]
    environment = _git_environment(repo)
    if no_execute_git_active():
        return _run_git_bounded(command, environment, what=args[0] if args else "")
    return subprocess.run(command, capture_output=True, text=True, check=False, env=environment)


def is_git_repo(repo: Path) -> bool:
    result = git(repo, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.strip() == "true"


def git_info(repo: Path) -> dict[str, Any]:
    if not is_git_repo(repo):
        return {"is_git": False, "commit": None, "branch": None, "changes": []}
    commit = git(repo, "rev-parse", "HEAD")
    branch = git(repo, "branch", "--show-current")
    # A submodule's status runs in its own repository, under its own config.
    submodules = ["--ignore-submodules=all"] if no_execute_git_active() else []
    status = git(repo, "status", "--short", "--untracked-files=all", *submodules)
    return {
        "is_git": True,
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "branch": branch.stdout.strip() or None,
        "changes": status.stdout.splitlines() if status.returncode == 0 else [],
    }


class RepositoryRefusal(RuntimeError):
    """hangover refused repository-controlled content (a crafted file list, tracked or foreign
    `.hangover/` state, a policy file reaching outside the checkout) rather than act on it. The CLI
    reports it as a tool error, never as a finished scan."""


# --------------------------------------------------------------------------- containment
#
# The one rule for opening a path the repository names (a manifest, a policy file, a gate script a
# package.json points at, a file git lists): it is a relative path with no '..' component, no
# component inside the repository is a symlink (the last one included), and it resolves inside the
# repository. Anything else is refused (RepositoryRefusal: a tool error, exit 2) before it is opened,
# so nothing outside the checkout is read, stored or printed because the checkout said so. Files are
# opened without following a link in any component, so a link swapped in after the check is not
# followed either, and a hard link (more than one name for one file; git never checks one out) is refused.
MAX_REPO_FILE_BYTES = MAX_CAPTURE_BYTES


def _symlinked_component(top: Path, parts: list[str], known: set[Path] | None = None) -> Path | None:
    """The first of top/parts[0], top/parts[0]/parts[1], ... that is a symlink, or None.

    Stops at the first component that does not exist (nothing below it can be a link). `known`
    caches directories already seen to be real, for a caller checking many paths."""
    current = top
    for part in parts:
        current = current / part
        if known is not None and current in known:
            continue
        try:
            info = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            return None
        if stat.S_ISLNK(info.st_mode):
            return current
        if known is not None and stat.S_ISDIR(info.st_mode):
            known.add(current)
    return None


def contained_path(repo: Path, relative: str | os.PathLike[str], *, purpose: str) -> Path:
    """The path `relative` names inside the repository, after the containment rule above.

    `purpose` names what is being read in the refusal ("gate script 'scripts/gate.sh'").
    The path need not exist. Raises RepositoryRefusal for an absolute path, a '..' component, a
    symlink in any component, or a path that resolves outside the repository."""
    text = os.fspath(relative)
    top = repo.resolve()

    def refuse(reason: str) -> RepositoryRefusal:
        return RepositoryRefusal(f"refusing symlinked or external {purpose}: {reason}")

    if os.path.isabs(text):
        raise refuse(f"{text!r} is an absolute path")
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if ".." in parts:
        raise refuse(f"{text!r} has a '..' component")
    link = _symlinked_component(top, parts)
    if link is not None:
        raise refuse(f"{link.relative_to(top).as_posix()!r} is a symlink")
    path = top.joinpath(*parts)
    if os.path.lexists(path) and not path.resolve().is_relative_to(top):
        raise refuse(f"{text!r} resolves outside the repository")
    return path


_NOFOLLOW_ANY = getattr(os, "O_NOFOLLOW_ANY", 0)  # macOS: no symlink in any component of the path.


def _open_beneath(top: Path, parts: list[str], flags: int, mode: int = 0o644) -> int:
    """A descriptor for top/parts[0]/.../parts[-1], opened without following a symlink in any
    component: O_NOFOLLOW_ANY where the OS has it, otherwise one directory at a time from `top`, each
    opened O_NOFOLLOW|O_DIRECTORY relative to the last. `top` must be a resolved path (no symlinks).
    OSError (ELOOP, or ENOTDIR for a link where a directory was expected) when a component is a link."""
    flags |= getattr(os, "O_CLOEXEC", 0)
    if _NOFOLLOW_ANY:
        return os.open(top.joinpath(*parts), flags | _NOFOLLOW_ANY, mode)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(top, directory_flags)
    try:
        for part in parts[:-1]:
            following = os.open(part, directory_flags | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        return os.open(parts[-1], flags | os.O_NOFOLLOW, mode, dir_fd=directory)
    finally:
        os.close(directory)


def _link_refusal(top: Path, parts: list[str], exc: OSError) -> bool:
    """Whether an open failed because a component of the path is a symlink."""
    if exc.errno in {errno.ELOOP, errno.EMLINK}:  # EMLINK: FreeBSD's O_NOFOLLOW answer.
        return True
    return exc.errno == errno.ENOTDIR and _symlinked_component(top, parts) is not None


def open_repo_file(repo: Path, relative: str | os.PathLike[str], *, purpose: str) -> Any:
    """A binary file object for a regular file inside the repository, or None when there is none.

    Applies `contained_path`, then opens without following a symlink in any component (so a link
    swapped in after the check is not followed either) and without blocking on a FIFO; anything but a
    regular file (a directory, a FIFO, a device) is None, never read. A file with more than one name
    (a hard link, which git never checks out) may be a file outside the repository: RepositoryRefusal,
    before any byte is returned."""
    path = contained_path(repo, relative, purpose=purpose)
    top = repo.resolve()
    parts = list(path.relative_to(top).parts)
    if not parts:
        return None  # The repository itself: a directory.
    try:
        descriptor = _open_beneath(top, parts, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (FileNotFoundError, IsADirectoryError):
        return None
    except OSError as exc:
        if _link_refusal(top, parts, exc):  # Became a link after the check.
            raise RepositoryRefusal(f"refusing symlinked or external {purpose}: {os.fspath(relative)!r} is or "
                                    "passes through a symlink") from exc
        if exc.errno == errno.ENOTDIR:
            return None
        raise
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        return None
    if info.st_nlink > 1:
        os.close(descriptor)
        raise RepositoryRefusal(
            f"refusing hard-linked {purpose}: {os.fspath(relative)!r} is a hard link ({info.st_nlink} names for "
            "one file), which a git checkout never makes, so it may be a file outside the repository")
    return os.fdopen(descriptor, "rb")


def read_repo_file(repo: Path, relative: str | os.PathLike[str], *, purpose: str, binary: bool = False,
                   errors: str = "strict", limit: int | None = MAX_REPO_FILE_BYTES) -> Any:
    """The content of a regular file inside the repository (`open_repo_file`), or None when there is
    none. Text is UTF-8 with universal newlines, as Path.read_text reads it; raises
    UnicodeDecodeError under errors="strict", and RepositoryRefusal past `limit` bytes."""
    handle = open_repo_file(repo, relative, purpose=purpose)
    if handle is None:
        return None
    with handle:
        data = handle.read() if limit is None else handle.read(limit + 1)
    if limit is not None and len(data) > limit:
        raise RepositoryRefusal(f"refusing {purpose}: larger than {limit} bytes")
    if binary:
        return data
    return data.decode("utf-8", errors=errors).replace("\r\n", "\n").replace("\r", "\n")


def contained_file(repo: Path, relative: str, *, purpose: str = "path") -> bool:
    """Whether `relative` is a regular file inside the repository under the containment rule; a path
    the rule refuses is simply not one (for references that only decide whether a line is a stage)."""
    try:
        path = contained_path(repo, relative, purpose=purpose)
    except RepositoryRefusal:
        return False
    return path.is_file() and not path.is_symlink()


def _contained_directory(repo: Path, relative: str) -> bool:
    """Whether `relative` is a real directory inside the repository (no symlink on the way, or at it)."""
    try:
        path = contained_path(repo, relative, purpose="path")
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except (RepositoryRefusal, OSError):
        return False


_HARDLINK_NOTICES: set[Path] = set()


LISTED_FILES_ARGS = ("ls-files", "--cached", "--others", "--exclude-standard", "-z")


def checked_files(repo: Path, listing: str | None) -> list[Path]:
    """The regular files of a repository, each one inside it through real directories.

    `listing` is the NUL-separated output of `git ls-files` with LISTED_FILES_ARGS, or None to walk
    the directory instead (not a Git repository, or git could not list it). Entries under
    IGNORED_DIRS are skipped; so are symlinks and anything that is not a regular file.

    The index is repository content: a hand-built one can name any path. Raises RepositoryRefusal
    when git lists a name that is absolute, has an empty, '.', '..' or '.git' component, leads
    through a symlinked directory or resolves outside the repository; nothing is opened then.
    Every file list hangover reads (inventory, issue selection, scope, Rust analysis) comes from here.
    """
    names: list[list[str]] = []
    if listing is not None:
        for raw in listing.split("\0"):
            if not raw or raw.endswith("/"):
                continue  # `--others` lists an untracked nested repository as `dir/`: not a file.
            parts = raw.split("/")
            if raw.startswith("/") or any(part in {"", ".", ".."} or part.lower() == ".git" for part in parts):
                raise RepositoryRefusal(
                    f"refusing the repository's file list: git lists {raw!r}, a path git never "
                    "checks out (absolute, or with an empty, '.', '..' or '.git' component)")
            names.append(parts)
    else:
        for root, directories, files in os.walk(repo):
            directories[:] = [name for name in directories
                              if name not in IGNORED_DIRS and name.lower() != ".git"]
            names += [Path(root, name).relative_to(repo).as_posix().split("/") for name in files]
    top = repo.resolve()
    real_directories: set[Path] = set()
    found = set()
    static = no_execute_git_active()
    for parts in names:
        if any(part in IGNORED_DIRS or part.lower() == ".git" for part in parts):
            continue
        # The containment rule (`contained_path`) for the directories on the way; a listed name that
        # is itself a symlink is skipped, not refused: git records symlinks, and hangover reads none.
        link = _symlinked_component(top, parts[:-1], real_directories)
        if link is not None:
            raise RepositoryRefusal(
                f"refusing the repository's file list: {'/'.join(parts)!r} leads through "
                f"{repo / link.relative_to(top)}, which is a symlink")
        candidate = repo.joinpath(*parts)
        try:
            info = os.lstat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if not candidate.resolve().is_relative_to(top):
            raise RepositoryRefusal(
                f"refusing the repository's file list: {'/'.join(parts)!r} resolves outside "
                f"the repository ({candidate.resolve()})")
        if static and info.st_nlink > 1:
            # Git never checks out a hard link, so one came from somewhere else (an archive, a copy)
            # and may share its inode with a file outside the checkout: static mode skips it.
            if candidate not in _HARDLINK_NOTICES:
                _HARDLINK_NOTICES.add(candidate)
                progress(f"note: skipping {'/'.join(parts)} under --no-checks: it is a hard link "
                         f"({info.st_nlink} names for one file), which a git checkout never makes")
            continue
        found.add(candidate)
    return sorted(found)


def repository_files(repo: Path) -> list[Path]:
    """Tracked and untracked, unignored regular files (`checked_files`); raises RepositoryRefusal."""
    listing = None
    if is_git_repo(repo):
        result = git(repo, *LISTED_FILES_ARGS)
        if result.returncode == 0:
            listing = result.stdout
    return checked_files(repo, listing)


def _line_count(repo: Path, path: Path) -> int | None:
    """Lines in a listed source file, None for a binary one or one the containment rule refuses."""
    try:
        handle = open_repo_file(repo, path.relative_to(repo).as_posix(), purpose="source file")
    except (RepositoryRefusal, ValueError, OSError):
        return None
    if handle is None:
        return None
    try:
        with handle:
            chunk = handle.read(4096)
            if b"\0" in chunk:
                return None
            lines = 0
            last = b""
            while chunk:
                lines += chunk.count(b"\n")
                last = chunk[-1:]
                chunk = handle.read(64 * 1024)
            return lines + bool(last and last != b"\n")
    except OSError:
        return None


def _relative(repo: Path, values: Iterable[Path]) -> list[str]:
    return [str(path.relative_to(repo)) for path in values]


def inventory(repo: Path) -> dict[str, Any]:
    files = repository_files(repo)
    suffixes: Counter[str] = Counter()
    source_lines: Counter[str] = Counter()
    largest: list[tuple[int, str]] = []
    docs: list[Path] = []
    instructions: list[Path] = []
    manifests: list[Path] = []
    risk_paths: set[str] = set()
    generated_present: set[str] = set()

    for path in files:
        relative = path.relative_to(repo)
        suffix = path.suffix.lower() or "[none]"
        suffixes[suffix] += 1
        if path.name in DOC_NAMES or ("docs" in relative.parts and suffix == ".md"):
            docs.append(path)
        if path.name in {"AGENTS.md", "CLAUDE.md"}:
            instructions.append(path)
        if path.name in {
            "Cargo.toml",
            "Makefile",
            "package.json",
            "pnpm-workspace.yaml",
            "pyproject.toml",
            "tsconfig.json",
        }:
            manifests.append(path)
        if any(part.lower() in RISK_PARTS for part in relative.parts):
            risk_paths.add(str(relative.parts[0]))
        lines = _line_count(repo, path) if suffix in SOURCE_SUFFIXES else None
        if lines is not None:
            source_lines[suffix] += lines
            largest.append((lines, str(relative)))

    for name in IGNORED_DIRS:
        if os.path.lexists(repo / name):  # Presence only: a link is not followed.
            generated_present.add(name)

    package = read_package(repo)
    dependencies = {
        **package.get("dependencies", {}),
        **package.get("devDependencies", {}),
    }
    framework_names = [
        name
        for name in (
            "@angular/core",
            "astro",
            "express",
            "next",
            "nuxt",
            "react",
            "remix",
            "svelte",
            "vue",
        )
        if name in dependencies
    ]
    public_surface = {
        key: package[key]
        for key in ("bin", "exports", "main", "module", "types")
        if key in package
    }
    return {
        "file_count": len(files),
        "files_by_suffix": dict(suffixes.most_common()),
        "source_lines_by_suffix": dict(source_lines.most_common()),
        "largest_source_files": [
            {"path": path, "lines": lines}
            for lines, path in sorted(largest, reverse=True)[:20]
        ],
        "instructions": _relative(repo, instructions),
        "docs": _relative(repo, docs[:80]),
        "manifests": _relative(repo, manifests),
        "frameworks": framework_names,
        "public_surface": public_surface,
        "risk_paths": sorted(risk_paths),
        "generated_or_vendor_present": sorted(generated_present),
        "typescript": contained_file(repo, "tsconfig.json")
        or bool(suffixes.keys() & TYPESCRIPT_SUFFIXES),
        "javascript": bool(suffixes.keys() & JAVASCRIPT_SUFFIXES),
        "rust": contained_file(repo, "Cargo.toml") and ".rs" in suffixes,
        "has_node_modules": _contained_directory(repo, "node_modules"),
    }


def read_package(repo: Path, directory: str = "") -> dict[str, Any]:
    """`directory`/package.json (the repository's own by default) as a dict, {} when absent or not
    JSON. Raises RepositoryRefusal when the containment rule refuses the path (a symlinked or
    external manifest), so a field from outside the checkout is never stored."""
    relative = f"{directory.rstrip('/')}/package.json" if directory else "package.json"
    try:
        text = read_repo_file(repo, relative, purpose=f"package manifest {relative!r}")
        value = json.loads(text) if text is not None else {}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _package_manager(repo: Path, package: dict[str, Any]) -> str:
    declared = str(package.get("packageManager", "")).split("@", 1)[0]
    if declared in {"bun", "npm", "pnpm", "yarn"}:
        return declared
    if contained_file(repo, "pnpm-lock.yaml"):
        return "pnpm"
    if contained_file(repo, "yarn.lock"):
        return "yarn"
    if contained_file(repo, "bun.lock") or contained_file(repo, "bun.lockb"):
        return "bun"
    return "npm"


COMBINED_GATE_SCRIPTS = (
    "verify",
    "gate",
    "check",
    "ci:quality",
    "ci",
    "quality",
    "check:all",
    "verify:all",
    "ci:check",
    "ci:verify",
)
# Package scripts that map to a canonical check name; other stages keep their
# own (sanitized) script name so two test stages cannot collide.
CANONICAL_STAGE_NAMES = {
    "format": ("fmt:check", "format:check", "prettier:check", "lint:format"),
    "lint": ("lint",),
    "typecheck": ("typecheck", "type-check", "check:types"),
    "build": ("build",),
    "test": ("test", "test:unit"),
    "security": ("security", "audit:security"),
}
# Static stages are marked narrow: `verify --affected` runs them.
CHEAP_STAGES = ("format", "lint", "typecheck")
# Order of separately discovered scripts (not a gate chain: they never stop early).
SEPARATE_ORDER = ("test", "typecheck", "lint", "format", "build", "security")
STAGE_RUNNER_BUILTINS = {
    "add", "audit", "dlx", "exec", "i", "install", "link", "publish", "remove", "rm", "x",
}
GENERIC_STAGE_HEADS = {"node", "python3", "python", "npx", "bunx", "bash", "sh"}
SHELL_METACHARACTERS = re.compile(r"[;|<>()$`{}*?\[~\\\n]")


def _stage_name(script: str) -> str:
    for canonical, options in CANONICAL_STAGE_NAMES.items():
        if script in options:
            return canonical
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", script).strip("-") or "stage"


def _runner_script(tokens: list[str], scripts: dict[str, Any]) -> str | None:
    """The package script a `<manager> run X` style command names, if it is exactly that."""
    if len(tokens) < 2 or tokens[0] not in {"npm", "pnpm", "yarn", "bun"}:
        return None
    manager, rest = tokens[0], tokens[1:]
    if rest[0] in {"run", "run-script"} and len(rest) == 2:
        script = rest[1]
    elif rest == ["test"] or (manager == "npm" and rest == ["t"]):
        script = "test"
    elif manager in {"pnpm", "yarn"} and len(rest) == 1 and rest[0] not in STAGE_RUNNER_BUILTINS:
        script = rest[0]
    else:
        return None
    return script if isinstance(scripts.get(script), str) else None


def _stage_from_piece(
    piece: str, scripts: dict[str, Any], *, generic: bool
) -> dict[str, Any] | None:
    """One simple command as a stage, or None when it cannot be read reliably.

    Automatic discovery passes generic=False: only package-script invocations
    through the package manager qualify. A proposed stage list read from a gate
    shell script also admits node/python/shell-script/npx commands.
    """
    if SHELL_METACHARACTERS.search(piece):
        return None
    try:
        tokens = shlex.split(piece)
    except ValueError:
        return None
    if not tokens or "=" in tokens[0]:
        return None
    script = _runner_script(tokens, scripts)
    if script:
        # Keep the gate's own runner and tokens exactly (`npm test` stays `npm test`).
        return {"name": _stage_name(script), "command": tokens, "script": script}
    head = tokens[0]
    if generic and (head in GENERIC_STAGE_HEADS or head.startswith("./")):
        arguments = [token for token in tokens[1:] if not token.startswith("-")]
        subject = Path(head if head.startswith("./") or not arguments else arguments[0]).name
        name = re.sub(r"[^A-Za-z0-9_.-]+", "-", Path(subject).stem).strip("-")
        if not name:
            return None
        return {"name": name, "command": tokens, "script": name}
    return None


def _pieces(text: str) -> list[str] | None:
    pieces = [piece.strip() for piece in text.split("&&")]
    return pieces if all(pieces) else None


def _gate_script_target(tokens: list[str]) -> str | None:
    if tokens and tokens[0] in {"bash", "sh"} and len(tokens) == 2:
        return tokens[1]
    if len(tokens) == 1 and tokens[0].startswith(("./", "scripts/")):
        return tokens[0]
    return None


def _gate_script_text(repo: Path, target: str) -> str | None:
    """The text of the gate script package.json names, or None when it cannot be read as text.

    Raises RepositoryRefusal, before opening anything, when the path reaches outside the repository
    (`../shared/gate.sh`, an absolute path) or through a symlink: none of its lines may be read,
    hashed or printed."""
    try:
        return read_repo_file(repo, target, purpose=f"gate script {target!r} (named in package.json)")
    except (OSError, UnicodeDecodeError):
        return None


def _definition_digest(repo: Path, scripts: dict[str, Any], combined: str) -> str:
    """A hash of everything the stage split was read from: the script text and any gate script file."""
    value = scripts.get(combined)
    content = None
    if isinstance(value, str):
        try:
            target = _gate_script_target(shlex.split(value.strip()))
        except ValueError:
            target = None
        if target is not None:
            content = _gate_script_text(repo, target)
    return sha256(json.dumps([value, content]).encode()).hexdigest()


def _gate_script_lines(repo: Path, tokens: list[str]) -> list[str] | None:
    """The command lines of a shell gate script, or None when the file is not simple."""
    target = _gate_script_target(tokens)
    if target is None:
        return None
    resolved = contained_path(repo, target, purpose=f"gate script {target!r} (named in package.json)")
    text = _gate_script_text(repo, target)
    if text is None:
        return None
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"set -[A-Za-z]+( -o pipefail| pipefail)?|set -o pipefail", line):
            continue
        if re.match(r"(echo|printf)\s", line) and not re.search(r"[;|<>`&]|\$\(", line):
            continue
        if re.fullmatch(r'cd "\$\(dirname "\$(0|\{BASH_SOURCE\[0\]\})"\)/\.\."', line):
            # Only a script one directory below the root, so the stages run where hangover runs them.
            if resolved.parent.parent != repo.resolve():
                return None
            continue
        lines.append(line)
    return lines


def _build_stages(
    stages: list[dict[str, Any]], combined: str, definition: str, *, adopted: bool
) -> list[dict[str, Any]] | None:
    """Checks for the stages, in the gate's declared order; None when two stages share a name."""
    seen: set[str] = set()
    for stage in stages:
        name = stage["name"]
        if name in seen or not SAFE_CHECK_NAME.fullmatch(name):
            # A repeated stage cannot be told apart from its twin: do not guess.
            return None
        seen.add(name)
    result = []
    for stage in stages:
        cheap = stage["name"] in CHEAP_STAGES
        item: dict[str, Any] = {
            "name": stage["name"],
            "command": stage["command"],
            "timeout_seconds": 900 if cheap else 1800,
            "stage_of": combined,
        }
        if adopted:
            item["adopted_from"] = {"script": combined, "sha256": definition}
        else:
            item["definition_sha256"] = definition
        if cheap:
            item["narrow"] = True
        result.append(item)
    return result


def _read_pieces(
    repo: Path, scripts: dict[str, Any], combined: str, *, from_file: bool
) -> list[str] | None:
    """The `&&` pieces of a combined script: its own text, or the lines of the gate script file."""
    value = scripts.get(combined)
    if not isinstance(value, str):
        return None
    if f"pre{combined}" in scripts or f"post{combined}" in scripts:
        # npm runs these hooks around the combined script; splitting would drop them.
        return None
    pieces = _pieces(value)
    if pieces is None:
        return None
    if not from_file:
        return pieces
    if len(pieces) != 1:
        return None
    try:
        tokens = shlex.split(pieces[0])
    except ValueError:
        return None
    lines = _gate_script_lines(repo, tokens)
    if lines is None:
        return None
    result: list[str] = []
    for line in lines:
        parts = _pieces(line)
        if parts is None:
            return None
        result.extend(parts)
    return result


def _gate_stages(
    repo: Path, scripts: dict[str, Any], combined: str, *, from_file: bool
) -> list[dict[str, Any]] | None:
    """Ordered stages of a combined gate, or None when they cannot be read reliably.

    Automatic discovery (from_file=False) accepts only a pure `&&` chain of
    package-script invocations through the package manager. A gate shell script
    is read only to *propose* stages (from_file=True); the operator adopts them.
    """
    pieces = _read_pieces(repo, scripts, combined, from_file=from_file)
    if pieces is None:
        return None
    stages = []
    for piece in pieces:
        stage = _stage_from_piece(piece, scripts, generic=from_file)
        if stage is None:
            return None
        stages.append(stage)
    if len(stages) < 2:
        return None
    return _build_stages(stages, combined, _definition_digest(repo, scripts, combined), adopted=from_file)


def propose_gate_stages(repo: Path) -> dict[str, Any] | None:
    """Stages read from a gate shell script, for the operator to adopt; never applied automatically."""
    package = read_package(repo)
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    combined = next((name for name in COMBINED_GATE_SCRIPTS if name in scripts), None)
    if not combined:
        return None
    try:
        target = _gate_script_target(shlex.split(str(scripts[combined]).strip()))
    except ValueError:
        return None
    stages = _gate_stages(repo, scripts, combined, from_file=True)
    if stages:
        return {"script": combined, "file": target, "checks": stages}
    return _reference_proposal(repo, scripts, combined, target)


PLAIN_PREFIX = re.compile(r"[A-Za-z_][\w-]*(?:\s+[\w:.-]+)*")
# A gate step that is not a package script: a shell script, a cargo subcommand, or a
# package-manager exec of a tool (`run rust bash scripts/gate-rust.sh`, `cargo clippy ...`).
COMMAND_REFERENCE = re.compile(
    r"(?:^|[\s;&|(])((?:bash|sh)\s+([\w./-]+\.sh)\b[^;&|#\n]*|cargo\s+([a-z][\w-]*)\b[^;&|#\n]*"
    r"|(?:pnpm|npm)\s+exec\s+([\w@./-]+)[^;&|#\n]*|npx\s+([\w@./-]+)[^;&|#\n]*)")
SHELL_KEYWORDS = {"if", "then", "elif", "else", "while", "until", "for", "do", "case", "exec", "time", "not"}
PACKAGE_REFERENCE = re.compile(r"(?:^|[\s;&|(])((?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([A-Za-z0-9:_.-]+)\b[^;&|#\n]*)")


def _workspace_has_script(repo: Path, tokens: list[str], script: str) -> bool:
    """`npm run build --workspace apps/web` names a script of that workspace's own package.json."""
    for index, token in enumerate(tokens):
        value = None
        if token in ("--workspace", "-w", "--filter") and index + 1 < len(tokens):
            value = tokens[index + 1]
        elif token.startswith(("--workspace=", "--filter=")):
            value = token.split("=", 1)[1]
        if value:
            try:
                package = read_package(repo, value)
            except RepositoryRefusal:
                continue  # A workspace outside the repository, or through a link: not read, no stage.
            if isinstance(package.get("scripts"), dict) and script in package["scripts"]:
                return True
    return False


def _reference_proposal(
    repo: Path, scripts: dict[str, Any], combined: str, target: str | None
) -> dict[str, Any] | None:
    """A weaker proposal for a gate script that is not a plain command list (functions, pins, checks).

    Its package-script invocations, in order of appearance, become the proposed stages; every
    other non-comment line is listed as `uncovered`, so the operator sees what adopting drops.
    """
    if not target:
        return None
    text = _gate_script_text(repo, target)
    if text is None:
        return None
    lines = text.splitlines()
    stages: list[dict[str, Any]] = []
    uncovered: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PACKAGE_REFERENCE.search(line)
        script = match.group(2) if match else None
        # Only an unconditional call: plain words before it (a wrapper such as `run_stage name`),
        # nothing after it. `if ...; then npm run lint; fi` or `a && npm test` stays uncovered.
        prefix = line[:match.start(1)].strip() if match else ""
        tail = line[match.end(1):].strip() if match else ""
        plain = (not prefix or (PLAIN_PREFIX.fullmatch(prefix) and prefix.split()[0] not in SHELL_KEYWORDS)) and (
            not tail or tail.startswith("#"))
        invocation = match.group(1).strip() if match else ""
        try:
            tokens = shlex.split(invocation)
        except ValueError:
            tokens = []
        if script and plain and (script in scripts or _workspace_has_script(repo, tokens, script)) and script != combined:
            if not tokens or SHELL_METACHARACTERS.search(invocation):
                tokens = [invocation.split()[0], "run", script]
            stages.append({"name": _stage_name(script), "command": tokens, "script": script})
        elif (stage := _command_stage(repo, line, target)) is not None:
            stages.append(stage)
        else:
            uncovered.append(line)
    if len(stages) < 2:
        return None
    checks = _build_stages(stages, combined, _definition_digest(repo, scripts, combined), adopted=True)
    if not checks:
        return None
    return {"script": combined, "file": target, "checks": checks, "kind": "references", "uncovered": uncovered}


def _command_stage(repo: Path, line: str, gate_file: str) -> dict[str, Any] | None:
    """A non-package gate step (shell script, cargo, tool exec) read as a stage, or None.

    Same bar as a package reference: an unconditional line, plain words before the
    command (a wrapper such as `run <name>`, whose last word names the stage), no shell
    syntax inside it, and a shell script that exists in the repository.
    """
    match = COMMAND_REFERENCE.search(line)
    if not match:
        return None
    invocation = match.group(1).strip()
    prefix = line[:match.start(1)].strip()
    if prefix and (not PLAIN_PREFIX.fullmatch(prefix) or prefix.split()[0] in SHELL_KEYWORDS):
        return None
    if SHELL_METACHARACTERS.search(invocation):
        return None
    try:
        tokens = shlex.split(invocation)
    except ValueError:
        return None
    script, cargo, tool = match.group(2), match.group(3), match.group(4) or match.group(5)
    words = prefix.split()
    if tool and len(words) < 2:
        # A bare tool exec is as often a helper inside a conditional as a gate step; only a
        # named wrapper line (`run check pnpm exec biome ci .`) reads as a stage.
        return None
    if script and (script == gate_file or not contained_file(repo, script)):
        return None
    derived = Path(script).stem if script else (f"cargo-{cargo}" if cargo else Path(str(tool)).name)
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", words[-1] if len(words) >= 2 else derived).strip("-")
    return {"name": name or "stage", "command": tokens, "script": name or "stage"} if name else None


def runs_gate(check: dict[str, Any], proposal: dict[str, Any]) -> bool:
    """Whether a configured check is the command that runs the proposed gate (not another check)."""
    command = check.get("command")
    if not isinstance(command, list) or not command or check.get("stage_of"):
        return False
    script, target = proposal["script"], proposal.get("file")
    if command[0] in {"npm", "pnpm", "yarn", "bun"} and command[1:] in (
        ["run", script], ["run-script", script], [script],
    ):
        return True
    return bool(target) and command[-1] == target and command[0] in {"bash", "sh", target}


def adopted_drift(repo: Path, checks: list[dict[str, Any]]) -> list[str]:
    """Gate scripts whose definition changed since their stages were adopted."""
    package = read_package(repo)
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    changed: dict[str, None] = {}
    for check in checks:
        adopted = check.get("adopted_from")
        if isinstance(adopted, dict) and adopted.get("sha256") != _definition_digest(
            repo, scripts, str(adopted.get("script"))
        ):
            changed[str(adopted.get("script"))] = None
    return list(changed)


def stage_drift(repo: Path, checks: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """Freshly discovered checks when the gate a saved stage list came from has changed, else None."""
    staged = [check for check in checks if check.get("stage_of") and not check.get("adopted_from")]
    if not staged:
        return None
    groups = {check["stage_of"] for check in staged}

    def signature(items: list[dict[str, Any]]) -> list[Any]:
        return [
            [item.get("name"), item.get("command"), item.get("stage_of"), item.get("definition_sha256")]
            for item in items if item.get("stage_of") in groups and not item.get("adopted_from")
        ]

    fresh = discover_checks(repo)
    return None if signature(fresh) == signature(staged) else fresh


def discover_checks(repo: Path) -> list[dict[str, Any]]:
    package = read_package(repo)
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    if scripts:
        manager = _package_manager(repo, package)
        combined = next((name for name in COMBINED_GATE_SCRIPTS if name in scripts), None)
        if combined:
            staged = _gate_stages(repo, scripts, combined, from_file=False)
            if staged:
                return staged
        names: list[tuple[str, str]] = []
        if combined:
            names.append(("verify", combined))
        else:
            for category in SEPARATE_ORDER:
                selected = next((name for name in CANONICAL_STAGE_NAMES[category] if name in scripts), None)
                if selected:
                    names.append((category, selected))
        if names:
            checks = []
            for category, script in names:
                check = {
                    "name": category,
                    "command": [manager, "run", script],
                    "timeout_seconds": 1800 if combined else 900,
                }
                if not combined and category in CHEAP_STAGES:
                    check["narrow"] = True
                checks.append(check)
            return checks

    text = read_repo_file(repo, "Makefile", purpose="Makefile", errors="replace") if shutil.which("make") else None
    if text is not None:
        targets = {
            match.group(1)
            for match in re.finditer(r"^([A-Za-z0-9_.-]+)\s*:(?!=)", text, re.MULTILINE)
        }
        selected = next((name for name in ("verify", "gate", "check", "test") if name in targets), None)
        if selected:
            return [
                {"name": selected, "command": ["make", selected], "timeout_seconds": 900}
            ]
    if contained_file(repo, "Cargo.toml") and shutil.which("cargo"):
        return cargo_checks()
    if contained_file(repo, "pyproject.toml") and _contained_directory(repo, "tests"):
        return [
            {
                "name": "test",
                "command": ["python3", "-m", "pytest"],
                "timeout_seconds": 900,
            }
        ]
    return []


def cargo_checks() -> list[dict[str, Any]]:
    """A Cargo workspace's own gate: formatting and clippy (warnings denied) are narrow, tests are not."""
    return [
        {"name": "fmt", "command": ["cargo", "fmt", "--all", "--check"], "timeout_seconds": 900, "narrow": True},
        {"name": "clippy", "command": ["cargo", "clippy", "--workspace", "--all-targets", "--all-features",
                                       "--", "-D", "warnings"], "timeout_seconds": 3600, "narrow": True},
        {"name": "test", "command": ["cargo", "test", "--workspace", "--all-features"], "timeout_seconds": 3600},
    ]


def captured_text(path: Path, limit: int = MAX_CAPTURE_BYTES) -> str:
    """Read a bounded capture with subprocess text-mode newline semantics."""
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"output exceeds the {limit}-byte parsing limit: {path}")
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def diagnostic_text(stdout: str, stderr: str, names: Iterable[str] = ()) -> str:
    """A bounded, terminal-safe reason without forwarded environment values."""
    message = stderr or stdout
    try:
        value = json.loads(stdout)
        error = value.get("error") if isinstance(value, dict) else None
        if isinstance(error, dict) and isinstance(error.get("message"), str):
            message = error["message"]
    except ValueError:
        pass
    for name in names:
        value = os.environ.get(name)
        if value:
            message = message.replace(value, f"<{name}>")
    first = next((line.strip() for line in ANSI.sub("", message).splitlines() if line.strip()), "no diagnostic")
    return "".join(character for character in first if character.isprintable())[:600]


def run_command(
    command: list[str],
    repo: Path,
    timeout_seconds: int,
    log_path: Path,
    *,
    progress_name: str | None = None,
    quiet: bool = False,
    max_output_bytes: int = MAX_CAPTURE_BYTES,
) -> dict[str, Any]:
    if progress_name:
        progress(f"{progress_name}: running ({' '.join(command)})", quiet=quiet)
        progress(f"{progress_name}: log {log_path}", quiet=quiet)
    started = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = log_path.with_suffix(".stdout")
    stderr_path = log_path.with_suffix(".stderr")
    capture = None
    try:
        # Native repository gates retain their normal environment. Only the
        # analyzer/reviewer adapters use the explicitly hardened environment.
        capture = run_logged(command, cwd=repo, env=None, stdout_path=stdout_path, stderr_path=stderr_path,
                             timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes)
        exit_code = capture.exit_code
        if capture.status != "exited":
            status = capture.status
        elif exit_code is not None and exit_code < 0:
            status = "error"
        else:
            status = "passed" if exit_code == 0 else "failed"
        stdout_tail = ANSI.sub("", capture.stdout_tail)[-1200:]
        stderr_tail = ANSI.sub("", capture.stderr_tail or "")[-1200:]
    except OSError as exc:
        exit_code = None
        stdout_tail = ""
        stderr_tail = str(exc)[-1200:]
        status = "missing" if isinstance(exc, FileNotFoundError) else "error"
        with stderr_path.open("ab") as handle:
            handle.write((str(exc) + "\n").encode(errors="replace"))
    duration = round(time.monotonic() - started, 3)
    with log_path.open("wb") as handle:
        handle.write(("$ " + " ".join(command) + "\n").encode(errors="backslashreplace"))
        for label, artifact in (("stdout", stdout_path), ("stderr", stderr_path)):
            handle.write(f"\n[{label}]\n".encode())
            if artifact.is_file():
                with artifact.open("rb") as stream:
                    shutil.copyfileobj(stream, handle, length=128 * 1024)
    output_hash = None
    output_bytes = 0
    if status in {"passed", "failed"}:
        # Preserve the existing ANSI-normalized fingerprint contract. The
        # captured streams have a combined bound enforced by run_logged.
        normalized = ANSI.sub("", captured_text(stdout_path, max_output_bytes) + "\n"
                              + captured_text(stderr_path, max_output_bytes))
        output_hash = sha256(normalized.encode()).hexdigest()
        output_bytes = len(normalized.strip().encode())
    result = {
        "command": command,
        "status": status,
        "exit_code": exit_code,
        "duration_seconds": duration,
        "output_sha256": output_hash,
        "output_bytes": output_bytes,
        "log": str(log_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "capture_truncated": capture.truncated if capture else False,
    }
    if progress_name:
        progress_result(
            progress_name,
            result,
            quiet=quiet,
            success_status="passed",
            success_label="passed",
            timeout_seconds=timeout_seconds,
        )
    return result


def progress(message: str, *, quiet: bool = False) -> None:
    if not quiet:
        print(message, file=sys.stderr, flush=True)


def progress_result(
    name: str,
    result: dict[str, Any],
    *,
    quiet: bool = False,
    success_status: str,
    success_label: str,
    timeout_seconds: int | None = None,
) -> None:
    duration = float(result.get("duration_seconds", 0))
    status = result.get("status")
    if status == success_status:
        detail = f"{success_label} in {duration:.1f}s"
    elif status == "timeout":
        elapsed = timeout_seconds if timeout_seconds is not None else round(duration, 1)
        detail = f"timed out after {elapsed}s"
    elif status == "failed" and result.get("exit_code") is not None:
        detail = f"failed (exit {result['exit_code']}) in {duration:.1f}s"
    elif status == "failed":
        detail = f"failed in {duration:.1f}s"
    else:
        detail = f"failed ({status}) in {duration:.1f}s"
    progress(f"{name}: {detail}", quiet=quiet)


def failure_excerpt(result: dict[str, Any], lines: int = 15) -> list[str]:
    """The last non-empty output lines a failed command left, terminal-safe."""
    text = ANSI.sub("", f"{result.get('stdout_tail') or ''}\n{result.get('stderr_tail') or ''}")
    kept = [
        "".join(character for character in line.rstrip() if character.isprintable() or character == "\t")
        for line in text.splitlines()
        if line.strip()
    ]
    return kept[-lines:]


def run_checks(
    repo: Path,
    checks: list[dict[str, Any]],
    run_dir: Path,
    *,
    quiet: bool = False,
    stop_when: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run the checks in order; `stop_when(result)` true skips the rest as not_run."""
    prepared = []
    names = set()
    for check in checks:
        name = str(check["name"])
        if not SAFE_CHECK_NAME.fullmatch(name):
            raise RuntimeError(
                f"check name {name!r} may contain only letters, numbers, dot, dash, and underscore"
            )
        if name in names:
            raise RuntimeError("check names must be unique so evidence cannot be overwritten")
        names.add(name)
        command = check.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(part, str) and part for part in command
        ):
            raise RuntimeError(f"check {name!r} must have a non-empty string-array command")
        value = check.get("timeout_seconds", 900)
        try:
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError
            timeout = int(value)
            if timeout <= 0:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"check {name!r} timeout_seconds must be a positive integer") from exc
        prepared.append((name, command, timeout))
    results = []
    stopped_at: str | None = None
    for name, command, timeout in prepared:
        log_path = run_dir / "checks" / f"{name}.log"
        if stopped_at is not None:
            results.append(
                {
                    "name": name,
                    "command": command,
                    "status": "not_run",
                    "exit_code": None,
                    "skipped_after": stopped_at,
                    "log": None,
                }
            )
            continue
        result = {
            "name": name,
            **run_command(
                command,
                repo,
                timeout,
                log_path,
                progress_name=f"check {name}",
                quiet=quiet,
            ),
        }
        results.append(result)
        if result["status"] != "passed":
            for line in failure_excerpt(result):
                progress(f"check {name}:   | {line}", quiet=quiet)
        if stop_when is not None and stop_when(result):
            stopped_at = name
            remaining = [item[0] for item in prepared[len(results):]]
            if remaining:
                progress(
                    f"check {name}: stopping here; not run: {', '.join(remaining)}",
                    quiet=quiet,
                )
    return results


def compare_checks(
    baseline: list[dict[str, Any]], current: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    original = {item["name"]: item for item in baseline}
    comparison = []
    for item in current:
        prior = original.get(item["name"])
        if item["status"] == "not_run":
            classification = "not_run"
        elif not prior:
            classification = "new_pass" if item["status"] == "passed" else "unbaselined_failure"
        elif prior.get("command") != item.get("command"):
            classification = "incomparable"
        elif item["status"] == "passed" and prior["status"] == "passed":
            classification = "unchanged_pass"
        elif item["status"] == "passed":
            classification = "improved"
        elif prior["status"] != "passed":
            # A nonzero exit alone cannot distinguish old debt from a new failure.
            unchanged_failure = (
                prior["status"] == item["status"] == "failed"
                and prior.get("exit_code") == item.get("exit_code")
                and bool(prior.get("output_sha256"))
                and prior["output_sha256"] == item.get("output_sha256")
                # Identical empty or near-empty output proves nothing about identical debt.
                and prior.get("output_bytes", 0) >= MIN_FAILURE_OUTPUT_BYTES
            )
            classification = "pre_existing_failure" if unchanged_failure else "incomparable"
        else:
            classification = "regression"
        comparison.append({"name": item["name"], "classification": classification})
    current_names = {item["name"] for item in current}
    comparison.extend(
        {"name": name, "classification": "incomparable", "reason": "check removed"}
        for name in original if name not in current_names
    )
    return comparison


def update_local_exclude(repo: Path) -> Path | None:
    """Add hangover's state directories to the checkout's `.git/info/exclude`; the path, or None.

    Only into the checkout's own git directory: when git's common directory is not `<repo>/.git` (a
    linked worktree, a submodule, a gitfile or `commondir` naming another repository's) nothing is
    written, since that exclude file belongs to another checkout. The file is opened without following
    a link in any component; a symlinked, hard-linked or non-regular one is refused."""
    if not is_git_repo(repo):
        return None
    common_result = git(repo, "rev-parse", "--git-common-dir")
    if common_result.returncode != 0:
        return None
    common = Path(common_result.stdout.strip())
    if not common.is_absolute():
        common = repo / common
    top = repo.resolve()
    dot_git = top / ".git"
    if os.path.islink(dot_git) or not dot_git.is_dir() or common.resolve() != dot_git:
        return None
    exclude = dot_git / "info" / "exclude"

    def refuse(reason: str) -> RuntimeError:
        return RepositoryRefusal(f"refusing Git exclude path outside the Git directory: {exclude} {reason}")

    info = dot_git / "info"
    if not os.path.lexists(info):
        info.mkdir()
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = _open_beneath(top, [".git", "info", "exclude"], flags)
    except OSError as exc:
        if _link_refusal(top, [".git", "info", "exclude"], exc):
            raise refuse("is or passes through a symlink") from exc
        raise
    with os.fdopen(descriptor, "r+b") as handle:
        status = os.fstat(handle.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_nlink > 1:
            raise refuse("is not a regular file with one name (a FIFO, device or hard link)")
        existing = handle.read(MAX_REPO_FILE_BYTES).decode("utf-8", errors="replace")
        entries = ["/.hangover/", "/.fallow/"]
        missing = [entry for entry in entries if entry not in existing.splitlines()]
        if missing:
            prefix = "" if not existing or existing.endswith("\n") else "\n"
            handle.write((prefix + "# Local analyzer state\n" + "\n".join(missing) + "\n").encode())
    return exclude


# --------------------------------------------------------------------------- state ownership
#
# Everything hangover reads from `.hangover/` (config.json's checks and review runner, command and env;
# state.json's baseline, cards and waivers; run snapshots; gate proofs) is trusted as hangover's own.
# A checkout can ship that directory: tracked in git, or inside an archive. Two rules keep it from
# choosing anything:
#
# 1. In every mode, a `.hangover/` path the repository tracks is refused. hangover excludes `.hangover/`
#    locally (`update_local_exclude`) and never commits it, so a tracked one came with the checkout.
# 2. In static mode (`scan`/`run --no-checks`), an existing `.hangover/` is used only when its owner
#    marker binds it to this directory: the marker records the repository path and the device and
#    inode of `.hangover/` itself, which an archive cannot know in advance. `hangover init` writes the
#    marker when it creates the directory, and adopts an existing one (the operator's assertion that
#    it is theirs).
STATE_OWNER_FILE = "owner"


def _state_identity(root: Path) -> dict[str, Any]:
    info = os.lstat(root)
    return {"tool": "hangover", "repo": str(root.parent), "device": info.st_dev, "inode": info.st_ino}


def mark_state_owner(repo: Path) -> Path:
    """Bind `.hangover/` to this directory (`hangover init`): what static mode checks before using it."""
    root = paths(repo)["root"]
    marker = root / STATE_OWNER_FILE
    write_json(marker, {**_state_identity(root),
                        "note": "hangover created or adopted this directory here; a copy elsewhere is not trusted "
                                "by --no-checks until `hangover init` adopts it"})
    return marker


def state_owned(repo: Path) -> bool:
    """Whether `.hangover/` carries an owner marker written for this very directory."""
    root = repo.resolve() / STATE_DIR
    marker = root / STATE_OWNER_FILE
    if root.is_symlink() or not root.is_dir() or marker.is_symlink() or not marker.is_file():
        return False
    try:
        # No-follow, not a FIFO, one name only (a hard link may be a file outside: RepositoryRefusal).
        text = read_repo_file(repo, f"{STATE_DIR}/{STATE_OWNER_FILE}", purpose="hangover state owner marker",
                              limit=64 * 1024)
        recorded = json.loads(text) if text is not None else None
    except (OSError, ValueError):
        return False
    if not isinstance(recorded, dict):
        return False
    identity = _state_identity(root)
    if recorded.get("tool") != "hangover":
        return False
    return all(recorded.get(key) == value for key, value in identity.items() if key != "tool")


def tracked_state(repo: Path) -> list[str]:
    """The paths under `.hangover/` (any letter case) that the repository's index tracks."""
    if not is_git_repo(repo):
        return []
    result = git(repo, "ls-files", "-z", "--cached", "--", f":(icase,literal){STATE_DIR}")
    if result.returncode != 0:
        raise RepositoryRefusal(f"could not list tracked files under {STATE_DIR}/ (git ls-files exited {result.returncode})")
    return [name for name in result.stdout.split("\0") if name]


def refuse_foreign_state(repo: Path, *, static: bool) -> None:
    """Raise RepositoryRefusal when `.hangover/` came with the checkout rather than from hangover.

    Tracked state is refused in every mode; in static mode an existing `.hangover/` without this
    directory's owner marker is refused too, so nothing the checkout ships there can select a
    review command, runner, environment or check."""
    tracked = tracked_state(repo)
    if tracked:
        shown = ", ".join(tracked[:3]) + (f", +{len(tracked) - 3} more" if len(tracked) > 3 else "")
        raise RepositoryRefusal(
            f"refusing {STATE_DIR}/: the repository tracks files there ({shown}). hangover keeps its own "
            f"campaign state in {STATE_DIR}/ and never commits it, so tracked state came with the checkout and "
            f"could choose hangover's checks, review command or environment. Remove it from the index "
            f"(`git rm -r --cached {STATE_DIR}`) and delete the directory if you did not create it")
    root = repo.resolve() / STATE_DIR
    if static and os.path.lexists(root) and not state_owned(repo):
        raise RepositoryRefusal(
            f"refusing {root} under --no-checks: hangover did not create it in this directory (no owner marker "
            f"for it), so it may have come with the checkout and could choose the review command or "
            f"environment. If the checkout is untrusted, delete {STATE_DIR}/; if this campaign is yours "
            f"(made by an older hangover, or moved here), `hangover init` adopts it")


def changed_files(repo: Path, base: str) -> list[str]:
    if not is_git_repo(repo):
        return []
    result = git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        base,
        "--",
    )
    names = result.stdout.splitlines() if result.returncode == 0 else []
    untracked = git(repo, "ls-files", "--others", "--exclude-standard")
    if untracked.returncode == 0:
        names.extend(untracked.stdout.splitlines())
    return sorted({name for name in names if name})


def resolve_revision(repo: Path, revision: str) -> str:
    result = git(
        repo,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{revision}^{{commit}}",
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "not a commit"
        raise RuntimeError(f"invalid audit base {revision!r}: {detail}")
    return result.stdout.strip()


def untracked_files(repo: Path) -> list[str]:
    result = git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    if result.returncode != 0:
        return []
    return sorted(
        value
        for value in result.stdout.split("\0")
        if value and not any(part in IGNORED_DIRS for part in Path(value).parts)
    )


def _untracked_diff_errors(repo: Path) -> list[str]:
    errors = []
    for relative in untracked_files(repo):
        try:
            handle = open_repo_file(repo, relative, purpose=f"untracked file {relative!r}")
        except RepositoryRefusal:
            continue  # A symlink (git diff --check does not read through one either) or a hard link.
        except OSError as exc:
            errors.append(f"{relative}: could not inspect untracked file: {exc}")
            continue
        if handle is None:
            continue
        try:
            with handle:
                if b"\0" in handle.read(8192):
                    continue
                handle.seek(0)
                for number, line in enumerate(handle, 1):
                    body = line.rstrip(b"\r\n")
                    if body.endswith((b" ", b"\t")):
                        errors.append(f"{relative}:{number}: trailing whitespace.")
                    if body.startswith((b"<<<<<<< ", b"=======", b">>>>>>> ")):
                        errors.append(f"{relative}:{number}: leftover conflict marker")
        except OSError as exc:
            errors.append(f"{relative}: could not inspect untracked file: {exc}")
    return errors


def diff_check(repo: Path, base: str, log_path: Path) -> dict[str, Any]:
    result = {
        "name": "git-diff-check",
        **run_command(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--check",
                base,
                "--",
            ],
            repo,
            120,
            log_path,
        ),
    }
    untracked_errors = _untracked_diff_errors(repo)
    if untracked_errors:
        suffix = "\n[untracked files]\n" + "\n".join(untracked_errors) + "\n"
        with log_path.open("a") as handle:
            handle.write(suffix)
        result.update(
            status="failed",
            exit_code=1,
            output_sha256=sha256(log_path.read_bytes()).hexdigest(),
            stdout_tail=(result["stdout_tail"] + suffix)[-1200:],
        )
    return result


def _untracked_patch(repo: Path) -> str:
    sections = []
    for relative in untracked_files(repo):
        candidate = repo / relative
        try:
            data = read_repo_file(repo, relative, purpose=f"untracked file {relative!r}", binary=True,
                                  limit=None)  # Hashed whole, as before; only small text is shown.
        except RepositoryRefusal:
            sections.append(f"Untracked symlink or hard link omitted: {relative}\n")
            continue
        except OSError as exc:
            sections.append(f"Unreadable untracked file {relative}: {exc}\n")
            continue
        if data is None:
            continue  # Not a regular file (a FIFO, a socket), or gone since git listed it.
        digest = sha256(data).hexdigest()
        lowered = candidate.name.lower()
        normalized_parts = {
            part
            for part in re.split(r"[^a-z0-9]+", lowered)
            if part
        }
        collapsed = re.sub(r"[^a-z0-9]+", "", lowered)
        sensitive = bool(
            lowered.startswith(".env")
            or lowered in SENSITIVE_FILENAMES
            or normalized_parts & SENSITIVE_NAME_PARTS
            or any(part in collapsed for part in ("privatekey", "serviceaccount"))
            or candidate.suffix.lower() in {".key", ".p12", ".pem", ".pfx"}
            or any(marker in data[:MAX_PATCH_FILE_BYTES].lower() for marker in SENSITIVE_CONTENT_MARKERS)
            or b"-----begin private key-----" in data[:MAX_PATCH_FILE_BYTES].lower()
        )
        if sensitive:
            sections.append(
                f"Sensitive untracked file omitted (size={len(data)}, sha256={digest}): {relative}\n"
            )
        elif len(data) > MAX_PATCH_FILE_BYTES:
            sections.append(
                f"Untracked file omitted (size={len(data)}, sha256={digest}): {relative}\n"
            )
        elif b"\0" in data[:8192]:
            sections.append(
                f"Binary untracked file omitted (size={len(data)}, sha256={digest}): {relative}\n"
            )
        else:
            text = data.decode(errors="replace")
            sections.extend(
                unified_diff(
                    [],
                    text.splitlines(keepends=True),
                    fromfile="/dev/null",
                    tofile=f"b/{relative}",
                )
            )
    return "".join(sections)


def capture_patch(repo: Path, path: Path, *, base: str | None = None) -> None:
    if not is_git_repo(repo):
        path.write_text("Not a Git repository.\n")
        return
    if base is not None:
        changes = git(
            repo,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            base,
            "--",
        )
        if changes.returncode != 0:
            detail = changes.stderr.strip() or "git diff failed"
            raise RuntimeError(f"cannot capture patch from base commit {base}: {detail}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"# changes since {base}\n"
            + changes.stdout
            + "\n# untracked\n"
            + _untracked_patch(repo)
        )
        return
    unstaged = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--")
    staged = git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--cached",
        "HEAD",
        "--",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# staged\n"
        + staged.stdout
        + "\n# unstaged\n"
        + unstaged.stdout
        + "\n# untracked\n"
        + _untracked_patch(repo)
    )
