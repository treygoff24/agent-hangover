#!/usr/bin/env python3
"""Migrate a local campaign for hangover 0.1.1 and later, preserving its card history.

A campaign that deslop created and that was renamed by hand from `.deslop/` to `.hangover/`
still holds deslop's names: every card ID starts `dslp-`, the owner marker may say
`"tool": "deslop"`, fix directories are named after `dslp-` IDs, and recorded paths point
into `.deslop/`. hangover 0.1.1 accepts none of these. This script rewrites them in place:

  * card IDs `dslp-<10 hex>` -> `hang-<10 hex>` (the identity hash is kept) in every JSON,
    JSONL and Markdown file under the state directory (state.json, run snapshots, review
    packets and contexts, fix packets and notes, gate proofs), in JSON object keys as well as
    values, and in file and directory names (fixes/dslp-<id>/ -> fixes/hang-<id>/);
  * the owner marker's `"tool": "deslop"` -> `"hangover"`, with hangover's own note; the
    recorded repo/device/inode binding is kept, never recomputed, so the migration grants no
    trust the marker did not already carry. A campaign with no marker is left without one;
  * absolute paths `<repo>/.deslop/...` -> `<repo>/.hangover/...`;
  * the Rust policy file name `.deslop-rust.json` -> `.hangover-rust.json` and the analysis
    label `deslop-rust N` -> `hangover-rust N` inside recorded cards and snapshots.

Only config, state, owner, gate-proofs and the runs/ and fixes/ artifact trees are
migrated and backed up. Audit checkouts and caches are left untouched. Raw tool output
(logs, stdout/stderr captures, patches) is history: its content is never inspected or rewritten.

Dry run by default: it prints what it would change. `--apply` writes, after copying the
state directory to `<dir>.pre-migrate-<UTC timestamp>`. Files are rewritten in
place inside the existing directory, so the directory's inode, which the owner marker binds,
does not change. A second run finds nothing to do. It refuses a state directory that git
tracks, a symlinked one, and one whose state lock another process holds.

Usage:
  python3 scripts/migrate-state.py [REPO]            # dry run; REPO defaults to the cwd
  python3 scripts/migrate-state.py [REPO] --apply

Python 3.11+, standard library only.
"""

from __future__ import annotations

import sys
import os

if sys.version_info < (3, 11):
    sys.stderr.write("migration needs Python 3.11 or newer\n")
    raise SystemExit(2)
if not sys.flags.isolated:
    os.execv(sys.executable, [sys.executable, "-I", os.path.abspath(__file__), *sys.argv[1:]])

import argparse
import errno
import fcntl
import json
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

STATE_DIR = ".hangover"
LEGACY_DIR = ".deslop"
OWNER_FILE = "owner"
LOCK_FILE = "state.json.lock"
OWNER_NOTE = ("hangover created or adopted this directory here; a copy elsewhere is not trusted "
              "by --no-checks until `hangover init` adopts it")
NEW_PREFIX = "hang-"
CARD_ID = re.compile(r"(?<![0-9A-Za-z])dslp-(?=[0-9a-f]{10}(?![0-9A-Za-z]))")
RUST_LABEL = re.compile(r"\bdeslop-rust (?=\d)")
TEXT_SUFFIXES = {".md"}
CAMPAIGN_FILES = {"config.json", "state.json", "state.json.lock", "owner", "gate-proofs.json"}
CAMPAIGN_DIRS = {"runs", "fixes"}

# Load the trusted tool's own helpers, never modules from the target repository.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hangover.repository import (  # noqa: E402
    RepositoryRefusal, no_execute_git_env, read_repo_file,
)


class Refusal(Exception):
    pass


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          env=no_execute_git_env(repo), timeout=120)


def is_git_repo(repo: Path) -> bool:
    result = git(repo, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.strip() == "true"


def string_rewriter(repo_paths: set[str]) -> Callable[[str], str]:
    # Only the state directory of this very repository (under any path it was recorded at).
    legacy_roots = [re.compile(re.escape(base.rstrip("/")) + r"/" + re.escape(LEGACY_DIR) + r"(?=/|$)")
                    for base in sorted(repo_paths, key=len, reverse=True) if base]

    def rewrite(value: str) -> str:
        value = CARD_ID.sub(NEW_PREFIX, value)
        for pattern in legacy_roots:
            value = pattern.sub(lambda match: match.group(0)[: -len(LEGACY_DIR)] + STATE_DIR, value)
        value = value.replace(".deslop-rust.json", ".hangover-rust.json")
        return RUST_LABEL.sub("hangover-rust ", value)

    return rewrite


def rewrite_value(value: Any, rewrite: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return rewrite(value)
    if isinstance(value, list):
        return [rewrite_value(item, rewrite) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            new_key = rewrite(key)
            if new_key in result:
                raise Refusal(f"rewriting key {key!r} collides with an existing key {new_key!r}")
            result[new_key] = rewrite_value(item, rewrite)
        return result
    return value


def json_text(value: Any) -> str:
    # hangover's own write_json format.
    return json.dumps(value, indent=2, sort_keys=False) + "\n"


def regular_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refusal(f"{path} is not a regular, single-link file")


def read_text(path: Path) -> str:
    regular_file(path)
    # Applies the same no-follow, no-hard-link policy as repository reads.
    value = read_repo_file(CAMPAIGN.parent,
                           path.relative_to(CAMPAIGN.parent),
                           purpose=f"campaign migration file {path.relative_to(CAMPAIGN)}")
    if value is None:
        raise Refusal(f"missing campaign file: {path}")
    return value


def parent_fd(path: Path) -> int:
    """Open each directory without following links, including the campaign root."""
    descriptor = os.open(CAMPAIGN.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parent.relative_to(CAMPAIGN.parent).parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_in_place(path: Path, text: str) -> None:
    """Replace only an inspected regular file through no-follow directory handles."""
    descriptor = parent_fd(path)
    tmp_name = f".migrate-{os.urandom(12).hex()}"
    try:
        info = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refusal(f"{path} changed to a link or special file")
        tmp = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      stat.S_IMODE(info.st_mode), dir_fd=descriptor)
        with os.fdopen(tmp, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        try:
            os.unlink(tmp_name, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def planned_owner(path: Path) -> tuple[str | None, str]:
    """(new text or None, a line describing the marker)."""
    if not os.path.lexists(path):
        return None, ("no owner marker: unchanged. hangover's executing commands accept this campaign; "
                      "static mode (--no-checks) refuses it until `hangover init` adopts it, as before")
    if path.is_symlink() or not path.is_file():
        raise Refusal(f"{path} is not a regular file")
    try:
        recorded = json.loads(read_text(path))
    except ValueError as exc:
        raise Refusal(f"{path} is not JSON: {exc}") from exc
    if not isinstance(recorded, dict):
        raise Refusal(f"{path} is not a JSON object")
    root = path.parent
    info = os.lstat(root)
    binds = (recorded.get("repo") == str(root.parent) and recorded.get("device") == info.st_dev
             and recorded.get("inode") == info.st_ino)
    binding = ("binds this directory" if binds else
               "does NOT bind this directory (copied or moved across filesystems); static mode refuses it "
               "until `hangover init` adopts it, as before")
    if recorded.get("tool") == "hangover":
        return None, f"owner marker already hangover's; it {binding}"
    if recorded.get("tool") != "deslop":
        raise Refusal(f"{path} names tool {recorded.get('tool')!r}, neither deslop nor hangover")
    updated = {**recorded, "tool": "hangover", "note": OWNER_NOTE}
    return json_text(updated), f"owner marker: tool deslop -> hangover; it {binding}"


def campaign_tree(root: Path):
    """Only campaign records and artifacts; audit checkouts and caches are not state."""
    for name in CAMPAIGN_FILES:
        if os.path.lexists(root / name):
            regular_file(root / name)
    for name in CAMPAIGN_DIRS:
        if os.path.lexists(root / name) and not stat.S_ISDIR((root / name).lstat().st_mode):
            raise Refusal(f"{root / name} is not a real directory")
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        if Path(directory) == root:
            dirnames[:] = [name for name in dirnames if name in CAMPAIGN_DIRS]
            filenames = [name for name in filenames if name in CAMPAIGN_FILES | CAMPAIGN_DIRS]
        yield directory, dirnames, filenames


def plan(root: Path, rewrite: Callable[[str], str]) -> tuple[dict[Path, str], list[tuple[Path, Path]], list[str]]:
    """File rewrites, path renames (deepest first) and notes, without writing anything."""
    rewrites: dict[Path, str] = {}
    renames: list[tuple[Path, Path]] = []
    notes: list[str] = []
    for directory, dirnames, filenames in reversed(list(campaign_tree(root))):
        base = Path(directory)
        for name in filenames:
            path = base / name
            regular_file(path)
            if base == root and name == OWNER_FILE:
                continue  # planned_owner handles the marker
            if name.endswith((".json", ".jsonl")):
                original = read_text(path)
                try:
                    if name.endswith(".jsonl"):
                        lines = [json.dumps(rewrite_value(json.loads(line), rewrite)) if line.strip() else line
                                 for line in original.split("\n")]
                        text = "\n".join(lines)
                        changed = text != original
                    else:
                        value = json.loads(original)
                        updated = rewrite_value(value, rewrite)
                        changed = updated != value
                        text = json_text(updated)
                except ValueError as exc:
                    raise Refusal(f"invalid JSON in {path.relative_to(root)}") from exc
                if changed:
                    rewrites[path] = text
            elif path.suffix in TEXT_SUFFIXES:
                original = read_text(path)
                text = rewrite(original)
                if text != original:
                    rewrites[path] = text
        for name in dirnames:
            if not stat.S_ISDIR((base / name).lstat().st_mode):
                raise Refusal(f"{base / name} is not a real directory")
        for name in [*filenames, *dirnames]:
            new_name = CARD_ID.sub(NEW_PREFIX, name)
            if new_name != name:
                destination = base / new_name
                if os.path.lexists(destination):
                    raise Refusal(f"cannot rename {base / name}: {destination} already exists")
                renames.append((base / name, destination))
    return rewrites, renames, notes


def lock_state(root: Path, create: bool) -> Any:
    lock_path = root / LOCK_FILE
    if not lock_path.exists() and not create:
        return None
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    descriptor = parent_fd(lock_path)
    try:
        handle = os.fdopen(os.open(lock_path.name, flags, 0o600, dir_fd=descriptor), "a+")
    finally:
        os.close(descriptor)
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        handle.close()
        raise Refusal(f"{lock_path} is not a regular, single-link file")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            raise Refusal(f"{lock_path} is held: a hangover command is running here; try again when it ends")
        raise
    return handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repo", nargs="?", default=".", help="the repository holding .hangover/ (default: cwd)")
    parser.add_argument("--apply", action="store_true", help="write the changes (default: dry run)")
    args = parser.parse_args(argv)

    global CAMPAIGN
    repo = Path(args.repo).expanduser().resolve()
    root = CAMPAIGN = repo / STATE_DIR
    try:
        if not os.path.lexists(root):
            if os.path.lexists(repo / LEGACY_DIR):
                raise Refusal(f"{repo / LEGACY_DIR} has not been renamed yet: run "
                              f"`mv {LEGACY_DIR} {STATE_DIR}` in {repo} first (same filesystem, so an owner "
                              "marker keeps its binding), then run this again")
            raise Refusal(f"no {STATE_DIR}/ in {repo}")
        if root.is_symlink() or not root.is_dir():
            raise Refusal(f"{root} is not a real directory")
        if os.path.lexists(repo / LEGACY_DIR):
            raise Refusal(f"both {LEGACY_DIR}/ and {STATE_DIR}/ exist in {repo}; settle which is the campaign first")
        if is_git_repo(repo):
            tracked = git(repo, "ls-files", "-z", "--cached", "--", f":(icase,literal){STATE_DIR}")
            if tracked.returncode != 0:
                raise Refusal(f"could not ask git whether {STATE_DIR}/ is tracked: {tracked.stderr.strip()}")
            names = [name for name in tracked.stdout.split("\0") if name]
            if names:
                raise Refusal(f"git tracks files under {STATE_DIR}/ ({', '.join(names[:3])}"
                              f"{', ...' if len(names) > 3 else ''}); that is not a local campaign, refusing")

        # Validate every entry before opening even the lock or configuration.
        for directory, dirnames, filenames in campaign_tree(root):
            for name in dirnames:
                if not stat.S_ISDIR((Path(directory) / name).lstat().st_mode):
                    raise Refusal(f"{Path(directory) / name} is not a real directory")
            for name in filenames:
                regular_file(Path(directory) / name)
        lock = lock_state(root, create=args.apply)
        try:
            repo_paths = {str(repo)}
            for name in ("state.json", "config.json"):
                try:
                    recorded = json.loads(read_text(root / name)).get("repo")
                except (OSError, ValueError, AttributeError):
                    recorded = None
                if isinstance(recorded, str):
                    repo_paths.add(recorded)
            rewrite = string_rewriter(repo_paths)
            owner_text, owner_line = planned_owner(root / OWNER_FILE)
            rewrites, renames, notes = plan(root, rewrite)

            print(f"campaign: {root}")
            print(f"  {owner_line}")
            ids = len({match for text in rewrites.values() for match in re.findall(r"hang-[0-9a-f]{10}", text)})
            print(f"  {len(rewrites)} file(s) to rewrite ({ids} distinct card ID(s) appear in them), "
                  f"{len(renames)} path(s) to rename")
            for path in sorted(rewrites):
                print(f"    rewrite {path.relative_to(root)}")
            for old, new in renames:
                print(f"    rename  {old.relative_to(root)} -> {new.name}")
            for note in notes:
                print(f"  note: {note}")
            legacy_policy, policy = repo / ".deslop-rust.json", repo / ".hangover-rust.json"
            if legacy_policy.exists() and not policy.exists():
                print(f"  WARNING: {legacy_policy.name} is in the repository but hangover reads {policy.name}; "
                      f"until you `git mv {legacy_policy.name} {policy.name}` and commit, Rust scans use the "
                      "default thresholds and none of its exclusions. This script does not touch repository files.")
            active = {}
            try:
                state = json.loads(read_text(root / "state.json"))
                active = {key: state.get(key) for key in ("active_remediation", "pending_audit_review")
                          if state.get(key)}
            except (OSError, ValueError):
                pass
            if active:
                print(f"  note: in-flight work ({', '.join(active)}): any recorded verification proof, prepared "
                      "review or audit proof is pinned to the old files and tool, so rerun `hangover verify` "
                      "(or the audit) after upgrading; the cards and batch themselves carry over")

            nothing = owner_text is None and not rewrites and not renames
            if nothing:
                print("nothing to migrate")
                return 0
            if not args.apply:
                print("dry run: nothing written; rerun with --apply")
                return 0

            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = root.with_name(f"{root.name}.pre-migrate-{stamp}")
            if os.path.lexists(backup):
                raise Refusal(f"{backup} already exists")
            shutil.copytree(root, backup, symlinks=True,
                            ignore=lambda directory, names: [name for name in names
                                if Path(directory) == root and name not in CAMPAIGN_FILES | CAMPAIGN_DIRS])
            print(f"backup: {backup}")
            print("  keep this private backup until you have checked the result; never commit it")

            for path, text in rewrites.items():
                write_in_place(path, text)
            if owner_text is not None:
                write_in_place(root / OWNER_FILE, owner_text)
            for old, new in renames:  # deepest first, so parents rename after their children
                if os.path.lexists(new):
                    raise Refusal(f"cannot rename {old}: {new} already exists (backup is at {backup})")
                descriptor = parent_fd(old)
                try:
                    os.rename(old.name, new.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
                finally:
                    os.close(descriptor)
            print("migrated")
            return 0
        finally:
            if lock is not None:
                lock.close()
    except (Refusal, RepositoryRefusal, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
