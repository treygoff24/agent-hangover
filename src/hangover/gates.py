"""Gate proof reuse: a passing full gate, remembered against the exact tree it saw.

A proof is keyed by `gate_key` (see its docstring and docs/workflow.md): the check
list, working-tree content, HEAD, the staged index, lockfiles and install
markers, and a mode/content fingerprint of ignored files outside dependency directories.
A proof is recorded only when the complete key before the gate equals the
complete key after it, so a gate that changes its own inputs never records. A
later verify whose key is identical may reuse the proof; anything else runs fresh. The environment is not part of the
key, so `verify --fresh-gate` always reruns.
"""
from __future__ import annotations

import json
import os
import stat
from hashlib import sha256
from pathlib import Path
from typing import Any

from .evidence import digest, file_digest, repo_file_digest, tree_identity
from .model import now, paths, write_json
from .repository import git, is_git_repo

GATE_PROOFS = "gate-proofs.json"
MAX_PROOFS = 20
MAX_IGNORED_FILES = 20_000
MAX_IGNORED_BYTES = 256 * 1024 * 1024
# Ignored directories whose churn is dependency or cache noise; their install
# state is read from the markers below instead of walking their files.
DEPENDENCY_DIRS = {
    "node_modules", ".git", ".hangover", ".fallow", ".cache", ".turbo", ".next",
    ".nuxt", ".parcel-cache", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "target", ".gradle", "coverage",
}
LOCKFILES = (
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
)
INSTALL_MARKERS = (
    "node_modules/.package-lock.json", "node_modules/.pnpm/lock.yaml", "node_modules/.modules.yaml",
    "node_modules/.yarn-state.yml", "node_modules/.yarn-integrity",
)


class ReuseUnavailable(RuntimeError):
    """The key cannot be computed safely, so the gate runs fresh; the message says why."""


def _inside(repo: Path, path: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(repo)))
    except ValueError:
        return False
    return True


def _check_link(repo: Path, path: Path) -> None:
    if path.is_symlink() and not _inside(repo, path):
        raise ReuseUnavailable(f"symlink points outside the repository: {path.relative_to(repo)}")


def _ignored_fingerprint(repo: Path) -> list[Any]:
    """Path, mode and content hash of ignored files outside dependency and cache directories.

    Content, not mtime, so a build that rewrites identical output still matches.
    More than MAX_IGNORED_FILES files or MAX_IGNORED_BYTES bytes, or any symlink
    to a directory or outside the repository, disables reuse.
    """
    result = git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
    if result.returncode:
        raise ReuseUnavailable("cannot list ignored files")
    entries: list[Any] = []
    count = 0
    total = 0

    def add(path: Path) -> None:
        nonlocal count, total
        count += 1
        if count > MAX_IGNORED_FILES:
            raise ReuseUnavailable(f"more than {MAX_IGNORED_FILES} ignored files to fingerprint")
        name = str(path.relative_to(repo))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            _check_link(repo, path)
            if path.is_dir():
                raise ReuseUnavailable(f"ignored symlink to a directory: {name}")
            entries.append([name, "symlink", os.readlink(path)])
            return
        total += info.st_size
        if total > MAX_IGNORED_BYTES:
            raise ReuseUnavailable(f"more than {MAX_IGNORED_BYTES // (1024 * 1024)} MB of ignored files to fingerprint")
        entries.append([name, stat.S_IMODE(info.st_mode), file_digest(path)])

    for name in sorted(filter(None, result.stdout.split("\0"))):
        relative = Path(name)
        if DEPENDENCY_DIRS & set(relative.parts):
            continue
        path = repo / relative
        if name.endswith("/"):
            for root, directories, files in os.walk(path):
                directories[:] = sorted(d for d in directories if d not in DEPENDENCY_DIRS)
                for directory in directories:
                    if (Path(root) / directory).is_symlink():
                        raise ReuseUnavailable(
                            f"ignored symlink to a directory: {(Path(root) / directory).relative_to(repo)}"
                        )
                for file in sorted(files):
                    add(Path(root) / file)
        elif path.exists() or path.is_symlink():
            add(path)
    return entries


def _tracked_links(repo: Path) -> None:
    result = git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    if result.returncode:
        raise ReuseUnavailable("cannot enumerate files")
    for name in filter(None, result.stdout.split("\0")):
        _check_link(repo, repo / name)


def gate_key(repo: Path, checks: list[dict[str, Any]]) -> str:
    """The reuse key. Raises ReuseUnavailable when it cannot be trusted.

    The key covers the check list, the working-tree content (tracked and
    non-ignored untracked), HEAD, the staged index entries, lockfiles and
    package-manager install markers, and a mode/content fingerprint of
    ignored files outside dependency and cache directories.
    """
    tree = tree_identity(repo)
    parts: dict[str, Any] = {"scope": "full", "checks": checks, "tree": tree}
    if is_git_repo(repo):
        _tracked_links(repo)
        head = git(repo, "rev-parse", "--verify", "-q", "HEAD")
        index = git(repo, "ls-files", "-s", "-z")
        if index.returncode:
            raise ReuseUnavailable("cannot read the git index")
        parts["head"] = head.stdout.strip() if head.returncode == 0 else None
        parts["index"] = sha256(index.stdout.encode()).hexdigest()
        parts["ignored"] = _ignored_fingerprint(repo)
    parts["installed"] = {
        # A symlinked or external lockfile is refused (RepositoryRefusal, a RuntimeError): reuse is off.
        name: repo_file_digest(repo, name)
        for name in (*LOCKFILES, *INSTALL_MARKERS)
    }
    return digest(parts)


def _store_path(repo: Path) -> Path:
    return paths(repo)["root"] / GATE_PROOFS


def _load(repo: Path) -> dict[str, Any]:
    try:
        value = json.loads(_store_path(repo).read_text())
    except (OSError, ValueError):
        return {}
    proofs = value.get("proofs") if isinstance(value, dict) else None
    return proofs if isinstance(proofs, dict) else {}


def find_gate_proof(repo: Path, key: str) -> dict[str, Any] | None:
    """The recorded passing gate for this exact key, or None. Never a partial run."""
    entry = _load(repo).get(key)
    if not isinstance(entry, dict):
        return None
    checks = entry.get("checks")
    if (not isinstance(checks, list) or not checks
            or any(not isinstance(item, dict) or item.get("status") != "passed" for item in checks)):
        return None
    if not isinstance(entry.get("run"), str):
        return None
    return entry


def record_gate_proof(repo: Path, key: str, run_id: str, checks: list[dict[str, Any]]) -> bool:
    """Remember a gate where every configured check passed; anything else records nothing."""
    if not checks or any(item.get("status") != "passed" for item in checks):
        return False
    proofs = _load(repo)
    proofs[key] = {"run": run_id, "recorded_at": now(), "checks": checks}
    newest = sorted(proofs.items(), key=lambda pair: str(pair[1].get("recorded_at", "")))[-MAX_PROOFS:]
    write_json(_store_path(repo), {"version": 1, "proofs": dict(newest)})
    return True


def invalidate_gate_proof(repo: Path, key: str) -> bool:
    """Drop the entry for this key so a failed fresh run cannot leave an older pass reusable."""
    proofs = _load(repo)
    if key not in proofs:
        return False
    del proofs[key]
    write_json(_store_path(repo), {"version": 1, "proofs": proofs})
    return True
