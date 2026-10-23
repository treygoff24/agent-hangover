"""Content-bound verification evidence, independent of the reviewer route.

This detects drift at execution boundaries, not adversarial concurrent writers.
Ignored dependencies, external services and arbitrary command environments are
not frozen. HEAD and staging are provenance, not working-tree content identity.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from .model import ISSUE_CONTRACT_FIELDS, active_remediation, digest, paths, read_json
from .oracles import fallow_version
from .rust import analyzer_identity as rust_analyzer_identity
from .repository import RepositoryRefusal, _symlinked_component, git, is_git_repo, open_repo_file

TOOL_ROOT = Path(__file__).resolve().parents[2]
LOCAL_STATE = {".git", ".hangover", ".fallow"}
SAFE_RUN_ID = re.compile(r"[A-Za-z0-9-]+")
REMEDIATION_INPUTS = (
    "id", "primary", "members", "fix_dir", "fix_started_at", "fix_base_commit",
    "fix_finding_ids", "fix_notes", "waivers",
)


def file_digest(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return sha256_stream(handle)
    except OSError as exc:
        raise RuntimeError(f"verification input unavailable: {path}") from exc


def repo_file_digest(repo: Path, name: str) -> str | None:
    """The digest of a regular file inside the repository, None when there is none. Under the
    containment rule (`repository.contained_path`): RepositoryRefusal for a symlinked or external
    one, so verification never hashes what a link points at."""
    try:
        handle = open_repo_file(repo, name, purpose=name)
    except OSError as exc:
        raise RuntimeError(f"verification input unavailable: {repo / name}") from exc
    if handle is None:
        return None
    with handle:
        return sha256_stream(handle)


def sha256_stream(handle: Any) -> str:
    result = sha256()
    while chunk := handle.read(128 * 1024):
        result.update(chunk)
    return result.hexdigest()


def run_artifact(repo: Path, run: str, name: str) -> Path:
    relative = Path(name)
    if (not isinstance(run, str) or not SAFE_RUN_ID.fullmatch(run)
            or relative.is_absolute() or ".." in relative.parts or not relative.parts):
        raise RuntimeError("invalid verification artifact path")
    directory = paths(repo)["runs"] / run
    path = directory
    for part in (".", *relative.parts):
        path /= part
        if path.is_symlink():
            raise RuntimeError("refusing symlinked verification artifact")
    return path


def tree_identity(repo: Path) -> str:
    if is_git_repo(repo):
        result = git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
        if result.returncode:
            raise RuntimeError("cannot enumerate verification inputs")
        names = set(filter(None, result.stdout.split("\0")))
    else:
        names = set()
        for root, directories, files in os.walk(repo):
            relative = Path(root).relative_to(repo)
            directories[:] = [name for name in directories if name not in LOCAL_STATE]
            links = [name for name in directories if (Path(root) / name).is_symlink()]
            names.update(str(relative / name) for name in [*files, *links])
    entries = []
    known: set[Path] = set()
    top = repo.resolve()
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("invalid verification input path")
        if relative.parts[0] in LOCAL_STATE:
            continue
        path = repo / relative
        # Never follow directory symlinks to read outside this repository (the containment rule).
        if _symlinked_component(top, list(relative.parts[:-1]), known) is not None:
            raise RepositoryRefusal(f"verification input traverses a symlink: {name}")
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue  # Deleted tracked files have no working-tree content.
        except OSError as exc:
            raise RuntimeError(f"verification input unavailable: {name}") from exc
        if stat.S_ISLNK(mode):
            entries.append([name, "symlink", os.readlink(path)])
        elif stat.S_ISREG(mode):
            entries.append([name, bool(mode & 0o111), repo_file_digest(repo, name)])
        else:
            raise RuntimeError(f"unsupported verification input (including submodules): {name}")
    return digest(entries)


def attempt_identity(state: dict[str, Any]) -> str:
    """Also identifies a legacy attempt before its explicit attachment."""
    record = active_remediation(state)
    primary = state.get("active_issue")
    members = record["members"] if record else state.get("active_batch") or [primary]
    return digest({
        "baseline": state.get("baseline_run"),
        "primary": primary,
        "members": members,
        "record": {key: record.get(key) for key in REMEDIATION_INPUTS} if record else None,
        "issues": [
            {key: state.get("issues", {}).get(identifier, {}).get(key)
             for key in (*REMEDIATION_INPUTS, "status")}
            for identifier in members
        ],
    })


def issue_contract_identity(state: dict[str, Any]) -> str:
    record = active_remediation(state)
    if record is None:
        raise RuntimeError("no active remediation contract; run `hangover verify` again")
    return digest({
        identifier: {key: state["issues"][identifier].get(key) for key in ISSUE_CONTRACT_FIELDS}
        for identifier in record["members"]
    })


def repository_inputs(repo: Path, fallow_binary: Path | None) -> dict[str, Any]:
    """Inputs shared by remediation verification and whole-change prevention."""
    config = read_json(paths(repo)["config"])
    tool_files = [*sorted((TOOL_ROOT / "src/hangover").glob("*.py")),
                  TOOL_ROOT / "schemas/review.schema.json", *sorted((TOOL_ROOT / "prompts").glob("*.md"))]
    return {
        "schema_version": 1,
        "tree": tree_identity(repo),
        "policy": {"checks": config.get("checks", []), "fallow": config.get("fallow", {}),
                   **({"rust": config["rust"]} if "rust" in config else {})},
        # Analyzer policy is an input even when deliberately Git-ignored.
        "analyzer_config": {
            name: repo_file_digest(repo, name)
            for name in (".fallowrc.json", ".fallowrc.jsonc", "fallow.toml", ".hangover-rust.json")
        },
        "verifier": digest([[str(path.relative_to(TOOL_ROOT)), file_digest(path)] for path in tool_files]),
        "python": [sys.version, str(Path(sys.executable).resolve())],
        "fallow": [str(fallow_binary.resolve()), file_digest(fallow_binary)] if fallow_binary else None,
        "fallow_version": fallow_version(),
        **({"rust": identity} if (identity := rust_analyzer_identity(repo)) else {}),
    }


def verification_inputs(repo: Path, state: dict[str, Any], fallow_binary: Path | None) -> dict[str, Any]:
    baseline = state.get("baseline_run")
    return {**repository_inputs(repo, fallow_binary),
            "baseline": [baseline, file_digest(run_artifact(repo, baseline, "snapshot.json"))],
            "attempt": attempt_identity(state)}


def require_attempt(state: dict[str, Any], identifier: str, expected: str) -> dict[str, Any] | None:
    record = active_remediation(state)
    members = record["members"] if record else state.get("active_batch") or [identifier]
    if (attempt_identity(state) != expected or state.get("active_issue") != identifier
            or any(state.get("issues", {}).get(member, {}).get("status") != "in_progress"
                   for member in members)):
        raise RuntimeError(f"issue {identifier} changed during review or verification; refusing to resolve stale evidence")
    return record


def require_proof(repo: Path, state: dict[str, Any], identifier: str,
                  fallow_binary: Path | None, expected: dict[str, Any] | None = None) -> dict[str, Any]:
    record = active_remediation(state)
    proof = record.get("verification") if record else None
    if not isinstance(proof, dict) or proof.get("status") != "passed":
        raise RuntimeError(
            "no current verification proof (the attempt may have changed during review); "
            "refusing to resolve; run `hangover verify` before post-fix review"
        )
    inputs = proof.get("inputs")
    if (not isinstance(inputs, dict) or not isinstance(inputs.get("attempt"), str)
            or not isinstance(proof.get("id"), str) or not isinstance(proof.get("run"), str)
            or not isinstance(proof.get("artifacts"), dict)):
        raise RuntimeError("incomplete verification proof; run `hangover verify` again")
    pinned = proof.get("branch")
    if isinstance(pinned, dict) and pinned.get("commit"):
        included = git(repo, "merge-base", "--is-ancestor", pinned["commit"], "HEAD")
        if included.returncode != 0:
            raise RuntimeError(
                f"branch {pinned.get('branch')} ({str(pinned['commit'])[:12]}), the commit this proof "
                "verified, is no longer an ancestor of HEAD; refusing to resolve; run `hangover verify` again"
            )
    require_attempt(state, identifier, proof["inputs"]["attempt"])
    if expected is not None and proof != expected:
        raise RuntimeError("verification proof was superseded; refusing stale review")
    if verification_inputs(repo, state, fallow_binary) != proof["inputs"]:
        raise RuntimeError("verification inputs changed; run `hangover verify` again")
    if issue_contract_identity(state) != proof.get("issue_contract"):
        raise RuntimeError("reviewed issue contract changed; run `hangover verify` again")
    if not {"snapshot.json", "before.patch", "after.patch"} <= set(proof.get("artifacts", {})):
        raise RuntimeError("incomplete verification artifacts; run `hangover verify` again")
    for name, checksum in proof["artifacts"].items():
        path = run_artifact(repo, proof["run"], name)
        if file_digest(path) != checksum:
            raise RuntimeError("verification artifact changed; run `hangover verify` again")
    return proof
