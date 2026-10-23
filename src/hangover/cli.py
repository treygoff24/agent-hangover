from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from uuid import uuid4

try:
    import fcntl
except ImportError:  # pragma: no cover - hangover's process control is POSIX-only
    fcntl = None  # type: ignore[assignment]

from . import __version__
from .fallow_evidence import caveat_reasons, degrading_index, empty_analysis, fallow_clock, type_aware_degradation
from .evidence import (
    attempt_identity,
    digest,
    file_digest,
    issue_contract_identity,
    repository_inputs,
    require_attempt,
    require_proof,
    run_artifact,
    verification_inputs,
)
from .gates import _load as _gate_proofs, find_gate_proof, gate_key, invalidate_gate_proof, record_gate_proof
from .finding_query import query_members
from .model import (
    ISSUE_ID,
    SCHEMA_VERSION,
    add_fix_notes,
    add_history,
    add_issue_event,
    active_remediation,
    add_to_batch,
    begin_fix,
    check_batch_candidates,
    focus_remediation,
    open_batches,
    open_remediation_ids,
    dedupe_open_subjective_issues,
    defer_issue,
    ensure_remediation,
    issue_id,
    load_state,
    merge_findings,
    reassign_duplication_fingerprints,
    mutate_state,
    next_issue,
    now,
    obsolete_issue,
    ordered_issues,
    paths,
    read_json,
    resolve_issue,
    release_issues,
    resolve_issue_by,
    suppress_issue,
    update_remediation,
    write_json,
)
from .oracles import (
    FALLOW_VERSION,
    TOOL_ROOT,
    _fallow_path,
    _fallow_error_line,
    codex_binary,
    delegate_binary,
    fallow_dead_code_mode,
    extract_fallow_findings,
    fallow_version,
    import_review,
    prepare_review_packet,
    review_findings,
    run_command_review,
    run_codex_review,
    run_delegate_review,
    run_fallow_audit,
    run_fallow_scan,
    validate_note_assessments,
)
from .repository import (
    adopted_drift,
    capture_patch,
    changed_files,
    compare_checks,
    diff_check,
    discover_checks,
    failure_excerpt,
    propose_gate_stages,
    runs_gate,
    git,
    git_safe_environment,
    git_info,
    inventory,
    JAVASCRIPT_SUFFIXES,
    SOURCE_SUFFIXES,
    TYPESCRIPT_SUFFIXES,
    is_git_repo,
    mark_state_owner,
    no_execute_git,
    no_execute_git_active,
    progress,
    progress_result,
    refuse_foreign_state,
    read_repo_file,
    RepositoryRefusal,
    resolve_repo,
    resolve_revision,
    run_checks,
    stage_drift,
    update_local_exclude,
)
from .rust import (
    POLICY_FILE as RUST_POLICY_FILE,
    add_suppression as add_rust_suppression,
    applicable as rust_applicable,
    extract_rust_findings,
    run_rust_audit,
    run_rust_scan,
    manifest_notice as rust_manifest_notice,
    rust_comparison,
    tool_versions as rust_tool_versions,
)
from .readiness import REVIEW_RUNNERS, command_binary, resolve_review, codex_startup_probe
from .packets import REVIEW_ARTIFACTS, compact_fix_packet, fix_packet
from .result import DriverError, DriverResult, Origin, collect_results, command_line, exit_code
from .scope import assess_scope, select_scope
from .selection import list_issues, preview_batch, project_issue
from .audit_evidence import (
    audit_blockers as _audit_blockers, begin_audit, fallow_failed, rust_analysis_failed, record_audit_review, require_audit, seal_audit,
)

SAFE_ISSUE_ID = ISSUE_ID
SAFE_BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")
SAFE_RUN_ID = re.compile(r"[A-Za-z0-9-]+")
REVIEW_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
REVIEW_ENV_RESERVED = {"HOME", "PATH", "SHELL"}


def _run_id(kind: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{kind}-{uuid4().hex[:6]}"


def _config(repo: Path) -> dict[str, Any]:
    config = read_json(paths(repo)["config"])
    if config.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported config schema {config.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )
    if Path(str(config.get("repo", ""))).resolve() != repo.resolve():
        raise RuntimeError(f"config belongs to {config.get('repo')}, not {repo}")
    _review_settings(config)
    return config


def _review_env(value: dict[str, Any]) -> list[str]:
    if "env" not in value:
        return []
    env = value["env"]
    if not isinstance(env, list):
        raise RuntimeError("review.env must be a list of environment variable names")
    for index, name in enumerate(env):
        if not isinstance(name, str) or REVIEW_ENV_NAME.fullmatch(name) is None:
            raise RuntimeError(
                f"review.env[{index}] must be a non-empty environment variable name "
                "matching [A-Za-z_][A-Za-z0-9_]*"
            )
        if name in REVIEW_ENV_RESERVED or name.startswith("GIT_"):
            raise RuntimeError(
                f"review.env[{index}] cannot forward {name}: the review environment pins "
                "HOME, PATH, SHELL, and GIT_* so a reviewer cannot resolve a different "
                "binary or reconfigure Git"
            )
    return list(env)


def _review_settings(config: dict[str, Any]) -> dict[str, Any]:
    value = config.get("review")
    if not isinstance(value, dict):
        value = {}
    delegate = value.get("delegate")
    if not isinstance(delegate, dict):
        delegate = {}
    return {
        "runner": value.get("runner", "codex"),
        "timeout_seconds": value.get("timeout_seconds", 1200),
        "delegate": {
            "lane": delegate.get("lane") or "codex",
            "model": delegate.get("model"),
            "reasoning_effort": delegate.get("reasoning_effort"),
        },
        "env": _review_env(value),
        "command": value.get("command"),
    }


def _initialize(repo: Path, force: bool = False, *, stream: TextIO | None = None) -> None:
    # A machine-facing caller owns stdout, so a command that initializes on
    # the way to its JSON result routes this prose to the stream it names.
    out = stream or sys.stdout
    state_paths = paths(repo)
    fresh = force or not state_paths["config"].exists()
    # Everything init reads from the repository (its package.json, Makefile, gate script) is read
    # first: a refusal (RepositoryRefusal) leaves no `.hangover/` behind.
    discovered = discover_checks(repo) if fresh else None
    proposal = propose_gate_stages(repo) if fresh else None
    if state_paths["root"].exists() and not state_paths["root"].is_dir():
        raise RuntimeError(
            f"{state_paths['root']} exists and is not a directory; hangover keeps its campaign state there, "
            "so move that file aside first"
        )
    state_paths["root"].mkdir(parents=True, exist_ok=True)
    state_paths["root"].chmod(0o700)
    # Reached only after refuse_foreign_state: binds the directory to this checkout, so --no-checks
    # can tell hangover's own campaign from a `.hangover/` an archive shipped.
    mark_state_owner(repo)
    config_path = state_paths["config"]
    if config_path.exists() and not force:
        excluded = update_local_exclude(repo)
        if not state_paths["state"].exists():
            mutate_state(repo, lambda state: None)
            print(f"recreated missing state: {state_paths['state']}", file=out)
            return
        print(f"already initialized: {state_paths['root']}", file=out)
        if excluded:
            print(f"local analyzer state ignored through {excluded}", file=out)
        return
    if config_path.exists():
        backup = config_path.with_name(
            f"config.json.bak-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )
        shutil.copy2(config_path, backup)
    config = {
        "schema_version": SCHEMA_VERSION,
        "repo": str(repo),
        "checks": discovered,
        "fallow": {"enabled": True},
        "rust": {"enabled": True},
        "review": {
            "runner": "codex",
            "timeout_seconds": 1200,
            "delegate": {"lane": "codex", "model": None, "reasoning_effort": None},
            "env": [],
            "command": None,
        },
    }
    write_json(config_path, config)
    if not state_paths["state"].exists():
        mutate_state(repo, lambda state: None)
    else:
        # A moved or copied checkout keeps its campaign: --force is the operator's assertion
        # that this state belongs here. The old path stays in history.
        existing = read_json(state_paths["state"])
        recorded = Path(str(existing.get("repo", ""))).resolve() if isinstance(existing, dict) else None
        if recorded is not None and recorded != repo.resolve():
            existing["repo"] = str(repo.resolve())
            add_history(existing, "state_rebound", **{"from": str(recorded), "to": str(repo.resolve())})
            write_json(state_paths["state"], existing)
            print(f"campaign state rebound from {recorded} to {repo.resolve()}", file=out)
    excluded = update_local_exclude(repo)
    print(f"initialized {state_paths['root']}", file=out)
    if config["checks"]:
        print(
            "checks: "
            + ", ".join(
                f'{item["name"]} ({" ".join(item["command"])})' for item in config["checks"]
            ),
            file=out,
        )
    else:
        print("checks: none discovered", file=out)
    if proposal:
        _print_gate_proposal(repo, out, proposal)
    print("edit .hangover/config.json to change the gate", file=out)
    if excluded:
        print(f"local analyzer state ignored through {excluded}", file=out)
    if not no_execute_git_active():
        print(
            "warning: configured checks execute repository code; use --no-checks for untrusted checkouts",
            file=out,
        )


def _print_gate_proposal(repo: Path, out: TextIO, proposal: dict[str, Any] | None = None) -> None:
    """Name stages read from a gate shell script. Nothing is applied: adoption is the operator's call.

    `propose_gate_stages` raises RepositoryRefusal for a gate script outside the repository or behind
    a link, so no line of such a file is ever printed."""
    proposal = proposal if proposal is not None else propose_gate_stages(repo)
    if not proposal:
        return
    config_path = paths(repo)["config"]
    if config_path.exists() and any(
        check.get("adopted_from") for check in read_json(config_path).get("checks", [])
    ):
        return
    print(
        f"proposed stages from the `{proposal['script']}` gate script (not applied): "
        + ", ".join(f'{c["name"]} ({" ".join(c["command"])})' for c in proposal["checks"]),
        file=out,
    )
    if proposal.get("kind") == "references":
        # Package calls that were not adopted first: they are the stages a reader most needs to see.
        uncovered = sorted(proposal.get("uncovered") or [],
                           key=lambda line: not re.search(r"\b(?:npm|pnpm|yarn|bun)\s+(?:run|test)\b", line))
        print("  read from the script's package-script, shell-script and cargo calls only; these lines are NOT covered by the "
              f"stages ({len(uncovered)}):", file=out)
        for line in uncovered[:12]:
            print(f"    {line}", file=out)
        if len(uncovered) > 12:
            print(f"    ... {len(uncovered) - 12} more", file=out)
    print(
        "  to adopt them as explicit ordered checks, asserting that this is the gate's order: "
        + command_line(repo, "init", "--stages-from-gate"),
        file=out,
    )


def _adopt_gate_stages(repo: Path, *, stream: TextIO | None = None) -> int:
    out = stream or sys.stdout
    _ensure_initialized(repo, stream=stream)
    proposal = propose_gate_stages(repo)
    if not proposal:
        print("no gate script with separately readable commands was found; nothing adopted", file=out)
        return 1

    config_path = paths(repo)["config"]
    config = _config(repo)
    backup = config_path.with_name(
        f"config.json.bak-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    )
    shutil.copy2(config_path, backup)
    # Replace only the check(s) that run the gate, in place; every other check stays where it is.
    checks: list[dict[str, Any]] = []
    placed = False
    for check in config.get("checks", []):
        previously_adopted = (check.get("adopted_from") or {}).get("script") == proposal["script"]
        if previously_adopted or runs_gate(check, proposal):
            if not placed:
                checks.extend(proposal["checks"])
                placed = True
        else:
            checks.append(check)
    if not placed:
        checks.extend(proposal["checks"])
    kept = {check["name"] for check in checks if not check.get("adopted_from")}
    clash = sorted(kept & {check["name"] for check in proposal["checks"]})
    if clash:
        print(f"check name(s) already configured: {', '.join(clash)}; rename one and retry; nothing adopted", file=out)
        return 1
    config["checks"] = checks
    write_json(config_path, config)
    print(
        f"adopted {len(proposal['checks'])} stages from `{proposal['script']}`: "
        + ", ".join(check["name"] for check in proposal["checks"]),
        file=out,
    )
    print(f"previous config saved to {backup}", file=out)
    if proposal.get("kind") == "references":
        print(f"note: {len(proposal.get('uncovered') or [])} line(s) of {proposal.get('file')} outside its "
              "package-script calls (version pins, prerequisite checks) are not part of the adopted stages",
              file=out)
    print(
        "stages are recorded with the gate script's hash; verify blocks if the script changes. "
        "Run `hangover scan --rebaseline --checks` to record the baseline stages",
        file=out,
    )
    return 0


def _ensure_initialized(repo: Path, *, stream: TextIO | None = None) -> None:
    state_paths = paths(repo)
    if not state_paths["config"].exists() or not state_paths["state"].exists():
        _initialize(repo, stream=stream)
    else:
        update_local_exclude(repo)


def _require_initialized(repo: Path) -> None:
    """Read-only commands report the campaign they find; they never create one."""
    state_paths = paths(repo)
    if not state_paths["config"].exists() or not state_paths["state"].exists():
        raise DriverError(
            f"no hangover campaign in {repo}; run `hangover init` first",
            next_action=command_line(repo, "init"),
        )


def _content_digest(path: Path) -> str | None:
    """The parsed JSON's canonical digest (so reformatting does not change it), else the bytes' digest."""
    if not path.is_file():
        return None
    try:
        return digest(json.loads(path.read_text()))
    except (OSError, ValueError):
        return file_digest(path)


def _reject_content(record: dict[str, Any], failed_output: Path) -> None:
    """Remember a failed runner's output by content, so a copy cannot pass as a fresh review."""
    checksum = _content_digest(failed_output)
    if checksum:
        digests = record.setdefault("rejected_import_digests", [])
        if checksum not in digests:
            digests.append(checksum)


def _is_rejected_content(import_path: Path, record: Any) -> bool:
    digests = record.get("rejected_import_digests") if isinstance(record, dict) else None
    return bool(digests) and _content_digest(import_path) in digests


def _import_step(repo: Path, review_id: str, issue_id: str | None,
                 scope_paths: list[str] | None = None) -> tuple[str, dict[str, str]]:
    """The command that consumes a prepared review, and what must exist first."""
    output = paths(repo)["runs"] / review_id / "review.json"
    record_path = output.parent / "review-run.json"
    if record_path.is_file() and read_json(record_path).get("status") not in {"prepared", "completed"}:
        output = output.with_name("manual-review.json")
    parts = ["review", "--issue", issue_id] if issue_id else ["review"]
    for path in scope_paths or []:
        parts.extend(["--scope", path])
    return (
        command_line(repo, *parts, "--import", str(output)),
        {
            "path": str(output),
            "prerequisite": (
                "a fresh reviewer reads review-prompt.md from this run and writes "
                "its verdict to this path before the import"
            ),
        },
    )


def _prepared_review_key(scope_paths: list[str] | None) -> str:
    return json.dumps(sorted(scope_paths or []))


def _run_holding(repo: Path, path: Path) -> str | None:
    """The run directory a path sits in, if any."""
    try:
        relative = path.resolve().relative_to(paths(repo)["runs"].resolve())
    except (OSError, ValueError):
        return None
    return relative.parts[0] if len(relative.parts) > 1 else None


def _run_dir(repo: Path, run_id: str) -> Path:
    _prune_runs(repo)
    directory = paths(repo)["runs"] / run_id
    directory.mkdir(parents=True, exist_ok=False)
    _take_run_lease(directory)
    return directory


RUN_RETENTION = 10
# A run's lease: an flock held on this file for as long as the process writing
# the run lives. Pruning skips a run whose lease is held; the OS releases the
# lease of a process that died, so a crashed run is ordinary history.
RUN_LEASE = ".lease"
RUN_DIRECTORY_NAME = re.compile(r"(\d{8}T\d{6}Z)-([a-z-]+)-[0-9a-f]{6}")
PRUNED_DIRECTORY_NAME = re.compile(r"\.pruned-[0-9a-f]{32}")
_RUN_LEASES: dict[Path, TextIO] = {}


def _take_run_lease(directory: Path) -> None:
    if fcntl is None:
        return
    handle = (directory / RUN_LEASE).open("a+")
    try:
        # A directory this process just created; no one else can hold it.
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise
    _RUN_LEASES[directory] = handle


def _release_run_leases() -> None:
    """The command is over: its runs are history now (exiting would release them too)."""
    while _RUN_LEASES:
        _, handle = _RUN_LEASES.popitem()
        handle.close()


def _claim_unleased_run(entry: Path) -> TextIO | bool:
    """Take the lease of a run no live process holds: the open handle, True when the run
    has no lease file (it predates leases), False when its lease is held."""
    lease = entry / RUN_LEASE
    if lease.is_symlink():
        return False
    try:
        handle = lease.open("r")
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    return handle


def _retained_runs(repo: Path, state: dict[str, Any]) -> set[str]:
    """Runs the campaign can still read: its baseline and latest records, open proofs and review
    tokens, prepared initial reviews, pending audit proofs, the runs whose check logs a kept run
    inherited (transitively), and recorded reusable gates."""
    keep = {state.get(key) for key in ("baseline_run", "latest_run", "latest_review", "latest_audit")}
    records = state.get("remediations") if isinstance(state.get("remediations"), dict) else {}
    for identifier in open_remediation_ids(state):
        record = records.get(identifier) or {}
        proof, pending = record.get("verification"), record.get("pending_review")
        if isinstance(proof, dict):
            keep.add(proof.get("run"))  # the proof's snapshot, patches and check logs
        if isinstance(pending, dict):
            keep.add(pending.get("id"))  # the prepared review packet its token is bound to
    prepared = state.get("prepared_reviews")
    if isinstance(prepared, dict):
        keep.update(prepared.values())  # initial review packets not yet imported or superseded
    audits = state.get("audit_reviews") if isinstance(state.get("audit_reviews"), dict) else {}
    for record in audits.values():
        if isinstance(record, dict) and not record.get("consumed"):
            keep.add(record.get("run"))
    try:
        keep.update(entry.get("run") for entry in _gate_proofs(repo).values() if isinstance(entry, dict))
    except (OSError, RuntimeError):
        pass
    # A rebaseline copies its predecessor's check results, log paths included, so
    # the logs live in the first run of the chain: follow it to the end.
    pending_runs = [value for value in keep if isinstance(value, str)]
    while pending_runs:
        run = pending_runs.pop()
        if not SAFE_RUN_ID.fullmatch(run):
            continue
        try:
            inherited = read_json(paths(repo)["runs"] / run / "snapshot.json").get("checks_inherited_from")
        except (OSError, RuntimeError, AttributeError):
            continue
        if isinstance(inherited, str) and inherited not in keep:
            keep.add(inherited)
            pending_runs.append(inherited)
    return {value for value in keep if isinstance(value, str)}


def _prune_runs(repo: Path) -> list[str]:
    """Keep `.hangover/runs/` bounded: the runs the campaign references, the newest
    RUN_RETENTION, and every run a live process holds the lease of; remove the rest.

    The references are read, and the removals made, under the state lock, so a
    run a concurrent command has just referenced cannot be removed from a stale
    reading. Removal under the lock is a rename; the deleting happens after it.
    """
    root = paths(repo)
    runs = root["runs"]
    if fcntl is None or not runs.is_dir() or runs.is_symlink() or not root["state"].is_file():
        return []
    for leftover in runs.iterdir():
        if PRUNED_DIRECTORY_NAME.fullmatch(leftover.name) and leftover.is_dir() and not leftover.is_symlink():
            shutil.rmtree(leftover, ignore_errors=True)  # an earlier prune that did not finish
    named = sorted(
        (entry for entry in runs.iterdir()
         if RUN_DIRECTORY_NAME.fullmatch(entry.name) and entry.is_dir() and not entry.is_symlink()),
        key=lambda entry: entry.name,
    )
    candidates = named[:-RUN_RETENTION] if len(named) > RUN_RETENTION else []
    if not candidates:
        return []
    trash = runs / f".pruned-{uuid4().hex}"
    removed = []
    with root["state_lock"].open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            keep = _retained_runs(repo, load_state(repo))
            for entry in candidates:
                if entry.name in keep:
                    continue
                claimed = _claim_unleased_run(entry)
                if claimed is False:
                    continue  # a live process is writing it
                try:
                    trash.mkdir(exist_ok=True)
                    os.rename(entry, trash / entry.name)
                except OSError:
                    continue  # Retention is housekeeping; a run it cannot move stays.
                finally:
                    if not isinstance(claimed, bool):
                        claimed.close()
                removed.append(entry.name)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    shutil.rmtree(trash, ignore_errors=True)
    return removed


def _fix_directory(repo: Path, issue: dict[str, Any]) -> Path:
    identifier = issue.get("id")
    if not isinstance(identifier, str) or not SAFE_ISSUE_ID.fullmatch(identifier):
        raise RuntimeError(f"invalid issue id in state: {identifier!r}")
    value = issue.get("fix_dir")
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"issue {identifier} has no fix directory")
    candidate = Path(value)
    root = paths(repo)["fixes"].resolve()
    # A promoted companion retains the original batch's evidence directory.
    started = next(
        (event for event in reversed(issue.get("history", []))
         if event.get("event") == "fix_started"),
        {},
    )
    owner = started.get("batch_primary", identifier)
    if not isinstance(owner, str) or not SAFE_ISSUE_ID.fullmatch(owner):
        raise RuntimeError(f"invalid fix artifact owner in state: {owner!r}")
    expected = root / owner
    try:
        relative = candidate.relative_to(expected)
    except ValueError as exc:
        raise RuntimeError(f"issue {identifier} has an unsafe fix directory: {candidate}") from exc
    if ".." in relative.parts or not candidate.resolve().is_relative_to(expected):
        raise RuntimeError(f"issue {identifier} has an unsafe fix directory: {candidate}")
    current = expected
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError(f"issue {identifier} has a symlinked fix directory: {candidate}")
    if not candidate.is_dir():
        raise RuntimeError(f"issue {identifier} fix directory is missing: {candidate}")
    return candidate


def _fix_artifact(fix_dir: Path, name: str) -> Path:
    artifact = fix_dir / name
    if artifact.is_symlink():
        raise RuntimeError(f"refusing symlinked fix artifact: {artifact}")
    return artifact


def _snapshot(repo: Path, run_id: str) -> dict[str, Any]:
    if not isinstance(run_id, str) or not SAFE_RUN_ID.fullmatch(run_id):
        raise RuntimeError(f"invalid run id in state: {run_id!r}")
    run_dir = paths(repo)["runs"] / run_id
    snapshot = run_dir / "snapshot.json"
    if run_dir.is_symlink() or snapshot.is_symlink():
        raise RuntimeError(f"refusing symlinked run state: {run_dir}")
    return read_json(snapshot)


def _fallow_comparison(
    baseline: dict[str, Any] | None, current: dict[str, Any]
) -> dict[str, Any]:
    if not baseline:
        return {"comparable": False, "kind": "no_baseline", "reason": "no baseline"}
    before = baseline.get("fallow", {})
    after = current.get("fallow", {})
    before_summary = before.get("summary", {})
    after_summary = after.get("summary", {})
    # A static scan never runs Fallow: absent evidence is neither a version change nor findings gone.
    if after.get("status") == "skipped":
        return {"comparable": False, "kind": "not_run",
                "reason": "Fallow was not run (--no-checks); its cards are left as they were"}
    if before.get("status") == "skipped":
        return {"comparable": False, "kind": "baseline_not_run",
                "reason": "the baseline scan did not run Fallow (--no-checks); run hangover scan --rebaseline"}
    if before.get("version") != after.get("version"):
        return {"comparable": False, "kind": "version_changed", "reason": "Fallow version changed",
                "from": before.get("version"), "to": after.get("version")}
    if empty_analysis(after):
        return {"comparable": False, "kind": "empty_analysis",
                "reason": "Fallow analyzed no source files; absent findings prove nothing"}
    before_mode = fallow_dead_code_mode(before)
    after_mode = fallow_dead_code_mode(after)
    degradation = type_aware_degradation(after)
    if before_mode == "type-aware" and degradation:
        return {"comparable": False, "kind": "type_aware_degraded", "reason": f"dead-code analysis mode degraded: {degradation}"}
    if before_mode != after_mode:
        return {
            "comparable": False,
            "kind": "mode_changed",
            "reason": (
                "dead-code analysis mode changed "
                f"(baseline {before_mode}, current {after_mode})"
            ),
        }
    if before_summary.get("resolved_config_sha256") != after_summary.get(
        "resolved_config_sha256"
    ):
        return {"comparable": False, "kind": "config_changed", "reason": "resolved Fallow config changed"}

    def number(value: Any) -> float | None:
        return float(value) if isinstance(value, (int, float)) else None

    metrics = {
        "health_score": (
            number(before_summary.get("health_score")),
            number(after_summary.get("health_score")),
            "higher",
        ),
        "dead_code_issues": (
            number(before_summary.get("total_dead_code_issues")),
            number(after_summary.get("total_dead_code_issues")),
            "lower",
        ),
        "clone_groups": (
            number(before_summary.get("duplication", {}).get("clone_groups")),
            number(after_summary.get("duplication", {}).get("clone_groups")),
            "lower",
        ),
    }
    changes = {}
    for name, (old, new, direction) in metrics.items():
        if old is not None and new is not None:
            changes[name] = {
                "baseline": old,
                "current": new,
                "delta": round(new - old, 3),
                "direction": direction,
            }
    return {"comparable": True, "kind": "comparable", "changes": changes}


def _scan(
    repo: Path,
    *,
    kind: str = "scan",
    no_checks: bool = False,
    no_execute: bool = False,
    defer_checks: bool = False,
    quiet: bool = False,
    rebaseline: bool = False,
    rebaseline_reason: str = "explicit",
    checks_inherited_from: str | None = None,
    rebaseline_requires_absent: str | None = None,
    stale_exclusions: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    # --no-checks: git itself must run no driver the checkout configures
    # (git status runs clean filters); entering refuses when git cannot promise it.
    with no_execute_git(repo) if no_execute else contextlib.nullcontext():
        try:
            return _scan_guarded(
                repo, kind=kind, no_checks=no_checks, no_execute=no_execute, defer_checks=defer_checks,
                quiet=quiet, rebaseline=rebaseline, rebaseline_reason=rebaseline_reason,
                checks_inherited_from=checks_inherited_from, rebaseline_requires_absent=rebaseline_requires_absent,
                stale_exclusions=stale_exclusions,
            )
        except RepositoryRefusal as exc:
            _record_refused_scan(repo, kind, str(exc))
            raise


def _record_refused_scan(repo: Path, kind: str, refusal: str) -> None:
    """Note a scan hangover refused, without touching what a scan records.

    A refused scan merges no findings and is never the baseline or the latest run (its evidence is
    whatever hangover agreed to gather, so cards it did not see would go stale on no evidence).
    `refused_scan` stands until a scan completes, and status reports it as a tool error."""
    def record(state: dict[str, Any]) -> None:
        state["refused_scan"] = {"kind": kind, "at": now(), "refusal": refusal}
        add_history(state, "scan_refused", kind=kind, refusal=refusal)

    if paths(repo)["state"].is_file():
        mutate_state(repo, record)


def _scan_guarded(
    repo: Path,
    *,
    kind: str,
    no_checks: bool,
    no_execute: bool,
    defer_checks: bool,
    quiet: bool,
    rebaseline: bool,
    rebaseline_reason: str,
    checks_inherited_from: str | None,
    rebaseline_requires_absent: str | None,
    stale_exclusions: list[str] | None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    config = _config(repo)
    run_id = _run_id(kind)
    run_dir = _run_dir(repo, run_id)
    before_git = git_info(repo)
    repo_inventory = inventory(repo)
    if checks_inherited_from:
        checks = _snapshot(repo, checks_inherited_from).get("checks", [])
    else:
        checks = (
            []
            if no_checks or defer_checks
            else run_checks(repo, config.get("checks", []), run_dir, quiet=quiet)
        )
    state_before_scan = load_state(repo)
    baseline_run_before_scan = state_before_scan.get("baseline_run")
    baseline_before_scan = (
        _snapshot(repo, baseline_run_before_scan) if baseline_run_before_scan else None
    )
    inherited_dead_code_mode = (
        None
        if rebaseline or not baseline_before_scan
        else fallow_dead_code_mode(baseline_before_scan.get("fallow", {}))
    )
    plan = _analyzer_plan(repo, config, repo_inventory, execute_repository_code=not no_execute)
    if plan["fallow"]["run"]:
        progress("fallow: running", quiet=quiet)
        started = time.monotonic()
        fallow = run_fallow_scan(
            repo,
            run_dir,
            repo_inventory,
            dead_code_mode=inherited_dead_code_mode,
            **({"clock_epoch": epoch} if not rebaseline and baseline_before_scan
               and (epoch := fallow_clock(baseline_before_scan.get("fallow", {})).get("epoch_secs")) is not None else {}),
        )
        progress_result(
            "fallow",
            {
                "status": fallow.get("status"),
                "duration_seconds": time.monotonic() - started,
            },
            quiet=quiet,
            success_status=(
                "not_applicable"
                if fallow.get("status") == "not_applicable"
                else "completed"
            ),
            success_label="done",
        )
    else:
        fallow = _skipped_fallow(plan["fallow"]["status"], plan["fallow"].get("reason"))
        if fallow["status"] == "skipped":
            progress(f"fallow: skipped ({fallow['reason']})", quiet=quiet)
    rust = _run_rust(repo, run_dir, plan["rust"], quiet=quiet)
    if rust.get("refusal"):
        raise RepositoryRefusal(f"Rust analysis refused repository content: {rust['refusal']}")
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "id": run_id,
        "kind": kind,
        "created_at": now(),
        "repo": str(repo),
        "git": before_git,
        "git_after_commands": git_info(repo),
        "inventory": repo_inventory,
        "checks": checks,
        "fallow": fallow,
        "rust": rust,
        "analyzer_coverage": _analyzer_coverage(repo_inventory.get("files_by_suffix") or {}, fallow, rust),
    }
    if no_execute:
        if not no_execute_git_active():
            raise RuntimeError("internal: a no-execute scan ran git outside no_execute_git")
        snapshot["repository_code_executed"] = False
    if checks_inherited_from:
        snapshot["checks_inherited_from"] = checks_inherited_from
    if defer_checks:
        snapshot["checks_deferred"] = True
    findings = extract_fallow_findings(fallow, repo=repo) + extract_rust_findings(rust)
    snapshot["complexity_families_seen"] = [list(family) for family in sorted({
        tuple(finding["complexity_identity"]["family"]) for finding in findings if finding.get("complexity_identity")
    })]

    def record_scan(state: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        previous_run = state.get("baseline_run")
        baseline = _snapshot(repo, previous_run) if previous_run else None
        # A deferred scan has not run the checks yet, so there is nothing to
        # compare; the caller runs them next and fills the comparison in.
        snapshot["check_comparison"] = [] if defer_checks else compare_checks(
            baseline.get("checks", []) if baseline else [], checks
        )
        snapshot["fallow_comparison"] = _fallow_comparison(baseline, snapshot)
        snapshot["rust_comparison"] = rust_comparison(baseline, snapshot)
        reassign_duplication_fingerprints(state.get("issues", {}), findings)
        reset_blocker = None
        if rebaseline_requires_absent and rebaseline_requires_absent in {issue_id(f) for f in findings}:
            reset_blocker = f"Fallow still reports {rebaseline_requires_absent}"
        elif fallow.get("status") == "skipped":
            reset_blocker = "Fallow was not run (--no-checks), so this scan cannot be the baseline"
        elif fallow.get("status") not in {"completed", "disabled", "not_applicable"}:
            reset_blocker = "Fallow did not complete"
        elif empty_analysis(fallow):
            reset_blocker = "Fallow analyzed no source files"
        elif type_aware_degradation(fallow):
            reset_blocker = "type-aware evidence degraded: " + type_aware_degradation(fallow)
        elif rust.get("repository_code_executed") is False:
            reset_blocker = "Rust analysis ran without cargo (--no-checks), so this scan cannot be the baseline"
        elif rust.get("status") not in {"completed", "disabled", "not_applicable"}:
            reset_blocker = "Rust analysis did not complete"
        elif previous_run != baseline_run_before_scan:
            reset_blocker = "the baseline changed while Fallow was running"
        snapshot["rebaseline_evidence_accepted"] = bool(rebaseline and not reset_blocker)
        before_counts = dict(Counter(issue["status"] for issue in state.get("issues", {}).values()))
        merged = merge_findings(
            state,
            findings,
            run_id,
            scan_result=snapshot,
            repo=repo,
            stale_exclusions=stale_exclusions or [],
            obsolete_fallow_rules=fallow.get("disabled_finding_categories", {}),
        )
        seen = merged["ids"]
        snapshot["finding_ids_seen"] = seen
        snapshot["pre_scan_cards"] = merged.get("pre_scan", {})
        if merged.get("held"):
            snapshot["held_findings"] = merged["held"]
        snapshot["stale_count"] = merged["stale"]
        snapshot["obsolete_count"] = merged.get("obsolete", 0)
        if merged.get("identity_migrations"):
            snapshot["identity_migrations"] = merged["identity_migrations"]
        if rebaseline and not reset_blocker:
            state["baseline_run"] = run_id
            snapshot["is_baseline"] = True
            add_history(
                state,
                "baseline_reset",
                run=run_id,
                previous_run=previous_run,
                reason=rebaseline_reason,
            )
            before_version = (baseline or {}).get("fallow", {}).get("version")
            if before_version and before_version != fallow.get("version"):
                upgrade = {"from": before_version, "to": fallow.get("version"),
                           "mode": fallow_dead_code_mode(fallow),
                           "clock_epoch": fallow_clock(fallow).get("epoch_secs"),
                           "before_counts": before_counts,
                           "after_counts": dict(Counter(issue["status"] for issue in state.get("issues", {}).values()))}
                add_history(state, "analyzer_upgraded", run=run_id, **upgrade)
                snapshot["analyzer_upgraded"] = upgrade
        elif rebaseline and reset_blocker:
            snapshot["is_baseline"] = False
            snapshot["baseline_reset_blocked_reason"] = reset_blocker
        elif not previous_run:
            state["baseline_run"] = run_id
            snapshot["is_baseline"] = True
            add_history(state, "baseline_recorded", run=run_id)
        else:
            snapshot["is_baseline"] = False
        state["latest_run"] = run_id
        state.pop("refused_scan", None)
        add_history(state, kind, run=run_id, findings_seen=len(seen))
        try:
            write_json(run_dir / "snapshot.json", snapshot)
        except OSError as exc:
            # The snapshot is the record of this scan. If it cannot be saved the
            # mutation is abandoned, so name the evidence the run directory kept.
            retained = sorted(
                str(path.relative_to(run_dir))
                for path in run_dir.rglob("*")
                if path.is_file()
            )
            raise RuntimeError(
                f"could not save the scan snapshot ({exc}); "
                f"{run_dir} retains: " + (", ".join(retained) or "no artifacts")
            ) from exc
        return state, seen

    state, seen = mutate_state(repo, record_scan)
    return snapshot, state, seen


FALLOW_NOT_RUN_STATIC = (
    "static mode does not run Fallow on untrusted checkouts (it follows tsconfig chains, node_modules "
    "manifests and plugin files that can lead outside the checkout); once the checkout is trusted, "
    "`hangover scan --rebaseline` records the Fallow analysis"
)
RUST_NOT_EXECUTED = (
    "--no-checks: cargo was not run (it would compile the checkout and run its build scripts and proc "
    "macros as you), so clippy and cargo-machete findings are missing; once the checkout is trusted, "
    "`hangover scan --rebaseline` records the full analysis"
)


def _analyzer_plan(
    repo: Path, config: dict[str, Any], repo_inventory: dict[str, Any], *, execute_repository_code: bool = True,
) -> dict[str, dict[str, Any]]:
    """Which analyzers a command runs, and why the others do not.

    The one place scan, verify, audit and doctor decide this. ``run`` is the
    decision; a skipped analyzer carries the status its result records.
    ``execute_repository_code`` is False for an explicit ``--no-checks``: an
    analyzer that compiles or runs the checkout's own code is skipped then.
    Fallow does not run either (``skipped``, which is no failure): it follows
    tsconfig chains, node_modules manifests and plugin files in ways no
    precheck can bound to the checkout. Rust analysis then reads manifests and
    sources with the bundled ast-grep and jscpd and never starts cargo, rustup
    or clippy.
    """
    if not config.get("fallow", {}).get("enabled", True):
        fallow: dict[str, Any] = {"run": False, "status": "disabled"}
    elif not (repo_inventory.get("javascript") or repo_inventory.get("typescript")):
        fallow = {"run": False, "status": "not_applicable"}
    elif not execute_repository_code:
        fallow = {"run": False, "status": "skipped", "reason": FALLOW_NOT_RUN_STATIC}
    else:
        fallow = {"run": True}
    if not rust_applicable(repo):
        rust: dict[str, Any] = {"run": False, "status": "not_applicable"}
    elif not config.get("rust", {}).get("enabled", True):
        rust = {"run": False, "status": "disabled"}
    else:
        rust = {"run": True, "execute": execute_repository_code}
    return {"fallow": fallow, "rust": rust}


ANALYZER_LANGUAGES = {
    "fallow": ("TypeScript/JavaScript", JAVASCRIPT_SUFFIXES | TYPESCRIPT_SUFFIXES),
    "rust": ("Rust", frozenset({".rs"})),
}
ANALYZED_STATUSES = {"completed", "partial"}


def _reported_files(name: str, result: dict[str, Any]) -> int | None:
    """How many files the analyzer itself says it analyzed, when it says.

    Fallow's health summary (``health`` in a scan, ``complexity`` in an audit)
    counts the files left after its own config (``ignorePatterns`` and the
    like); Rust analysis reports the files of its Cargo workspace.
    """
    if name == "rust":
        value = (result.get("summary") or {}).get("files")
    else:
        health = ((result.get("commands") or {}).get("health") or {}).get("data")
        if not isinstance(health, dict):
            health = (((result.get("command") or {}).get("data") or {}).get("complexity"))
        value = ((health if isinstance(health, dict) else {}).get("summary") or {}).get("files_analyzed")
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _analyzer_coverage(
    files_by_suffix: dict[str, int], fallow: dict[str, Any], rust: dict[str, Any]
) -> dict[str, Any]:
    """Which source files a deterministic analyzer looked at, by language.

    The language files are counted from the inventory's file suffixes; what an
    analyzer analyzed is the count it reports (``files``, with ``files_basis``
    "reported"), and the rest of its language files are ``not_analyzed`` (its
    config excluded them, or it skipped them). An analyzer that ran without
    reporting a count leaves ``files`` None, basis "unreported": only its
    language support is known, and those files count as ``unknown_files``. An
    analyzer that did not run, or failed, covers nothing.
    """
    source = {suffix: count for suffix, count in files_by_suffix.items() if suffix in SOURCE_SUFFIXES and count}
    uncovered = dict(source)
    analyzers: dict[str, Any] = {}
    not_analyzed_total = unknown = 0
    for name, result in (("fallow", fallow), ("rust", rust)):
        language, suffixes = ANALYZER_LANGUAGES[name]
        present = sum(source.get(suffix, 0) for suffix in suffixes)
        status = (result or {}).get("status")
        if status not in ANALYZED_STATUSES:
            analyzers[name] = {"language": language, "status": status, "files": 0, "language_files": present,
                               "files_basis": "not_run", "not_analyzed": present}
            continue
        for suffix in suffixes:
            uncovered.pop(suffix, None)  # this analyzer's language; what it skipped is counted below
        reported = _reported_files(name, result or {})
        if reported is None:
            unknown += present
            analyzers[name] = {"language": language, "status": status, "files": None, "language_files": present,
                               "files_basis": "unreported", "not_analyzed": None}
            continue
        covered = min(present, reported)
        not_analyzed_total += present - covered
        analyzers[name] = {"language": language, "status": status, "files": covered, "language_files": present,
                           "files_basis": "reported", "not_analyzed": present - covered}
    uncovered = {suffix: count for suffix, count in sorted(uncovered.items(), key=lambda item: (-item[1], item[0])) if count}
    return {
        "source_files": sum(source.values()),
        "analyzers": analyzers,
        "uncovered_files": sum(uncovered.values()) + not_analyzed_total,
        "uncovered_by_suffix": uncovered,
        "unknown_files": unknown,
    }


def _snapshot_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    if isinstance(snapshot.get("analyzer_coverage"), dict):
        return snapshot["analyzer_coverage"]
    return _analyzer_coverage((snapshot.get("inventory") or {}).get("files_by_suffix") or {},
                              snapshot.get("fallow") or {}, snapshot.get("rust") or {})


def _coverage_lines(coverage: dict[str, Any], *, noun: str = "source files") -> list[str]:
    """Say which languages were analyzed, and how much nothing deterministic read."""
    total = coverage.get("source_files", 0)
    if not total:
        return [f"coverage: no {noun} found"]
    ran = []
    skipped = []
    unreported = []
    for name, item in coverage.get("analyzers", {}).items():
        if item.get("status") not in ANALYZED_STATUSES:
            continue
        files, present = item.get("files"), item.get("language_files", 0)
        if files is None:
            # A snapshot from before files_basis claimed the language count; say only what is known.
            ran.append(f"{item['language']} ({name} ran; it reported no file count, "
                       f"{present} file(s) in languages it supports)")
            unreported.append(name)
        elif files == present:
            ran.append(f"{item['language']} {files} file(s) ({name})")
        else:
            ran.append(f"{item['language']} {files} of {present} file(s) ({name})")
        if item.get("not_analyzed"):
            skipped.append(f"{name} did not analyze {item['not_analyzed']}, which its config excludes or it skipped")
    lines = ["analyzed: " + (", ".join(ran) if ran else "nothing (no deterministic analyzer ran)")]
    uncovered = coverage.get("uncovered_files", 0)
    unknown = coverage.get("unknown_files", 0)
    if uncovered:
        detail = [f"{suffix} {count}" for suffix, count in list(coverage.get("uncovered_by_suffix", {}).items())[:8]]
        lines.append(f"coverage: no deterministic analyzer covers {uncovered} of {total} {noun} "
                     f"({'; '.join(part for part in (', '.join(detail), *skipped) if part)}); only a model review reads them")
    if unknown:
        lines.append(f"coverage: unknown for {unknown} of {total} {noun} ({', '.join(unreported)} reported no count "
                     "of the files it analyzed)")
    if not uncovered and not unknown:
        lines.append(f"coverage: deterministic analyzers cover all {total} {noun}")
    return lines


def _skipped_fallow(status: str, reason: str | None = None) -> dict[str, Any]:
    """The scan result of a Fallow the plan does not run (the shapes earlier snapshots recorded).

    `skipped` (static mode) never starts the Fallow binary, not even for its version."""
    if status == "not_applicable":
        return {"status": status, "version": fallow_version(), "dead_code_mode": "syntactic", "commands": {}}
    return {"status": status, **({"reason": reason} if reason else {}), "commands": {}, "summary": {}}


def _rust_not_run(repo: Path, status: str) -> dict[str, Any]:
    """A Rust result the plan did not run; a Cargo.toml hangover was not pointed at is said, even under --quiet."""
    result: dict[str, Any] = {"status": status, "commands": {}, "findings": []}
    notice = rust_manifest_notice(repo) if status == "not_applicable" else None
    if notice:
        result["notice"] = notice
        print(f"hangover: {notice}", file=sys.stderr)
    return result


def _run_rust(repo: Path, run_dir: Path, plan: dict[str, Any], *, quiet: bool) -> dict[str, Any]:
    if not plan["run"]:
        return _rust_not_run(repo, plan["status"])
    execute = plan.get("execute", True)
    progress("rust: running" if execute else "rust: running without cargo (--no-checks)", quiet=quiet)
    started = time.monotonic()
    rust = run_rust_scan(repo, run_dir, progress=lambda line: progress(line, quiet=quiet), execute=execute)
    if not execute:
        rust["repository_code_executed"] = False
    progress_result("rust", {"status": rust.get("status"), "duration_seconds": time.monotonic() - started},
                    quiet=quiet, success_status="completed", success_label="done")
    return rust


def _print_rust(snapshot: dict[str, Any]) -> None:
    rust = snapshot.get("rust") or {}
    if rust.get("status") in {None, "not_applicable", "disabled"}:
        return
    if rust.get("repository_code_executed") is False:
        print(f"  rust: static analysis only ({RUST_NOT_EXECUTED})")
    summary = rust.get("summary") or {}
    counts = summary.get("by_category") or {}
    print(f"  rust: {rust.get('status')} | {summary.get('findings', 0)} findings"
          + (" (" + ", ".join(f"{category} {count}" for category, count in counts.items()) + ")" if counts else "")
          + (f" | {summary['suppressed']} suppressed" if summary.get("suppressed") else ""))
    for warning in rust.get("warnings") or []:
        print(f"  rust warning: {warning}")
    comparison = snapshot.get("rust_comparison") or {}
    if not snapshot.get("is_baseline") and comparison.get("comparable") is False and comparison.get("reason"):
        print(f"  rust baseline: not comparable — {comparison['reason']}; run hangover scan --rebaseline")


def _print_check_failure(check: dict[str, Any]) -> None:
    print(f"    failing stage: {check['name']} ({check.get('status')}, exit {check.get('exit_code')})")
    if check.get("log"):
        print(f"    log: {check['log']}")
    for line in failure_excerpt(check):
        print(f"    | {line}")


def _print_scan(snapshot: dict[str, Any]) -> None:
    label = "baseline" if snapshot.get("is_baseline") else snapshot["kind"]
    print(f"{label}: {snapshot['id']}")
    comparison = snapshot.get("fallow_comparison", {})
    if comparison.get("kind") == "version_changed" and not snapshot.get("rebaseline_evidence_accepted"):
        print("  ledger unchanged: Fallow version changed "
              f"({comparison.get('from')} -> {comparison.get('to')}); run hangover scan --rebaseline")
    if snapshot.get("analyzer_upgraded"):
        upgrade = snapshot["analyzer_upgraded"]
        print(f"  analyzer upgraded: {upgrade['from']} -> {upgrade['to']} | mode {upgrade['mode']} | clock {upgrade['clock_epoch']}")
    if snapshot.get("identity_migrations"):
        migrations = snapshot["identity_migrations"]
        for category in ("complexity", "duplication"):
            selected = [item for item in migrations if item.get("category", "complexity") == category]
            if selected:
                carried = sum(item.get("inherited_status") == "deferred" for item in selected)
                print(f"  native identities: {len(selected)} legacy {category} issue(s) refined; history retained"
                      + (f"; {carried} deferred ruling(s) carried forward" if carried else ""))
    held = snapshot.get("held_findings") or []
    if held:
        print(f"  identity migration held for {len(held)} finding(s): this scan cannot migrate, so no new card "
              "was created and their old cards stay as they were (not resolved, not re-seen)")
        for item in held[:10]:
            print(f"    {item['finding']} {item.get('title', '')} <- {', '.join(item['candidates'])}")
        if len(held) > 10:
            print(f"    ... {len(held) - 10} more in the run snapshot (held_findings)")
    for check in snapshot.get("checks", []):
        comparison = "baseline" if snapshot.get("is_baseline") else next(
            (
                item["classification"]
                for item in snapshot.get("check_comparison", [])
                if item["name"] == check["name"]
            ),
            "observed",
        )
        print(f"  {check['name']}: {check['status']} ({comparison})")
        if check.get("status") == "not_run":
            print(f"    not run: stopped after failing stage {check.get('skipped_after')}")
        elif check.get("status") != "passed":
            _print_check_failure(check)
    gate = snapshot.get("gate") or {}
    if gate.get("mode") == "reused":
        print(
            f"  gate: reused the passing gate of run {gate['from_run']} "
            "(identical tree and checks; --fresh-gate reruns it)"
        )
    elif gate.get("mode") == "partial":
        skipped = ", ".join(gate.get("checks_not_run", [])) or "none"
        print(
            f"  gate: PARTIAL proof; ran {', '.join(gate.get('checks_run', [])) or 'no checks'}; "
            f"not run: {skipped}"
        )
    elif gate.get("mode") == "not_run":
        print(f"  gate: not run ({gate.get('reason')})")
    elif gate.get("mode") == "model_only":
        print(f"  gate: NONE, model-only proof ({gate.get('reason') or MODEL_ONLY_REASON})")
    for stage in gate.get("pre_existing_failures", []):
        print(f"  gate: passed with pre-existing failure in {stage} (identical to the baseline's output)")
    if gate.get("reuse_disabled"):
        print(f"  gate: proof reuse disabled ({gate['reuse_disabled']})")
    if gate.get("not_recorded"):
        print(f"  gate: not recorded for reuse ({gate['not_recorded']})")
    if gate.get("stages_rediscovered"):
        print("  gate: stages re-discovered after the gate definition changed: "
              + ", ".join(gate["stages_rediscovered"]))
    fallow = snapshot.get("fallow", {})
    summary = fallow.get("summary", {})
    if fallow.get("status") == "skipped":
        print(f"  fallow: skipped ({fallow.get('reason') or FALLOW_NOT_RUN_STATIC})")
    elif fallow.get("status") not in {"not_applicable", "disabled"}:
        dead_code_issues = summary.get("total_dead_code_issues")
        dead_code_display = (
            "unavailable" if dead_code_issues is None else dead_code_issues
        )
        print(
            "  fallow: "
            f"{fallow.get('status')} | mode {fallow_dead_code_mode(fallow)} "
            f"| health {summary.get('health_score', '?')} "
            f"| dead {dead_code_display} "
            f"| clones {summary.get('duplication', {}).get('clone_groups', '?')}"
        )
        commands = fallow.get("commands", {})
        for name, command in commands.items():
            if command.get("status") == "completed":
                continue
            first_line = _fallow_error_line(command)
            print(
                f"  fallow {name.replace('_', '-')}: {command.get('status')} — "
                f"{first_line}"
            )
        dead_code = commands.get("dead_code", {})
        degradation = type_aware_degradation(fallow)
        if degradation:
            print(f"  warning: type-aware evidence degraded: {degradation}")
        if dead_code.get("fallback") == "type_aware_failed":
            print(
                "  fallow dead-code: type-aware sidecar failed "
                f"({dead_code.get('fallback_reason', 'unknown failure')}); "
                "findings come from the non-type-aware scan"
            )
        for disabled in fallow.get("disabled_rule_findings", []):
            print(
                "  warning: Fallow reported "
                f"{disabled['count']} finding(s) for disabled rule "
                f"{disabled['rule']}; excluded from hangover"
            )
        comparison = snapshot.get("fallow_comparison", {})
        if not snapshot.get("is_baseline") and comparison.get("comparable") is False and comparison.get("reason"):
            print(f"  fallow baseline: not comparable — {comparison['reason']}; run hangover scan --rebaseline")
        if fallow.get("dependency_analysis") == "incomplete":
            print("  warning: node_modules absent; dependency findings are incomplete")
    _print_rust(snapshot)
    if snapshot.get("analyzer_coverage") or snapshot.get("inventory"):
        for line in _coverage_lines(_snapshot_coverage(snapshot)):
            print(f"  {line}")
    if snapshot.get("stale_count"):
        print(
            f"  stale: {snapshot['stale_count']} issue(s) no longer reported "
            "(hangover status --stale to list)"
        )
    if snapshot.get("git", {}).get("changes") != snapshot.get("git_after_commands", {}).get(
        "changes"
    ):
        print("  warning: one or more configured commands changed the working tree")


def _active_batch_ids(state: dict[str, Any], primary: str) -> list[str]:
    record = active_remediation(state)
    if record is not None and record["primary"] == primary:
        return list(record["members"])
    batch = state.get("active_batch")
    if state.get("active_issue") == primary and isinstance(batch, list) and batch:
        return [str(identifier) for identifier in batch]
    return [primary]


def _review_result(
    repo: Path,
    state_name: str,
    review_id: str,
    review_plan: dict[str, Any] | None,
    issue_id: str | None,
    *,
    proof: dict[str, Any] | None = None,
    blockers: list[str] | None = None,
    verdict: str | None = None,
    merged: dict[str, Any] | None = None,
    next_action: str | None = None,
    batch: list[str] | None = None,
    import_step: dict[str, str] | None = None,
) -> DriverResult:
    """A review of a remediation checks its proof; an initial review has none.

    A reviewer that did not complete may have changed inputs after the proof
    was last checked, so a tool_error never reports the proof as checked.
    """
    data: dict[str, Any] = {"review": _review_route(repo, review_id, review_plan)}
    if verdict is not None:
        data["verdict"] = verdict
    if merged is not None:
        data["new_findings"] = merged["new"]
        data["already_tracked_findings"] = merged["already_tracked"]
    if import_step is not None:
        data["import"] = import_step
        directory = paths(repo)["runs"] / review_id
        data["review"]["schema"] = str(directory / "review-schema.json")
        data["review"]["prompt"] = str(directory / "review-prompt.md")
        data["review"]["verification_token"] = read_json(directory / "review-packet.json").get("verification_token")
    return DriverResult(
        command="review",
        state=state_name,
        repo=str(repo),
        run=proof["run"] if proof else None,
        proof=proof["id"] if proof else None,
        review_run=review_id,
        issue_id=issue_id,
        batch=list(batch or []),
        blockers=blockers or [],
        artifacts={"run_dir": str(paths(repo)["runs"] / review_id),
                   **({"coverage": str(paths(repo)["runs"] / review_id / "review-coverage.json")}
                      if (paths(repo)["runs"] / review_id / "review-coverage.json").is_file() else {})},
        proof_freshness=(
            "checked" if proof and state_name != "tool_error" else "not_checked"
        ),
        next_action=next_action,
        data=data,
    )


def _execute_review_runner(
    repo: Path, review_dir: Path, packet: Path, mode: str, settings: dict[str, Any],
    *, quiet: bool = False, prompt_path: Path | None = None,
) -> dict[str, Any]:
    """One runner dispatch for remediation and whole-change review."""
    runner, timeout = settings["runner"], settings["timeout_seconds"]
    lane = settings["delegate"]["lane"]
    model = settings["delegate"]["model"]
    reasoning_effort = settings["delegate"]["reasoning_effort"]
    prompt_arguments = {"prompt_path": prompt_path} if prompt_path else {}
    schema_path = TOOL_ROOT / "schemas" / "review.schema.json"
    progress(f"review: running ({runner})", quiet=quiet)
    started = time.monotonic()
    try:
        if runner == "codex":
            result = run_codex_review(repo, review_dir, packet, mode, timeout, **prompt_arguments)
        elif runner == "delegate":
            result = run_delegate_review(
                repo,
                review_dir,
                packet,
                mode,
                timeout,
                lane=lane,
                model=model,
                reasoning_effort=reasoning_effort,
                env=settings["env"],
                schema_path=schema_path,
                **prompt_arguments,
            )
        else:
            result = run_command_review(
                repo,
                review_dir,
                packet,
                mode,
                settings["command"],
                timeout,
                schema_path=schema_path,
                **prompt_arguments,
                env=settings["env"],
            )
    except Exception:
        progress_result(
            "review",
            {
                "status": "error",
                "duration_seconds": time.monotonic() - started,
            },
            quiet=quiet,
            success_status="completed",
            success_label="done",
            timeout_seconds=timeout,
        )
        raise
    progress_result(
        "review",
        result,
        quiet=quiet,
        success_status="completed",
        success_label="done",
        timeout_seconds=timeout,
    )
    result["runner"] = runner
    if runner == "delegate":
        result["lane"] = lane
        result["model"] = model
        result["reasoning_effort"] = reasoning_effort
        reported = result.get("reported_route") or {}
        for field in ("engine", "model", "reasoning_effort"):
            expected, actual = settings["preflight"].get(field), reported.get(field)
            if result["status"] == "completed" and isinstance(expected, str) and isinstance(actual, str):
                same = expected.casefold() == actual.casefold() if field == "reasoning_effort" else expected == actual
                if not same:
                    result.update(status="route_mismatch", error=f"Delegate {field} changed after preflight; refusing approval", review=None)
                    break
    return result


def _route_arguments(plan: dict[str, Any]) -> list[str]:
    arguments = ["--runner", plan["runner"]]
    if plan["runner"] == "delegate":
        for field in ("lane", "model", "reasoning_effort"):
            value = plan["delegate"].get(field)
            if value:
                arguments.extend(["--" + field.replace("_", "-"), value])
    return arguments


def _review(
    repo: Path,
    *,
    issue_id: str | None = None,
    prepare_only: bool = False,
    import_path: Path | None = None,
    runner_override: str | None = None,
    lane_override: str | None = None,
    model_override: str | None = None,
    reasoning_effort_override: str | None = None,
    snapshot: dict[str, Any] | None = None,
    quiet: bool = False,
    review_plan: dict[str, Any] | None = None,
    as_json: bool = False,
    emit_result: bool = False,
    origin: Origin | None = None,
    scope_paths: list[str] | None = None,
    expected_proof: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | None, str]:
    # A machine-facing caller owns stdout; this command's prose goes to stderr.
    # verify passes as_json to claim stdout and reports the outcome itself;
    # emit_result is set only when review is the top-level command.
    prose = sys.stderr if as_json else sys.stdout
    origin = origin or Origin(command="review", repo=str(repo))
    if issue_id and scope_paths:
        raise RuntimeError("--scope cannot narrow a post-fix review; its entire change and batch must be reviewed")
    review_scope = select_scope(repo, scope_paths) if not issue_id else None
    config = _config(repo)
    review_settings = review_plan or resolve_review(
        repo, _review_settings(config), runner=runner_override, lane=lane_override,
        model=model_override, reasoning_effort=reasoning_effort_override,
        execute=not prepare_only and import_path is None,
    )
    state = load_state(repo)
    if not state.get("latest_run"):
        raise RuntimeError("no scan exists; run `hangover scan` first")
    issue = state.get("issues", {}).get(issue_id) if issue_id else None
    if issue_id and not issue:
        raise RuntimeError(f"unknown issue {issue_id}")
    batch_ids = _active_batch_ids(state, issue_id) if issue else []
    if issue:
        issue = {
            **issue,
            "batch_issues": [state["issues"][identifier] for identifier in batch_ids],
        }
        origin.issue_id = issue_id
        origin.batch = list(batch_ids)
    mode = "post_fix" if issue else "initial"
    runner = review_settings["runner"]
    proof = None
    pending = None
    before_patch = after_patch = None
    if issue:
        proof = require_proof(repo, state, issue_id, _fallow_path(), expected_proof)
        origin.run, origin.proof = proof["run"], proof["id"]
        snapshot = _snapshot(repo, proof["run"])
        before_patch = paths(repo)["runs"] / proof["run"] / "before.patch"
        after_patch = paths(repo)["runs"] / proof["run"] / "after.patch"
        if import_path:
            pending = active_remediation(state).get("pending_review")
            if (not isinstance(pending, dict) or pending.get("consumed")
                    or pending.get("proof") != proof["id"]
                    or not isinstance(pending.get("token"), str)):
                raise RuntimeError("no pending review token; prepare a review of the current verification proof first")
            failed_output = pending.get("rejected_import_path")
            if isinstance(failed_output, str):
                failed_path = Path(failed_output)
                same_output = import_path.resolve() == failed_path.resolve()
                if import_path.is_file() and failed_path.is_file():
                    same_output = same_output or import_path.samefile(failed_path)
                same_output = same_output or _is_rejected_content(import_path, pending)
                if same_output:
                    raise RuntimeError("failed runner output cannot be imported; a fresh reviewer must write a separate artifact")
            review = import_review(import_path, mode)
            if review.get("verification_token") != pending["token"]:
                raise RuntimeError("manual review must carry the verification_token from its prepared packet")
            packet = run_artifact(repo, pending["id"], "review-packet.json")
    else:
        snapshot = snapshot or _snapshot(repo, state["latest_run"])
    review_id = _run_id("post-review" if issue else "review")
    origin.review_run = review_id
    review_dir = _run_dir(repo, review_id)
    origin.artifacts["review_dir"] = str(review_dir)
    if not (issue and import_path):
        token = uuid4().hex if issue else None
        packet = prepare_review_packet(
            repo, review_dir, mode, snapshot, issue=issue,
            before_patch=before_patch, after_patch=after_patch,
            verification_token=token,
            review_scope=review_scope,
        )
        if issue:
            pending = {
                "id": review_id, "token": token, "proof": proof["id"], "consumed": False,
                "artifacts": {name: file_digest(review_dir / name) for name in REVIEW_ARTIFACTS},
            }

            def bind_review(current: dict[str, Any]) -> None:
                require_proof(repo, current, issue_id, _fallow_path(), proof)
                active_remediation(current)["pending_review"] = pending

            mutate_state(repo, bind_review)
    if prepare_only or (runner == "none" and not import_path):
        record = {
            "id": review_id,
            "status": "prepared",
            "mode": mode,
            "packet": str(packet),
            "runner": runner,
            "preflight": review_settings["preflight"],
            "requested_review": review_settings["requested"],
        }
        write_json(review_dir / "review-run.json", record)

        def record_prepared(current: dict[str, Any]) -> None:
            add_history(current, "review_prepared", run=review_id, issue=issue_id)
            if not issue_id:
                # A post-fix packet is retained by its remediation's pending_review; an
                # initial one by this record, until it is imported or a newer packet
                # of the same scope supersedes it.
                current.setdefault("prepared_reviews", {})[_prepared_review_key(scope_paths)] = review_id

        mutate_state(repo, record_prepared)
        print(f"review packet: {packet}", file=prose)
        print(f"review prompt: {review_dir / 'review-prompt.md'}", file=prose)
        print(f"review schema: {review_dir / 'review-schema.json'}", file=prose)
        next_action, import_step = _import_step(repo, review_id, issue_id, scope_paths)
        if pending:
            print(f"verification_token: {pending['token']}", file=prose)
        print(f"next: a fresh read-only reviewer reads {review_dir / 'review-prompt.md'} "
              f"and writes schema-conforming JSON to {import_step['path']}", file=prose)
        print(f"import with: {next_action}", file=prose)
        if emit_result:
            _review_result(
                repo, "review_pending", review_id, review_settings, issue_id,
                proof=proof, batch=batch_ids,
                next_action=next_action, import_step=import_step,
            ).emit()
        return 0, None, review_id

    if import_path:
        if not issue:
            review = import_review(import_path, mode)
        write_json(review_dir / "review.json", review)
        result = {
            "status": "completed",
            "packet": str(packet),
            "output": str(review_dir / "review.json"),
            "review": review,
            "runner": "import",
        }
    else:
        result = _execute_review_runner(repo, review_dir, packet, mode, review_settings, quiet=quiet)
    result["preflight"] = review_settings["preflight"]
    result["requested_review"] = review_settings["requested"]
    if review_scope is not None:
        result["scope"] = {"kind": review_scope["kind"], "requested": review_scope["requested"],
                           "selected_count": len(review_scope["files"]),
                           "unselected_count": len(review_scope["unselected_files"])}
        if result["status"] == "completed" and result.get("review"):
            coverage = assess_scope(review_scope, result["review"])
            write_json(run_artifact(repo, review_id, "review-coverage.json"),
                       {"scope": review_scope, "coverage": coverage})
            result["coverage"] = {"evidence": coverage["evidence"], "exhaustive": False,
                                  "reported_count": len(coverage["reported_files"]),
                                  "remaining_selected_count": len(coverage["remaining_selected_files"]),
                                  "unselected_count": len(coverage["unselected_files"]),
                                  "limitation": coverage["limitation"]}
    write_json(review_dir / "review-run.json", {key: value for key, value in result.items() if key != "review"})
    if result["status"] != "completed" or not result.get("review"):
        def record_failure(current: dict[str, Any]) -> None:
            add_history(current, "review_failed", run=review_id, issue=issue_id, status=result["status"])
            remediation = active_remediation(current) if issue_id else None
            current_pending = remediation.get("pending_review") if remediation else None
            if isinstance(current_pending, dict) and current_pending.get("id") == review_id:
                current_pending["rejected_import_path"] = result.get("output", str(review_dir / "review.json"))
                _reject_content(current_pending, Path(current_pending["rejected_import_path"]))

        mutate_state(repo, record_failure)
        print(f"review: tool_error/unverifiable ({result['status']}); "
              f"{result.get('error') or 'review did not complete'}; packet retained at {packet}", file=sys.stderr)
        if emit_result:
            _review_result(
                repo, "tool_error", review_id, review_settings, issue_id,
                proof=proof, batch=batch_ids,
                blockers=[_review_failure_blocker(result["status"], result.get("error"))],
                next_action=command_line(
                    repo, "review", *(["--issue", issue_id] if issue_id else []),
                    *(part for path in scope_paths or [] for part in ("--scope", path)),
                    *_route_arguments(review_settings),
                ),
            ).emit()
        return 2, None, review_id

    review = result["review"]
    source = "post-review" if issue else "subjective-review"
    findings = review_findings(review, source, issue_id)

    def record_review(
        current: dict[str, Any],
    ) -> tuple[dict[str, Any], str | None]:
        if issue_id:
            require_proof(repo, current, issue_id, _fallow_path(), proof)
            validate_note_assessments(review, active_remediation(current)["fix_notes"])
            current_pending = active_remediation(current).get("pending_review")
            if current_pending != pending or current_pending.get("consumed"):
                raise RuntimeError("review token was superseded or consumed; refusing stale review")
            # Every post-fix review echoes its packet's token, automated runners
            # included: a stale, cached or packet-blind reviewer output cannot close
            # this attempt, whichever route delivered it.
            supplied_token = review.get("verification_token")
            if supplied_token is None:
                raise RuntimeError("review returned no verification_token; a post-fix review must echo "
                                   "the token from its packet, so this output cannot close the remediation")
            if supplied_token != pending["token"]:
                raise RuntimeError("review returned a different verification_token")
            if (not isinstance(pending.get("artifacts"), dict)
                    or set(pending["artifacts"]) != set(REVIEW_ARTIFACTS)):
                raise RuntimeError("incomplete prepared review artifacts; prepare a new review")
            for name, checksum in pending["artifacts"].items():
                if file_digest(run_artifact(repo, pending["id"], name)) != checksum:
                    raise RuntimeError("prepared review artifact changed; refusing stale review")
        merged = merge_findings(current, findings, review_id)
        seen = merged["ids"]
        current["latest_review"] = review_id
        if not issue_id and import_path and isinstance(current.get("prepared_reviews"), dict):
            source = _run_holding(repo, import_path)
            current["prepared_reviews"] = {
                key: value for key, value in current["prepared_reviews"].items() if value != source}
        add_history(
            current,
            "review_completed",
            run=review_id,
            issue=issue_id,
            verdict=review["verdict"],
            findings=len(seen),
            new=merged["new"],
            already_tracked=merged["already_tracked"],
            **({"scope": result["scope"], "coverage": result["coverage"],
                "coverage_artifact": str(review_dir / "review-coverage.json")} if review_scope is not None else {}),
        )
        conflict = None
        if issue_id and review["verdict"] == "pass" and snapshot.get("kind") == "verify":
            conflict = _active_fix_conflict(current, issue_id, "review", "resolve")
            if not conflict:
                blockers = _batch_verification_blockers(
                    current, issue_id, snapshot, snapshot.get("finding_ids_seen", [])
                )
                if not blockers:
                    current_pending["consumed"] = True
                    current_pending["review_run"] = review_id
                    _resolve_superseded_post_review_findings(
                        current, issue_id, seen, snapshot["id"], review_id
                    )
                    _resolve_side_effect_fallow_issues(
                        current,
                        issue_id,
                        snapshot.get("side_effect_candidate_ids", []),
                        snapshot["id"],
                        complexity_families=snapshot.get("complexity_families_seen", []),
                        fallow=snapshot.get("fallow", {}),
                    )
                    for batch_id in _active_batch_ids(current, issue_id):
                        resolve_issue(
                            current,
                            batch_id,
                            snapshot["id"],
                            review_id,
                            review.get("declared_changes_assessed", []),
                        )
        return merged, conflict

    merged, conflict = mutate_state(repo, record_review)
    print(
        f"review: {review['verdict']} | {merged['new']} new, "
        f"{merged['already_tracked']} already tracked | {review_id}",
        file=prose,
    )
    if conflict:
        if emit_result:
            _review_result(
                repo, "tool_error", review_id, review_settings, issue_id,
                proof=proof, batch=batch_ids, blockers=[conflict],
                verdict=review["verdict"], merged=merged,
                next_action=command_line(repo, "status"),
            ).emit()
        print(f"hangover: {conflict}", file=sys.stderr)
        return 2, review, review_id
    resolved = bool(
        issue_id
        and load_state(repo).get("issues", {}).get(issue_id, {}).get("status")
        == "resolved"
    )
    if issue_id and review["verdict"] != "pass":
        # fail and partial alike: only a pass approves a remediation.
        state_name, blockers = "blocked", [_refusal_blocker(review)]
    elif resolved:
        state_name, blockers = "resolved", []
    else:
        # An initial review's verdict describes the code it read; its findings
        # are the backlog it adds, not a refusal of anything.
        state_name, blockers = "passed", []
    if emit_result:
        _review_result(
            repo, state_name, review_id, review_settings, issue_id, proof=proof,
            batch=batch_ids, blockers=blockers, verdict=review["verdict"],
            merged=merged,
            next_action=(
                command_line(repo, "fix", issue_id) if state_name == "blocked" and issue_id
                else command_line(repo, "next")
            ),
        ).emit()
    return 0, review, review_id


def _refusal_blocker(review: dict[str, Any], *, fresh: bool = False) -> str:
    """Name the verdict and the reviewer's summary: a partial is a refusal, not a quiet pass."""
    summary = str(review.get("summary") or "no summary").strip()
    return (f"the {'fresh ' if fresh else ''}review did not approve the remediation "
            f"(verdict {review.get('verdict')}: {summary[:300]})")


def _resolve_superseded_post_review_findings(
    state: dict[str, Any],
    parent_issue: str,
    current_findings: list[str],
    verify_run: str,
    review_run: str,
) -> None:
    failed_runs = {
        entry.get("run")
        for entry in state.get("history", [])
        if entry.get("event") == "review_completed"
        and entry.get("issue") == parent_issue
        and entry.get("verdict") != "pass"
    }
    for candidate in state.get("issues", {}).values():
        if (
            candidate["id"] not in current_findings
            and candidate.get("source") == "post-review"
            and candidate.get("status") in {"open", "reopened"}
            and (
                candidate.get("parent_issue") == parent_issue
                or candidate.get("last_seen_run") in failed_runs
            )
        ):
            resolve_issue(state, candidate["id"], verify_run, review_run)


def _resolve_side_effect_fallow_issues(
    state: dict[str, Any], primary: str, candidates: list[str], verify_run: str,
    *, complexity_families: list[list[str]] | None = None,
    fallow: dict[str, Any] | None = None,
) -> None:
    index = degrading_index(fallow or {})  # once, not per candidate
    for identifier in candidates:
        issue = state.get("issues", {}).get(identifier)
        if (
            issue
            and issue.get("source") in {"fallow", "rust"}
            and issue.get("status") in {"open", "reopened", "stale"}
        ):
            if caveat_reasons(fallow or {}, issue.get("files", []), index):
                continue
            identity = issue.get("complexity_identity") or {}
            if identity.get("ambiguous") and identity.get("family") in (complexity_families or []):
                continue
            resolve_issue_by(state, identifier, primary, verify_run)


def _fix_packet_result(
    repo: Path,
    packet: dict[str, Any],
    primary: str,
    batch_ids: list[str],
    *,
    proof: dict[str, Any] | None,
    resumed: bool,
) -> DriverResult:
    """The run and proof are the ones this invocation started from or resumed.

    A fresh start has no proof by construction; a resume reports the proof its
    own starting read found. Neither consults state written after the start,
    so a verify that lands while the packet is being written is not reported
    as this command's origin.
    """
    artifacts = {"fix_dir": packet["issue"]["fix_dir"], "before_patch": packet["before_patch"]}
    artifacts["fix_packet"] = str(Path(artifacts["fix_dir"]) / "fix-packet.json")
    if proof:
        artifacts["proof_run"] = str(paths(repo)["runs"] / proof["run"])
    return DriverResult(
        command="fix",
        state="in_progress",
        repo=str(repo),
        run=proof["run"] if proof else packet.get("latest_run"),
        proof=proof["id"] if proof else None,
        issue_id=primary,
        batch=list(batch_ids),
        artifacts=artifacts,
        next_action=command_line(repo, "verify", "--issue", primary),
        data={"packet": packet, "resumed": resumed},
    )


def _disposition_result(
    repo: Path, action: str, issues: list[str], reason: str | None
) -> DriverResult:
    """Report the disposition, then what the campaign still offers."""
    remaining = next_issue(load_state(repo))
    return DriverResult(
        command="fix",
        state="ready" if remaining else "no_open_work",
        repo=str(repo),
        run=remaining.get("last_seen_run") if remaining else None,
        issue_id=remaining["id"] if remaining else None,
        next_action=(
            command_line(repo, "fix", remaining["id"]) if remaining else command_line(repo, "scan")
        ),
        data={"action": action, "issues": issues, "reason": reason},
    )


def _begin_fix(
    repo: Path,
    identifiers: list[str],
    defer_reason: str | None,
    obsolete_reason: str | None,
    release: bool = False,
    as_json: bool = False,
    branch: str | None = None,
    add: bool = False,
) -> int:
    identifier = identifiers[0] if identifiers else None
    if add and (release or defer_reason or obsolete_reason or branch):
        raise RuntimeError("--add cannot combine with --release, --defer, --obsolete or --branch")
    if branch is not None and not SAFE_BRANCH.fullmatch(branch):
        raise RuntimeError(f"invalid branch name {branch!r}")
    if branch and (release or defer_reason or obsolete_reason):
        raise RuntimeError("--branch applies only when starting a batch")
    if add:
        if len(identifiers) < 2:
            raise RuntimeError("--add takes the batch's primary first, then the ids to add")
        mutate_state(repo, lambda state: add_to_batch(state, identifiers[0], identifiers[1:]))
    if release:
        if not identifiers:
            raise RuntimeError("--release requires explicit issue ids")

        mutate_state(repo, lambda state: release_issues(state, identifiers))
        released = list(dict.fromkeys(identifiers))
        if as_json:
            _disposition_result(repo, "released", released, None).emit()
            return 0
        for candidate_id in released:
            print(f"released {candidate_id} from the active batch")
        return 0
    if defer_reason:
        def defer_selected(state: dict[str, Any]) -> list[str]:
            selected = identifiers or ([next_issue(state)["id"]] if next_issue(state) else [])
            if len(selected) > 1:
                for candidate_id in selected:
                    issue = state.get("issues", {}).get(candidate_id)
                    if not issue:
                        raise RuntimeError(f"unknown issue {candidate_id}")
                    if issue.get("status") == "in_progress":
                        raise RuntimeError(f"issue {candidate_id} is in_progress; refusing disposition")
                    if issue.get("status") not in {"open", "reopened"}:
                        raise RuntimeError(f"issue {candidate_id} is {issue.get('status')}; cannot defer")
            for candidate_id in selected:
                defer_issue(state, candidate_id, defer_reason)
            return selected

        deferred = mutate_state(repo, defer_selected)
        if as_json:
            _disposition_result(repo, "deferred", deferred, defer_reason).emit()
            return 0
        if not deferred:
            print("no open issues")
            return 0
        for candidate_id in deferred:
            print(f"deferred {candidate_id}: {defer_reason}")
        return 0

    if obsolete_reason:
        def obsolete_selected(state: dict[str, Any]) -> list[str]:
            selected = identifiers or ([next_issue(state)["id"]] if next_issue(state) else [])
            for candidate_id in selected:
                issue = state.get("issues", {}).get(candidate_id)
                if not issue:
                    raise RuntimeError(f"unknown issue {candidate_id}")
                if len(selected) > 1 and issue.get("status") == "in_progress":
                    raise RuntimeError(f"issue {candidate_id} is in_progress; refusing disposition")
                if len(selected) > 1 and issue.get("status") not in {"open", "reopened"}:
                    raise RuntimeError(f"issue {candidate_id} is {issue.get('status')}; cannot mark obsolete")
                if issue.get("source") in {"fallow", "rust"}:
                    raise RuntimeError(
                        f"issue {candidate_id}: {issue['source'].capitalize()} issues are governed by `hangover scan`; "
                        "rescan after removing their files"
                    )
            for candidate_id in selected:
                obsolete_issue(state, candidate_id, obsolete_reason)
            return selected

        obsolete = mutate_state(repo, obsolete_selected)
        if as_json:
            _disposition_result(repo, "obsolete", obsolete, obsolete_reason).emit()
            return 0
        if not obsolete:
            print("no open issues")
            return 0
        for candidate_id in obsolete:
            print(f"obsolete {candidate_id}: {obsolete_reason}")
        return 0

    starting_state = load_state(repo)
    selected = (
        starting_state.get("issues", {}).get(identifier)
        if identifier
        else next_issue(starting_state)
    )
    if identifier and not selected:
        raise DriverError(f"unknown issue {identifier}; `hangover list` shows the tracked issues",
                          next_action=command_line(repo, "list"))
    if not selected:
        if as_json:
            DriverResult(
                command="fix",
                state="no_open_work",
                repo=str(repo),
                next_action=command_line(repo, "scan"),
                data={"packet": None},
            ).emit()
            return 0
        print("no open issues")
        return 0
    selected_id = selected["id"]
    if (selected.get("status") == "in_progress" and starting_state.get("active_issue") != selected_id
            and any(record["primary"] == selected_id for record in open_batches(starting_state))):
        # Resuming a parked batch makes it the one single-batch commands act on.
        mutate_state(repo, lambda state: focus_remediation(state, selected_id))
        starting_state = load_state(repo)
    if selected.get("status") == "in_progress" and starting_state.get("active_issue") == selected_id:
        if branch:
            raise RuntimeError("a branch is recorded when the batch starts; release it to restart with --branch")
        batch_ids = _active_batch_ids(starting_state, selected_id)
        if len(identifiers) > 1 and identifiers != batch_ids and not add:
            raise RuntimeError(
                "cannot replace an active batch; release members explicitly first "
                "(or extend it with `hangover fix <primary> <ids...> --add`)"
            )
        conflict = _active_fix_conflict(starting_state, selected_id, "fix resume", "resume")
        if conflict:
            raise RuntimeError(conflict)
        fix_dir = _fix_directory(repo, selected)
        packet = read_json(_fix_artifact(fix_dir, "fix-packet.json"))
        packet.update(
            issue=selected,
            issues=[starting_state["issues"][candidate] for candidate in batch_ids],
            resumed=True,
        )
        packet = compact_fix_packet(packet)
        if add:
            write_json(fix_dir / "fix-packet.json", packet)
        if as_json:
            _fix_packet_result(
                repo, packet, selected_id, batch_ids,
                proof=_recorded_proof(starting_state, selected_id), resumed=True,
            ).emit()
            return 0
        print(json.dumps(packet, indent=2))
        return 0
    batch_ids = identifiers or [selected_id]
    for batch_id in batch_ids:
        if not SAFE_ISSUE_ID.fullmatch(batch_id):
            raise RuntimeError(f"invalid issue id in state: {batch_id!r}")
    fix_base_commit = git_info(repo).get("commit")
    fix_dir = paths(repo)["fixes"] / selected_id / datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ"
    )
    fix_dir.mkdir(parents=True, exist_ok=False)
    before = fix_dir / "before.patch"
    capture_patch(repo, before)

    def start_fix(state: dict[str, Any]) -> dict[str, Any]:
        issue = state.get("issues", {}).get(selected_id)
        if not issue:
            raise RuntimeError("no open issues remain")
        latest = _snapshot(repo, state["latest_run"]) if state.get("latest_run") else {}
        issue = begin_fix(
            state,
            issue["id"],
            state.get("latest_run"),
            fix_base_commit,
            batch_ids[1:],
            fix_dir=str(fix_dir),
            finding_ids=latest.get("finding_ids_seen", []),
            branch=branch,
        )
        finish = (f"Commit on branch {branch} and stop; the coordinator proves it after merging with "
                  "`hangover verify --merged` (read-only commands work from a worktree: "
                  "`hangover list --state-from <main checkout>`)."
                  if branch else f"Finish with `hangover verify --issue {issue['id']}`.")
        packet = fix_packet(
            state, repo, issue, [state["issues"][batch_id] for batch_id in batch_ids],
            fix_base_commit, str(before), finish,
            **({"branch": branch} if branch else {}),
        )
        return packet

    packet = mutate_state(repo, start_fix)
    write_json(fix_dir / "fix-context.json", packet)
    packet = compact_fix_packet(packet)
    write_json(fix_dir / "fix-packet.json", packet)
    if as_json:
        _fix_packet_result(
            repo, packet, selected_id, batch_ids, proof=None, resumed=False
        ).emit()
        return 0
    print(json.dumps(packet, indent=2))
    return 0


def _check_packet_destination(out: Path, checkouts: list[Path], force: bool) -> None:
    """Refuse a destination that could overwrite campaign state or git metadata, or an existing file."""
    target = out.expanduser().resolve()  # follows symlinks; a new file resolves through its parent
    protected: set[Path] = set()
    for checkout in checkouts:
        roots = {checkout, *( [main] if (main := _worktree_context(checkout)[1]) else [])}
        for root in roots:
            protected |= {(root / ".hangover").resolve(), (root / ".git").resolve()}
        for flag in ("--git-common-dir", "--git-dir"):
            found = git(checkout, "rev-parse", "--path-format=absolute", flag)
            if found.returncode == 0:
                protected.add(Path(found.stdout.strip()).resolve())
    for guarded in protected:
        if target == guarded or target.is_relative_to(guarded):
            raise RuntimeError(f"refusing to write a packet inside {guarded}; choose another --out")
    if target.exists() and not force:
        raise RuntimeError(f"{target} already exists; pass --force to overwrite it")


def _packet(repo: Path, identifiers: list[str], out: Path | None, as_json: bool,
            invoked: Path | None = None, force: bool = False) -> int:
    """Write a fix packet for a set of cards without activating anything.

    The membership rules are the ones `fix` applies, so a packet can only name
    a batch that `fix` would accept right now; the batch itself is registered
    later by whoever coordinates (`hangover fix <ids> --branch <name>`).
    """
    if not identifiers:
        raise RuntimeError("packet requires explicit issue ids")
    for identifier in identifiers:
        if not SAFE_ISSUE_ID.fullmatch(identifier):
            raise RuntimeError(f"invalid issue id: {identifier!r}")
    if out is not None:
        _check_packet_destination(out, [repo, *([invoked] if invoked else [])], force)
    state = load_state(repo)
    check_batch_candidates(state, identifiers)
    members = [state["issues"][identifier] for identifier in identifiers]
    packet = compact_fix_packet(fix_packet(
        state, repo, members[0], members, git_info(repo).get("commit"), None,
        "Make the change on your own branch and commit it; do not run `hangover fix` or `hangover verify` "
        "from a worktree. The coordinator registers the batch and proves it after merging.",
        activated=False,
    ))
    text = json.dumps(packet, indent=2) + "\n"
    if out is None:
        print(text, end="")
        return 0
    out.write_text(text)
    if as_json:
        DriverResult(command="packet", state="ready", repo=str(repo), issue_id=identifiers[0],
                     batch=list(identifiers), data={"packet": str(out), "activated": False}).emit()
        return 0
    print(f"wrote packet for {len(identifiers)} card(s) to {out}")
    return 0


FALLOW_READ_ONLY = frozenset({
    "dead-code", "dupes", "health", "flags", "security", "similar-code", "audit", "list", "inspect", "trace",
    "trace-error", "guard", "decision-surface", "workspaces", "explain", "suppressions", "doctor", "config",
    "config-schema", "plugin-schema", "plugin-check", "rule-pack-schema", "type-aware", "schema", "help",
})
FALLOW_MUTATING = frozenset({
    "fix", "watch", "init", "agent", "audit-cache", "recommend", "migrate", "rule-pack", "ci", "ci-template",
    "report", "hooks", "setup-hooks", "coverage", "license", "telemetry", "viz", "impact",
})
FALLOW_WRITE_FLAGS = ("--fix", "--yes", "--write", "--apply", "--force", "--save", "--update", "--output-file",
                      "--sarif-file", "--summary-file")


def _fallow_refusal(arguments: list[str]) -> str | None:
    """Why these arguments may not run: hangover fallow is read-only evidence, never a mutator."""
    for argument in arguments:
        if argument in ("--root", "-r") or argument.startswith(("--root=", "-r=")) or (
                argument.startswith("-r") and not argument.startswith("--")):
            return "hangover fallow fixes --root to this checkout; run `hangover --repo PATH fallow -- ...` to analyze another"
        if argument == "-y" or argument.startswith(FALLOW_WRITE_FLAGS) or (
                argument.startswith("-o") and not argument.startswith("--")):
            return f"hangover fallow is read-only; {argument} writes or applies changes"
    mutating = next((a for a in arguments if a in FALLOW_MUTATING), None)
    if mutating:
        return f"hangover fallow is read-only; `fallow {mutating}` is not allowed (allowed: analysis and inspection commands)"
    # Allowlist too: the command is the first word that is not a flag's value; it must be a known
    # read-only command (or absent, for the bare combined analysis), so an unlisted command cannot run.
    previous = None
    for argument in arguments:
        if not argument.startswith("-") and not (previous and previous.startswith("-") and "=" not in previous):
            if argument not in FALLOW_READ_ONLY:
                return (f"hangover fallow is read-only; `fallow {argument}` is not an allowed command "
                        f"(allowed: {', '.join(sorted(FALLOW_READ_ONLY))})")
            break
        previous = argument
    return None


def _fallow_passthrough(repo: Path, arguments: list[str]) -> int:
    """Run the pinned Fallow against this checkout, as hangover's own scans run it."""
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    refusal = _fallow_refusal(arguments)
    if refusal:
        raise RuntimeError(refusal)
    binary = _fallow_path()
    if not binary:
        raise RuntimeError("Fallow is not installed; run `npm install` in the hangover checkout")
    actual = fallow_version()
    if actual != f"fallow {FALLOW_VERSION}":
        raise RuntimeError(f"expected fallow {FALLOW_VERSION}, got {actual or 'an unreadable version'}")
    environment = {**git_safe_environment(), "npm_config_loglevel": "error"}
    environment.pop("FALLOW_CLOCK_EPOCH", None)
    return subprocess.run([str(binary), "--root", str(repo), *arguments], cwd=repo, env=environment,
                          check=False).returncode


def _worktree_context(repo: Path) -> tuple[bool, Path | None]:
    """(is a linked worktree, its main checkout when that can be determined)."""
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    own = git(repo, "rev-parse", "--path-format=absolute", "--git-dir")
    if common.returncode or own.returncode or common.stdout.strip() == own.stdout.strip():
        return False, None
    listing = git(repo, "worktree", "list", "--porcelain", "-z")
    if listing.returncode:
        return True, None
    first: list[str] = []
    for token in listing.stdout.split("\0"):
        if not token:
            break  # an empty field ends the first record
        first.append(token)
    main = next((token[len("worktree "):] for token in first if token.startswith("worktree ")), None)
    if main is None or "bare" in first or not Path(main).is_dir():
        return True, None
    return True, Path(main).resolve()


def _suppress(
    repo: Path,
    identifier: str,
    reason: str,
    *,
    rebaseline: bool = True,
    quiet: bool = False,
) -> int:
    def suppress(state: dict[str, Any]) -> tuple[str, str, str]:
        issue = state.get("issues", {}).get(identifier)
        if not issue:
            raise RuntimeError(f"unknown issue {identifier}")
        if issue.get("status") == "suppressed":
            return "already", "", ""
        if issue.get("status") == "resolved":
            raise RuntimeError(f"issue {identifier} is already resolved; nothing to suppress")
        recipe = issue.get("suppression")
        if not recipe:
            raise RuntimeError(
                f"issue {identifier} carries no analyzer config suppression recipe; "
                "run `hangover scan` to refresh imported findings, or the category has no config-keyed remedy"
            )
        config_key, value = recipe["config_key"], recipe["value"]
        if issue.get("source") == "rust":
            try:
                policy_path = add_rust_suppression(repo, value)
            except OSError as exc:
                raise RuntimeError(f"could not update {RUST_POLICY_FILE}: {exc}") from exc
            suppress_issue(state, identifier, reason, policy_path.name)
            return "suppressed", config_key, value
        jsonc_path = repo / ".fallowrc.jsonc"
        config_path = repo / ".fallowrc.json"
        if config_path.is_symlink() or not config_path.resolve().is_relative_to(repo):
            raise RuntimeError(f"refusing symlinked or external Fallow config: {config_path}")
        if jsonc_path.exists() and not config_path.exists():
            raise RuntimeError(
                f"{jsonc_path} is JSONC, which hangover will not rewrite; "
                f"add {value!r} to {config_key!r} there yourself, then rescan"
            )
        text = read_repo_file(repo, config_path.name, purpose="Fallow config")
        if text is not None:
            try:
                config = json.loads(text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{config_path} is not valid JSON; fix it before suppressing") from exc
            if not isinstance(config, dict):
                raise RuntimeError(f"{config_path} must contain a JSON object")
        else:
            config = {}
        target = config
        leaf = config_key
        if config_key == "duplicates.ignoredClones":
            target = config.setdefault("duplicates", {})
            if not isinstance(target, dict):
                raise RuntimeError(f"{config_path} key 'duplicates' is not an object; fix it before suppressing")
            leaf = "ignoredClones"
        values = target.setdefault(leaf, [])
        if not isinstance(values, list):
            raise RuntimeError(
                f"{config_path} key {config_key!r} is not a list; fix it before suppressing"
            )
        if value not in values:
            values.append(value)
            try:
                write_json(config_path, config)
            except OSError as exc:
                raise RuntimeError(f"could not update {config_path}: {exc}") from exc
        suppress_issue(state, identifier, reason, config_path.name)
        return "suppressed", config_key, value

    action, config_key, value = mutate_state(repo, suppress)
    if action == "already":
        print(f"{identifier} is already suppressed")
        return 0
    analyzer = "Rust" if load_state(repo)["issues"][identifier].get("source") == "rust" else "Fallow"
    config_path = repo / (RUST_POLICY_FILE if analyzer == "Rust" else ".fallowrc.json")
    print(f"suppressed {identifier}: {config_key} += {value!r} in {config_path}")
    if not rebaseline:
        print(f"{analyzer} config changed; run hangover scan --rebaseline before the next verify")
        return 0

    previous_run = load_state(repo).get("baseline_run")
    if not previous_run:
        print(f"no {analyzer} baseline exists; run hangover scan --rebaseline before the next verify")
        return 1
    snapshot, _, _ = _scan(
        repo,
        kind="suppression",
        quiet=quiet,
        rebaseline=True,
        rebaseline_reason="suppression",
        checks_inherited_from=previous_run,
        rebaseline_requires_absent=identifier,
    )
    if snapshot.get("is_baseline"):
        print(
            f"{analyzer} baseline reset: {snapshot['id']} "
            f"(checks inherited from {previous_run})"
        )
        return 0
    print(
        f"{snapshot.get('baseline_reset_blocked_reason', 'suppression could not be verified')}; "
        f"baseline remains {previous_run}"
    )
    return 1


def _active_fix_conflict(
    state: dict[str, Any], identifier: str, phase: str, action: str
) -> str | None:
    active_issue = state.get("active_issue")
    for batch_id in _active_batch_ids(state, identifier):
        issue = state.get("issues", {}).get(batch_id)
        status = issue.get("status") if issue else "missing"
        if status != "in_progress" or active_issue != identifier:
            return (
                f"issue {batch_id} changed during {phase} "
                f"(status={status}, active_issue={active_issue}); refusing to {action}"
            )
    return None


KNOWN_CARD_STATUSES = frozenset({"open", "reopened", "deferred", "in_progress"})


def _introduced_line(identifier: str, card: dict[str, Any] | None, before: dict[str, Any] | None = None) -> str:
    """One line saying what the new card is; complexity cards say old -> new metrics.

    `before` is the card as it stood just before this scan's merge, so the old
    side is what was recorded then, not an older history event.
    """
    if not card:
        return identifier
    metrics = card.get("complexity_metrics")
    if card.get("category") != "complexity" or not isinstance(metrics, dict):
        return f"{identifier}: {card.get('title', 'untitled finding')}"
    # Fallow measures cyclomatic and cognitive; Rust (clippy) cognitive, lines and arguments.
    recorded = (before or {}).get("metrics")
    names = [name for name in ("cyclomatic", "cognitive", "line_count", "arguments") if f"max_{name}" in metrics
             and (name in metrics or name in (recorded if isinstance(recorded, dict) else {}))]

    def show(values: dict[str, Any]) -> str:
        return ", ".join(f"{name.replace('_count', 's')} {values.get(name, '?')}" for name in names)
    old = show(recorded) if isinstance(recorded, dict) else "not previously tracked"
    limits = "/".join(str(metrics.get(f"max_{name}", "?")) for name in names)
    return f"{identifier}: {card.get('title', 'complexity')}: {old} -> {show(metrics)} (thresholds {limits})"


def _verification_blockers(
    snapshot: dict[str, Any], issue: dict[str, Any], seen: list[str],
    cards: dict[str, Any] | None = None, blame: Any = None,
) -> list[str]:
    blockers = []
    member = snapshot.get("dead_code_query", {}).get("members", {}).get(issue["id"])
    if member and member["status"] not in {"gone", "not applicable"}:
        blockers.append(f"{issue['id']}: dead-code {member['status']}: {member['reason']}")
    caveat_files = set(snapshot.get("changed_files", [])) | set(issue.get("files", []))
    blockers.extend(caveat_reasons(snapshot.get("fallow", {}), caveat_files))
    if snapshot.get("verification_inputs_changed"):
        blockers.append("verification inputs changed during native checks or analysis; rerun verification on stable inputs")
    fix_base_commit = issue.get("fix_base_commit")
    if fix_base_commit and snapshot.get("fix_base_commit_exists") is False:
        blockers.append(f"fix base commit {fix_base_commit} no longer exists")
    diff = snapshot.get("diff_check")
    if isinstance(diff, dict) and diff.get("status") != "passed":
        blockers.append(
            f"git diff --check {diff.get('status')}; fix the whitespace errors it lists "
            f"({diff.get('log')})"
        )
    blockers.extend(
        [
            f"native check {item['name']} regressed"
            for item in snapshot.get("check_comparison", [])
            if item["classification"]
            in {"regression", "incomparable", "unbaselined_failure", "not_run"}
        ]
    )
    if issue.get("source") == "fallow" and issue["id"] in seen:
        blockers.append("the original Fallow finding is still present")
    if issue.get("source") == "rust" and issue["id"] in seen:
        blockers.append("the original Rust finding is still present")
    identity = issue.get("complexity_identity") or {}
    if (identity.get("ambiguous") and issue["id"] not in seen
            and identity.get("family") in snapshot.get("complexity_families_seen", [])):
        blockers.append(
            f"{issue['id']} has an ambiguous complexity identity and its family "
            "still has same-name findings; release/reselect it or address the "
            "whole family"
        )
    if "fix_finding_ids" in issue:
        waived = {waiver["id"] for waiver in issue.get("waivers", [])}
        pre_scan = snapshot.get("pre_scan_cards") or {}
        started = issue.get("fix_started_at")

        def known(identifier: str) -> bool:
            # A card that was open, reopened or deferred before this fix began was
            # tracked work that merely was not reported at fix start (a function
            # back over its threshold, say). A card created after the fix began,
            # such as one an earlier failed verify introduced, stays introduced.
            record = pre_scan.get(identifier) or {}
            first_seen = record.get("first_seen")
            return (record.get("status") in KNOWN_CARD_STATUSES and bool(started)
                    and isinstance(first_seen, str) and first_seen <= started)

        introduced = sorted(identifier for identifier in set(seen) - set(issue["fix_finding_ids"]) - waived
                            if not known(identifier))
        if blame is not None:
            # One verify over several batches: an introduced finding blocks the
            # batches whose files it touches, and every batch when it touches none.
            introduced = [item for item in introduced if blame(item, (cards or {}).get(item))]
        if introduced:
            blockers.append(
                "the fix introduced new deterministic finding(s): " + ", ".join(introduced)
            )
            # One line per card, after the summary so its `...: id, id` shape is unchanged.
            blockers.extend(f"introduced {_introduced_line(item, (cards or {}).get(item), pre_scan.get(item))}" for item in introduced)
    fallow_status = snapshot.get("fallow", {}).get("status")
    fallow_required = (
        issue.get("source") == "fallow"
        or fallow_status not in {"not_applicable", "disabled"}
    )
    if fallow_required and fallow_status != "completed":
        blockers.append("Fallow did not complete, so deterministic resolution is unverified")
    fallow_comparison = snapshot.get("fallow_comparison", {})
    if fallow_required and not fallow_comparison.get("comparable", False):
        reason = fallow_comparison.get("reason", "unknown reason")
        blockers.append(
            "Fallow evidence is not comparable with the recorded baseline "
            f"({reason}); run hangover scan --rebaseline"
        )
    rust = snapshot.get("rust") or {}
    if rust.get("status") not in {None, "not_applicable", "disabled"}:
        if rust.get("status") != "completed":
            failed = ", ".join(f"{name} {status}" for name, status in (rust.get("sections") or {}).items()
                               if status not in {"completed", "unavailable"})
            blockers.append(f"Rust analysis did not complete ({failed or rust.get('status')}), so deterministic resolution is unverified")
        rust_comparison_result = snapshot.get("rust_comparison") or {}
        if not rust_comparison_result.get("comparable", False):
            blockers.append(
                "Rust evidence is not comparable with the recorded baseline "
                f"({rust_comparison_result.get('reason', 'unknown reason')}); run hangover scan --rebaseline"
            )
    elif issue.get("source") == "rust":
        blockers.append("Rust analysis did not run, so the Rust finding's resolution is unverified")
    return blockers


def _blame_for(snapshot: dict[str, Any], primary: str) -> Any:
    """Which introduced findings count against this batch, when one verify covers several.

    The snapshot carries the files each batch's branch changed. A finding whose
    files meet none of them cannot be attributed and counts against every batch.
    """
    touched = (snapshot.get("attribution") or {}).get("touched")
    if not isinstance(touched, dict) or primary not in touched:
        return None
    union = {path for files in touched.values() for path in files}
    own = set(touched[primary])

    def blame(_identifier: str, card: dict[str, Any] | None) -> bool:
        files = {str(path) for path in (card or {}).get("files") or []}
        return not files & union or bool(files & own)

    return blame


def _batch_verification_blockers(
    state: dict[str, Any], primary: str, snapshot: dict[str, Any], seen: list[str],
) -> list[str]:
    blame = _blame_for(snapshot, primary)
    batch_ids = _active_batch_ids(state, primary)
    blockers: list[str] = []
    shared: set[str] = set()
    for identifier in batch_ids:
        issue = state.get("issues", {}).get(identifier)
        if not issue:
            blockers.append(f"{identifier}: issue is missing")
            continue
        for blocker in _verification_blockers(snapshot, issue, seen, state.get("issues", {}), blame=blame):
            if blocker in {"the original Fallow finding is still present", "the original Rust finding is still present"}:
                blockers.append(f"{identifier}: {blocker}")
            elif blocker not in shared:
                blockers.append(blocker)
                shared.add(blocker)
    return blockers


def _verify_artifacts(repo: Path, run_id: str) -> dict[str, str]:
    run_dir = paths(repo)["runs"] / run_id
    return {"run_dir": str(run_dir), "snapshot": str(run_dir / "snapshot.json")}


def _review_failure_blocker(status: str, error: Any, *, fresh: bool = False) -> str:
    """Name why the review did not complete, preferring the adapter's diagnostic.

    The adapter's error is already bounded and terminal-safe; the packet path is
    reported alongside in data.review, so the blocker carries the reason.
    """
    which = "the fresh review" if fresh else "the review"
    blocker = f"{which} did not complete (status={status})"
    if isinstance(error, str) and error.strip():
        blocker += f": {error.strip()}"
    return blocker + "; its packet is retained"


def _review_route(
    repo: Path, review_id: str | None, review_plan: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Report the route that was actually resolved and what the adapter said.

    reported_route and error are passed through only when the adapter supplies
    them; a model is never inferred from reviewer prose.
    """
    route: dict[str, Any] = {}
    if review_plan:
        route["requested_review"] = review_plan["requested"]
        route["preflight"] = review_plan["preflight"]
    if review_id:
        record_path = run_artifact(repo, review_id, "review-run.json")
        if record_path.is_file():
            record = read_json(record_path)
            for field in (
                "status", "runner", "lane", "model", "reasoning_effort", "packet",
                "output", "preflight", "requested_review", "reported_route", "error", "scope", "coverage",
            ):
                if field in record:
                    route[field] = record[field]
    return route or None


def _refresh_gate_stages(repo: Path, *, quiet: bool) -> list[str] | None:
    """Re-discover saved gate stages when the gate they were read from has changed.

    A stage list saved at init is only a reading of the gate as it was then. If
    the gate script or package script has changed, running the old list and
    calling it the gate would be a false full proof, so the config is updated
    from a fresh reading before anything is hashed or run.
    """
    config = _config(repo)
    checks = config.get("checks", [])
    stale = adopted_drift(repo, checks)
    if stale:
        raise DriverError(
            "adopted gate stages are stale: " + ", ".join(stale)
            + " changed since the stages were adopted; re-adopt them with "
            "`hangover init --stages-from-gate` or edit .hangover/config.json",
            next_action=command_line(repo, "init", "--stages-from-gate"),
        )
    fresh = stage_drift(repo, checks)
    if fresh is None:
        return None
    names = {check["name"] for check in fresh}
    config["checks"] = [*fresh, *(c for c in checks if not c.get("stage_of") and c["name"] not in names)]
    write_json(paths(repo)["config"], config)
    listed = [check["name"] for check in fresh]
    progress(
        "gate: the gate definition changed since init; re-discovered stages: "
        + (", ".join(listed) or "none")
        + " (config updated; `hangover scan --rebaseline --checks` records them in the baseline)",
        quiet=quiet,
    )
    return listed


BLOCKING_CHECK_CLASSES = {"regression", "incomparable", "unbaselined_failure", "not_run"}
MODEL_ONLY_REASON = "no checks are configured; the analyzers and the model review alone decide (--model-only)"


def _require_gate_or_model_only(
    repo: Path, checks: list[dict[str, Any]], identifier: str, *, model_only: bool, affected: bool
) -> None:
    """A proof that resolves an item needs the repository's own gate, or an explicit opt-out.

    With no configured checks, "the gate passes and a reviewer agrees" would
    quietly become "a reviewer agrees". verify refuses that unless the operator
    says --model-only, and the proof then says so wherever it is shown.
    """
    if affected:
        return
    if not checks and not model_only:
        raise DriverError(
            "no checks are configured (.hangover/config.json `checks` is empty), so nothing of the repository's "
            "own would test this change and it would resolve on the model review alone; add the repository's "
            "test and lint commands to `checks`, or pass --model-only to accept a model-only proof",
            next_action=command_line(repo, "verify", "--issue", identifier, "--model-only"),
        )
    if checks and model_only:
        raise DriverError(
            "--model-only applies only when no checks are configured; this repository has "
            f"{len(checks)} configured check(s), and verify runs them",
            next_action=command_line(repo, "verify", "--issue", identifier),
        )


def _gate_phase(
    repo: Path,
    state: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    affected: bool,
    fresh_gate: bool,
    quiet: bool,
) -> None:
    """Run (or reuse) the configured checks for a verify run and record them on its snapshot.

    Full mode runs every check in order and stops at the first failure that
    blocks (a failure identical to the baseline's does not stop it, so later
    stages still get proved). A passing gate is reused only for a byte-identical
    tree and check config. `affected` runs the checks marked narrow and labels
    the result partial; it never reads or records a reusable gate proof.
    """
    configured = _config(repo).get("checks", [])
    baseline_run = state.get("baseline_run")
    baseline_checks = _snapshot(repo, baseline_run).get("checks", []) if baseline_run else []
    run_dir = paths(repo)["runs"] / snapshot["id"]
    if affected:
        selected = [check for check in configured if check.get("narrow") is True]
        ran = [check["name"] for check in selected]
        baseline_checks = [item for item in baseline_checks if item.get("name") in set(ran)]
        gate: dict[str, Any] = {
            "mode": "partial",
            "checks_run": ran,
            "checks_not_run": [check["name"] for check in configured if check not in selected],
        }
        progress(
            f"gate: partial proof (--affected): running {', '.join(ran) or 'no checks'}; "
            f"not running {', '.join(gate['checks_not_run']) or 'nothing'}",
            quiet=quiet,
        )
    elif not configured:
        # Reached only with --model-only: nothing of the repository's own ran.
        selected = []
        gate = {"mode": "model_only", "reason": MODEL_ONLY_REASON}
        progress(f"gate: none ({MODEL_ONLY_REASON})", quiet=quiet)
    else:
        selected = configured
        gate = {"mode": "full"}
    key = None
    reused = None
    if not affected and configured:
        try:
            key = gate_key(repo, configured)
        except RuntimeError as exc:
            gate["reuse_disabled"] = str(exc)
            progress(f"gate: proof reuse disabled ({exc}); running fresh", quiet=quiet)
        if key and not fresh_gate:
            reused = find_gate_proof(repo, key)
    if reused:
        checks = [{**item, "reused_from": reused["run"]} for item in reused["checks"]]
        gate = {"mode": "reused", "from_run": reused["run"], "key": key, "reused": True}
        progress(
            f"gate: reusing the passing gate of run {reused['run']} (identical tree and checks)",
            quiet=quiet,
        )
    else:
        if key:
            # A fresh run supersedes any older pass for this exact state, even if it fails.
            invalidate_gate_proof(repo, key)

        declared = {check["name"] for check in selected if check.get("stage_of")}

        def blocks(result: dict[str, Any]) -> bool:
            # Only a declared chain (split gate or adopted stages) stops early; separately
            # discovered scripts are independent checks and all run.
            return result["name"] in declared and compare_checks(
                baseline_checks, [result]
            )[0]["classification"] in BLOCKING_CHECK_CLASSES

        if selected and not affected:
            progress(
                f"gate: running {len(selected)} check(s) in order ({', '.join(c['name'] for c in selected)}); "
                "stops at the first blocking failure",
                quiet=quiet,
            )
        checks = run_checks(repo, selected, run_dir, quiet=quiet, stop_when=blocks)
        stopped = next((item.get("skipped_after") for item in checks if item.get("status") == "not_run"), None)
        if stopped:
            gate["stopped_after"] = stopped
        if key and checks and all(item.get("status") == "passed" for item in checks):
            try:
                # Recorded only when the gate left every key input as it found it.
                if gate_key(repo, configured) == key:
                    record_gate_proof(repo, key, snapshot["id"], checks)
                else:
                    gate["not_recorded"] = "the gate changed its own inputs (tree, index or ignored files)"
                    progress(f"gate: not recorded for reuse ({gate['not_recorded']})", quiet=quiet)
            except RuntimeError as exc:
                gate["reuse_disabled"] = str(exc)
    snapshot["checks"] = checks
    snapshot["check_comparison"] = compare_checks(baseline_checks, checks)
    pre_existing = [
        item["name"] for item in snapshot["check_comparison"] if item["classification"] == "pre_existing_failure"
    ]
    if pre_existing:
        gate["pre_existing_failures"] = pre_existing
    snapshot["gate"] = gate
    snapshot["git_after_commands"] = git_info(repo)


def _clone_shared_scan(repo: Path, scan: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Give a later batch its own run directory holding the shared cheap-phase evidence."""
    source = scan["snapshot"]
    run_id = _run_id("verify")
    run_dir = paths(repo)["runs"] / run_id
    shutil.copytree(paths(repo)["runs"] / source["id"], run_dir,
                    ignore=shutil.ignore_patterns("before.patch", "after.patch", "snapshot.json", RUN_LEASE))
    _take_run_lease(run_dir)
    snapshot = {**copy.deepcopy(source), "id": run_id, "shared_scan_from": source["id"]}
    write_json(run_dir / "snapshot.json", snapshot)
    return snapshot, load_state(repo), list(scan["seen"])


class SharedEvidenceChanged(RuntimeError):
    """The tree, baseline, policy or tools moved after the shared evidence was gathered."""


def _shared_inputs(repo: Path, state: dict[str, Any]) -> dict[str, Any]:
    """The batch-independent inputs a shared scan and gate result are only valid for."""
    baseline = state.get("baseline_run")
    return {**repository_inputs(repo, _fallow_path()),
            "baseline": [baseline, file_digest(run_artifact(repo, baseline, "snapshot.json"))]}


def _pin_branch(repo: Path, branch: str | None) -> tuple[str | None, str]:
    """The branch's commit now, or why there is none. The commit, not the name, is what is verified."""
    if not branch:
        return None, "no branch recorded"
    for name in (f"refs/heads/{branch}", branch):
        resolved = git(repo, "rev-parse", "--verify", "--quiet", f"{name}^{{commit}}")
        if resolved.returncode == 0:
            return resolved.stdout.strip(), "pinned"
    return None, f"branch {branch} not found"


def commit_in_head(repo: Path, commit: str) -> bool | None:
    result = git(repo, "merge-base", "--is-ancestor", commit, "HEAD")
    return result.returncode == 0 if result.returncode in (0, 1) else None


NOT_INCLUDED = ("is not an ancestor of HEAD: not merged yet, or merged by squash or rebase, which hangover "
                "does not recognise because it does not guess equivalence; use a merge commit or fast-forward")


def _batch_touched(repo: Path, record: dict[str, Any], pin: str | None) -> list[str] | None:
    """Files the batch changed: its pinned commit's diff from the base, else the tree's; None if unknown."""
    base = record.get("fix_base_commit")
    if not base:
        return None
    if pin:
        diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--name-only", f"{base}...{pin}", "--")
        return sorted(filter(None, diff.stdout.splitlines())) if diff.returncode == 0 else None
    return sorted(set(changed_files(repo, base)))


def _mark_stale_shared_evidence(repo: Path, record_ids: list[str], reason: str) -> None:
    """Record an explicit terminal outcome for every batch the stopped run did not finish."""
    def mark(current: dict[str, Any]) -> None:
        for record_id in record_ids:
            record = current.get("remediations", {}).get(record_id)
            if record is None or record_id not in open_remediation_ids(current):
                continue
            record["verification"] = {"id": uuid4().hex, "status": "stale_shared_evidence", "reason": reason}
            record["pending_review"] = None
            for member in record["members"]:
                add_issue_event(current["issues"][member], "stale_shared_evidence", reason=reason)
            add_history(current, "stale_shared_evidence", issue=record["primary"], reason=reason)
    mutate_state(repo, mark)


def _verify_open_batches(repo: Path, scope: str, *, as_json: bool, origin: Origin, **options: Any) -> int:
    """One verify over every open batch whose branch is merged (`merged`) or all open batches (`all`).

    The cheap phase and the gate run once, for the first batch that gets that
    far, and later batches reuse the result only while the tree, baseline,
    policy and tools are exactly what they were; each batch still gets its own
    proof and its own fresh review. Each branch is pinned to one commit at
    selection; that commit decides inclusion and attribution, is recorded in
    the proof, and must still be in HEAD when the batch closes. Introduced
    findings count against the batches whose pinned commit touched their
    files, and against all when unattributable. Under `all`, a batch with no
    branch is proven by the tree alone, as a plain verify does.
    """
    # A state from before remediation records has its one batch attached here, under the lock.
    mutate_state(repo, lambda current: ensure_remediation(current)
                 if current.get("active_issue") and not current.get("active_remediation") else None)
    state = load_state(repo)
    records = open_batches(state)
    if not records:
        raise DriverError("no open batches; start one with `hangover fix <issue> --branch <name>`",
                          next_action=command_line(repo, "fix"))
    selected: list[tuple[dict[str, Any], str | None]] = []
    skipped: list[dict[str, str]] = []
    for record in records:
        branch = record.get("branch")
        pin, why = _pin_branch(repo, branch)
        if branch and pin is None:
            skipped.append({"batch": record["primary"], "reason": why})
        elif pin and commit_in_head(repo, pin) is not True:
            skipped.append({"batch": record["primary"], "reason": f"branch {branch} ({pin[:12]}) {NOT_INCLUDED}"})
        elif not branch and scope == "merged":
            skipped.append({"batch": record["primary"], "reason": why})
        else:
            selected.append((record, pin))
    if not selected:
        raise DriverError(
            "no open batch can be verified against HEAD ("
            + "; ".join(f"{item['batch']}: {item['reason']}" for item in skipped)
            + ")",
            next_action=command_line(repo, "verify", "--merged"),
        )
    touched = {record["primary"]: _batch_touched(repo, record, pin) for record, pin in selected}
    attribution = None if any(files is None for files in touched.values()) else {"touched": touched}
    shared: dict[str, Any] = {"attribution": attribution}
    notes = [f"{record['primary']}: no branch recorded; proven by the tree alone"
             for record, pin in selected if scope == "all" and not record.get("branch")]
    outcomes: list[dict[str, Any]] = []
    worst = 0
    with collect_results() as collected:
        for index, (record, pin) in enumerate(selected):
            record_id = record["id"]

            def focus(current: dict[str, Any]) -> str | None:
                if record_id not in open_remediation_ids(current):
                    return None
                focus_remediation(current, record_id)
                return current["active_issue"]

            primary = mutate_state(repo, focus)
            if primary is None:
                continue
            shared["pin"] = {"branch": record.get("branch"), "commit": pin} if pin else None
            before = len(collected)
            stop = False
            try:
                code = _verify(repo, primary, shared=shared, as_json=as_json,
                               origin=Origin(command="verify", repo=str(repo)), **options)
            except RuntimeError as exc:
                print(f"hangover: {primary}: {exc}", file=sys.stderr)
                code = 2
                collected.append(Origin(command="verify", repo=str(repo)).tool_error(str(exc)).payload())
                stop = isinstance(exc, SharedEvidenceChanged)
                stale_reason = str(exc)
            worst = max(worst, code)
            outcomes.append({"batch": primary, "exit": code, "result": collected[before:][-1] if len(collected) > before else None})
            if stop:
                # Evidence gathered for the first batch no longer describes this tree; re-run.
                unfinished = [later["id"] for later, _ in selected[index:]]
                _mark_stale_shared_evidence(repo, unfinished, stale_reason)
                for later, _ in selected[index + 1:]:
                    skipped.append({"batch": later["primary"], "reason": "stale_shared_evidence: re-run"})
                break
    verdicts = [(item["batch"], (item["result"] or {}).get("state")
                 or ("passed" if item["exit"] == 0 else f"failed (exit {item['exit']})")) for item in outcomes]
    if as_json:
        blockers = [f"{batch}: {line}" for item in outcomes
                    for batch in [item["batch"]] for line in (item["result"] or {}).get("blockers", [])]
        states = {state_name for _, state_name in verdicts}
        aggregate = ("tool_error" if "tool_error" in states or worst >= 2 else
                     "blocked" if blockers or "blocked" in states or worst == 1 else
                     "review_pending" if "review_pending" in states else
                     "in_progress" if "in_progress" in states else "resolved")
        DriverResult(
            command="verify", state=aggregate, repo=str(repo), batch=[item["batch"] for item in outcomes],
            blockers=blockers or (["a batch did not verify; see data.batches"] if aggregate in {"blocked", "tool_error"} else []),
            next_action=command_line(repo, "verify", "--all" if scope == "all" else "--merged"),
            data={"batches": [item["result"] for item in outcomes], "skipped": skipped, "notes": notes,
                  "scope": scope, "shared_scan": (shared.get("scan") or {}).get("snapshot", {}).get("id")},
        ).emit()
        return exit_code(aggregate)
    for batch, state_name in verdicts:
        print(f"batch {batch}: {state_name}")
    for item in skipped:
        print(f"skipped {item['batch']}: {item['reason']}")
    for note in notes:
        print(f"note {note}")
    return worst


def _verify(
    repo: Path,
    identifier: str | None,
    no_review: bool,
    runner_override: str | None = None,
    lane_override: str | None = None,
    model_override: str | None = None,
    reasoning_effort_override: str | None = None,
    accept_ids: list[str] | None = None,
    accept_reason: str | None = None,
    notes: list[str] | None = None,
    note_files: list[Path] | None = None,
    quiet: bool = False,
    as_json: bool = False,
    origin: Origin | None = None,
    retry_review: bool = False,
    affected: bool = False,
    fresh_gate: bool = False,
    shared: dict[str, Any] | None = None,
    model_only: bool = False,
) -> int:
    origin = origin or Origin(command="verify", repo=str(repo))
    if affected and (retry_review or fresh_gate):
        raise DriverError("--affected cannot combine with --retry-review or --fresh-gate",
                          next_action=command_line(repo, "verify", *(["--issue", identifier] if identifier else [])))
    if retry_review and (no_review or accept_ids or accept_reason or notes or note_files):
        raise DriverError("cannot combine --retry-review with notes, waivers, or --no-review",
                          next_action=command_line(repo, "verify", *(["--issue", identifier] if identifier else [])))
    state = load_state(repo)
    identifier = identifier or state.get("active_issue")
    if not identifier:
        raise DriverError(
            "no active issue; run `hangover fix <issue>` first",
            next_action=command_line(repo, "fix"),
        )
    issue = state.get("issues", {}).get(identifier)
    if not issue or issue.get("status") != "in_progress":
        raise RuntimeError(f"issue {identifier} is not in progress")
    if state.get("active_issue") != identifier:
        raise RuntimeError(
            f"issue {identifier} is a batch companion; verify primary "
            f"{state.get('active_issue')} instead"
        )
    batch_ids = _active_batch_ids(state, identifier)
    origin.issue_id, origin.batch = identifier, list(batch_ids)
    fix_dir = _fix_directory(repo, issue)
    expected_attempt = attempt_identity(state)
    note_texts = list(notes or [])
    for note_file in note_files or []:
        try:
            note_texts.append(note_file.read_text())
        except OSError as exc:
            raise RuntimeError(f"could not read note file {note_file}: {exc}") from exc
    if any(not text.strip() for text in note_texts):
        raise RuntimeError("implementer notes must not be blank")
    if accept_ids and not accept_reason:
        raise RuntimeError("--accept requires --accept-reason")
    if not retry_review:
        _require_gate_or_model_only(repo, _config(repo).get("checks", []), identifier,
                                    model_only=model_only, affected=affected)
    review_plan = None if no_review or affected else resolve_review(
        repo, _review_settings(_config(repo)), runner=runner_override, lane=lane_override,
        model=model_override, reasoning_effort=reasoning_effort_override,
    )
    if retry_review:
        recorded = _recorded_proof(state, identifier)
        if recorded:
            origin.run, origin.proof = recorded["run"], recorded["id"]
            origin.artifacts = _verify_artifacts(repo, recorded["run"])
        try:
            proof = require_proof(repo, state, identifier, _fallow_path())
        except RuntimeError as exc:
            raise DriverError(str(exc), next_action=command_line(repo, "verify", "--issue", identifier)) from exc
        snapshot = _snapshot(repo, proof["run"])
        mutate_state(repo, lambda current: add_history(current, "review_retry", issue=identifier,
                                                       proof=proof["id"], run=proof["run"],
                                                       requested_review=review_plan["requested"]))
        progress(f"review retry: reusing proof {proof['id']} from {proof['run']}", quiet=quiet)
        return _finish_verification_review(repo, identifier, batch_ids, snapshot, proof, review_plan,
                                           origin, quiet=quiet, as_json=as_json, reused=True)
    if shared is not None and "inputs" in shared and _shared_inputs(repo, state) != shared["inputs"]:
        # Checked before this batch's recorded proof is touched.
        raise SharedEvidenceChanged(
            "the tree, baseline, policy or tools changed since the shared scan and gate ran; "
            "their results no longer describe this tree, so nothing further is verified (re-run)"
        )
    verification_id = uuid4().hex

    def start_verification(current: dict[str, Any]) -> list[dict[str, str]]:
        require_attempt(current, identifier, expected_attempt)
        record = ensure_remediation(current)
        entries = add_fix_notes(current, note_texts)
        # Invalidate an older passing proof BEFORE any new gate runs.
        record["verification"] = {"id": verification_id, "status": "running"}
        record["pending_review"] = None
        return entries

    entries = mutate_state(repo, start_verification)
    state = load_state(repo)
    issue = state["issues"][identifier]
    expected_attempt = attempt_identity(state)
    if entries:
        notes_path = _fix_artifact(fix_dir, "notes.md")
        with notes_path.open("a") as handle:
            for entry in entries:
                handle.write(f"## {entry['at']}\n\n{entry['text']}\n\n")
    if accept_ids:
        def record_waivers(current: dict[str, Any]) -> None:
            require_attempt(current, identifier, expected_attempt)
            conflict = _active_fix_conflict(
                current, identifier, "waiver recording", "record waivers"
            )
            if conflict:
                raise RuntimeError(conflict)
            record = ensure_remediation(current)
            waivers = list(record["waivers"])
            already = {waiver["id"] for waiver in waivers}
            for accepted in accept_ids:
                if accepted in already:
                    continue
                waivers.append({"id": accepted, "reason": accept_reason, "at": now()})
                already.add(accepted)
                for batch_id in record["members"]:
                    current_issue = current["issues"][batch_id]
                    add_issue_event(current_issue, "finding_waived", finding=accepted, reason=accept_reason)
            update_remediation(current, waivers=waivers)

        mutate_state(repo, record_waivers)
        state = load_state(repo)
        issue = state["issues"][identifier]
        expected_attempt = attempt_identity(state)
    fix_base_commit = issue.get("fix_base_commit")
    fix_base_commit_exists = True
    if fix_base_commit:
        try:
            resolve_revision(repo, fix_base_commit)
        except RuntimeError:
            fix_base_commit_exists = False
    rediscovered = _refresh_gate_stages(repo, quiet=quiet)
    if rediscovered is not None:
        _require_gate_or_model_only(repo, _config(repo).get("checks", []), identifier,
                                    model_only=model_only, affected=affected)
    inputs = verification_inputs(repo, state, _fallow_path())
    if shared is not None:
        current_shared = _shared_inputs(repo, state)
        if shared.setdefault("inputs", current_shared) != current_shared:
            raise SharedEvidenceChanged(
                "the tree, baseline, policy or tools changed since the shared scan and gate ran; "
                "their results no longer describe this tree, so nothing further is verified (re-run)"
            )
    previous_finding_ids = set(issue.get("fix_finding_ids", []))
    side_effect_candidates = [
        candidate_id
        for candidate_id in previous_finding_ids - set(batch_ids)
        if (
            (candidate := state.get("issues", {}).get(candidate_id))
            and candidate.get("source") in {"fallow", "rust"}
            and candidate.get("status") in {"open", "reopened"}
        )
    ]
    # Cheap evidence first: the git diff check, the Fallow scan and the
    # introduced-findings check. The configured gate runs only if they pass.
    if shared is not None and "scan" in shared:
        # One verify over several batches: the cheap phase ran for the first.
        snapshot, state, seen = _clone_shared_scan(repo, shared["scan"])
    else:
        snapshot, state, seen = _scan(
            repo,
            kind="verify",
            quiet=quiet,
            stale_exclusions=side_effect_candidates,
            defer_checks=True,
        )
        if shared is not None:
            shared["scan"] = {"snapshot": copy.deepcopy(snapshot), "seen": list(seen)}
    issue = state["issues"][identifier]
    origin.run = snapshot["id"]
    origin.artifacts = _verify_artifacts(repo, snapshot["id"])
    run_dir = paths(repo)["runs"] / snapshot["id"]
    snapshot["fix_base_commit"] = fix_base_commit
    snapshot["changed_files"] = changed_files(repo, fix_base_commit) if fix_base_commit_exists and fix_base_commit else []
    snapshot["current_head"] = snapshot.get("git", {}).get("commit")
    if shared is not None:
        snapshot["attribution"] = shared["attribution"]
    snapshot["fix_base_commit_exists"] = fix_base_commit_exists
    if fix_base_commit_exists and fix_base_commit:
        snapshot["diff_check"] = diff_check(repo, fix_base_commit, run_dir / "checks" / "git-diff-check.log")
    snapshot["side_effect_candidate_ids"] = sorted(
        set(side_effect_candidates) - set(seen)
    )
    snapshot["gate"] = {"mode": "pending"}
    snapshot["verification_inputs_changed"] = verification_inputs(repo, state, _fallow_path()) != inputs
    early_blockers = _batch_verification_blockers(state, identifier, snapshot, seen)
    snapshot["dead_code_query"] = query_members(
        repo, run_dir, state, batch_ids, snapshot, seen,
        skip_reason="cheap evidence already blocks" if early_blockers else None,
    )
    if snapshot["dead_code_query"].get("command"):
        snapshot["verification_inputs_changed"] = verification_inputs(repo, state, _fallow_path()) != inputs
    write_json(run_dir / "snapshot.json", snapshot)
    query = snapshot["dead_code_query"]
    if query.get("status") in {"skipped", "not_applicable"}:
        progress(f"dead-code query: {query['status']} ({query['reason']})", quiet=quiet)
    for member_id, result in query.get("members", {}).items():
        if result["status"] != "not applicable":
            progress(f"dead-code {member_id}: {result['status']} ({result['reason']})", quiet=quiet)

    def record_verification_failure(current: dict[str, Any]) -> list[str]:
        require_attempt(current, identifier, expected_attempt)
        conflict = _active_fix_conflict(
            current, identifier, "verification", "record stale results"
        )
        if conflict:
            raise RuntimeError(conflict)
        current_blockers = _batch_verification_blockers(
            current, identifier, snapshot, seen
        )
        if current_blockers:
            for batch_id in _active_batch_ids(current, identifier):
                add_issue_event(current["issues"][batch_id], "verification_failed", run=snapshot["id"], reasons=current_blockers)
            add_history(
                current,
                "verification_failed",
                issue=identifier,
                run=snapshot["id"],
                reasons=current_blockers,
            )
        return current_blockers

    def fail_if_blocked(found: list[str]) -> int | None:
        """Record and report blockers; None when the state no longer blocks."""
        if not found:
            return None
        blockers = mutate_state(repo, record_verification_failure)
        if not blockers:
            return None
        if as_json:
            # No proof exists yet, so there is nothing whose binding was checked.
            origin.result(
                "blocked",
                blockers=blockers,
                proof_freshness="not_checked",
                next_action=command_line(repo, "verify", "--issue", identifier),
                data={
                    "review": None,
                    "gate": snapshot.get("gate"),
                    "dead_code_query": snapshot.get("dead_code_query"),
                    "failed_checks": [
                        {
                            "name": check["name"],
                            "status": check.get("status"),
                            "exit_code": check.get("exit_code"),
                            "log": check.get("log"),
                            "last_lines": failure_excerpt(check),
                        }
                        for check in snapshot.get("checks", [])
                        if check.get("status") not in {"passed", "not_run"}
                    ],
                },
            ).emit()
            return 1
        _print_scan(snapshot)
        for blocker in blockers:
            print(f"blocker: {blocker}", file=sys.stderr)
        return 1

    cheap_blockers = _batch_verification_blockers(state, identifier, snapshot, seen)
    if cheap_blockers:
        snapshot["gate"] = {
            "mode": "not_run",
            "reason": "blocked by cheap evidence (git diff check, Fallow, introduced findings)",
        }
        write_json(run_dir / "snapshot.json", snapshot)
        progress("gate: not run; cheap evidence (diff check, Fallow, introduced findings) already blocks", quiet=quiet)
        rc = fail_if_blocked(cheap_blockers)
        if rc is not None:
            return rc
    if shared is not None and "gate" in shared:
        progress("gate: shared with the first batch of this verify", quiet=quiet)
        snapshot.update(copy.deepcopy(shared["gate"]))
    else:
        _gate_phase(repo, state, snapshot, affected=affected, fresh_gate=fresh_gate, quiet=quiet)
        if shared is not None:
            snapshot["gate"]["shared_from"] = snapshot["id"]
            shared["gate"] = {key: copy.deepcopy(snapshot[key]) for key in
                              ("checks", "check_comparison", "gate", "git_after_commands")}
    if rediscovered:
        snapshot["gate"]["stages_rediscovered"] = rediscovered
    snapshot["verification_inputs_changed"] = verification_inputs(repo, state, _fallow_path()) != inputs
    write_json(run_dir / "snapshot.json", snapshot)
    rc = fail_if_blocked(_batch_verification_blockers(state, identifier, snapshot, seen))
    if rc is not None:
        return rc
    state = load_state(repo)
    issue = state["issues"][identifier]
    proof_dir = paths(repo)["runs"] / snapshot["id"]
    shutil.copyfile(_fix_artifact(fix_dir, "before.patch"), proof_dir / "before.patch")
    capture_patch(repo, proof_dir / "after.patch", base=fix_base_commit)
    proof = {
        "id": verification_id,
        "status": "partial" if affected else "passed",
        "run": snapshot["id"],
        "inputs": inputs,
        "issue_contract": issue_contract_identity(state),
        **({"branch": shared["pin"]} if shared and shared.get("pin") else {}),
        "artifacts": {
            str(path.relative_to(proof_dir)): file_digest(run_artifact(repo, snapshot["id"], str(path.relative_to(proof_dir))))
            for path in sorted(proof_dir.rglob("*")) if path.is_file()
        },
    }

    def record_proof(current: dict[str, Any]) -> None:
        record = require_attempt(current, identifier, expected_attempt)
        if record.get("verification", {}).get("id") != verification_id:
            raise RuntimeError("verification was superseded; refusing stale results")
        if verification_inputs(repo, current, _fallow_path()) != inputs:
            raise RuntimeError("verification inputs changed; run `hangover verify` again")
        if issue_contract_identity(current) != proof["issue_contract"]:
            raise RuntimeError("issue contract changed during verification; run `hangover verify` again")
        record["verification"] = proof
        for batch_id in record["members"]:
            add_issue_event(current["issues"][batch_id], "deterministic_verification_passed", run=snapshot["id"],
                            **({"model_only": True} if proof.get("model_only") else {}))

    proof["gate"] = {
        key: snapshot["gate"][key]
        for key in ("mode", "from_run", "pre_existing_failures", "stages_rediscovered")
        if key in snapshot["gate"]
    }
    if snapshot["gate"].get("mode") == "model_only":
        proof["model_only"] = True
    if affected:
        proof["scope"] = "partial"
        proof["checks_run"] = snapshot["gate"].get("checks_run", [])
        proof["checks_not_run"] = snapshot["gate"].get("checks_not_run", [])
    mutate_state(repo, record_proof)
    origin.proof = verification_id
    if affected:
        # A partial proof is real evidence for the operator but resolves nothing:
        # require_proof and the review import accept only a "passed" proof.
        next_action = command_line(repo, "verify", "--issue", identifier)
        if as_json:
            origin.result(
                "in_progress",
                proof_freshness="checked",
                next_action=next_action,
                data={"review": None, "deterministic": "partial", "gate": snapshot["gate"],
                      "dead_code_query": snapshot.get("dead_code_query")},
            ).emit()
            return 0
        _print_scan(snapshot)
        print("partial verification passed; nothing is resolved. Run a full `hangover verify` for the gate and review")
        return 0
    if no_review:
        if as_json:
            # The gate passed and bound its proof, but nothing is remediated
            # until a fresh review approves it.
            origin.result(
                "review_pending",
                proof_freshness="checked",
                next_action=command_line(repo, "review", "--issue", identifier),
                data={"review": None, "deterministic": "passed",
                      "dead_code_query": snapshot.get("dead_code_query"),
                      **({"model_only": True, "gate": snapshot["gate"]} if proof.get("model_only") else {})},
            ).emit()
            return 0
        _print_scan(snapshot)
        print("deterministic verification passed" + (" (model-only: no repository checks ran)" if proof.get("model_only") else "")
              + "; fresh review still required")
        return 0
    return _finish_verification_review(repo, identifier, batch_ids, snapshot, proof, review_plan,
                                       origin, quiet=quiet, as_json=as_json)


def _finish_verification_review(
    repo: Path, identifier: str, batch_ids: list[str], snapshot: dict[str, Any],
    proof: dict[str, Any], review_plan: dict[str, Any], origin: Origin,
    *, quiet: bool = False, as_json: bool = False, reused: bool = False,
) -> int:
    evidence = {"deterministic": "reused" if reused else "passed",
                "dead_code_query": snapshot.get("dead_code_query"),
                **({"model_only": True, "gate": proof.get("gate")} if proof.get("model_only") else {})}
    state = load_state(repo)
    conflict = _active_fix_conflict(state, identifier, "verification", "start review")
    if conflict:
        raise RuntimeError(conflict)
    review_rc, review, review_id = _review(
        repo,
        issue_id=identifier,
        snapshot=snapshot,
        quiet=quiet,
        review_plan=review_plan,
        as_json=as_json,
        origin=origin,
        expected_proof=proof,
    )
    state = load_state(repo)
    if review_rc == 0 and not review:
        if as_json:
            next_action, import_step = _import_step(repo, review_id, identifier)
            route = _review_result(repo, "review_pending", review_id, review_plan, identifier,
                                   proof=proof, batch=batch_ids, import_step=import_step).data["review"]
            origin.result(
                "review_pending",
                proof_freshness="checked",
                next_action=next_action,
                data={**evidence,
                    "review": route,
                    "import": import_step,
                },
            ).emit()
            return 0
        _print_scan(snapshot)
        print(
            "deterministic verification passed; fresh review still required"
        )
        return 0
    if review_rc != 0 or not review:
        if as_json:
            route = _review_route(repo, review_id, review_plan) or {}
            origin.tool_error(
                _review_failure_blocker(route.get("status", "unknown"), route.get("error"), fresh=True),
                next_action=command_line(repo, "verify", "--issue", identifier, "--retry-review", *_route_arguments(review_plan)),
                data={**evidence, "review": route or None},
            ).emit()
        return review_rc or 2
    if review["verdict"] != "pass":
        def record_review_failure(current: dict[str, Any]) -> None:
            for batch_id in _active_batch_ids(current, identifier):
                current_issue = current.get("issues", {}).get(batch_id)
                if not current_issue:
                    raise RuntimeError(f"unknown issue {batch_id}")
                add_issue_event(current_issue, "post_review_failed", run=review_id)

        mutate_state(repo, record_review_failure)
        if as_json:
            origin.result(
                "blocked",
                blockers=[_refusal_blocker(review, fresh=True)],
                proof_freshness="checked",
                next_action=command_line(repo, "fix", identifier),
                data={**evidence,
                    "verdict": review["verdict"],
                    "review": _review_route(repo, review_id, review_plan),
                },
            ).emit()
            return 1
        print(_refusal_blocker(review, fresh=True), file=sys.stderr)
        return 1
    state = load_state(repo)
    for batch_id in batch_ids:
        current_issue = state.get("issues", {}).get(batch_id)
        if (
            not current_issue
            or current_issue.get("status") != "resolved"
            or current_issue.get("verified_run") != snapshot["id"]
            or current_issue.get("review_run") != review_id
        ):
            status = current_issue.get("status") if current_issue else "missing"
            raise RuntimeError(
                f"issue {batch_id} changed during review "
                f"(status={status}, active_issue={state.get('active_issue')}); refusing to resolve"
            )
    if as_json:
        origin.result(
            "resolved",
            proof_freshness="checked",
            next_action=command_line(repo, "next"),
            data={**evidence,
                "verdict": review["verdict"],
                "review": _review_route(repo, review_id, review_plan),
            },
        ).emit()
        return 0
    _print_scan(snapshot)
    print("resolved " + ", ".join(batch_ids)
          + (" on a MODEL-ONLY proof: no repository checks ran (--model-only)" if proof.get("model_only") else ""))
    return 0


def _audit_action(repo: Path, base: str, full: bool, *options: str) -> str:
    return command_line(repo, "audit", "--base", base, "--require-review", *(["--full"] if full else []), *options)


QUICK_AUDIT_CHECKS = {"lint", "typecheck", "security"}


def _audit_checks(config: dict[str, Any], full: bool) -> tuple[list[dict[str, Any]], str]:
    """Pick the native checks an audit runs and name why.

    A repository whose only discovered gate is a combined script (recorded as
    ``verify``) has no quick check; running nothing would pass the audit with
    no native evidence, so it falls back to every configured check.
    """
    checks = config.get("checks", [])
    if full:
        return checks, "full"
    quick = [check for check in checks if check.get("name") in QUICK_AUDIT_CHECKS]
    if quick:
        return quick, "quick"
    return checks, "all_no_quick_checks" if checks else "none_configured"


def _audit_data(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {"base": snapshot["base"], "requested_base": snapshot["requested_base"],
            "check_selection": snapshot.get("check_selection"),
            "changed_files": snapshot["changed_files"], "diff_check": snapshot["diff_check"]["status"],
            "fallow": {"status": snapshot["fallow"].get("status"), "verdict": snapshot["fallow"].get("verdict")},
            "rust": {key: (snapshot.get("rust") or {}).get(key) for key in ("status", "verdict", "introduced")},
            "checks": [{"name": check["name"], "status": check["status"]} for check in snapshot["checks"]],
            **({"analyzer_coverage": snapshot["analyzer_coverage"]} if "analyzer_coverage" in snapshot else {})}


def _finish_audit_review(
    repo: Path, proof: dict[str, Any], plan: dict[str, Any], origin: Origin,
    *, full: bool, prepare_only: bool, import_path: Path | None,
    quiet: bool, as_json: bool,
) -> int:
    snapshot = _snapshot(repo, proof["run"])
    packet = run_artifact(repo, proof["run"], "review-packet.json")
    prompt = run_artifact(repo, proof["run"], "review-prompt.md")
    review_id = _run_id("audit-review")
    directory = _run_dir(repo, review_id)
    origin.run, origin.proof, origin.review_run = proof["run"], proof["id"], review_id
    origin.artifacts.update(_verify_artifacts(repo, proof["run"]), review_dir=str(directory),
                            review_packet=str(packet), review_prompt=str(prompt))
    output = directory / "review.json"
    prepared = not import_path and (prepare_only or plan["runner"] == "none")
    if prepared:
        result = {"status": "prepared", "runner": plan["runner"], "packet": str(packet), "output": str(output)}
    elif import_path:
        if _is_rejected_content(import_path, load_state(repo).get("audit_reviews", {}).get(proof["id"], {})):
            raise RuntimeError("failed runner output cannot be imported; a fresh reviewer must write a separate artifact")
        review = import_review(import_path, "prevention")
        write_json(output, review)
        result = {"status": "completed", "runner": "import", "packet": str(packet),
                  "output": str(output), "review": review}
    else:
        result = _execute_review_runner(repo, directory, packet, "prevention", plan, quiet=quiet, prompt_path=prompt)
    result.update(preflight=plan["preflight"], requested_review=plan["requested"])
    write_json(directory / "review-run.json", {key: value for key, value in result.items() if key != "review"})
    data = {**_audit_data(snapshot), "review": _review_route(repo, review_id, plan)}
    if prepared:
        state_name, code, blockers = "review_pending", 0, []
        next_action = _audit_action(repo, proof["base"], full, "--import", str(output))
        data["import"] = {"path": str(output), "prerequisite": f"a fresh reviewer reads {prompt} and writes its token-bound verdict here"}
    elif result["status"] != "completed" or not result.get("review"):
        state_name, code = "tool_error", 2
        blockers = [_review_failure_blocker(result["status"], result.get("error"))]

        def reject_failed_output(state: dict[str, Any]) -> None:
            record = state.get("audit_reviews", {}).get(proof["id"])
            if isinstance(record, dict):
                _reject_content(record, Path(result.get("output", str(output))))

        mutate_state(repo, reject_failed_output)
        manual_output = directory / "manual-review.json"
        next_action = _audit_action(repo, proof["base"], full, "--import", str(manual_output))
        data["import"] = {"path": str(manual_output), "prerequisite": f"a fresh reviewer reads {prompt} and writes a new verdict here; failed runner output is retained separately"}
    else:
        review = result["review"]
        accepted = record_audit_review(repo, proof, review, review_id, _fallow_path())
        state_name, code = ("passed", 0) if accepted else ("blocked", 1)
        blockers = [] if accepted else (
            [finding["title"] for finding in review["findings"]]
            or [f"the whole-change review did not approve (verdict {review.get('verdict')}: "
                f"{str(review.get('summary') or 'no summary').strip()[:300]})"])
        next_action = command_line(repo, "next") if accepted else _audit_action(
            repo, proof["base"], full, *_route_arguments(plan), *(["--prepare"] if import_path else []))
        data.update(verdict=review["verdict"], findings=review["findings"])
    if as_json:
        origin.result(state_name, blockers=blockers, next_action=next_action, data=data,
                      proof_freshness="not_checked" if state_name == "tool_error" else "checked").emit()
    else:
        print(f"reviewed audit: {state_name} | {proof['run']} | review {review_id}")
        print(f"review packet: {packet}")
        if prepared:
            print(f"fresh review still required; write {output}, then run:\n{next_action}")
        for blocker in blockers:
            print(f"blocker: {blocker}", file=sys.stderr)
    return code


def _audit(
    repo: Path, base: str, full: bool, *, quiet: bool = False, as_json: bool = False,
    require_review: bool = False, prepare_only: bool = False, import_path: Path | None = None,
    runner_override: str | None = None, lane_override: str | None = None,
    model_override: str | None = None, reasoning_effort_override: str | None = None,
    origin: Origin | None = None,
) -> int:
    origin = origin or Origin(command="audit", repo=str(repo))
    if not require_review and (prepare_only or import_path or runner_override or lane_override or model_override or reasoning_effort_override):
        raise RuntimeError("audit review options require explicit --require-review")
    _ensure_initialized(repo, stream=sys.stderr if as_json else None)
    config = _config(repo)
    if not is_git_repo(repo):
        raise RuntimeError("prevention audit requires a Git repository")
    requested_base = base
    base = resolve_revision(repo, base)
    plan = resolve_review(repo, _review_settings(config), runner=runner_override, lane=lane_override,
                          model=model_override, reasoning_effort=reasoning_effort_override,
                          execute=not prepare_only and import_path is None) if require_review else None
    if import_path:
        state = load_state(repo)
        records = state.get("audit_reviews", {})
        recorded = records.get(state.get("pending_audit_review")) if isinstance(records, dict) else None
        if isinstance(recorded, dict):
            origin.run, origin.proof = recorded.get("run"), recorded.get("id")
            if origin.run:
                origin.artifacts["run_dir"] = str(run_artifact(repo, origin.run, "snapshot.json").parent)
        try:
            proof = require_audit(repo, base, full, _fallow_path(), expected=recorded)
        except RuntimeError as exc:
            raise DriverError(str(exc), next_action=_audit_action(repo, base, full, "--prepare")) from exc
        return _finish_audit_review(repo, proof, plan, origin, full=full,
                                    prepare_only=False, import_path=import_path, quiet=quiet, as_json=as_json)
    run_id = _run_id("audit")
    run_dir = _run_dir(repo, run_id)
    origin.run = run_id
    origin.artifacts = _verify_artifacts(repo, run_id)
    pending = begin_audit(repo, run_id, base, full, _fallow_path()) if require_review else None
    selected, check_selection = _audit_checks(config, full)
    repo_inventory = inventory(repo)
    analyzers = _analyzer_plan(repo, config, repo_inventory)
    if analyzers["fallow"]["run"]:
        progress("fallow: running", quiet=quiet)
        started = time.monotonic()
        fallow = run_fallow_audit(repo, run_dir, base)
        progress_result(
            "fallow",
            {
                "status": fallow.get("status"),
                "duration_seconds": time.monotonic() - started,
            },
            quiet=quiet,
            success_status="completed",
            success_label="done",
        )
    else:
        fallow = {"status": analyzers["fallow"]["status"], "version": fallow_version(), "verdict": None}
    if analyzers["rust"]["run"]:
        progress("rust: running (this tree and the base)", quiet=quiet)
        started = time.monotonic()
        rust = run_rust_audit(repo, run_dir, base, progress=lambda line: progress(line, quiet=quiet))
        progress_result("rust", {"status": rust.get("status"), "duration_seconds": time.monotonic() - started},
                        quiet=quiet, success_status="completed", success_label="done")
        if rust.get("refusal"):
            # As for a scan: a tool error, and no audit record built on evidence hangover refused to gather.
            raise RepositoryRefusal(f"Rust analysis refused repository content: {rust['refusal']}")
    else:
        rust = {**_rust_not_run(repo, analyzers["rust"]["status"]), "verdict": None}
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "id": run_id,
        "kind": "audit",
        "created_at": now(),
        "repo": str(repo),
        "base": base,
        "requested_base": requested_base,
        "full": full,
        "check_selection": check_selection,
        "git": git_info(repo),
        "inventory": repo_inventory,
        "changed_files": changed_files(repo, base),
        "diff_check": diff_check(repo, base, run_dir / "checks" / "git-diff-check.log"),
        "checks": run_checks(repo, selected, run_dir, quiet=quiet),
        "fallow": fallow,
        "rust": rust,
    }
    snapshot["analyzer_coverage"] = _analyzer_coverage(
        dict(Counter(Path(name).suffix.lower() or "[none]" for name in snapshot["changed_files"])), fallow, rust)
    write_json(run_dir / "snapshot.json", snapshot)
    def record_audit(state: dict[str, Any]) -> None:
        state["latest_audit"] = run_id
        add_history(state, "audit", run=run_id, base=base, requested_base=requested_base)

    mutate_state(repo, record_audit)
    blockers = _audit_blockers(snapshot, analyzers)
    analyzer_failed = fallow_failed(snapshot, analyzers) or rust_analysis_failed(snapshot)
    # Unknown evidence is a tool error, not a verdict, whatever else blocks.
    state_name = "tool_error" if analyzer_failed else "blocked" if blockers else "passed"
    if require_review and not blockers:
        after = run_artifact(repo, run_id, "after.patch")
        capture_patch(repo, after, base=base)
        prepare_review_packet(repo, run_dir, "prevention", snapshot, after_patch=after, verification_token=pending["token"])
        proof = seal_audit(repo, pending, _fallow_path(), analyzers)
        return _finish_audit_review(repo, proof, plan, origin, full=full,
                                    prepare_only=prepare_only, import_path=None, quiet=quiet, as_json=as_json)
    if as_json:
        # The changed-code gate examines no remediation proof, so freshness
        # stays not_checked however many checks ran.
        if state_name == "passed":
            next_action = command_line(repo, "next")
        elif require_review:
            next_action = _audit_action(repo, base, full, *_route_arguments(plan), *(["--prepare"] if prepare_only else []))
        else:
            next_action = command_line(repo, "audit", "--base", requested_base, *(["--full"] if full else []))
        DriverResult(
            command="audit",
            state=state_name,
            repo=str(repo),
            run=run_id,
            blockers=blockers,
            artifacts={
                "run_dir": str(run_dir),
                "snapshot": str(run_dir / "snapshot.json"),
            },
            next_action=next_action,
            data=_audit_data(snapshot),
        ).emit()
        return exit_code(state_name)
    print(f"audit: {state_name} | {run_id} | {len(snapshot['changed_files'])} changed file(s)")
    print(f"  git diff --check: {snapshot['diff_check']['status']}")
    print(f"  fallow: {snapshot['fallow'].get('verdict') or snapshot['fallow']['status']}")
    if snapshot["rust"].get("status") != "not_applicable":
        print(f"  rust: {snapshot['rust'].get('verdict') or snapshot['rust']['status']}"
              + (f" ({len(snapshot['rust'].get('introduced') or [])} introduced)" if snapshot["rust"].get("verdict") else ""))
        for item in (snapshot["rust"].get("introduced") or [])[:20]:
            print(f"    introduced {item['id']}: [{item['category']}] {item['title']}")
    if check_selection == "all_no_quick_checks":
        print("  native checks: no lint/typecheck/security check configured; ran every configured check")
    elif check_selection == "none_configured":
        print("  native checks: none configured; this audit has no repository test or lint evidence")
    for check in snapshot["checks"]:
        print(f"  {check['name']}: {check['status']}")
    for line in _coverage_lines(snapshot["analyzer_coverage"], noun="changed source files"):
        print(f"  {line}")
    for blocker in blockers:
        print(f"blocker: {blocker}", file=sys.stderr)
    return exit_code(state_name)


def _dedupe(repo: Path, apply: bool, as_json: bool) -> int:
    if apply:
        pairs = mutate_state(
            repo,
            lambda state: dedupe_open_subjective_issues(state, apply=True),
        )
    else:
        pairs = dedupe_open_subjective_issues(load_state(repo), apply=False)
    payload = {"dry_run": not apply, "pairs": pairs, "count": len(pairs)}
    if as_json:
        print(json.dumps(payload, indent=2))
        return 0
    if not pairs:
        print("no duplicate open issues")
        return 0
    action = "closed" if apply else "would close"
    strong = sum(pair["match"] == "same_remediation" for pair in pairs)
    print(f"{action} {strong} duplicate issue(s); {len(pairs) - strong} overlap suggestion(s) kept open")
    for pair in pairs:
        print(f"  {pair['duplicate']} -> {pair['canonical']} ({pair['match']})")
        print(f"    {pair['duplicate_title']!r} -> {pair['canonical_title']!r}")
    return 0


def _status(repo: Path, as_json: bool, list_stale: bool = False) -> int:
    """Print the campaign's status; the tool_error exit while the last scan stands refused."""
    state = load_state(repo)
    issues = ordered_issues(state)
    counts = Counter(issue["status"] for issue in issues)
    counts.setdefault("stale", 0)
    counts.setdefault("obsolete", 0)
    stale_issues = [
        issue for issue in issues if issue.get("status") in {"stale", "obsolete"}
    ]
    next_item = next_issue(state)
    latest = _snapshot(repo, state["latest_run"]) if state.get("latest_run") else None
    baseline = (
        _snapshot(repo, state["baseline_run"]) if state.get("baseline_run") else None
    )
    value = {
        "repo": str(repo),
        "baseline_run": state.get("baseline_run"),
        "latest_run": state.get("latest_run"),
        "latest_review": state.get("latest_review"),
        "latest_audit": state.get("latest_audit"),
        "active_issue": state.get("active_issue"),
        "open_batches": [
            {"primary": record["primary"], "members": list(record["members"]), "branch": record.get("branch")}
            for record in open_batches(state)
        ],
        "issues": dict(counts),
        "next": next_item,
        "latest_checks": latest.get("checks", []) if latest else [],
        "latest_fallow": latest.get("fallow", {}).get("summary", {}) if latest else {},
        "latest_rust": {key: (latest.get("rust") or {}).get(key) for key in ("status", "summary")}
        if latest and (latest.get("rust") or {}).get("status") not in {None, "not_applicable"} else None,
        "latest_fallow_mode": (
            fallow_dead_code_mode(latest.get("fallow", {})) if latest else None
        ),
        "baseline_fallow_mode": (
            fallow_dead_code_mode(baseline.get("fallow", {})) if baseline else None
        ),
        "baseline_checks_inherited_from": (
            baseline.get("checks_inherited_from") if baseline else None
        ),
        "baseline_checks": [item["name"] for item in (baseline or {}).get("checks", [])],
        "baseline_red_stages": [
            item["name"] for item in (baseline or {}).get("checks", [])
            if item.get("status") != "passed"
        ],
        "latest_gate": latest.get("gate") if latest else None,
        "configured_checks": [check.get("name") for check in _configured_checks(repo)],
        "analyzer_coverage": _snapshot_coverage(latest) if latest else None,
    }
    active = state.get("active_issue")
    record = active_remediation(state) if active else None
    verification = record.get("verification") if record else None
    if isinstance(verification, dict) and verification.get("status") == "partial":
        value["partial_proof"] = {
            "issue": active,
            "run": verification.get("run"),
            "checks_run": verification.get("checks_run", []),
            "checks_not_run": verification.get("checks_not_run", []),
        }
    value["delta"] = _baseline_delta(baseline, latest)
    if list_stale:
        value["stale_issues"] = stale_issues
    refused = state.get("refused_scan")
    if not isinstance(refused, dict) and latest and (latest.get("rust") or {}).get("refusal"):
        # A refused scan an older hangover recorded as the latest run.
        refused = {"kind": latest.get("kind"), "at": latest.get("created_at"), "run": latest.get("id"),
                   "refusal": f"Rust analysis refused repository content: {latest['rust']['refusal']}"}
    value["refused_scan"] = refused if isinstance(refused, dict) else None
    rc = exit_code("tool_error") if value["refused_scan"] else 0
    if value["refused_scan"]:
        print(f"hangover: the last {value['refused_scan'].get('kind') or 'scan'} was refused: "
              f"{value['refused_scan'].get('refusal')}", file=sys.stderr)
    if as_json:
        print(json.dumps(value, indent=2))
        return rc
    print(f"repo: {repo}")
    print(f"baseline: {value['baseline_run'] or 'none'}")
    if value["baseline_checks_inherited_from"]:
        print(
            "baseline checks: inherited from "
            f"{value['baseline_checks_inherited_from']}"
        )
    print(f"latest: {value['latest_run'] or 'none'}")
    if baseline:
        if value["baseline_red_stages"]:
            print("baseline red stages: " + ", ".join(value["baseline_red_stages"]))
        elif value["baseline_checks"]:
            print(f"baseline stages: all {len(value['baseline_checks'])} passed")
        else:
            print("baseline stages: none recorded (scan ran without --checks)")
    gate = value["latest_gate"]
    if gate:
        detail = {
            "reused": f"reused from {gate.get('from_run')}",
            "partial": f"PARTIAL (ran {', '.join(gate.get('checks_run', [])) or 'no checks'})",
            "not_run": f"not run ({gate.get('reason')})",
            "model_only": "NONE, model-only proof (no checks configured)",
            "pending": "pending (verification did not finish)",
        }.get(gate.get("mode"), "ran" + (f", stopped after {gate['stopped_after']}" if gate.get("stopped_after") else ""))
        print(f"latest gate: {detail}")
    if not value["configured_checks"]:
        print("checks: none configured; verify will not resolve an item without --model-only")
    if value.get("partial_proof"):
        print(
            f"partial proof: {value['partial_proof']['issue']} (not resolved; "
            "a full verify is still required)"
        )
    if value["delta"]:
        print(value["delta"]["line"])
    if value["latest_fallow_mode"]:
        print(
            "fallow mode: "
            f"baseline {value['baseline_fallow_mode'] or 'none'} | "
            f"latest {value['latest_fallow_mode']}"
        )
    if value["latest_rust"]:
        rust_summary = value["latest_rust"].get("summary") or {}
        print(f"rust: {value['latest_rust']['status']} | {rust_summary.get('findings', 0)} findings | "
              + ", ".join(f"{key} {count}" for key, count in (rust_summary.get("by_category") or {}).items()))
    if value["analyzer_coverage"]:
        for line in _coverage_lines(value["analyzer_coverage"]):
            print(line)
    print("issues: " + (", ".join(f"{key}={count}" for key, count in sorted(counts.items())) or "none"))
    if len(value["open_batches"]) > 1 or any(batch["branch"] for batch in value["open_batches"]):
        for batch in value["open_batches"]:
            print(f"open batch: {batch['primary']} ({len(batch['members'])} card(s))"
                  + (f" on branch {batch['branch']}" if batch["branch"] else ""))
    if next_item:
        print(f"next: {next_item['id']} [{next_item['priority']}] {next_item['title']}")
    else:
        print("next: none")
    if list_stale:
        print("stale/obsolete issues:")
        if not stale_issues:
            print("  none")
        for issue in stale_issues:
            print(
                f"  [{issue['status']}] {issue['id']} "
                f"[{issue['category']}] {issue['title']}"
            )
    return rc


def _configured_checks(repo: Path) -> list[dict[str, Any]]:
    try:
        checks = read_json(paths(repo)["config"]).get("checks", [])
    except (OSError, RuntimeError, AttributeError):
        return []
    return [check for check in checks if isinstance(check, dict)] if isinstance(checks, list) else []


def _baseline_delta(
    baseline: dict[str, Any] | None, latest: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Recorded baseline-to-latest numbers; no comparability claim is made."""
    if not baseline or not latest or baseline is latest:
        return None
    before = baseline.get("fallow", {}).get("summary", {})
    after = latest.get("fallow", {}).get("summary", {})
    pairs = {
        "dead_code": (before.get("total_dead_code_issues"), after.get("total_dead_code_issues")),
        "clone_groups": (
            (before.get("duplication") or {}).get("clone_groups"),
            (after.get("duplication") or {}).get("clone_groups"),
        ),
        "health": (before.get("health_score"), after.get("health_score")),
    }
    if all(a is None and b is None for a, b in pairs.values()):
        return None
    show = lambda v: "?" if v is None else v
    text = ", ".join(f"{name} {show(a)} -> {show(b)}" for name, (a, b) in pairs.items())
    return {
        "line": f"delta since baseline (recorded, not a comparability proof): {text}",
        **{name: {"baseline": a, "latest": b} for name, (a, b) in pairs.items()},
    }


def _recorded_proof(state: dict[str, Any], primary: str) -> dict[str, Any] | None:
    """The proof the fix recorded, read from its remediation, never from latest_run."""
    record = active_remediation(state)
    if record is None or record.get("primary") != primary:
        return None
    proof = record.get("verification")
    if not isinstance(proof, dict) or proof.get("status") != "passed":
        return None
    return proof


def _next_result(repo: Path, state: dict[str, Any]) -> DriverResult:
    """Read-only: this command runs no gate, so proof freshness is not_checked."""
    issue = next_issue(state)
    if not issue:
        return DriverResult(
            command="next",
            state="no_open_work",
            repo=str(repo),
            next_action=command_line(repo, "scan"),
            data={"issue": None},
        )
    identifier = issue["id"]
    if issue.get("status") == "in_progress" and state.get("active_issue") == identifier:
        proof = _recorded_proof(state, identifier)
        artifacts = {}
        if issue.get("fix_dir"):
            artifacts["fix_dir"] = issue["fix_dir"]
        if proof:
            artifacts["proof_run"] = str(paths(repo)["runs"] / proof["run"])
        return DriverResult(
            command="next",
            state="in_progress",
            repo=str(repo),
            run=proof["run"] if proof else issue.get("last_seen_run"),
            proof=proof["id"] if proof else None,
            issue_id=identifier,
            batch=_active_batch_ids(state, identifier),
            artifacts=artifacts,
            next_action=command_line(repo, "verify", "--issue", identifier, *(["--retry-review"] if proof else [])),
            data={"issue": project_issue(issue)},
        )
    return DriverResult(
        command="next",
        state="ready",
        repo=str(repo),
        run=issue.get("last_seen_run"),
        issue_id=identifier,
        next_action=command_line(repo, "fix", identifier),
        data={"issue": project_issue(issue)},
    )


def _next(repo: Path, as_json: bool) -> None:
    state = load_state(repo)
    issue = next_issue(state)
    latest = _snapshot(repo, state["latest_run"]) if state.get("latest_run") else None
    coverage = _snapshot_coverage(latest) if latest else None
    if as_json:
        result = _next_result(repo, state)
        if coverage is not None:
            result.data["analyzer_coverage"] = coverage
        result.emit()
    elif issue:
        _print_issue(issue)
        action = _next_result(repo, state).next_action
        label = "Resume" if issue.get("status") == "in_progress" else "Start"
        print(f"\n{label}: {action}")
    else:
        print("no open issues")
        if coverage and (coverage.get("uncovered_files") or coverage.get("unknown_files")):
            # "Nothing open" from analyzers that read none of these files is not a clean bill of health.
            for line in _coverage_lines(coverage):
                print(line)


def _print_issue(issue: dict[str, Any]) -> None:
    """One card for a person to read; `--json` carries the whole record."""
    print(f"{issue['id']} [{issue.get('priority', '?')}] {issue.get('title', '')}")
    print(f"  {issue.get('source', '?')} / {issue.get('category', '?')} | status {issue.get('status', '?')}")
    files = list(issue.get("files") or [])
    if files:
        print("  files: " + ", ".join(files[:8]) + (f" (+{len(files) - 8} more)" if len(files) > 8 else ""))
    for heading, field in (("evidence", "evidence"), ("verify by", "verification")):
        lines = [str(line) for line in issue.get(field) or [] if str(line).strip()]
        if lines:
            print(f"  {heading}:")
            for line in lines[:6]:
                print(f"    - {line}")
            if len(lines) > 6:
                print(f"    ... {len(lines) - 6} more (hangover next --json)")


def _doctor(repo: Path, as_json: bool = False) -> int:
    def version(command: list[str], fallback: list[str] | None = None) -> str | None:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=git_safe_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            output = (result.stdout or result.stderr).strip().splitlines()
            clean = [line for line in output if line and not line.startswith("[")]
            if result.returncode == 0 and clean:
                return clean[0]
        if fallback:
            try:
                result = subprocess.run(
                    fallback,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                    env=git_safe_environment(),
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            output = (result.stdout or result.stderr).strip().splitlines()
            clean = [line for line in output if line and not line.startswith("[")]
            return clean[0] if result.returncode == 0 and clean else None
        return None

    configured_runner = "codex"
    command_template: list[str] | None = None
    review_settings = _review_settings({})
    config_path = paths(repo)["config"]
    if config_path.is_file():
        try:
            configured = read_json(config_path)
            if isinstance(configured, dict):
                settings = _review_settings(configured)
                review_settings = settings
                if isinstance(settings["runner"], str):
                    configured_runner = settings["runner"]
                command_template = settings["command"]
        except (OSError, RuntimeError):
            pass

    reviewer_binary = codex_binary()
    delegate_reviewer_binary = delegate_binary()
    configured_command_binary = command_binary(command_template, repo)
    tools = {
        "hangover": __version__,
        "python": sys.version.split()[0],
        "node": version(["node", "--version"]),
        "fallow": fallow_version(),
        "codex": version([str(reviewer_binary), "--version"]) if reviewer_binary else None,
        "delegate": (
            version(
                [str(delegate_reviewer_binary), "--version"],
                [str(delegate_reviewer_binary), "--help"],
            )
            if delegate_reviewer_binary
            else None
        ),
        "command": str(configured_command_binary) if configured_command_binary else None,
    }
    doctor_config: dict[str, Any] = {}
    if config_path.is_file():
        try:
            doctor_config = read_json(config_path)
        except (OSError, RuntimeError):
            doctor_config = {}
    if _analyzer_plan(repo, doctor_config, {})["rust"]["run"]:
        # Probed outside the checkout: in it, rustup obeys the checkout's
        # rust-toolchain.toml, whose `path` can name any binary to run.
        with tempfile.TemporaryDirectory(prefix="hangover-doctor-") as neutral:
            tools["rust"] = rust_tool_versions(Path(neutral))
    codex_auth = "unknown"
    uses_local_codex = configured_runner == "codex" or (
        configured_runner == "delegate" and review_settings["delegate"]["lane"] == "codex"
    )
    if configured_runner == "codex" and reviewer_binary:
        try:
            auth_result = subprocess.run(
                [str(reviewer_binary), "login", "status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=git_safe_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            auth_result = None
        if auth_result is not None:
            auth_output = f"{auth_result.stdout}\n{auth_result.stderr}".casefold()
            if "not logged in" in auth_output:
                codex_auth = "not_logged_in"
            elif auth_result.returncode == 0 and "logged in" in auth_output:
                codex_auth = "logged_in"
    codex_startup: dict[str, Any] = {"status": "not_invoked"}
    codex_startup_error: str | None = None
    if uses_local_codex and reviewer_binary:
        try:
            codex_startup = codex_startup_probe(reviewer_binary)
        except (OSError, RuntimeError) as exc:
            codex_startup_error = str(exc)
            codex_startup = {"status": "failed", "error": codex_startup_error}
    # The delegate runner checks its configured authentication profile at launch
    # and refuses an authenticated run without one. Run the same read-only dry-run preflight
    # the review route runs, so doctor reports that refusal here instead of
    # letting the repository gate end in an instant review failure.
    delegate_preflight_state = "not_invoked"
    delegate_preflight_error: str | None = None
    if configured_runner == "delegate" and delegate_reviewer_binary:
        try:
            if paths(repo)["root"].is_dir() and not codex_startup_error:
                delegate_preflight_state = resolve_review(
                    repo, review_settings, execute=True
                )["preflight"]["status"]
        except (OSError, RuntimeError) as exc:
            delegate_preflight_state = "failed"
            delegate_preflight_error = str(exc)
    report = {
        "repo": str(repo),
        "git": is_git_repo(repo),
        "review_runner": configured_runner,
        "codex_auth": codex_auth,
        "codex_startup": codex_startup,
        "delegate_preflight": delegate_preflight_state,
        "tools": tools,
    }
    missing = ["node"] if not tools["node"] else []
    if configured_runner == "codex" and not tools["codex"]:
        missing.append("codex")
    elif configured_runner == "codex" and codex_auth == "not_logged_in":
        missing.append("codex (not logged in)")
    elif uses_local_codex and codex_startup_error:
        missing.append(f"codex ({codex_startup_error})")
    elif configured_runner == "delegate" and not tools["delegate"]:
        missing.append("delegate")
    elif configured_runner == "delegate" and delegate_preflight_error:
        missing.append(f"delegate ({delegate_preflight_error})")
    elif configured_runner == "command" and not configured_command_binary:
        missing.append("command")
    if tools["fallow"] != f"fallow {FALLOW_VERSION}":
        missing.append("fallow")
    for name, value in (tools.get("rust") or {}).items():
        if not value and name != "cargo_machete":
            missing.append(f"rust {name}")
    if as_json:
        print(json.dumps({**report, "missing": missing}, indent=2))
    else:
        _print_doctor(report, missing)
    if tools.get("rust") and not tools["rust"].get("cargo_machete"):
        print("note: cargo-machete is not installed; Rust unused-dependency analysis is skipped "
              "(cargo install cargo-machete)", file=sys.stderr)
    _print_gate_proposal(repo, sys.stderr if as_json else sys.stdout)
    if missing:
        print("missing: " + ", ".join(missing), file=sys.stderr)
        if codex_auth == "not_logged_in":
            print(
                "hint: run `codex login`, or set review.runner in .hangover/config.json to command (your own "
                "reviewer, review.command) or delegate, or to none to prepare review packets "
                "(`hangover review --prepare`) for a reviewer you run yourself",
                file=sys.stderr,
            )
        return 1
    return 0


def _print_doctor(report: dict[str, Any], missing: list[str]) -> None:
    tools = report["tools"]
    print(f"repo: {report['repo']}" + ("" if report["git"] else " (not a Git repository)"))
    print(f"hangover {tools['hangover']} | python {tools['python']} | node {tools['node'] or 'MISSING'}")
    print(f"fallow: {tools['fallow'] or 'MISSING'} (pinned {FALLOW_VERSION})")
    runner = report["review_runner"]
    detail = {
        "codex": f"codex {tools['codex'] or 'MISSING'}, login {report['codex_auth']}, "
                 f"read-only sandbox {report['codex_startup'].get('status')}",
        "delegate": f"delegate {tools['delegate'] or 'MISSING'}, dry-run {report['delegate_preflight']}",
        "command": f"review.command {tools['command'] or 'UNRESOLVED'}",
        "none": "no runner; reviews are prepared for a reviewer you run yourself",
    }.get(runner, runner)
    print(f"review runner: {runner} ({detail})")
    for name, version in (tools.get("rust") or {}).items():
        print(f"rust {name}: {version or 'missing'}")
    print("ready" if not missing else "not ready: " + ", ".join(missing))


def _run(repo: Path, no_checks: bool, no_review: bool, *, quiet: bool = False, runner: str | None = None) -> int:
    with no_execute_git(repo) if no_checks else contextlib.nullcontext():
        return _run_guarded(repo, no_checks, no_review, quiet=quiet, runner=runner)


def _run_guarded(repo: Path, no_checks: bool, no_review: bool, *, quiet: bool, runner: str | None) -> int:
    _ensure_initialized(repo)
    review_plan = None if no_review else resolve_review(repo, _review_settings(_config(repo)), runner=runner)
    # --no-checks is the inspection mode for an untrusted checkout: nothing that
    # compiles or runs the checkout's code (checks, cargo) runs.
    # A refusal (RepositoryRefusal) raises out of the scan: a tool error, and no review of evidence
    # hangover refused to gather.
    snapshot, _, _ = _scan(repo, no_checks=no_checks, no_execute=no_checks, quiet=quiet)
    _print_scan(snapshot)
    if not no_review:
        review_rc, _, _ = _review(repo, quiet=quiet, review_plan=review_plan)
        if review_rc:
            return review_rc
    _status(repo, False)
    return 0


READ_ONLY_COMMANDS = ("status", "next", "list", "preview", "packet")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="hangover",
        description="Behavior-preserving codebase simplification campaign harness.",
    )
    root.add_argument("--repo", type=Path, default=Path.cwd(), help="target repository")
    root.add_argument(
        "--quiet",
        action="store_true",
        help="suppress live phase progress on stderr",
    )
    root.add_argument("--version", action="version", version=f"hangover {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="discover repository checks and create local state")
    init.add_argument("--force", action="store_true", help="refresh config after writing a backup")
    init.add_argument(
        "--stages-from-gate", action="store_true",
        help="adopt the commands of a gate shell script as explicit ordered checks (your assertion; verify blocks if the script later changes)",
    )

    scan = commands.add_parser("scan", help="capture deterministic baseline/current evidence")
    scan_checks = scan.add_mutually_exclusive_group()
    scan_checks.add_argument(
        "--checks", action="store_true",
        help="also run the configured native checks (default: analyzers only)",
    )
    scan_checks.add_argument(
        "--no-checks", action="store_true",
        help="static mode for an untrusted checkout: no checks, no Fallow, and Rust analysis without cargo "
             "(no clippy or cargo-machete)",
    )
    scan.add_argument(
        "--rebaseline",
        action="store_true",
        help="record this scan as the new operator-approved baseline",
    )

    status = commands.add_parser("status", help="show campaign state")
    status.add_argument("--json", action="store_true")
    status.add_argument(
        "--stale", action="store_true", help="list stale and obsolete issues"
    )

    nxt = commands.add_parser("next", help="show the highest-priority open remediation")
    nxt.add_argument("--json", action="store_true")

    listing = commands.add_parser(
        "list", help="list tracked issues, filtered, without reading all state"
    )
    listing.add_argument("--json", action="store_true")
    for name, help_text in (
        ("source", "issue source, e.g. fallow or subjective-review"),
        ("category", "issue category"),
        ("status", "issue status"),
        ("file", "repository path or directory the issue touches"),
    ):
        listing.add_argument(
            f"--{name}", action="append", default=[], metavar=name.upper(),
            help=f"filter by {help_text}; repeatable",
        )

    listing.add_argument("--group-by", choices=("dir", "file", "category"),
                         help="summarize findings per directory, file or category")
    listing.add_argument("--sort", choices=("lines",),
                         help="largest duplicated/affected line weight first")
    listing.add_argument("--exclude-tests", action="store_true",
                         help="drop tests, spikes, docs and fixtures (by path convention)")

    preview = commands.add_parser(
        "preview",
        help="describe a candidate remediation batch without activating anything",
    )
    preview.add_argument("issue", nargs="*")
    preview.add_argument("--json", action="store_true")
    preview.add_argument(
        "--limit", type=int, default=3,
        help="how many open issues to preview when none are named",
    )

    review = commands.add_parser("review", help="run or import a fresh subjective review")
    review.add_argument("--json", action="store_true")
    review.add_argument("--prepare", action="store_true", help="write a packet without invoking a runner")
    review.add_argument("--import", dest="import_path", type=Path, help="import schema-valid review JSON")
    review.add_argument("--issue", help="review an in-progress remediation")
    review.add_argument("--scope", action="append", default=[], metavar="PATH",
                        help="initial-review file or directory selection; repeatable")
    review.add_argument("--runner", choices=("codex", "delegate", "command", "none"))
    review.add_argument("--lane")
    review.add_argument("--model")
    review.add_argument("--reasoning-effort")

    suppress = commands.add_parser(
        "suppress",
        help="apply a finding's Fallow config remedy as repo policy and mark it suppressed",
    )
    suppress.add_argument("issue")
    suppress.add_argument("--reason", required=True, metavar="REASON")
    suppress.add_argument(
        "--no-rebaseline",
        action="store_true",
        help="apply the config edit without refreshing the Fallow baseline",
    )

    fix = commands.add_parser("fix", help="start one remediation batch and emit its fix packet")
    fix.add_argument("issue", nargs="*")
    fix.add_argument("--json", action="store_true")
    fix.add_argument(
        "--branch", metavar="NAME",
        help="record the batch against this branch; this is what lets a second batch be open at once",
    )
    fix.add_argument(
        "--add", action="store_true",
        help="add the ids after the first (an open batch's primary) to that batch",
    )
    disposition = fix.add_mutually_exclusive_group()
    disposition.add_argument("--defer", metavar="REASON")
    disposition.add_argument("--obsolete", metavar="REASON")
    disposition.add_argument(
        "--release", action="store_true",
        help="detach only the named batch members; unfinished members return to open",
    )

    verify = commands.add_parser("verify", help="verify and independently review one remediation")
    verify.add_argument("--issue")
    scope = verify.add_mutually_exclusive_group()
    scope.add_argument(
        "--merged", action="store_true",
        help="verify every open batch whose branch is merged into HEAD, with one gate run",
    )
    scope.add_argument(
        "--all", action="store_true", dest="all_batches",
        help="verify every open batch against this tree, with one gate run",
    )
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--no-review", action="store_true")
    verify.add_argument("--runner", choices=("codex", "delegate", "command", "none"))
    verify.add_argument(
        "--affected", action="store_true",
        help="run Fallow and only the checks marked narrow; records a partial proof that resolves nothing",
    )
    verify.add_argument(
        "--fresh-gate", action="store_true",
        help="rerun the gate even when a passing gate for this exact tree and config is recorded",
    )
    verify.add_argument("--retry-review", action="store_true",
                        help="reuse an unchanged deterministic proof and run only a fresh reviewer")
    verify.add_argument(
        "--model-only", action="store_true",
        help="with no configured checks, accept a proof from the analyzers and the model review alone "
             "(refused otherwise); the proof is labelled model-only",
    )
    verify.add_argument("--lane")
    verify.add_argument("--model")
    verify.add_argument("--reasoning-effort")
    verify.add_argument(
        "--accept",
        action="append",
        metavar="FINDING_ID",
        help="waive an introduced deterministic finding already tracked as its own issue",
    )
    verify.add_argument("--accept-reason", metavar="REASON")
    verify.add_argument("--note", action="append", default=[], metavar="TEXT")
    verify.add_argument(
        "--note-file", action="append", default=[], type=Path, metavar="PATH"
    )

    run = commands.add_parser("run", help="initialize, scan, review, and select the next remediation")
    run.add_argument(
        "--no-checks", action="store_true",
        help="static mode for an untrusted checkout: no checks, no Fallow, and Rust analysis without cargo "
             "(no clippy or cargo-machete)",
    )
    run.add_argument("--no-review", action="store_true", help="skip the model review")
    run.add_argument(
        "--runner", choices=("codex", "delegate", "command", "none"),
        help="review runner for this run (default: review.runner in .hangover/config.json); "
             "none prepares the review packet without invoking a reviewer",
    )

    audit = commands.add_parser("audit", help="gate only changed-code regressions")
    audit.add_argument("--base", default="HEAD")
    audit.add_argument("--json", action="store_true")
    audit.add_argument("--full", action="store_true", help="also run every configured native check")
    audit.add_argument("--require-review", action="store_true", help="require fresh approval of this exact base-to-tree change")
    audit_review = audit.add_mutually_exclusive_group()
    audit_review.add_argument("--prepare", action="store_true", help="seal evidence and prepare a whole-change review")
    audit_review.add_argument("--import", dest="import_path", type=Path, help="import the pending whole-change review")
    audit.add_argument("--runner", choices=("codex", "delegate", "command", "none"))
    audit.add_argument("--lane")
    audit.add_argument("--model")
    audit.add_argument("--reasoning-effort")

    packet = commands.add_parser(
        "packet", help="write a fix packet for a set of cards without activating anything"
    )
    packet.add_argument("issue", nargs="*")
    packet.add_argument("--out", type=Path, metavar="FILE", help="write the packet here instead of stdout")
    packet.add_argument("--force", action="store_true", help="overwrite an existing --out file")
    packet.add_argument("--json", action="store_true")

    fallow = commands.add_parser(
        "fallow", help="run the pinned Fallow in this checkout: hangover fallow -- <fallow args>"
    )
    fallow.add_argument("fallow_args", nargs=argparse.REMAINDER)

    for name in READ_ONLY_COMMANDS:
        commands.choices[name].add_argument(
            "--state-from", type=Path, metavar="PATH",
            help="read campaign state from this main checkout (default: found from a linked worktree)",
        )

    doctor = commands.add_parser("doctor", help="show tool availability and versions")
    doctor.add_argument("--json", action="store_true")

    dedupe = commands.add_parser(
        "dedupe", help="collapse duplicate open subjective issues"
    )
    dedupe.add_argument(
        "--apply",
        action="store_true",
        help="close duplicates; default is a dry run",
    )
    dedupe.add_argument("--json", action="store_true")
    return root




def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    finally:
        _release_run_leases()


def _main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # argparse fills the namespace as it goes, so after a rejected invocation it
    # still holds the parsed --repo and the selected subcommand; no raw-token guessing.
    args = argparse.Namespace()
    try:
        parser().parse_args(arguments, namespace=args)
    except SystemExit as exc:
        if exc.code and "--json" in arguments:
            Origin(
                command=getattr(args, "command", None) or "hangover",
                repo=str(getattr(args, "repo", None) or "."),
            ).tool_error("invalid arguments; usage is on stderr").emit()
        raise
    origin = Origin(command=args.command, repo=str(args.repo))
    as_json = getattr(args, "json", False)
    try:
        # --no-checks (static mode) is for untrusted checkouts: the checkout's git data may not choose
        # which directory hangover scans or writes `.hangover/` into.
        static = args.command in {"run", "scan"} and bool(getattr(args, "no_checks", False))
        repo = resolve_repo(args.repo, static=static)
        origin.repo = str(repo)
        if not repo.is_dir():
            raise RuntimeError(f"repository path is not a directory: {repo}")
        invoked_repo = repo
        # Static mode resolved a regular clone (a linked worktree is refused there), so no git runs here.
        linked, main_checkout = (False, None) if static else _worktree_context(repo)
        in_campaign_worktree = bool(main_checkout and paths(main_checkout)["state"].exists())
        if linked and main_checkout is None and args.command not in (*READ_ONLY_COMMANDS, "doctor", "fallow", "audit"):
            raise RuntimeError(
                "this is a linked worktree whose main checkout cannot be determined (bare, removed or "
                "unreadable); campaign writes are refused here, and reads need --state-from PATH"
            )
        if in_campaign_worktree and args.command not in (*READ_ONLY_COMMANDS, "doctor", "fallow", "audit"):
            # Decided by the main checkout's state alone, so nothing a worktree
            # creates locally (an audit record, say) can unlock campaign writes.
            raise RuntimeError(
                f"this is a linked worktree of {main_checkout}, where the campaign state lives; "
                "run this command there (a worktree may only run list, next, status, preview, packet, "
                "audit, doctor and fallow)"
            )
        if args.command != "fallow":
            # `.hangover/` the checkout tracks or (under --no-checks) did not get from hangover here is
            # refused before anything reads it; static mode checks under the no-execute git environment.
            with no_execute_git(repo) if static else contextlib.nullcontext():
                refuse_foreign_state(repo, static=static)
        if args.command == "init":
            _initialize(repo, args.force)
            return _adopt_gate_stages(repo) if args.stages_from_gate else 0
        if args.command == "run":
            return _run(repo, args.no_checks, args.no_review, quiet=args.quiet, runner=args.runner)
        if args.command == "doctor":
            return _doctor(repo, args.json)
        if args.command == "fallow":
            return _fallow_passthrough(repo, args.fallow_args)
        if args.command in READ_ONLY_COMMANDS:
            # State lives in the main checkout; a worktree reads it, never writes it.
            source = getattr(args, "state_from", None)
            if source is not None:
                repo = resolve_repo(source)
            elif in_campaign_worktree:
                repo = main_checkout
            elif linked and main_checkout is None:
                raise RuntimeError("the main checkout of this linked worktree cannot be determined; pass --state-from PATH")
            origin.repo = str(repo)
            if repo != invoked_repo:
                refuse_foreign_state(repo, static=False)
            _require_initialized(repo)
        else:
            with no_execute_git(repo) if static else contextlib.nullcontext():
                _ensure_initialized(repo, stream=sys.stderr if as_json else None)
        if args.command == "scan":
            previous_run = load_state(repo).get("baseline_run")
            snapshot, _, _ = _scan(
                repo, no_checks=not args.checks, no_execute=args.no_checks, quiet=args.quiet,
                rebaseline=args.rebaseline,
            )
            _print_scan(snapshot)
            if snapshot.get("is_baseline") and not snapshot.get("checks") and _config(repo).get("checks"):
                print(
                    "note: this baseline holds no native check results, so a stage that is "
                    "already red will block verify; run `hangover scan --rebaseline --checks` "
                    "to record which stages are red"
                )
            if args.rebaseline:
                if snapshot.get("baseline_reset_blocked_reason"):
                    print(f"baseline reset blocked: {snapshot['baseline_reset_blocked_reason']}")
                    return 2
                print(
                    f"baseline reset: {snapshot['id']} "
                    f"(previous {previous_run or 'none'})"
                )
            return 0
        if args.command == "status":
            return _status(repo, args.json, args.stale)
        if args.command == "next":
            _next(repo, args.json)
            return 0
        if args.command == "list":
            list_issues(
                repo,
                args.json,
                {
                    "source": args.source,
                    "category": args.category,
                    "status": args.status,
                    "file": args.file,
                },
                group_by=args.group_by,
                sort=args.sort,
                exclude_tests=args.exclude_tests,
            )
            return 0
        if args.command == "packet":
            return _packet(repo, args.issue, args.out, args.json, invoked=invoked_repo, force=args.force)
        if args.command == "preview":
            return preview_batch(repo, args.issue, args.limit, args.json)
        if args.command == "review":
            rc, review, _ = _review(
                repo,
                issue_id=args.issue,
                prepare_only=args.prepare,
                import_path=args.import_path,
                runner_override=args.runner,
                lane_override=args.lane,
                model_override=args.model,
                reasoning_effort_override=args.reasoning_effort,
                quiet=args.quiet,
                as_json=args.json,
                emit_result=args.json,
                origin=origin,
                scope_paths=args.scope,
            )
            if rc == 0 and review is not None and args.issue and review.get("verdict") != "pass":
                # A post-fix review that refuses the remediation is a blocked
                # verdict, as it is when verify runs the same review.
                return exit_code("blocked")
            return rc
        if args.command == "suppress":
            return _suppress(
                repo,
                args.issue,
                args.reason,
                rebaseline=not args.no_rebaseline,
                quiet=args.quiet,
            )
        if args.command == "fix":
            return _begin_fix(
                repo, args.issue, args.defer, args.obsolete, args.release, args.json,
                branch=args.branch, add=args.add,
            )
        if args.command == "verify" and (args.merged or args.all_batches):
            if args.issue or args.retry_review or args.accept or args.accept_reason or args.note or args.note_file:
                raise RuntimeError("--merged and --all cannot combine with --issue, --retry-review, notes or waivers")
            return _verify_open_batches(
                repo, "all" if args.all_batches else "merged", as_json=as_json, origin=origin,
                no_review=args.no_review, runner_override=args.runner, lane_override=args.lane,
                model_override=args.model, reasoning_effort_override=args.reasoning_effort,
                quiet=args.quiet, affected=args.affected, fresh_gate=args.fresh_gate,
                model_only=args.model_only,
            )
        if args.command == "verify":
            return _verify(
                repo,
                args.issue,
                args.no_review,
                args.runner,
                args.lane,
                args.model,
                args.reasoning_effort,
                args.accept,
                args.accept_reason,
                args.note,
                args.note_file,
                args.quiet,
                args.json,
                origin=origin,
                retry_review=args.retry_review,
                affected=args.affected,
                fresh_gate=args.fresh_gate,
                model_only=args.model_only,
            )
        if args.command == "audit":
            return _audit(
                repo, args.base, args.full, quiet=args.quiet, as_json=args.json,
                require_review=args.require_review, prepare_only=args.prepare, import_path=args.import_path,
                runner_override=args.runner, lane_override=args.lane, model_override=args.model,
                reasoning_effort_override=args.reasoning_effort, origin=origin,
            )
        if args.command == "dedupe":
            return _dedupe(repo, args.apply, args.json)
        raise RuntimeError(f"unsupported command {args.command}")
    except (RuntimeError, OSError) as exc:
        # One machine result per invocation, built from what this invocation
        # itself bound; the prose stays on stderr in both modes. An OSError is
        # the filesystem or OS refusing an expected operation (an occupied or
        # unwritable .hangover path, a full disk), not a programming defect, so
        # it gets the same envelope; anything else still raises.
        message = str(exc) if isinstance(exc, RuntimeError) else _os_error_message(exc)
        print(f"hangover: {message}", file=sys.stderr)
        if as_json:
            origin.tool_error(message, next_action=getattr(exc, "next_action", None)).emit()
        return exit_code("tool_error")


def _os_error_message(exc: OSError) -> str:
    detail = exc.strerror or str(exc) or type(exc).__name__
    where = f": {exc.filename}" if exc.filename else ""
    return f"{detail}{where}" + (f" -> {exc.filename2}" if exc.filename2 else "")


if __name__ == "__main__":
    raise SystemExit(main())
