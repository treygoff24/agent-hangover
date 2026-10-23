from __future__ import annotations

import copy
import json
import os
import posixpath
import re
import sys
import tempfile
from collections.abc import Iterable
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, TypeVar
from uuid import uuid4
from .finding_identity import duplication_spans
from .fallow_evidence import caveat_reasons, degrading_index

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
STATE_DIR = ".hangover"
# Every card ID: this prefix, then the first 10 hex digits of the card fingerprint's digest.
ISSUE_ID_PREFIX = "hang-"
ISSUE_ID = re.compile(rf"{ISSUE_ID_PREFIX}[0-9a-f]{{10}}")
OPEN_STATUSES = {"open", "reopened", "in_progress"}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
FULL_SCAN_KINDS = {"scan", "baseline", "verify"}
# Deterministic analyzers: their cards are governed by scans (stale when no longer
# reported), never merged as subjective review claims.
ANALYZER_SOURCES = frozenset({"fallow", "rust"})
# Which Rust analysis section reports each category: a Rust card goes stale only
# when its section completed in the scan that no longer reports it.
RUST_SECTION_BY_CATEGORY = {
    "complexity": "clippy",
    "dead_code": "clippy",
    "unused_imports": "clippy",
    "duplication": "dupes",
    "unused_dependencies": "machete",
    "unused_pub_items": "items",
    "crate_local_pub": "items",
    "wide_pub_surface": "items",
    "god_file": "items",
    "oversized_module": "items",
    "oversized_crate": "items",
}
FALLOW_SECTION_BY_CATEGORY = {
    "duplication": "dupes",
    "feature_flag": "flags",
    "complexity": "health",
    "fallow_unmapped": "dead_code",
}
MutationResult = TypeVar("MutationResult")
SHARED_FIX_FIELDS = (
    "fix_base_commit", "fix_dir", "fix_finding_ids", "fix_started_at", "fix_notes", "waivers",
)
ISSUE_CONTRACT_FIELDS = (
    "id", "source", "source_version", "category", "title", "evidence", "files", "symbols",
    "harm", "proposed_change", "invariants", "verification", "chesterton", "risk",
    "priority", "confidence", "parent_issue", "suppression", "complexity_identity", "duplication_identity", "identity_from",
)


def is_analyzer(item: dict[str, Any]) -> bool:
    return item.get("source") in ANALYZER_SOURCES


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def paths(repo: Path) -> dict[str, Path]:
    repo = repo.resolve()
    root = repo / STATE_DIR
    values = {
        "root": root,
        "config": root / "config.json",
        "state": root / "state.json",
        "state_lock": root / "state.json.lock",
        "runs": root / "runs",
        "fixes": root / "fixes",
    }
    for path in values.values():
        if path.is_symlink() or not path.resolve().is_relative_to(repo):
            raise RuntimeError(f"refusing state path outside the repository: {path}")
    return values


def digest(value: Any) -> str:
    """Canonical JSON digest: key order and whitespace do not change it."""
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing {path}; run `hangover init` first") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"expected a JSON object in {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=False) + "\n"
    descriptor, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def new_state(repo: Path) -> dict[str, Any]:
    timestamp = now()
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": str(repo),
        "created_at": timestamp,
        "updated_at": timestamp,
        "revision": 0,
        "baseline_run": None,
        "latest_run": None,
        "active_issue": None,
        "active_batch": [],
        "active_remediation": None,
        "remediations": {},
        "issues": {},
        "history": [{"at": timestamp, "event": "initialized"}],
    }


def load_state(repo: Path) -> dict[str, Any]:
    state = read_json(paths(repo)["state"])
    if state.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported state schema {state.get('schema_version')!r}; "
            f"this hangover supports {SCHEMA_VERSION}"
        )
    recorded_repo = Path(str(state.get("repo", ""))).resolve()
    if recorded_repo != repo.resolve():
        raise RuntimeError(
            f"state belongs to {recorded_repo}, not {repo.resolve()}; re-run `hangover init --force`"
        )
    _project_active_remediation(state)
    return state


def save_state(repo: Path, state: dict[str, Any]) -> None:
    state.setdefault("revision", 0)
    state["updated_at"] = now()
    state_path = paths(repo)["state"]
    write_json(state_path, state)
    if os.environ.get("HANGOVER_DEBUG_STATE") == "1":
        print(
            f"state_saved path={state_path} revision={state['revision']}",
            file=sys.stderr,
        )


def mutate_state(repo: Path, fn: Callable[[dict[str, Any]], MutationResult]) -> MutationResult:
    state_paths = paths(repo)
    state_paths["root"].mkdir(parents=True, exist_ok=True)
    with state_paths["state_lock"].open("a+") as lock:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            state = (
                load_state(repo)
                if state_paths["state"].exists()
                else new_state(repo.resolve())
            )
            result = fn(state)
            revision = state.get("revision", 0)
            if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
                raise RuntimeError(f"invalid state revision {revision!r}")
            state["revision"] = revision + 1
            save_state(repo, state)
            return result
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def add_history(state: dict[str, Any], event: str, **details: Any) -> None:
    entry = {"at": now(), "event": event}
    entry.update(details)
    state.setdefault("history", []).append(entry)


def add_issue_event(issue: dict[str, Any], event: str, /, *, at: str | None = None, **details: Any) -> None:
    issue.setdefault("history", []).append({"at": at or now(), "event": event, **details})


def issue_id(finding: dict[str, Any]) -> str:
    fingerprint = finding.get("fingerprint")
    if not fingerprint:
        fingerprint = {
            "source": finding.get("source"),
            "category": finding.get("category"),
            "title": finding.get("title"),
            "files": sorted(finding.get("files", [])),
        }
    return f"{ISSUE_ID_PREFIX}{digest(fingerprint)[:10]}"


def normalize_repo_path(path: str) -> str:
    return posixpath.normpath(str(path).replace("\\", "/"))


def _file_set(item: dict[str, Any]) -> set[str]:
    return {normalize_repo_path(path) for path in item.get("files") or [] if str(path).strip()}


def _symbol_set(item: dict[str, Any]) -> set[str]:
    return {str(symbol) for symbol in item.get("symbols") or [] if str(symbol)}


def subjective_related(new_finding: dict[str, Any], existing: dict[str, Any]) -> bool:
    if new_finding.get("category") != existing.get("category"):
        return False
    new_files = _file_set(new_finding)
    existing_files = _file_set(existing)
    smaller = min(len(new_files), len(existing_files))
    if smaller == 0:
        return False
    if len(new_files & existing_files) / smaller < 0.5:
        return False
    new_symbols = _symbol_set(new_finding)
    existing_symbols = _symbol_set(existing)
    if new_symbols and existing_symbols and new_symbols.isdisjoint(existing_symbols):
        return False
    return True


def subjective_duplicate(new_finding: dict[str, Any], existing: dict[str, Any]) -> bool:
    if not subjective_related(new_finding, existing):
        return False
    if any(new_finding.get(field) != existing.get(field) for field in ("source", "parent_issue")):
        return False
    if _file_set(new_finding) != _file_set(existing) or _symbol_set(new_finding) != _symbol_set(existing):
        return False
    if not _symbol_set(new_finding) and new_finding.get("title") != existing.get("title"):
        return False
    for field in ("harm", "proposed_change"):
        value = new_finding.get(field)
        if not isinstance(value, str) or not value.strip() or value != existing.get(field):
            return False
    invariants = set(new_finding.get("invariants") or [])
    return bool(invariants) and invariants == set(existing.get("invariants") or [])


def _merge_subjective_claim(
    previous: dict[str, Any], finding: dict[str, Any], run_id: str | None, timestamp: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    fields = (
        "source", "source_version", "parent_issue", "category", "title", "evidence", "files", "symbols",
        "harm", "proposed_change", "invariants", "verification", "chesterton", "priority", "risk", "confidence",
    )
    incoming = {field: finding[field] for field in fields if field in finding}
    merged = dict(incoming)
    merged["title"] = previous["title"]
    for field in ("evidence", "files", "symbols", "invariants", "verification"):
        merged[field] = list(dict.fromkeys([*(previous.get(field) or []), *(finding.get(field) or [])]))
    for field, ranking, choose in (("priority", PRIORITY_ORDER, min), ("risk", RISK_ORDER, max),
                                   ("confidence", CONFIDENCE_ORDER, max)):
        values = [item[field] for item in (previous, finding) if item.get(field) in ranking]
        if values:
            merged[field] = choose(values, key=ranking.__getitem__)
    event = {"at": timestamp, "event": "seen_again", "run": run_id,
             "as": finding.get("title"), "finding": incoming}
    # Lists are unioned. Preserve scalar claims displaced by newer evidence too.
    displaced = {field: previous[field] for field in fields
                 if field in previous and not isinstance(previous[field], list)
                 and previous[field] != merged.get(field)}
    if displaced:
        event["previous"] = displaced
    return merged, event if any(value != previous.get(field) for field, value in incoming.items()) else None


def _open_subjective_duplicate(
    issues: dict[str, Any], finding: dict[str, Any]
) -> dict[str, Any] | None:
    matches = [
        issue
        for issue in issues.values()
        if issue.get("status") in OPEN_STATUSES | {"obsolete"}
        and not is_analyzer(issue)
        and subjective_duplicate(finding, issue)
    ]
    if not matches:
        return None
    return min(matches, key=lambda item: (item.get("first_seen", ""), item["id"]))


def _recorded_canonical(
    issues: dict[str, Any], existing: dict[str, Any], finding: dict[str, Any],
) -> dict[str, Any]:
    current = existing
    visited = set()
    while current.get("status") == "closed":
        if current["id"] in visited:
            return existing
        visited.add(current["id"])
        target_id = next((entry.get("of") for entry in reversed(current.get("history", []))
                          if isinstance(entry, dict) and entry.get("event") == "closed_duplicate"), None)
        if not isinstance(target_id, str):
            return existing
        target = issues.get(target_id)
        if target is None or not subjective_duplicate(finding, target):
            return existing
        current = target
    return current


MIGRATION_SUPERSEDED_STATUSES = frozenset({"open", "reopened", "stale"})


def _migration_supersedes_legacy(migration: dict[str, Any]) -> bool:
    return (migration["previous_status"] in MIGRATION_SUPERSEDED_STATUSES
            or bool(migration.get("inherited_status")))


def _migrate_complexity_identities(
    issues: dict[str, Any], findings: list[dict[str, Any]], run_id: str, timestamp: str,
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        identity = finding.get("complexity_identity")
        if (finding.get("source") != "fallow" or finding.get("category") != "complexity"
                or not isinstance(identity, dict) or identity.get("version") not in {2, 3}):
            continue
        legacy_id = issue_id({"fingerprint": ["fallow", "complexity", *identity["family"]]})
        legacy = issues.get(legacy_id)
        if (legacy and legacy.get("source") == "fallow" and legacy.get("category") == "complexity"
                and not legacy.get("complexity_identity")):
            finding["identity_from"] = legacy_id
            if not legacy.get("identity_migrated"):
                groups.setdefault(legacy_id, []).append(finding)
    active = [identifier for identifier in groups if issues[identifier].get("status") == "in_progress"]
    if active:
        raise RuntimeError(
            "legacy complexity identity is active; run `hangover fix --release "
            + " ".join(sorted(active)) + "`, then scan and select the anchored issues"
        )
    migrations = []
    for legacy_id, replacements in groups.items():
        legacy = issues[legacy_id]
        migration = {"from_issue": legacy_id, "previous_status": legacy["status"],
                     "replacements": [issue_id(finding) for finding in replacements]}
        # A deferral is a human ruling about this code, not about its old ID.
        # When the legacy card maps to exactly one anchored function that has
        # no card of its own yet, that function inherits the ruling instead of
        # resurfacing as open. A collision split is left open: the ruling was
        # made on one member's evidence and cannot be attributed to the others.
        # An anchored card that already exists keeps its own disposition and
        # the legacy card keeps the deferral.
        inherited = None
        if (legacy["status"] == "deferred" and len(replacements) == 1
                and migration["replacements"][0] not in issues):
            reason = next((entry.get("reason") for entry in reversed(legacy.get("history", []))
                           if isinstance(entry, dict) and entry.get("event") == "deferred"), None)
            inherited = {"status": "deferred", "reason": reason}
            migration["inherited_status"] = "deferred"
        migrations.append(migration)
        legacy["identity_migrated"] = True
        add_issue_event(legacy, "identity_refined", at=timestamp, run=run_id, **migration)
        if _migration_supersedes_legacy(migration):
            legacy["status"] = "obsolete"
        for finding in replacements:
            finding["_identity_migration"] = {"at": timestamp, "event": "identity_refined", "run": run_id,
                                              "from_issue": legacy_id, "previous_status": migration["previous_status"]}
            if inherited:
                finding["_identity_migration"]["inherited"] = inherited
    return migrations


TRACKED_STATUSES = frozenset({"open", "reopened", "stale", "deferred", "in_progress"})


def _carry_card(issues: dict[str, Any], old_id: str, new_id: str, run_id: str, timestamp: str, **details: Any) -> None:
    """Move a card's whole record (status, history, first_seen) to its new identifier.

    The old record stays as a pointer: marked migrated, and obsolete when it
    was still a live disposition, so only the new card is worked from.
    """
    old = issues[old_id]
    previous_status = old["status"]
    carried = copy.deepcopy(old)
    carried.pop("identity_migrated", None)
    carried.update(id=new_id, identity_from=old_id)
    carried["history"] = [*carried.get("history", []),
                          {"at": timestamp, "event": "identity_migrated", "run": run_id, "from_issue": old_id,
                           "previous_status": previous_status, **details}]
    issues[new_id] = carried
    old["identity_migrated"] = True
    if previous_status in MIGRATION_SUPERSEDED_STATUSES or previous_status == "deferred":
        old["status"] = "obsolete"
    add_issue_event(old, "identity_migrated", at=timestamp, run=run_id, replacements=[new_id], previous_status=previous_status, **details)


def _refuse_active_legacy(issues: dict[str, Any], legacy_ids: Iterable[str], what: str) -> None:
    active = sorted(old for old in legacy_ids if issues[old].get("status") == "in_progress")
    if active:
        raise RuntimeError(f"legacy {what} identity is active; run `hangover fix --release "
                           + " ".join(active) + "` before scanning")


def _legacy_dead_code_card(issues, finding):
    legacy = finding.get("legacy_fingerprint")
    if finding.get("source") != "fallow" or not finding.get("finding_id") or not legacy:
        return None
    legacy_id = issue_id({"fingerprint": legacy})
    card = issues.get(legacy_id)
    if card and card.get("source") == "fallow" and card.get("category") == finding.get("category") \
            and not card.get("identity_migrated"):
        return legacy_id
    return None


def _migrate_finding_id_identities(issues, findings, run_id, timestamp):
    """Dead-code cards keyed by path+symbol move to Fallow's stable `finding_id` by exact match."""
    # Group every current finding sharing a legacy key before looking at whether
    # a destination card exists: a multi-finding family never inherits, even when
    # one destination was seeded by an earlier scan.
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        legacy_id = _legacy_dead_code_card(issues, finding)
        finding.pop("legacy_fingerprint", None)
        if legacy_id:
            groups.setdefault(legacy_id, []).append(finding)
    _refuse_active_legacy(issues, [old for old, members in groups.items()
                                   if any(issue_id(f) not in issues for f in members)], "dead-code")
    migrations = []
    for legacy_id, members in groups.items():
        fresh = [finding for finding in members if issue_id(finding) not in issues]
        if not fresh:
            continue
        previous_status = issues[legacy_id]["status"]
        replacement_ids = [issue_id(finding) for finding in fresh]
        migration = {"from_issue": legacy_id, "previous_status": previous_status,
                     "replacements": replacement_ids, "category": fresh[0].get("category")}
        if len(members) == 1:
            _carry_card(issues, legacy_id, replacement_ids[0], run_id, timestamp,
                        finding_id=fresh[0]["finding_id"])
            migration["inherited_status"] = previous_status
        else:
            # Several findings shared one path+symbol key: the old card cannot
            # be attributed to any one of them, so each starts open and linked.
            legacy = issues[legacy_id]
            legacy["identity_migrated"] = True
            if previous_status in MIGRATION_SUPERSEDED_STATUSES:
                legacy["status"] = "obsolete"
            add_issue_event(legacy, "identity_refined", at=timestamp, run=run_id, **migration)
            for finding in fresh:
                finding["identity_from"] = legacy_id
                finding["_identity_migration"] = {"at": timestamp, "event": "identity_refined", "run": run_id,
                                                  "from_issue": legacy_id, "previous_status": previous_status}
        migrations.append(migration)
    return migrations


def _span_cards(issues, identity):
    """Pre-upgrade span-anchored cards for one (file, name), any status but already-migrated."""
    return [
        old_id for old_id, card in issues.items()
        if card.get("source") == "fallow" and card.get("category") == "complexity"
        and not card.get("identity_migrated")
        and (card.get("complexity_identity") or {}).get("version") == 2
        and not (card.get("complexity_identity") or {}).get("ambiguous")
        and (card.get("complexity_identity") or {}).get("family") == identity["family"]
    ]


def _function_candidates(issues, identity):
    """Which old cards exactly describe this function: its surviving span, else the only card.

    A stale or settled card of the same name is not proof of lineage (it may be
    a removed sibling), so several cards without an exact span match stay
    ambiguous. Returns (candidates, exact).
    """
    cards = _span_cards(issues, identity)
    anchor = identity.get("span_sha256")
    exact = [old_id for old_id in cards
             if anchor and issues[old_id]["complexity_identity"].get("span_sha256") == anchor]
    if len(exact) == 1:
        return exact, True
    if exact:
        return exact, False
    return cards, len(cards) == 1


def _migrate_function_identities(issues, findings, run_id, timestamp):
    """Span-anchored complexity cards move to the (file, function) key by exact evidence."""
    migrations = []
    for finding in findings:
        identity = finding.get("complexity_identity")
        if (finding.get("source") != "fallow" or finding.get("category") != "complexity"
                or not isinstance(identity, dict) or identity.get("version") != 3):
            continue
        new_id = issue_id(finding)
        if new_id in issues:
            continue
        candidates, exact = _function_candidates(issues, identity)
        if not candidates:
            continue
        if not exact:
            finding["_identity_migration"] = {"at": timestamp, "event": "identity_ambiguous", "run": run_id,
                                              "candidates": sorted(candidates)}
            continue
        _refuse_active_legacy(issues, candidates, "complexity")
        old_id = candidates[0]
        migrations.append({"from_issue": old_id, "previous_status": issues[old_id]["status"],
                           "replacements": [new_id], "category": "complexity",
                           "inherited_status": issues[old_id]["status"]})
        _carry_card(issues, old_id, new_id, run_id, timestamp, family=identity["family"])
    return migrations


def _has_pending_migration(issues, finding) -> list[str]:
    """Ids of old cards that a complete scan would migrate this finding from (none: nothing pending)."""
    if issue_id(finding) in issues:
        return []
    if finding.get("legacy_fingerprint"):
        legacy_id = _legacy_dead_code_card(issues, finding)
        return [legacy_id] if legacy_id else []
    if finding.get("source") == "fallow" and finding.get("category") == "duplication":
        spans = duplication_spans(finding)
        return [old for old, card in issues.items()
                if spans and card.get("source") == "fallow" and card.get("category") == "duplication"
                and card.get("status") in TRACKED_STATUSES and duplication_spans(card) & spans]
    identity = finding.get("complexity_identity")
    if (finding.get("source") == "fallow" and finding.get("category") == "complexity"
            and isinstance(identity, dict) and identity.get("version") in {2, 3}):
        legacy_id = issue_id({"fingerprint": ["fallow", "complexity", *identity["family"]]})
        legacy = issues.get(legacy_id)
        pending = [legacy_id] if (legacy and not legacy.get("complexity_identity")
                                  and not legacy.get("identity_migrated")) else []
        return pending + (_span_cards(issues, identity) if identity.get("version") == 3 else [])
    return []


REASSIGNABLE_FINGERPRINT = re.compile(r"dup:[0-9a-f]+-r[1-9][0-9]*")


def reassign_duplication_fingerprints(issues: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Give a rank-suffixed clone group that took over another group's fingerprint its own card.

    Fallow reassigns `dup:<hash>-rN` to different groups as code changes. When
    the existing card for that fingerprint shares no instance with the group
    now reported, they are different groups: reusing the card would reopen it
    with a ruling about unrelated code. Idempotent: a reassigned finding keeps
    the marker, and a later scan finds its card by overlapping spans.
    """
    for finding in findings:
        fingerprint = finding.get("fingerprint")
        if (finding.get("source") != "fallow" or finding.get("category") != "duplication"
                or not isinstance(fingerprint, list) or len(fingerprint) != 3
                or not isinstance(fingerprint[2], str) or not REASSIGNABLE_FINGERPRINT.fullmatch(fingerprint[2])):
            continue
        base = issues.get(issue_id(finding))
        spans = duplication_spans(finding)
        if (not base or not spans or base.get("source") != "fallow" or base.get("category") != "duplication"):
            continue
        held = duplication_spans(base)
        if not held or held & spans:
            continue
        # Only the complete span set identifies the earlier successor; a partial
        # overlap is new work that the span-set migration links to its history.
        successors = [card for card in issues.values()
                      if card.get("reassigned_from") == base["id"] and duplication_spans(card) == spans]
        token = (successors[0]["reassigned_token"] if len(successors) == 1 and "reassigned_token" in successors[0]
                 else sha256(json.dumps(sorted(spans)).encode()).hexdigest()[:12])
        finding["fingerprint"] = [*fingerprint, "reassigned", token]
        finding["reassigned_from"] = base["id"]
        finding["reassigned_token"] = token


def _migrate_duplication_identities(issues, findings, run_id, timestamp):
    candidates = {key: duplication_spans(card) for key, card in issues.items()
                  if card.get("source") == "fallow" and card.get("category") == "duplication"
                  and card.get("status") in {"open", "reopened", "stale", "deferred", "in_progress"}}
    new = {issue_id(item): item for item in findings
           if item.get("category") == "duplication" and item.get("source") == "fallow"}
    overlaps = {key: [old for old, spans in candidates.items() if spans & duplication_spans(item)]
                for key, item in new.items()}
    exact = {key: [old for old in matches if candidates[old] == duplication_spans(new[key])]
             for key, matches in overlaps.items()}
    groups = {}
    for key, item in new.items():
        if key in issues or not overlaps[key]:
            continue
        spans = duplication_spans(item)
        best = min(overlaps[key], key=lambda old: (candidates[old] != spans, -len(spans & candidates[old]), old))
        item["identity_from"] = best
        if not issues[best].get("identity_migrated"):
            groups.setdefault(best, []).append(key)
    active = [old for old in groups if issues[old]["status"] == "in_progress"]
    if active:
        raise RuntimeError("legacy duplication identity is active; run `hangover fix --release "
                           + " ".join(sorted(active)) + "` before scanning")
    migrations = []
    for old, replacements in groups.items():
        legacy = issues[old]
        migration = dict(from_issue=old, previous_status=legacy["status"], replacements=replacements,
                         category="duplication")
        key = replacements[0]
        # Whole span sets, not shared instances, establish exact identity.
        inherits = (len(replacements) == 1 and len(exact[key]) == 1
                    and sum(old in matches for matches in exact.values()) == 1)
        inherited = None
        if inherits:
            status = "deferred" if legacy["status"] == "deferred" else "open"
            reason = next((entry.get("reason") for entry in reversed(legacy.get("history", []))
                           if isinstance(entry, dict) and entry.get("event") == "deferred"), None) if status == "deferred" else None
            inherited = dict(status=status, reason=reason, first_seen=legacy.get("first_seen", timestamp))
            migration["inherited_status"] = status
        for key in replacements:
            new[key]["_identity_migration"] = dict(at=timestamp, event="identity_refined", run=run_id,
                                                   from_issue=old, previous_status=legacy["status"])
            if inherited:
                new[key]["_identity_migration"]["inherited"] = inherited
        legacy["identity_migrated"] = True
        if _migration_supersedes_legacy(migration):
            legacy["status"] = "obsolete"
        add_issue_event(legacy, "identity_refined", at=timestamp, run=run_id, **migration)
        migrations.append(migration)
    return migrations


def merge_findings(
    state: dict[str, Any],
    findings: Iterable[dict[str, Any]],
    run_id: str,
    *,
    scan_result: dict[str, Any] | None = None,
    repo: Path | None = None,
    stale_exclusions: Iterable[str] = (),
    obsolete_fallow_rules: dict[str, str] | None = None,
) -> dict[str, Any]:
    seen: list[str] = []
    new_count = 0
    already_tracked = 0
    timestamp = now()
    issues = state.setdefault("issues", {})
    findings = [dict(raw) for raw in findings]
    comparison = (scan_result or {}).get("fallow_comparison", {})
    if (comparison.get("kind") == "version_changed"
            and not (scan_result or {}).get("rebaseline_evidence_accepted")):
        # Do not seed new fingerprint cards before the atomic upgrade: doing
        # so would consume the migration's no-preexisting-card precondition.
        return {"ids": [issue_id(item) for item in findings], "new": 0,
                "already_tracked": 0, "stale": 0, "obsolete": 0}
    migration_allowed = (not scan_result or (
        scan_result.get("fallow", {}).get("status", "completed") == "completed"
        and (comparison.get("comparable") is not False or comparison.get("kind") == "no_baseline"
             or scan_result.get("rebaseline_evidence_accepted"))))
    reassign_duplication_fingerprints(issues, findings)
    held: list[str] = []
    held_findings: list[dict[str, Any]] = []
    if not migration_allowed:
        # Seeding a new-identity card now would consume the migration's
        # no-preexisting-destination precondition and strand the old ruling.
        # Treat the old card as the one that was seen and create nothing.
        kept = []
        for finding in findings:
            pending = _has_pending_migration(issues, finding)
            if pending:
                held.extend(pending)
                held_findings.append({"finding": issue_id(finding), "title": finding.get("title"),
                                      "category": finding.get("category"), "candidates": sorted(set(pending))})
            else:
                kept.append(finding)
        findings = kept
    legacy_pre = {key: {"status": card.get("status"), "first_seen": card.get("first_seen"),
                        "metrics": copy.deepcopy(card.get("complexity_metrics"))}
                  for key, card in issues.items()
                  if card.get("source") == "fallow" and card.get("category") in {"complexity", "duplication"}}
    migrations = []
    if migration_allowed:
        migrations = _migrate_complexity_identities(issues, findings, run_id, timestamp)
        migrations.extend(_migrate_function_identities(issues, findings, run_id, timestamp))
        migrations.extend(_migrate_finding_id_identities(issues, findings, run_id, timestamp))
        migrations.extend(_migrate_duplication_identities(issues, findings, run_id, timestamp))
    seen.extend(held)
    pre_scan = {}
    for raw in findings:
        existing_card = issues.get(issue_id(raw))
        if existing_card is not None:
            pre_scan[issue_id(raw)] = {"status": existing_card.get("status"),
                                       "first_seen": existing_card.get("first_seen"),
                                       "metrics": copy.deepcopy(existing_card.get("complexity_metrics"))}
    for migration in migrations:
        # An unambiguous 1:1 destination stands for its legacy card: what the
        # legacy card was before this scan is what verify must compare against.
        # Splits and partial matches (no inherited status for duplication) stay unmapped.
        (dest,) = migration["replacements"] if len(migration.get("replacements", [])) == 1 else (None,)
        if (dest and migration["from_issue"] in legacy_pre and dest not in pre_scan
                and (migration.get("category") == "complexity" or migration.get("inherited_status"))):
            pre_scan[dest] = legacy_pre[migration["from_issue"]]
    for raw in findings:
        finding = dict(raw)
        identifier = issue_id(finding)
        finding.pop("fingerprint", None)
        finding.pop("legacy_fingerprint", None)
        migration_event = finding.pop("_identity_migration", None)
        existing = issues.get(identifier)
        if existing and not is_analyzer(finding) and not subjective_duplicate(finding, existing):
            # Old review IDs omit symbols and claims. Refine only a collision,
            # leaving existing campaign IDs and dispositions intact otherwise.
            identifier = issue_id({"fingerprint": [
                "review-claim", identifier,
                {field: finding.get(field) for field in (
                    "source", "parent_issue", "category", "title", "harm", "proposed_change",
                )},
                sorted(_file_set(finding)), sorted(_symbol_set(finding)),
                sorted(set(finding.get("invariants") or [])),
            ]})
            existing = issues.get(identifier)
        previous = existing
        if previous is None and not is_analyzer(finding):
            previous = _open_subjective_duplicate(issues, finding)
            if previous:
                identifier = previous["id"]
        if previous and not is_analyzer(finding):
            previous = _recorded_canonical(issues, previous, finding)
            identifier = previous["id"]
        claim_event = None
        if previous and not is_analyzer(finding):
            finding, claim_event = _merge_subjective_claim(previous, finding, run_id, timestamp)
        if not is_analyzer(finding):
            related = [candidate["id"] for candidate in issues.values()
                       if not is_analyzer(candidate) and candidate["id"] != identifier
                       and subjective_related(finding, candidate)]
            finding["possible_duplicates"] = sorted(related)
        seen.append(identifier)
        if previous:
            already_tracked += 1
            status = previous["status"]
            if status in {"resolved", "suppressed", "stale", "obsolete", "closed"}:
                status = "reopened"
                history = previous.get("history", []) + [
                    {"at": timestamp, "event": "reopened", "run": run_id}
                ]
            else:
                history = previous.get("history", [])
            first_seen = previous["first_seen"]
            if (finding.get("complexity_metrics") and previous.get("complexity_metrics")
                    and finding["complexity_metrics"] != previous["complexity_metrics"]):
                # Drift on an existing function updates the card; it is not a new finding.
                history = [*history, {"at": timestamp, "event": "metrics_changed", "run": run_id,
                                      "from": previous["complexity_metrics"], "to": finding["complexity_metrics"]}]
        else:
            new_count += 1
            status = "open"
            history = [{"at": timestamp, "event": "opened", "run": run_id}]
            first_seen = timestamp
        if claim_event:
            history = [*history, claim_event]
        if migration_event:
            # Migration only attaches `inherited` when no card exists for
            # this identifier, so `previous` is None here.
            inherited = migration_event.pop("inherited", None)
            if inherited and "first_seen" in inherited:
                first_seen = inherited["first_seen"]
            history = [*history, migration_event]
            if inherited:
                status = inherited["status"]
                history = [*history, {"at": timestamp, "event": inherited["status"], "run": run_id,
                                      "reason": inherited["reason"],
                                      "inherited_from": migration_event["from_issue"]}]
        issues[identifier] = {
            **(previous or {}),
            "id": identifier,
            **finding,
            "status": status,
            "first_seen": first_seen,
            "last_seen": timestamp,
            "last_seen_run": run_id,
            "history": history,
        }
    stale_count = 0
    obsolete_count = sum(_migration_supersedes_legacy(item) for item in migrations)
    if scan_result and scan_result.get("kind") in FULL_SCAN_KINDS:
        commands = scan_result.get("fallow", {}).get("commands", {})
        completed_sections = {
            name
            for name, command in commands.items()
            if isinstance(command, dict) and command.get("status") == "completed"
        }
        seen_ids = set(seen)
        excluded_from_stale = set(stale_exclusions)
        rust_completed = {
            name
            for name, command in scan_result.get("rust", {}).get("commands", {}).items()
            if isinstance(command, dict) and command.get("status") == "completed"
        }

        def incomparable(comparison: dict[str, Any]) -> bool:
            return (comparison.get("comparable") is False
                    # An explicit rule-off config edit is existing repo
                    # policy, not analyzer disappearance credit; an analyzer
                    # that did not run (`not_run`) says nothing about its cards.
                    and comparison.get("kind") not in {"no_baseline", "config_changed", "not_run"}
                    and not scan_result.get("rebaseline_evidence_accepted"))

        fallow = scan_result.get("fallow", {})
        caveat_index = degrading_index(fallow)
        for identifier, issue in issues.items():
            if identifier in seen_ids or not is_analyzer(issue):
                continue
            if issue.get("source") == "rust":
                comparison = scan_result.get("rust_comparison", {})
                reasons = []
            else:
                comparison = scan_result.get("fallow_comparison", {})
                reasons = caveat_reasons(fallow, _file_set(issue), caveat_index)
            if incomparable(comparison):
                reasons.append(comparison.get("reason", "incomparable analyzer evidence"))
            if reasons:
                excluded_from_stale.add(identifier)
                if issue.get("status") in {"open", "reopened"}:
                    history = issue.setdefault("history", [])
                    reason = "; ".join(reasons)
                    last = history[-1] if history else {}
                    if last.get("event") != "unverifiable" or last.get("reason") != reason:
                        history.append(dict(at=timestamp, event="unverifiable", run=run_id, reason=reason))
        obsolete_statuses = {"open", "reopened", "stale"}
        if scan_result.get("kind") != "verify":
            obsolete_statuses.add("in_progress")
        for identifier, issue in issues.items():
            rule = (obsolete_fallow_rules or {}).get(issue.get("category"))
            if (
                not rule
                or identifier in excluded_from_stale
                or identifier in seen_ids
                or issue.get("source") != "fallow"
                or issue.get("status") not in obsolete_statuses
            ):
                continue
            reason = f"rule {rule} is off in the resolved Fallow config"
            issue["status"] = "obsolete"
            add_issue_event(issue, "obsolete", at=timestamp, run=run_id, reason=reason)
            obsolete_count += 1
        for identifier, issue in issues.items():
            if (
                identifier in seen_ids
                or identifier in excluded_from_stale
                or not is_analyzer(issue)
                or issue.get("status") not in {"open", "reopened"}
            ):
                continue
            if issue.get("source") == "rust":
                if RUST_SECTION_BY_CATEGORY.get(issue.get("category")) not in rust_completed:
                    continue
            elif FALLOW_SECTION_BY_CATEGORY.get(issue.get("category"), "dead_code") not in completed_sections:
                continue
            issue["status"] = "stale"
            add_issue_event(issue, "stale", at=timestamp, run=run_id, reason="not reported by the latest scan")
            stale_count += 1
        if repo is not None:
            for identifier, issue in issues.items():
                files = _file_set(issue)
                if (
                    identifier in seen_ids
                    or is_analyzer(issue)
                    or issue.get("status") not in {"open", "reopened", "stale"}
                    or not files
                    or any((repo / path).exists() for path in files)
                ):
                    continue
                issue["status"] = "obsolete"
                add_issue_event(issue, "obsolete", at=timestamp, run=run_id, reason="every referenced file was removed")
        if scan_result.get("kind") != "verify":
            _prune_active_batch(state)
    result = {
        "ids": seen,
        "new": new_count,
        "already_tracked": already_tracked,
        "stale": stale_count,
    }
    if scan_result and scan_result.get("kind") in FULL_SCAN_KINDS:
        result["obsolete"] = obsolete_count
    # What each reported card was (status, metrics) just before this scan changed it,
    # carried cards included under their new id; `verify` reads it to tell a new
    # finding from a known card that was merely absent from the fix-start scan.
    if held_findings:
        result["held"] = held_findings
    if pre_scan:
        result["pre_scan"] = pre_scan
    if migrations:
        result["identity_migrations"] = migrations
    return result


def dedupe_open_subjective_issues(
    state: dict[str, Any], *, apply: bool = False
) -> list[dict[str, str]]:
    candidates = [
        issue
        for issue in state.get("issues", {}).values()
        if issue.get("status") in OPEN_STATUSES and not is_analyzer(issue)
    ]
    candidates.sort(key=lambda item: (item.get("first_seen", ""), item["id"]))
    pairs: list[dict[str, str]] = []
    duplicated: set[str] = set()
    for index, later in enumerate(candidates):
        earlier = [candidate for candidate in candidates[:index] if candidate["id"] not in duplicated]
        strong = next((candidate for candidate in earlier if subjective_duplicate(later, candidate)), None)
        match = strong or next((candidate for candidate in earlier if subjective_related(later, candidate)), None)
        if match is None:
            continue
        if strong:
            duplicated.add(later["id"])
        pairs.append(
            {
                "duplicate": later["id"],
                "canonical": match["id"],
                "duplicate_title": str(later.get("title") or ""),
                "canonical_title": str(match.get("title") or ""),
                "match": "same_remediation" if strong else "overlap_only",
            }
        )
    if apply:
        timestamp = now()
        issues = state.setdefault("issues", {})
        for pair in pairs:
            if pair["match"] != "same_remediation":
                continue
            later = issues[pair["duplicate"]]
            canonical = issues[pair["canonical"]]
            claim, event = _merge_subjective_claim(canonical, later, later.get("last_seen_run"), timestamp)
            canonical.update(claim)
            if event:
                canonical.setdefault("history", []).append(event)
            later["status"] = "closed"
            add_issue_event(later, "closed_duplicate", at=timestamp, of=pair["canonical"])
            add_history(
                state, "issue_closed_duplicate", issue=later["id"], of=pair["canonical"]
            )
        _prune_active_batch(state)
    return pairs


def ordered_issues(state: dict[str, Any], *, open_only: bool = False) -> list[dict[str, Any]]:
    values = list(state.get("issues", {}).values())
    if open_only:
        values = [item for item in values if item.get("status") in {"open", "reopened"}]
    return sorted(
        values,
        key=lambda item: (
            PRIORITY_ORDER.get(item.get("priority"), 9),
            CONFIDENCE_ORDER.get(item.get("confidence"), 9),
            RISK_ORDER.get(item.get("risk"), 9),
            item.get("first_seen", ""),
            item["id"],
        ),
    )


def next_issue(state: dict[str, Any]) -> dict[str, Any] | None:
    active = state.get("active_issue")
    if active:
        issue = state.get("issues", {}).get(active)
        if issue and issue.get("status") == "in_progress":
            return issue
    issues = ordered_issues(state, open_only=True)
    return issues[0] if issues else None


def active_remediation(state: dict[str, Any]) -> dict[str, Any] | None:
    identifier = state.get("active_remediation")
    if identifier is None:
        return None
    records = state.get("remediations")
    if not isinstance(identifier, str) or not isinstance(records, dict):
        raise RuntimeError("invalid active remediation record")
    record = records.get(identifier)
    if not isinstance(record, dict) or record.get("id") != identifier:
        raise RuntimeError("invalid active remediation record")
    return record


def _project_active_remediation(state: dict[str, Any]) -> None:
    record = active_remediation(state)
    if record is None:
        return
    members = record.get("members")
    if (
        not isinstance(members, list) or not members
        or not all(isinstance(identifier, str) for identifier in members)
        or len(set(members)) != len(members)
    ):
        raise RuntimeError("invalid active remediation membership")
    if record.get("primary") != members[0]:
        raise RuntimeError("invalid active remediation primary")
    for identifier in members:
        issue = state.get("issues", {}).get(identifier)
        if issue is None:
            raise RuntimeError(f"active remediation refers to missing issue {identifier}")
        issue["remediation"] = record["id"]
        for field in SHARED_FIX_FIELDS:
            issue[field] = record.get(field)
    state["active_issue"] = record["primary"]
    state["active_batch"] = list(members)


def open_remediation_ids(state: dict[str, Any]) -> list[str]:
    """Every open batch's remediation id, focused batch included.

    A state written before several batches could be open has no list; its one
    active batch (if any) is the whole list, so migration loses nothing.
    """
    listed = state.get("open_remediations")
    active = state.get("active_remediation")
    if listed is None:
        listed = [active] if active else []
    records = state.get("remediations")
    if (not isinstance(listed, list) or len(set(listed)) != len(listed)
            or (listed and not isinstance(records, dict))):
        raise RuntimeError("invalid open remediation list")
    ids = list(listed)
    if active and active not in ids:
        ids.insert(0, active)
    for identifier in ids:
        record = records.get(identifier) if isinstance(records, dict) else None
        if not isinstance(identifier, str) or not isinstance(record, dict) or record.get("id") != identifier:
            raise RuntimeError("invalid open remediation record")
    return ids


def open_batches(state: dict[str, Any]) -> list[dict[str, Any]]:
    """Open batch records, focused first."""
    records = [state["remediations"][identifier] for identifier in open_remediation_ids(state)]
    active = state.get("active_remediation")
    return sorted(records, key=lambda record: record["id"] != active)


def focus_remediation(state: dict[str, Any], identifier: str) -> dict[str, Any]:
    """Make the open batch with this member (or this record id) the one single-batch commands act on."""
    for record in open_batches(state):
        if identifier == record["id"] or identifier in record["members"]:
            state["active_remediation"] = record["id"]
            _project_active_remediation(state)
            return record
    raise RuntimeError(f"issue {identifier} is not a member of an open batch")


def ensure_remediation(state: dict[str, Any]) -> dict[str, Any]:
    """Attach a legacy active batch only during an explicit locked mutation."""
    record = active_remediation(state)
    if record is not None:
        return record
    primary = state.get("active_issue")
    members = list(state.get("active_batch") or ([primary] if primary else []))
    if not members or primary != members[0] or len(set(members)) != len(members):
        raise RuntimeError("no consistent active batch to attach")
    issues = state.get("issues", {})
    if any(issues.get(identifier, {}).get("status") != "in_progress" for identifier in members):
        raise RuntimeError("active batch contains settled or missing members; scan or release them first")
    first = issues[primary]
    for field in ("fix_base_commit", "fix_dir", "fix_finding_ids"):
        if any(issues[identifier].get(field) != first.get(field) for identifier in members):
            raise RuntimeError(f"active batch has inconsistent {field}; release and reselect it")
    started = next((event for event in reversed(first.get("history", [])) if event.get("event") == "fix_started"), {})
    record = {
        "id": uuid4().hex, "owner": started.get("batch_primary", primary),
        "primary": primary, "members": members, "issues": list(members),
        "baseline_run": state.get("baseline_run"), "from_run": started.get("from_run"),
        **{field: first.get(field) for field in SHARED_FIX_FIELDS},
    }
    for field in ("fix_notes", "waivers"):
        unique = {}
        for identifier in members:
            for entry in issues[identifier].get(field) or []:
                unique.setdefault(json.dumps(entry, sort_keys=True), dict(entry))
        record[field] = list(unique.values())
    record["fix_finding_ids"] = list(record.get("fix_finding_ids") or [])
    state.setdefault("remediations", {})[record["id"]] = record
    state["active_remediation"] = record["id"]
    state["open_remediations"] = list(dict.fromkeys([*open_remediation_ids(state), record["id"]]))
    _project_active_remediation(state)
    add_history(state, "remediation_attached", remediation=record["id"], issues=members)
    return record


def update_remediation(state: dict[str, Any], **fields: Any) -> dict[str, Any]:
    if fields.keys() - set(SHARED_FIX_FIELDS):
        raise ValueError("unsupported shared remediation field")
    record = ensure_remediation(state)
    record.update(fields)
    _project_active_remediation(state)
    return record


def add_fix_notes(state: dict[str, Any], texts: Iterable[str]) -> list[dict[str, str]]:
    """Identify legacy claims once, then append this invocation's new claims."""
    record = ensure_remediation(state)
    notes = []
    seen = set()
    for original in record["fix_notes"]:
        if not isinstance(original, dict) or not isinstance(original.get("text"), str):
            raise RuntimeError("invalid implementer note in remediation state")
        note = dict(original)
        identifier = note.setdefault("id", "note-" + uuid4().hex)
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise RuntimeError("implementer notes require distinct non-empty IDs")
        seen.add(identifier)
        notes.append(note)
    entries = [{"id": "note-" + uuid4().hex, "at": now(), "text": text.strip()} for text in texts]
    update_remediation(state, fix_notes=[*notes, *entries])
    return entries


def check_batch_candidates(state: dict[str, Any], identifiers: list[str], *, primary_new: bool = True) -> None:
    """The membership rules for a new batch, shared by `fix`, `fix --add` and `packet`.

    With `primary_new` false the first id is an existing primary and only the
    companions (identifiers[1:]) are checked as new members.
    """
    if len(set(identifiers)) != len(identifiers):
        raise RuntimeError("a fix batch cannot contain the same issue more than once")
    issues = state.get("issues", {})
    for index, candidate_id in enumerate(identifiers):
        candidate = issues.get(candidate_id)
        if not candidate:
            raise RuntimeError(f"unknown issue {candidate_id}")
        status = candidate.get("status")
        if not primary_new and not index:
            continue
        first = primary_new and not index
        if first and status == "in_progress":
            raise RuntimeError(
                f"issue {candidate_id} is already in progress; resume it or release it before restarting"
            )
        if status == "obsolete":
            raise RuntimeError(
                f"issue {candidate_id} is obsolete; the files this issue names no longer "
                "exist; rescan if they came back"
            )
        if not first and status not in {"open", "reopened"}:
            raise RuntimeError(
                f"batch companion {candidate_id} is {status}; companions must be open or reopened"
            )
        if first and status in {"resolved", "deferred", "closed", "stale"}:
            detail = "; rescan to confirm it before fixing" if status == "stale" else ""
            raise RuntimeError(f"issue {candidate_id} is {status}{detail}")


def begin_fix(
    state: dict[str, Any],
    identifier: str,
    run_id: str | None,
    fix_base_commit: str | None,
    companion_ids: Iterable[str] = (),
    *,
    fix_dir: str | None = None,
    finding_ids: Iterable[str] = (),
    branch: str | None = None,
) -> dict[str, Any]:
    identifiers = [identifier, *companion_ids]
    check_batch_candidates(state, identifiers)
    issues = state.get("issues", {})
    other = state.get("active_issue")
    parked: list[str] = []
    if other and other != identifier:
        if not branch:
            raise RuntimeError(
                f"issue {other} is already in progress; another batch can be open "
                "at the same time only when it names its branch (`--branch <name>`)"
            )
        ensure_remediation(state)
        parked = open_remediation_ids(state)
    if branch and any(record.get("branch") == branch for record in open_batches(state)):
        raise RuntimeError(f"branch {branch} already belongs to an open batch")
    timestamp = now()
    finding_ids = list(finding_ids)
    for index, candidate_id in enumerate(identifiers):
        issue = issues[candidate_id]
        issue["status"] = "in_progress"
        issue["fix_base_commit"] = fix_base_commit
        issue["fix_notes"] = []
        issue["waivers"] = []
        issue["fix_dir"] = fix_dir
        issue["fix_finding_ids"] = list(finding_ids)
        issue["fix_started_at"] = timestamp
        event = {
            "at": timestamp,
            "event": "fix_started",
            "from_run": run_id,
            "fix_base_commit": fix_base_commit,
        }
        if index:
            event["batch_primary"] = identifier
        issue.setdefault("history", []).append(event)
    state["active_issue"] = identifier
    state["active_batch"] = identifiers
    state["active_remediation"] = None
    state["open_remediations"] = parked
    record = ensure_remediation(state)
    if branch:
        record["branch"] = branch
    add_history(state, "fix_started", issue=identifier, batch=identifiers, **({"branch": branch} if branch else {}))
    return issues[identifier]


def add_to_batch(state: dict[str, Any], primary: str, new_ids: Iterable[str]) -> dict[str, Any]:
    """Add open cards to an open batch, under the rules for starting one.

    The batch keeps its base commit and finding set. Its recorded proof no
    longer describes the enlarged contract, so it is dropped here.
    """
    additions = list(new_ids)
    if not additions:
        raise RuntimeError("--add requires at least one issue id to add")
    if state.get("active_issue") and not state.get("active_remediation"):
        ensure_remediation(state)
    record = focus_remediation(state, primary)
    for candidate_id in additions:
        if candidate_id in record["members"]:
            raise RuntimeError(f"issue {candidate_id} is already in this batch")
    check_batch_candidates(state, [primary, *additions], primary_new=False)
    issues = state["issues"]
    timestamp = now()
    first = issues[record["members"][0]]
    for candidate_id in additions:
        issue = issues[candidate_id]
        issue["status"] = "in_progress"
        for field in ("fix_base_commit", "fix_dir", "fix_finding_ids", "fix_started_at"):
            issue[field] = first.get(field)
        issue["fix_notes"] = []
        issue["waivers"] = []
        add_issue_event(issue, "fix_started", at=timestamp, from_run=record.get("from_run"), fix_base_commit=first.get("fix_base_commit"), batch_primary=record["primary"], added_to_batch=True)
    record["members"] = [*record["members"], *additions]
    record["issues"] = [*record.get("issues", []), *additions]
    record.pop("verification", None)
    record["pending_review"] = None
    _project_active_remediation(state)
    add_history(state, "batch_extended", issue=record["primary"], added=additions)
    return record


def obsolete_issue(
    state: dict[str, Any], identifier: str, reason: str, *, run_id: str | None = None
) -> None:
    issue = state.get("issues", {}).get(identifier)
    if not issue:
        raise RuntimeError(f"unknown issue {identifier}")
    if is_analyzer(issue):
        raise RuntimeError(
            f"{issue['source'].capitalize()} issues are governed by `hangover scan`; rescan after removing their files"
        )
    issue["status"] = "obsolete"
    event = {"at": now(), "event": "obsolete", "reason": reason}
    if run_id is not None:
        event["run"] = run_id
    issue.setdefault("history", []).append(event)
    _prune_active_batch(state)
    add_history(state, "issue_obsolete", issue=identifier, reason=reason)


def defer_issue(state: dict[str, Any], identifier: str, reason: str) -> None:
    # Deferring an open batch's primary defers the whole batch, parked or focused.
    batch = next((record["members"] for record in open_batches(state) if record["primary"] == identifier), None)
    if batch is None and state.get("active_issue") == identifier:
        batch = state.get("active_batch")
    identifiers = list(batch) if batch else [identifier]
    for candidate_id in identifiers:
        issue = state.get("issues", {}).get(candidate_id)
        if not issue:
            raise RuntimeError(f"unknown issue {candidate_id}")
        issue["status"] = "deferred"
        add_issue_event(issue, "deferred", reason=reason)
        add_history(state, "issue_deferred", issue=candidate_id, reason=reason)
    _prune_active_batch(state)


def _prune_active_batch(state: dict[str, Any]) -> None:
    issues = state.get("issues", {})
    ids = open_remediation_ids(state)
    if not ids:
        batch = state.get("active_batch") or (
            [state["active_issue"]] if state.get("active_issue") else []
        )
        remaining = [identifier for identifier in batch
                     if issues.get(identifier, {}).get("status") == "in_progress"]
        state["active_batch"] = remaining
        state["active_issue"] = remaining[0] if remaining else None
        return
    kept = []
    for identifier in ids:
        record = state["remediations"][identifier]
        remaining = [member for member in record["members"]
                     if issues.get(member, {}).get("status") == "in_progress"]
        record["members"] = remaining
        if remaining:
            record["primary"] = remaining[0]
            kept.append(identifier)
    state["open_remediations"] = kept
    if state.get("active_remediation") not in kept:
        state["active_remediation"] = kept[0] if kept else None
    if kept:
        _project_active_remediation(state)
    else:
        state["active_batch"] = []
        state["active_issue"] = None


def release_issues(state: dict[str, Any], identifiers: Iterable[str]) -> None:
    selected = list(dict.fromkeys(identifiers))
    issues = state.get("issues", {})
    batch = [member for record in open_batches(state) for member in record["members"]] or [
        *(state.get("active_batch") or [state.get("active_issue")])
    ]
    for identifier in selected:
        if identifier not in issues or identifier not in batch:
            raise RuntimeError(f"issue {identifier} is not an active batch member")
    for identifier in selected:
        issue = issues[identifier]
        if issue.get("status") == "in_progress":
            issue["status"] = "open"
        add_issue_event(issue, "released")
        add_history(state, "issue_released", issue=identifier)
    _prune_active_batch(state)


def suppress_issue(
    state: dict[str, Any], identifier: str, reason: str, config_path: str
) -> None:
    issue = state.get("issues", {}).get(identifier)
    if not issue:
        raise RuntimeError(f"unknown issue {identifier}")
    issue["status"] = "suppressed"
    add_issue_event(issue, "suppressed", reason=reason, config=config_path)
    _prune_active_batch(state)
    add_history(state, "issue_suppressed", issue=identifier, reason=reason, config=config_path)


def resolve_issue(
    state: dict[str, Any], identifier: str, run_id: str, review_run: str | None,
    declared_changes_assessed: list[dict[str, Any]] | None = None,
) -> None:
    issue = state.get("issues", {}).get(identifier)
    if not issue:
        raise RuntimeError(f"unknown issue {identifier}")
    issue["status"] = "resolved"
    issue["resolved_at"] = now()
    issue["verified_run"] = run_id
    issue["review_run"] = review_run
    event = {
            "at": now(),
            "event": "resolved",
            "run": run_id,
            "review_run": review_run,
        }
    if issue.get("fix_notes"):
        event["fix_notes"] = issue["fix_notes"]
    if declared_changes_assessed:
        event["declared_changes_assessed"] = declared_changes_assessed
    issue.setdefault("history", []).append(event)
    _prune_active_batch(state)
    add_history(state, "issue_resolved", issue=identifier, run=run_id)


def resolve_issue_by(
    state: dict[str, Any], identifier: str, primary: str, run_id: str
) -> None:
    issue = state.get("issues", {}).get(identifier)
    if not issue:
        raise RuntimeError(f"unknown issue {identifier}")
    issue["status"] = "resolved"
    issue["resolved_at"] = now()
    issue["verified_run"] = run_id
    add_issue_event(issue, "resolved_by", issue=primary, run=run_id)
    add_history(state, "issue_resolved_by", issue=identifier, primary=primary, run=run_id)
