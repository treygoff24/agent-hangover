"""Exact dead-code member evidence; a query never supplies a gate proof."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .oracles import (
    _fallow_command_failed, _fallow_error_line, _normalize_fallow_result,
    _run_fallow, fallow_dead_code_mode,
)

# These scopes affect the query as a whole. Unknown reasons stay fail-closed;
# file filtering and rule policy must be judged for the individual member.
QUERY_WIDE_REASONS = {
    "production", "include-entry-exports", "package-baselines", "baseline",
    "scope", "changed-since", "workspace", "changed-workspaces", "issue-type-filter",
}


def member_results(
    command: dict[str, Any], members: dict[str, dict[str, Any]], seen: list[str],
    disabled_categories: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    data = command.get("data")
    query = data.get("finding_id_query") if isinstance(data, dict) else None
    query = query if isinstance(query, dict) else {}
    fingerprint = query.get("analysis_fingerprint")
    results = {}
    valid = (command.get("status") == "completed"
             and isinstance(fingerprint, str) and bool(fingerprint)
             and all(isinstance(query.get(key), list)
                     and all(isinstance(value, str) for value in query[key])
                     for key in ("requested", "found", "missing", "filtered", "inconclusive_reasons"))
             and set(query["requested"]) == {card["finding_id"] for card in members.values()}
             and isinstance(query.get("conclusive"), bool)
             # Fallow's contract: reasons are empty exactly when the answer is conclusive.
             and query["conclusive"] == (not query["inconclusive_reasons"]))
    for identifier, card in members.items():
        finding_id = card["finding_id"]
        status, reason = "unknown", "missing or invalid finding-id query evidence"
        if valid:
            found = finding_id in query["found"]
            missing = finding_id in query["missing"]
            filtered = finding_id in query["filtered"]
            reasons = set(query["inconclusive_reasons"])
            member_reasons = reasons - QUERY_WIDE_REASONS
            if not filtered:
                member_reasons.discard("filtered")
            if (disabled_categories is not None and card.get("category")
                    and card["category"] not in disabled_categories):
                member_reasons.discard("rule-off")
            # A positive answer and a scan disagreement are evidence even when the
            # query as a whole is inconclusive, so they are judged before "not applicable".
            if filtered or member_reasons:
                reason = ", ".join(sorted(member_reasons)) or "filtered"
            elif found == missing:
                reason = "query does not give one unambiguous answer for this id"
            elif found != (identifier in seen):
                reason = "finding-id query and full Fallow scan disagree"
            elif found:
                status, reason = "still present", "finding-id query confirms the full scan"
            elif not query["conclusive"] and reasons:
                status, reason = "not applicable", ", ".join(sorted(reasons))
            elif not query["conclusive"]:
                reason = "query is inconclusive"
            else:
                status, reason = "gone", "conclusive missing id agrees with the full scan"
        if command.get("fallback_reason"):
            reason += "; " + command["fallback_reason"]
        results[identifier] = {"finding_id": finding_id, "status": status,
                               "reason": reason, "analysis_fingerprint": fingerprint}
    return results


def query_members(
    repo: Path, run_dir: Path, state: dict[str, Any], batch_ids: list[str],
    snapshot: dict[str, Any], seen: list[str], *, skip_reason: str | None = None,
) -> dict[str, Any]:
    cards = state.get("issues", {})
    members = {identifier: card for identifier in batch_ids
               if (card := cards.get(identifier)) and card.get("source") == "fallow"
               and card.get("finding_id")}
    if not members:
        return {}
    results = {identifier: {"finding_id": card["finding_id"], "status": "still present",
                           "reason": "reported by the full Fallow scan", "analysis_fingerprint": None}
               for identifier, card in members.items() if identifier in seen}
    if skip_reason:
        return {"status": "skipped", "reason": skip_reason, "members": results}
    pending = {identifier: card for identifier, card in members.items() if identifier not in seen}
    fallow = snapshot.get("fallow", {})
    dead_code = fallow.get("commands", {}).get("dead_code", {})
    mode = "syntactic" if dead_code.get("fallback") == "type_aware_failed" else fallow_dead_code_mode(fallow)
    arguments = ["dead-code", "--type-aware" if mode == "type-aware" else "--no-type-aware"]
    for card in pending.values():
        arguments.extend(["--finding-id", card["finding_id"]])
    command = _normalize_fallow_result(_run_fallow(repo, run_dir, "dead-code-query", arguments))
    if mode == "type-aware" and _fallow_command_failed(command):
        attempt = command
        arguments = ["dead-code", "--no-type-aware", *arguments[2:]]
        command = _normalize_fallow_result(_run_fallow(repo, run_dir, "dead-code-query-syntactic", arguments))
        command["type_aware_attempt"] = attempt
        command["fallback_reason"] = "syntactic retry after type-aware query failed: " + _fallow_error_line(attempt)
    queried = member_results(command, pending, seen, fallow.get("disabled_finding_categories"))
    results.update(queried)
    if all(result["status"] == "not applicable" for result in queried.values()):
        reason = ", ".join(sorted({result["reason"] for result in queried.values()}))
        return {"status": "not_applicable", "reason": reason, "command": command, "members": results}
    return {"status": "completed", "command": command, "members": results}
