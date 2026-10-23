"""Small working packets; full history is retained separately, not fed to reviewers."""
from typing import Any

from .model import ISSUE_CONTRACT_FIELDS, SCHEMA_VERSION, SHARED_FIX_FIELDS

REVIEW_ARTIFACTS = ("review-packet.json", "review-prompt.md", "review-context.json", "review-schema.json")


def _contract(issue: dict[str, Any]) -> dict[str, Any]:
    # Use the same field set as the immutable proof, so compacting cannot drop
    # an invariant, declared harm, or other part of the issue being verified.
    return {key: issue[key] for key in (*ISSUE_CONTRACT_FIELDS, "status") if key in issue}


def fix_packet(
    state: dict[str, Any], repo: Any, primary: dict[str, Any], members: list[dict[str, Any]],
    fix_base_commit: str | None, before_patch: str | None, finish: str, **extra: Any,
) -> dict[str, Any]:
    """The packet `fix` emits and `packet` hands out; only `finish` and `extra` differ."""
    return {
        "schema_version": SCHEMA_VERSION,
        "repo": str(repo),
        "issue": primary,
        "issues": members,
        "baseline_run": state.get("baseline_run"),
        "latest_run": state.get("latest_run"),
        "fix_base_commit": fix_base_commit,
        "before_patch": before_patch,
        **extra,
        "rules": [
            "Establish why the code exists before deleting non-obviously-dead behavior.",
            "Prefer delete, consolidate, reuse, inline, simplify, rename, then abstract.",
            "Change only the coherent remediation unit and its behavior-focused tests.",
            "Release any member you will not fix with `hangover fix --release <issue>`.",
            "Never run Fallow auto-fix or weaken checks to improve metrics.",
            finish,
        ],
    }


def compact_fix_packet(packet: dict[str, Any]) -> dict[str, Any]:
    primary = packet["issue"]
    return {**packet, "schema_version": 2,
            "issue": {key: primary[key] for key in ("id", "fix_dir") if key in primary},
            "issues": [_contract(member) for member in packet["issues"]],
            "remediation": {key: primary[key] for key in SHARED_FIX_FIELDS if key in primary}}


def compact_review_issue(issue: dict[str, Any] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if issue is None:
        return None, None
    primary = _contract(issue)
    # Preserve this short provenance alias for v1 packet consumers; long shared
    # facts have a single owner under remediation or implementer_notes.
    if "fix_base_commit" in issue:
        primary["fix_base_commit"] = issue["fix_base_commit"]
    primary["batch_issues"] = [_contract(member) for member in issue.get("batch_issues", [])
                              if member["id"] != issue["id"]]
    shared = {key: issue[key] for key in SHARED_FIX_FIELDS if key in issue and key != "fix_notes"}
    return primary, shared
