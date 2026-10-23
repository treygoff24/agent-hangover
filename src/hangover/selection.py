"""Read-only selection surface: list, filter, and preview issues.

Nothing here runs a gate, activates a batch, or writes campaign state, so a
driver can browse the backlog and stage a coherent remediation without
touching evidence freshness.
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .finding_identity import duplication_spans
from .model import load_state, normalize_repo_path, ordered_issues
from .repository import SOURCE_SUFFIXES, _line_count, repository_files
from .result import DriverResult, command_line


LIST_FIELDS = (
    "id",
    "status",
    "source",
    "category",
    "priority",
    "title",
    "files",
    "last_seen_run",
)

SELECTABLE_STATUSES = {"open", "reopened"}


def issue_files(issue: dict[str, Any]) -> list[str]:
    return [
        normalize_repo_path(path)
        for path in issue.get("files") or []
        if str(path).strip()
    ]


def matches_path(issue: dict[str, Any], selectors: list[str]) -> bool:
    files = issue_files(issue)
    for selector in selectors:
        wanted = normalize_repo_path(selector)
        if any(path == wanted or path.startswith(wanted + "/") for path in files):
            return True
    return False


def project_issue(issue: dict[str, Any]) -> dict[str, Any]:
    """A selection projection: enough to choose work, without replaying history."""
    return {
        field: (list(issue.get("files") or []) if field == "files" else issue.get(field))
        for field in LIST_FIELDS
    }


def filter_issues(
    state: dict[str, Any], filters: dict[str, list[str]]
) -> list[dict[str, Any]]:
    matched = []
    for issue in ordered_issues(state):
        if filters.get("source") and issue.get("source") not in filters["source"]:
            continue
        if filters.get("category") and issue.get("category") not in filters["category"]:
            continue
        if filters.get("status") and issue.get("status") not in filters["status"]:
            continue
        if filters.get("file") and not matches_path(issue, filters["file"]):
            continue
        matched.append(issue)
    return matched


NON_SOURCE_PARTS = {
    "tests", "test", "__tests__", "spikes", "spike", "docs", "doc",
    "fixtures", "fixture", "__fixtures__", "e2e", "cypress", "__mocks__",
}
NON_SOURCE_NAME = re.compile(r"(?:^test_.*\.py$|_test\.[^.]+$|\.(?:test|spec)\.[^.]+$)")


def is_non_source_path(path: str) -> bool:
    """Tests, spikes, docs and fixtures by path convention only."""
    parts = path.split("/")
    return any(part in NON_SOURCE_PARTS for part in parts[:-1]) or bool(
        NON_SOURCE_NAME.search(parts[-1])
    )


def issue_line_weight(
    issue: dict[str, Any], keep: set[str] | None = None
) -> tuple[int | None, bool]:
    """(duplicated lines, estimated). One unit: lines summed over instance spans,
    restricted to `keep` files when given. Without spans the weight is estimated
    as per-clone lines x instance count; None when the issue records neither."""
    spans = duplication_spans(issue)
    if spans:
        return sum(
            end - start + 1 for path, start, end in spans
            if keep is None or normalize_repo_path(path) in keep
        ), False
    for line in issue.get("evidence") or []:
        match = re.match(r"Fallow found (\d+) duplicated lines.*? across (\d+) instances", str(line))
        if match:
            instances = int(match[2])
            if keep is not None:
                instances = min(instances, len(keep))
            return int(match[1]) * instances, True
    return None, False


def _weight(issue: dict[str, Any]) -> tuple[int | None, bool]:
    return issue["_weight"] if "_weight" in issue else issue_line_weight(issue)


def _group_key(path: str, group_by: str) -> str:
    if group_by == "file":
        return path
    return path.rsplit("/", 1)[0] if "/" in path else "."


def directory_source_lines(repo: Path) -> dict[str, int]:
    """Source-line count per directory (the inventory's own counting rule)."""
    totals: dict[str, int] = Counter()
    for path in repository_files(repo):
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        lines = _line_count(repo, path)
        if lines:
            totals[_group_key(str(path.relative_to(repo)), "dir")] += lines
    return dict(totals)


def group_issues(
    repo: Path, issues: list[dict[str, Any]], group_by: str, sort: str | None
) -> list[dict[str, Any]]:
    """Group issues by dir, file or category. An issue touching several dirs or
    files appears in each (and its weight counts in each); counts are not additive."""
    groups: dict[str, dict[str, Any]] = {}
    for issue in issues:
        if group_by == "category":
            keys = [str(issue.get("category"))]
        else:
            keys = sorted({_group_key(path, group_by) for path in issue_files(issue)})
        weight, estimated = _weight(issue)
        for key in keys:
            group = groups.setdefault(
                key, {"group": key, "findings": 0, "lines": 0, "lines_estimated": False, "ids": []})
            group["findings"] += 1
            group["lines"] += weight or 0
            group["lines_estimated"] = group["lines_estimated"] or estimated
            group["ids"].append(issue["id"])
    if group_by == "dir":
        source_lines = directory_source_lines(repo)
        for key, group in groups.items():
            group["source_lines"] = source_lines.get(key, 0)
    rows = list(groups.values())
    rows.sort(key=lambda g: (-g["lines"], -g["findings"], g["group"]) if sort == "lines"
              else (-g["findings"], g["group"]))
    return rows


def list_issues(
    repo: Path, as_json: bool, filters: dict[str, list[str]],
    group_by: str | None = None, sort: str | None = None,
    exclude_tests: bool = False,
) -> None:
    """Read-only selection surface: no gate runs, so freshness stays not_checked."""
    state = load_state(repo)
    matched = filter_issues(state, filters)
    if exclude_tests:
        kept = []
        for issue in matched:
            files = issue_files(issue)
            source = [path for path in files if not is_non_source_path(path)]
            if source or not files:
                kept.append(
                    {**issue, "files": source,
                     "_weight": issue_line_weight(issue, set(source))}
                    if files else issue)
        matched = kept
    if sort == "lines":
        matched = sorted(matched, key=lambda issue: -(_weight(issue)[0] or 0))
    groups = group_issues(repo, matched, group_by, sort) if group_by else None
    selectable = [
        issue for issue in matched if issue.get("status") in SELECTABLE_STATUSES
    ]
    applied = {key: value for key, value in filters.items() if value}
    if as_json:
        DriverResult(
            command="list",
            state="ready" if selectable else "no_open_work",
            repo=str(repo),
            run=selectable[0].get("last_seen_run") if selectable else None,
            issue_id=selectable[0]["id"] if selectable else None,
            next_action=(
                command_line(repo, "fix", selectable[0]["id"]) if selectable
                else command_line(repo, "scan")
            ),
            data={
                "filters": applied,
                "count": len(matched),
                "total": len(state.get("issues", {})),
                **({"group_by": group_by, "groups": groups} if groups is not None else {}),
                "issues": [
                    {**project_issue(issue), "lines": _weight(issue)[0],
                     "lines_estimated": _weight(issue)[1]}
                    if sort == "lines" else project_issue(issue)
                    for issue in matched
                ],
            },
        ).emit()
        return
    if not matched:
        print("no issues match the filter")
        return
    print(f"{len(matched)} of {len(state.get('issues', {}))} issue(s)")
    if groups is not None:
        for group in groups:
            extra = f", {group['source_lines']} source lines" if "source_lines" in group else ""
            print(f"  {group['group']}: {group['findings']} finding(s), "
                  f"{group['lines']}{'~' if group['lines_estimated'] else ''} duplicated lines{extra}")
        return
    for issue in matched:
        print(
            f"  [{issue['status']}] {issue['id']} [{issue['priority']}] "
            f"[{issue['source']}/{issue['category']}] {issue['title']}"
        )
        for path in issue_files(issue):
            print(f"      {path}")


OVERLAP_CAVEAT = (
    "file overlap is not semantic coherence; confirm the remediation unit "
    "before activating this batch"
)


def batch_overlap(members: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe what the files say and nothing more."""
    counts = Counter(path for member in members for path in set(issue_files(member)))
    shared = sorted(path for path, count in counts.items() if count > 1)
    every = sorted(counts)
    if not shared:
        overlap = "none"
    elif len(shared) == len(every):
        overlap = "total"
    else:
        overlap = "partial"
    return {
        "shared_files": shared,
        "file_overlap": overlap,
        "categories": sorted({str(member.get("category")) for member in members}),
        "sources": sorted({str(member.get("source")) for member in members}),
        "caveat": OVERLAP_CAVEAT,
    }


def batch_outliers(members: list[dict[str, Any]]) -> list[dict[str, str]]:
    outliers = []
    for member in members:
        files = set(issue_files(member))
        others = {
            path
            for other in members
            if other["id"] != member["id"]
            for path in issue_files(other)
        }
        if len(members) > 1 and not files & others:
            outliers.append(
                {
                    "id": member["id"],
                    "reason": "shares no file with another selected member",
                }
            )
    return outliers


def preview_batch(repo: Path, identifiers: list[str], limit: int, as_json: bool) -> int:
    """Read-only: this never activates a batch, writes a campaign, or runs a gate."""
    state = load_state(repo)
    issues = state.get("issues", {})
    blockers = []
    if identifiers:
        selected = []
        for identifier in dict.fromkeys(identifiers):
            issue = issues.get(identifier)
            if not issue:
                raise RuntimeError(f"unknown issue {identifier}")
            if issue.get("status") not in SELECTABLE_STATUSES:
                blockers.append(
                    f"{identifier} is {issue.get('status')}; only open or "
                    "reopened issues are selectable"
                )
            selected.append(issue)
    else:
        selected = ordered_issues(state, open_only=True)[:limit]
    members = [project_issue(issue) for issue in selected]
    files = sorted({path for issue in selected for path in issue_files(issue)})
    data = {
        "members": members,
        "files": files,
        "overlap": batch_overlap(selected),
        "outliers": batch_outliers(selected),
    }
    if blockers:
        state_name = "blocked"
    elif members:
        state_name = "ready"
    else:
        state_name = "no_open_work"
    batch = [member["id"] for member in members]
    next_action = command_line(repo, "scan")
    if state_name == "ready":
        next_action = command_line(repo, "fix", *batch)
    elif state_name == "blocked":
        next_action = command_line(
            repo,
            "preview",
            *(
                identifier
                for identifier in batch
                if issues[identifier].get("status") in SELECTABLE_STATUSES
            ),
        )
    if as_json:
        DriverResult(
            command="preview",
            state=state_name,
            repo=str(repo),
            issue_id=batch[0] if batch else None,
            batch=batch,
            blockers=blockers,
            next_action=next_action,
            data=data,
        ).emit()
        return 1 if blockers else 0
    if not members:
        print("no open issues to preview")
        return 0
    print(f"preview: {len(members)} issue(s) — nothing is activated")
    for member in members:
        print(
            f"  [{member['status']}] {member['id']} [{member['priority']}] "
            f"[{member['source']}/{member['category']}] {member['title']}"
        )
        for path in member["files"]:
            print(f"      {path}")
    overlap = data["overlap"]
    print(
        "  shared files: "
        + (", ".join(overlap["shared_files"]) or "none")
        + f" ({overlap['file_overlap']})"
    )
    for outlier in data["outliers"]:
        print(f"  outlier: {outlier['id']} — {outlier['reason']}")
    for blocker in blockers:
        print(f"blocker: {blocker}", file=sys.stderr)
    print(f"  note: {OVERLAP_CAVEAT}")
    print("  activate with: " + next_action)
    return 1 if blockers else 0
