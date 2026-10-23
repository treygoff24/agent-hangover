"""Review selection and self-reported inspection, never a cleanliness score."""
from pathlib import Path
from typing import Any

from .repository import repository_files


def _relative(value: str) -> Path:
    path = Path(value)
    if not value.strip() or path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"review scope must be a repository-relative path without traversal: {value!r}")
    return path


def select_scope(repo: Path, requested: list[str] | None = None) -> dict[str, Any]:
    requested = requested or []
    files = {str(path.relative_to(repo)) for path in repository_files(repo)
             if not any(parent.is_symlink() for parent in path.parents
                        if parent != repo and repo in parent.parents)}
    selected: set[str] = set()
    normalized = []
    for value in requested:
        relative = _relative(value)
        path = repo
        for part in relative.parts:
            path /= part
            if path.is_symlink():
                raise RuntimeError(f"review scope traverses a symlink: {value!r}")
        matches = {name for name in files if Path(name).is_relative_to(relative)}
        if not matches:
            raise RuntimeError(f"review scope selects no repository files: {value!r}")
        selected.update(matches)
        normalized.append(str(relative))
    if not requested:
        selected = files
    return {"kind": "selected" if requested else "repository",
            "requested": sorted(set(normalized)), "files": sorted(selected),
            "unselected_files": sorted(files - selected), "finding_limit": 12}


def assess_scope(scope: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    names = [str(_relative(path)) for path in review["reviewed_files"]]
    selected = set(scope["files"])
    if len(names) != len(set(names)) or not set(names) <= selected:
        raise RuntimeError("reviewed_files contains duplicates or files outside the review scope")
    if scope["kind"] == "selected":
        for finding in review.get("findings", []):
            if not {str(_relative(path)) for path in finding["files"]} <= selected:
                raise RuntimeError("finding is outside the requested review scope; select a wider scope explicitly")
    return {"evidence": "reviewer_reported",
            "reported_files": sorted(names), "remaining_selected_files": sorted(selected - set(names)),
            "unselected_files": list(scope["unselected_files"]), "exhaustive": False,
            "limitation": "Self-reported inspection is not proof of complete review; findings are capped at 12."}
