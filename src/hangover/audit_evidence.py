"""One-use approval for a whole base-to-tree change, not a remediation receipt.

An audit starts before gates, seals their artifacts only on success, and checks
the same local inputs before recording a review. A newer reviewed audit replaces
the pending one; records remain available for inspection. External-state limits
are those of evidence.repository_inputs, not an assertion of hermetic execution.
"""
from pathlib import Path
from typing import Any
from uuid import uuid4

from .evidence import file_digest, repository_inputs, run_artifact
from .model import add_history, load_state, mutate_state, paths, read_json, write_json
from .oracles import _validate_review, import_review, validate_note_assessments
from .packets import REVIEW_ARTIFACTS
from .repository import resolve_revision

REQUIRED_ARTIFACTS = {"snapshot.json", "after.patch", *REVIEW_ARTIFACTS}


def fallow_failed(snapshot: dict[str, Any], analyzers: dict[str, dict[str, Any]]) -> bool:
    """Fallow was meant to run (the command's analyzer plan) and did not complete."""
    return bool(analyzers["fallow"]["run"] and snapshot["fallow"].get("status") != "completed")


def audit_blockers(snapshot: dict[str, Any], analyzers: dict[str, dict[str, Any]]) -> list[str]:
    """Why an audit cannot pass. ``analyzers`` is the plan the audit ran under
    (cli._analyzer_plan): a Fallow the plan skipped, disabled or not applicable,
    is no failure, and every caller, sealing included, judges by that one plan."""
    analyzer_failed = fallow_failed(snapshot, analyzers)
    blockers = []
    if snapshot["diff_check"]["status"] != "passed":
        blockers.append(f"git diff --check {snapshot['diff_check']['status']}")
    blockers.extend(f"native check {check['name']} {check['status']}"
                    for check in snapshot["checks"] if check["status"] != "passed")
    if snapshot["fallow"].get("verdict") == "fail":
        blockers.append("the Fallow changed-code verdict is fail")
    if analyzer_failed:
        blockers.append("Fallow did not complete, so the changed-code verdict is unverified")
    rust = snapshot.get("rust") or {}
    if rust.get("verdict") == "fail":
        introduced = rust.get("introduced") or []
        blockers.append(f"the Rust changed-code verdict is fail: {len(introduced)} introduced finding(s): "
                        + "; ".join(f"{item['id']} {item['title']}" for item in introduced[:10])
                        + (f"; +{len(introduced) - 10} more" if len(introduced) > 10 else ""))
    if rust_analysis_failed(snapshot):
        blockers.append("Rust analysis did not complete, so the changed-code verdict is unverified")
    return blockers


def rust_analysis_failed(snapshot: dict[str, Any]) -> bool:
    return (snapshot.get("rust") or {}).get("status") not in {None, "not_applicable", "disabled", "completed"}


def _inputs(repo: Path, base: str, full: bool, binary: Path | None) -> dict[str, Any]:
    return {**repository_inputs(repo, binary), "repo": str(repo.resolve()),
            "base": resolve_revision(repo, base), "full": full}


def begin_audit(repo: Path, run: str, base: str, full: bool, binary: Path | None) -> dict[str, Any]:
    run_artifact(repo, run, "snapshot.json")  # Validate the run path before changing state.
    inputs = _inputs(repo, base, full, binary)
    record = {"id": uuid4().hex, "run": run, "base": inputs["base"], "full": full,
              "inputs": inputs, "token": uuid4().hex, "status": "checking",
              "artifacts": {}, "consumed": False}

    def start(state: dict[str, Any]) -> None:
        state.setdefault("audit_reviews", {})[record["id"]] = record
        state["pending_audit_review"] = record["id"]
        add_history(state, "audit_review_started", proof=record["id"], run=run, base=record["base"])

    mutate_state(repo, start)
    return record


def _current(state: dict[str, Any], expected: dict[str, Any] | None = None) -> dict[str, Any]:
    records = state.get("audit_reviews", {})
    record = records.get(state.get("pending_audit_review")) if isinstance(records, dict) else None
    if not isinstance(record, dict) or record.get("consumed"):
        raise RuntimeError("no pending audit proof; prepare a new audit --require-review")
    if expected is not None and record != expected:
        raise RuntimeError("audit proof was superseded or changed; refusing stale review")
    return record


def _require(repo: Path, state: dict[str, Any], base: str, full: bool, binary: Path | None,
             expected: dict[str, Any] | None = None) -> dict[str, Any]:
    record = _current(state, expected)
    if record.get("status") != "passed":
        raise RuntimeError("audit has no passing deterministic proof; run audit --require-review again")
    if _inputs(repo, base, full, binary) != record.get("inputs"):
        raise RuntimeError("audit inputs or base changed; run audit --require-review again")
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict) or not REQUIRED_ARTIFACTS <= artifacts.keys():
        raise RuntimeError("incomplete audit artifacts; prepare a new reviewed audit")
    for name, checksum in artifacts.items():
        if file_digest(run_artifact(repo, record["run"], name)) != checksum:
            raise RuntimeError("audit artifact changed; refusing stale review")
    return record


def require_audit(repo: Path, base: str, full: bool, binary: Path | None,
                  *, expected: dict[str, Any] | None = None) -> dict[str, Any]:
    return _require(repo, load_state(repo), base, full, binary, expected)


def seal_audit(repo: Path, pending: dict[str, Any], binary: Path | None,
               analyzers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    directory = paths(repo)["runs"] / pending["run"]
    snapshot = read_json(run_artifact(repo, pending["run"], "snapshot.json"))
    if (snapshot.get("kind") != "audit" or snapshot.get("id") != pending["run"]
            or snapshot.get("base") != pending["base"]):
        raise RuntimeError("audit snapshot does not describe this proof")
    blockers = audit_blockers(snapshot, analyzers)
    if blockers:
        raise RuntimeError("cannot seal a failing audit: " + "; ".join(blockers))
    artifacts = {str(path.relative_to(directory)): file_digest(run_artifact(repo, pending["run"], str(path.relative_to(directory))))
                 for path in sorted(directory.rglob("*")) if path.is_file()}
    if not REQUIRED_ARTIFACTS <= artifacts.keys():
        raise RuntimeError("incomplete audit artifacts; prepare a new reviewed audit")

    def seal(state: dict[str, Any]) -> dict[str, Any]:
        record = _current(state, pending)
        if _inputs(repo, record["base"], record["full"], binary) != record["inputs"]:
            raise RuntimeError("audit inputs changed during gates; rerun on stable inputs")
        record.update(status="passed", artifacts=artifacts)
        return record

    return mutate_state(repo, seal)


def record_audit_review(repo: Path, proof: dict[str, Any], review: dict[str, Any],
                        review_run: str, binary: Path | None) -> bool:
    _validate_review(review, "prevention")
    validate_note_assessments(review, [])  # Prevention issues no implementer-note IDs.
    if review.get("verification_token") != proof.get("token"):
        raise RuntimeError("review returned a different audit verification_token")

    def finish(state: dict[str, Any]) -> bool:
        record = _require(repo, state, proof["base"], proof["full"], binary, proof)
        output = run_artifact(repo, review_run, "review.json")
        if output.exists():
            if import_review(output, "prevention") != review:
                raise RuntimeError("retained audit review output changed; refusing to overwrite it")
        else:
            write_json(output, review)
        checksum = file_digest(output)
        accepted = review["verdict"] == "pass"
        record.update(review_run=review_run, review_digest=checksum, review_verdict=review["verdict"], consumed=accepted)
        if accepted:
            state["pending_audit_review"] = None
        add_history(state, "audit_review_completed", proof=proof["id"], run=proof["run"],
                    review_run=review_run, verdict=review["verdict"], review_digest=checksum)
        return accepted

    return mutate_state(repo, finish)
