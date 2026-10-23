"""One explicitly passed record per CLI invocation.

The driver builds a `DriverResult` from the values the invocation itself
produced and hands it to the command that prints it. Nothing here reads
campaign state, so an interleaved scan cannot rewrite a reported run or
proof id after the fact. `Origin` is the invocation's own record of what it
has bound so far; a command fills it in as it goes, and the error path
reports from it instead of re-reading mutable state.
"""
from __future__ import annotations

import json
import shlex
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

RESULT_SCHEMA_VERSION = 1

# The process exit status of each state: 0 the operation completed (whatever is
# still owed is named by the state), 1 a verdict blocked it (a regression, a
# failed review, a failed prevention gate), 2 evidence or execution failed.
EXIT_CODES = {
    "ready": 0,
    "in_progress": 0,
    "review_pending": 0,
    "resolved": 0,
    "passed": 0,
    "blocked": 1,
    "tool_error": 2,
    "no_open_work": 0,
}
STATES = tuple(EXIT_CODES)

FRESHNESS = ("not_checked", "checked")


def exit_code(state: str) -> int:
    """The one mapping from a driver state to the process exit status."""
    if state not in EXIT_CODES:
        raise RuntimeError(f"unsupported driver state {state!r}")
    return EXIT_CODES[state]

_collected: list[dict[str, Any]] | None = None


@contextmanager
def collect_results():
    """Gather the payloads emitted inside the block instead of printing them.

    A command that runs several sub-verifications uses this to print exactly
    one machine record at the end.
    """
    global _collected
    previous, _collected = _collected, []
    try:
        yield _collected
    finally:
        _collected = previous

STATES_REQUIRING_BLOCKERS = ("blocked", "tool_error")


@dataclass
class DriverResult:
    command: str
    state: str
    repo: str
    run: str | None = None
    proof: str | None = None
    review_run: str | None = None
    issue_id: str | None = None
    batch: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    proof_freshness: str = "not_checked"
    next_action: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise RuntimeError(f"unsupported driver state {self.state!r}")
        if self.proof_freshness not in FRESHNESS:
            raise RuntimeError(
                f"unsupported proof freshness {self.proof_freshness!r}"
            )
        if self.state in STATES_REQUIRING_BLOCKERS and not self.blockers:
            raise RuntimeError(f"state {self.state} must name at least one blocker")

    @property
    def exit_code(self) -> int:
        return exit_code(self.state)

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "command": self.command,
            "state": self.state,
            "repo": self.repo,
            "run": self.run,
            "proof": self.proof,
            "review_run": self.review_run,
            "issue_id": self.issue_id,
            "batch": list(self.batch),
            "blockers": list(self.blockers),
            "artifacts": dict(self.artifacts),
            "proof_freshness": self.proof_freshness,
            "next_action": self.next_action,
            "data": self.data,
        }

    def emit(self, stream: TextIO | None = None) -> None:
        """Machine stdout is exactly one JSON value."""
        if _collected is not None:
            _collected.append(self.payload())
            return
        print(json.dumps(self.payload(), indent=2), file=stream or sys.stdout)


class DriverError(RuntimeError):
    """A refusal that knows the command which would clear it."""

    def __init__(self, message: str, *, next_action: str | None = None) -> None:
        super().__init__(message)
        self.next_action = next_action


@dataclass
class Origin:
    """What this invocation itself has established.

    Only the command that owns the invocation writes here, and only with ids it
    created or checked. A result built from it therefore names the failing
    invocation's run and proof even when an interleaved scan, verify, or
    restart has moved the campaign's latest state on.
    """

    command: str
    repo: str
    issue_id: str | None = None
    batch: list[str] = field(default_factory=list)
    run: str | None = None
    proof: str | None = None
    review_run: str | None = None
    artifacts: dict[str, str] = field(default_factory=dict)

    def result(self, state: str, **fields: Any) -> DriverResult:
        values: dict[str, Any] = {
            "command": self.command,
            "state": state,
            "repo": self.repo,
            "run": self.run,
            "proof": self.proof,
            "review_run": self.review_run,
            "issue_id": self.issue_id,
            "batch": list(self.batch),
            "artifacts": dict(self.artifacts),
        }
        values.update(fields)
        return DriverResult(**values)

    def tool_error(
        self, blocker: str, next_action: str | None = None, **fields: Any
    ) -> DriverResult:
        """An error never claims a checked proof: the gate or reviewer that
        failed may have changed inputs after the last binding check."""
        return self.result(
            "tool_error",
            blockers=[blocker],
            proof_freshness="not_checked",
            next_action=next_action,
            **fields,
        )


def command_line(repo: Path, *parts: str) -> str:
    """A next_action names its repository, so it does the same thing from any cwd."""
    return shlex.join(["hangover", "--repo", str(repo), *parts])
