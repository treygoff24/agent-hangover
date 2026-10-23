"""Readiness handshakes shared by process lifecycle and adapter tests."""

import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch


def _wait_for_file(path: Path, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.02)
    raise AssertionError(f"{path} was never written")


@contextmanager
def _after_ready(path: Path):
    """Exclude fixture startup from cleanup-test deadlines, not from real runs.

    The child writes readiness only after the descendant/handler under test is
    installed. This tests timeout cleanup rather than host spawn latency; the
    real supervisor, timeout budget and group termination still run unchanged.
    """
    from hangover.process import _supervise

    timing = {}

    def supervise(process, pgid, pump, budget, deadline, grace_seconds):
        started = time.monotonic()
        # This blocks the pump: fixtures must not fill a pipe before signalling ready.
        _wait_for_file(path)
        timing["ready_at"] = time.monotonic()
        startup = timing["ready_at"] - started
        return _supervise(process, pgid, pump, budget, deadline + startup, grace_seconds)

    with patch("hangover.process._supervise", side_effect=supervise):
        yield timing
