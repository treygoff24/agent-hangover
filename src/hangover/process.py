"""Bounded, group-owning subprocess runner.

``run_logged`` streams a child's output to artifact files with bounded memory,
enforces a combined output cap, and terminates the process group it created
(and only that group) on timeout, output limit, or interruption. Descendants
that deliberately leave the group (their own ``setsid``) are outside the
termination guarantee; if one keeps a pipe open past the run's boundary the
result is reported as ``incomplete`` rather than as a clean exit, and capture
stops at that boundary. POSIX only; stdlib only.
"""

from __future__ import annotations

import errno
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

CHUNK_BYTES = 64 * 1024
POLL_SECONDS = 0.05


@dataclass(frozen=True)
class RunResult:
    status: str  # "exited" | "timeout" | "output_limit" | "incomplete"
    exit_code: int | None  # wait status when exited (negative for a signal); None for any other status
    duration_seconds: float
    stdout_path: str
    stderr_path: str | None  # None when stderr was merged into stdout
    stdout_bytes: int
    stderr_bytes: int | None
    stdout_tail: str
    stderr_tail: str | None
    truncated: bool


class _Budget:
    """Combined byte budget shared by the streams, plus the first artifact-writer
    failure so it can be raised instead of hidden."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.exceeded = False
        self.writer_error: OSError | None = None

    def fail(self, error: OSError) -> None:
        if self.writer_error is None:
            self.writer_error = error

    def take(self, wanted: int) -> int:
        granted = max(0, min(wanted, self.limit - self.used))
        self.used += granted
        if granted < wanted:
            self.exceeded = True
        return granted


class _StreamSink:
    """Writes one stream's chunks to a file, keeping only a bounded tail in memory."""

    def __init__(self, file, budget: _Budget, tail_bytes: int) -> None:
        self._file = file
        self._budget = budget
        self._tail_bytes = tail_bytes
        self.written = 0
        self.tail = b""

    def feed(self, chunk: bytes) -> None:
        # Past the cap or after a writer failure the pipe is still drained so
        # the child never blocks on it while we terminate, but nothing is kept.
        keep = 0 if self._budget.writer_error is not None else self._budget.take(len(chunk))
        if not keep:
            return
        try:
            _write_all(self._file, chunk[:keep])
        except OSError as error:
            self._budget.fail(error)
            return
        self.written += keep
        if self._tail_bytes:
            self.tail = (self.tail + chunk[:keep])[-self._tail_bytes :]

    def close(self) -> None:
        try:
            self._file.close()
        except OSError as error:
            self._budget.fail(error)

    def tail_text(self) -> str:
        return self.tail.decode("utf-8", errors="replace")


def _write_all(file, data: bytes) -> None:
    # Artifacts are opened unbuffered so a failing disk surfaces on the write
    # that hits it, not at close; raw writes may be partial, so loop. A write
    # that makes no progress (0 or None) would otherwise spin forever.
    view = memoryview(data)
    while view:
        written = file.write(view)
        if not written:
            raise OSError(errno.EIO, "artifact write made no progress")
        view = view[written:]


class _Pump:
    """Single-threaded selector loop over the child's pipes: drains stdout and
    stderr into their sinks and delivers stdin, all non-blocking, so capture
    can be stopped at whatever boundary the caller chooses. Nothing here can
    outlive ``close``."""

    def __init__(
        self,
        process: subprocess.Popen,
        readers: Sequence[tuple[object, _StreamSink]],
        stdin_data: bytes | None,
    ) -> None:
        self._selector = selectors.DefaultSelector()
        self._input = memoryview(stdin_data if stdin_data is not None else b"")
        # An interruption mid-wiring leaves the caller without a reference to
        # this half-built pump, so its cleanup cannot be left to GC.
        try:
            for pipe, sink in readers:
                self._register(pipe, selectors.EVENT_READ, sink)
            if process.stdin is not None:
                self._register(process.stdin, selectors.EVENT_WRITE, None)
        except BaseException:
            self.close()
            raise

    def _register(self, pipe, events: int, sink: _StreamSink | None) -> None:
        os.set_blocking(pipe.fileno(), False)
        self._selector.register(pipe.fileno(), events, (pipe, sink))

    @property
    def settled(self) -> bool:
        """True once every pipe has reached EOF (or, for stdin, been fully
        delivered or refused) and is closed."""
        return not self._selector.get_map()

    def step(self, timeout: float) -> None:
        for key, _ in self._selector.select(max(0.0, timeout)):
            pipe, sink = key.data
            if sink is None:
                self._deliver_input(key.fd, pipe)
            else:
                self._drain(key.fd, pipe, sink)

    def _drain(self, fd: int, pipe, sink: _StreamSink) -> None:
        try:
            chunk = os.read(fd, CHUNK_BYTES)
        except BlockingIOError:
            return
        if chunk:
            sink.feed(chunk)
        else:
            self._release(fd, pipe)

    def _deliver_input(self, fd: int, pipe) -> None:
        try:
            sent = os.write(fd, self._input[:CHUNK_BYTES])
        except BlockingIOError:
            return
        except OSError:
            # The child closed stdin or exited before reading everything; its
            # exit status tells the story.
            self._input = memoryview(b"")
            self._release(fd, pipe)
            return
        self._input = self._input[sent:]
        if not self._input:
            self._release(fd, pipe)

    def _release(self, fd: int, pipe) -> None:
        self._selector.unregister(fd)
        pipe.close()

    def close(self) -> None:
        for key in list(self._selector.get_map().values()):
            self._release(key.fd, key.data[0])
        self._selector.close()


def _darwin_group_has_live_members(pgid: int) -> bool | None:
    """Inspect only the owned group via Darwin's public libproc ABI.

    False means every observed member is gone, a zombie, or already in exit().
    None means inspection failed/raced; it must never authorize a clean result.
    No helper subprocess is spawned during exceptional/interrupt cleanup.
    """
    import ctypes

    class BsdShortInfo(ctypes.Structure):
        # proc_bsdshortinfo in <sys/proc_info.h>, PROC_PIDT_SHORTBSDINFO (13).
        _fields_ = [("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32),
                    ("pgid", ctypes.c_uint32), ("status", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16), ("flags", ctypes.c_uint32),
                    ("ids", ctypes.c_uint32 * 7)]

    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        libproc.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        libproc.proc_listpids.restype = ctypes.c_int
        libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                        ctypes.c_void_p, ctypes.c_int]
        libproc.proc_pidinfo.restype = ctypes.c_int
        # PROC_PGRP_ONLY (2); proc_listpids returns bytes, not a PID count.
        ctypes.set_errno(0)
        needed = libproc.proc_listpids(2, pgid, None, 0)
        if needed < 0 or (needed == 0 and ctypes.get_errno()):
            return None
        members = (ctypes.c_int * (needed // ctypes.sizeof(ctypes.c_int) + 16))()
        ctypes.set_errno(0)
        filled = libproc.proc_listpids(2, pgid, members, ctypes.sizeof(members))
        if filled < 0 or (filled == 0 and ctypes.get_errno()) or filled >= ctypes.sizeof(members):
            return None  # A growing/truncated snapshot is not evidence of death.
        for pid in members[:filled // ctypes.sizeof(ctypes.c_int)]:
            info = BsdShortInfo()
            size = libproc.proc_pidinfo(pid, 13, 0, ctypes.byref(info), ctypes.sizeof(info))
            if size != ctypes.sizeof(info):
                if size == 0 and ctypes.get_errno() == errno.ESRCH:
                    continue
                return None
            if info.pgid == pgid and info.status != 5 and not (info.flags & 4):
                return True  # SZOMB=5; PROC_FLAG_INEXIT=4.
        return False
    except (OSError, AttributeError):
        return None


def _kill_group(process: subprocess.Popen, pgid: int, signum: int, until: float) -> bool:
    """Signal/probe the owned group; False means it no longer exists."""
    while True:
        try:
            os.killpg(pgid, signum)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            if sys.platform != "darwin":
                raise
            # XNU reports EPERM when the group exists but no member can be
            # signalled: a leader mid-exit (not yet waitable), our unreaped
            # leader, OR a zombie descendant awaiting its parent/launchd.
            # Reap only our own child; the other states need time, not another
            # immediate killpg. Linux EPERM remains a genuine permission error.
            process.poll()
            if signum == 0:
                return True  # Not empty yet: let the caller's grace loop wait.
            live = _darwin_group_has_live_members(pgid)
            if live is False:
                return True  # No executing target remains; zombies need no signal.
            if live is True:
                raise  # An actually live, unsignalable member is a real denial.
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise  # Persistent EPERM is not proof of successful cleanup.
            time.sleep(min(0.005, remaining))


def _signal_group(process: subprocess.Popen, pgid: int, signum: int, until: float) -> None:
    # start_new_session pinned this group id at spawn. On macOS and Linux,
    # surviving group members remain addressable after the leader is reaped.
    # Once empty, the id can be recycled: ownership is practical, not formal.
    _kill_group(process, pgid, signum, until)


def _group_is_empty(process: subprocess.Popen, pgid: int) -> bool:
    # An exited leader may need reaping before the probe is meaningful on
    # Darwin. Other zombies may keep a group visible until their parent reaps
    # them, so the caller must retain its bounded grace window.
    return not _kill_group(process, pgid, 0, time.monotonic())


def _pump_until(pump: _Pump, until: float) -> bool:
    """Run the pump until every pipe settles or the deadline passes. Returns
    whether the pump settled."""
    while not pump.settled:
        remaining = until - time.monotonic()
        if remaining <= 0:
            break
        pump.step(min(POLL_SECONDS, remaining))
    return pump.settled


def _wait_for_group(process: subprocess.Popen, pgid: int, pump: _Pump, until: float) -> None:
    """Wait for the leader to be reaped and the owned group to empty, or for
    the deadline. Pipes are drained while they are open so a handler that
    flushes output is not wedged, but the wait is for the processes: settled
    pipes say nothing about whether a handler has finished cleaning up, and
    the leader exiting first says nothing about its descendants."""
    while True:
        if process.poll() is not None and _group_is_empty(process, pgid):
            return
        remaining = until - time.monotonic()
        if remaining <= 0:
            return
        if pump.settled:
            time.sleep(min(POLL_SECONDS, remaining))
        else:
            pump.step(min(POLL_SECONDS, remaining))


def _terminate_group(process: subprocess.Popen, pgid: int, pump: _Pump, grace_seconds: float) -> float:
    """SIGTERM, wait the group's grace, then SIGKILL whatever is left.

    Return the final drain deadline; Darwin signal retries share that window
    rather than adding an extra grace to the run's wall-clock bound.
    """
    until = time.monotonic() + grace_seconds
    _signal_group(process, pgid, signal.SIGTERM, until)
    _wait_for_group(process, pgid, pump, until)
    until = time.monotonic() + grace_seconds
    _signal_group(process, pgid, signal.SIGKILL, until)
    process.wait()
    return until


def _supervise(
    process: subprocess.Popen,
    pgid: int,
    pump: _Pump,
    budget: _Budget,
    deadline: float,
    grace_seconds: float,
) -> str:
    status: str | None = None
    while True:
        pump.step(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))
        if budget.writer_error is not None:
            status = "writer_error"
            break
        if budget.exceeded:
            status = "output_limit"
            break
        if process.poll() is not None:
            break
        if time.monotonic() >= deadline:
            status = "timeout"
            break

    if status is None:
        # The leader exited on its own. Give the group one grace to flush,
        # then kill the whole owned group so nothing outlives the run whether
        # or not it still holds a pipe. Only a writer that escaped the group
        # can keep a pipe open past that; then capture is cut here and the
        # result is not a clean exit.
        settled = _pump_until(pump, time.monotonic() + grace_seconds)
        until = time.monotonic() + grace_seconds
        _signal_group(process, pgid, signal.SIGKILL, until)
        if not settled:
            settled = _pump_until(pump, until)
        if budget.exceeded:
            status = "output_limit"
        elif settled:
            status = "exited"
        else:
            status = "incomplete"
    else:
        until = _terminate_group(process, pgid, pump, grace_seconds)
        _pump_until(pump, until)
    pump.close()
    return status


def _abandon(
    process: subprocess.Popen, pgid: int, pump: _Pump | None, grace_seconds: float, original: BaseException
) -> None:
    """Best-effort cleanup without replacing the exception already in flight.

    A failed SIGTERM must not skip SIGKILL or the wait. If even SIGKILL fails,
    bound the wait too: a genuine permission denial can leave a live child.
    """
    try:
        for signum in (signal.SIGTERM, signal.SIGKILL):
            until = time.monotonic() + grace_seconds
            failed = False
            try:
                _signal_group(process, pgid, signum, until)
            except OSError as error:
                original.add_note(f"Process-group cleanup ({signal.Signals(signum).name}) failed: {error!r}")
                failed = True
            try:
                if signum == signal.SIGKILL and not failed:
                    process.wait()
                else:
                    process.wait(timeout=max(0.0, until - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                if signum == signal.SIGKILL:
                    original.add_note(f"Process-group cleanup could not reap leader: {error!r}")
            except OSError as error:
                original.add_note(f"Process-group cleanup wait failed: {error!r}")
    finally:
        try:
            if pump is not None:
                pump.close()
        except OSError as error:
            original.add_note(f"Capture cleanup failed: {error!r}")
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError as error:
                    original.add_note(f"Capture pipe cleanup failed: {error!r}")


def run_logged(
    command: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None,
    env: Mapping[str, str] | None,
    stdout_path: str | os.PathLike[str],
    stderr_path: str | os.PathLike[str] | None = None,
    timeout_seconds: float,
    input_text: str | None = None,
    max_output_bytes: int = 64 * 1024 * 1024,
    tail_bytes: int = 8192,
    grace_seconds: float = 2.0,
) -> RunResult:
    """Run ``command`` in its own process group, streaming output to files.

    ``status`` is ``exited`` only when the leader exited on its own, every
    pipe reached EOF, stdin (if any) was delivered or refused, and the output
    cap was not exceeded; ``exit_code`` is set only then. ``output_limit``
    and ``timeout`` mean we terminated the group. ``incomplete`` means the
    leader exited but a pipe never settled within the grace (a writer that
    escaped the group still held it); capture stopped at return and the
    artifacts are whatever was received by then.

    Raises OSError when the command cannot be spawned, a log path cannot be
    opened, or an artifact write fails mid-run (the group is terminated first;
    a partial artifact is never reported as a completed run).
    ``KeyboardInterrupt``/``SystemExit`` at any point after spawn terminate
    the owned group and are re-raised. Wall-clock bound: ``timeout_seconds``
    for the leader plus at most two ``grace_seconds`` windows.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_output_bytes < 0 or tail_bytes < 0:
        raise ValueError("byte limits must be non-negative")
    stdin_data = input_text.encode("utf-8") if input_text is not None else None

    stdout_file = Path(stdout_path)
    stderr_file = Path(stderr_path) if stderr_path is not None else None
    budget = _Budget(max_output_bytes)

    # Open artifacts before spawning so a bad path never leaves a child behind.
    files = [open(stdout_file, "wb", buffering=0)]
    try:
        if stderr_file is not None:
            files.append(open(stderr_file, "wb", buffering=0))
        started = time.monotonic()
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if stderr_file is not None else subprocess.STDOUT,
            start_new_session=True,
        )
    except BaseException:
        for handle in files:
            handle.close()
        raise
    pgid = process.pid

    sinks = [_StreamSink(handle, budget, tail_bytes) for handle in files]
    pump: _Pump | None = None
    try:
        readers = [(process.stdout, sinks[0])]
        if stderr_file is not None:
            readers.append((process.stderr, sinks[1]))
        pump = _Pump(process, readers, stdin_data)
        status = _supervise(process, pgid, pump, budget, started + timeout_seconds, grace_seconds)
    except BaseException as error:
        try:
            _abandon(process, pgid, pump, grace_seconds, error)
        finally:
            for sink in sinks:
                sink.close()
        raise
    for sink in sinks:
        sink.close()
    if budget.writer_error is not None:
        raise budget.writer_error
    duration = time.monotonic() - started

    stdout_sink = sinks[0]
    stderr_sink = sinks[1] if len(sinks) > 1 else None
    return RunResult(
        status=status,
        exit_code=process.returncode if status == "exited" else None,
        duration_seconds=duration,
        stdout_path=str(stdout_file),
        stderr_path=None if stderr_file is None else str(stderr_file),
        stdout_bytes=stdout_sink.written,
        stderr_bytes=None if stderr_sink is None else stderr_sink.written,
        stdout_tail=stdout_sink.tail_text(),
        stderr_tail=None if stderr_sink is None else stderr_sink.tail_text(),
        truncated=budget.exceeded,
    )
