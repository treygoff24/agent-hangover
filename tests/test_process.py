import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from itertools import count
from pathlib import Path
from unittest.mock import Mock, call, patch

from hangover.process import RunResult, _terminate_group, _wait_for_group, run_logged

if __package__:
    from .process_support import _after_ready, _wait_for_file
else:  # unittest discovery and direct file execution
    from process_support import _after_ready, _wait_for_file

PYTHON = sys.executable

# Writes a growing marker file from a grandchild that survives its parent's death
# unless the whole process group is terminated. The parent then blocks.
DESCENDANT_WRITER = (
    "( while :; do echo tick >> \"$MARK\"; sleep 0.05; done ) & sleep 30"
)


def _assert_stops_growing(test: unittest.TestCase, path: Path) -> None:
    size = path.stat().st_size
    time.sleep(0.4)
    test.assertEqual(size, path.stat().st_size, "descendant kept writing after cleanup")


class ProcessGroupTests(unittest.TestCase):
    def setUp(self):
        # Exercise the bounded fallback independently of this host's process table.
        inspection = patch("hangover.process._darwin_group_has_live_members", return_value=None)
        inspection.start()
        self.addCleanup(inspection.stop)

    def test_darwin_signalling_retries_mid_exit_and_reaped_descendant_eperm(self):
        for leader_status in (None, 0):
            with self.subTest(leader_status=leader_status):
                process = Mock()
                process.poll.return_value = leader_status
                with patch("sys.platform", "darwin"), patch(
                    "hangover.process.os.killpg",
                    side_effect=[PermissionError(), PermissionError(), ProcessLookupError(),
                                 ProcessLookupError(), ProcessLookupError()],
                ) as killpg:
                    _terminate_group(process, 12345, Mock(settled=True), 0.1)
                self.assertEqual([call(12345, signal.SIGTERM)] * 3, killpg.call_args_list[:3])
                process.poll.assert_called()
                process.wait.assert_called_once_with()

    def test_darwin_probe_eperm_keeps_waiting_for_group_to_disappear(self):
        process = Mock()
        process.poll.return_value = 0
        with patch("sys.platform", "darwin"), patch(
            "hangover.process.os.killpg", side_effect=[PermissionError(), PermissionError(), ProcessLookupError()]
        ) as killpg:
            _wait_for_group(process, 12345, Mock(settled=True), time.monotonic() + 1)
        self.assertEqual([call(12345, 0)] * 3, killpg.call_args_list)

    def test_linux_eperm_is_immediately_a_permission_error_even_after_leader_exit(self):
        process = Mock()
        process.poll.return_value = 0
        with patch("sys.platform", "linux"), patch(
            "hangover.process.os.killpg", side_effect=PermissionError()
        ) as killpg:
            with self.assertRaises(PermissionError):
                _terminate_group(process, 12345, Mock(settled=True), 1)
        killpg.assert_called_once_with(12345, signal.SIGTERM)

    def test_darwin_persistent_signal_eperm_raises_only_after_bounded_retries(self):
        process = Mock()
        process.poll.return_value = None
        denied = PermissionError("persistent denial")
        with patch("sys.platform", "darwin"), patch(
            "hangover.process.os.killpg", side_effect=denied
        ) as killpg, patch("hangover.process.time.monotonic", side_effect=count(10, 0.01)), patch(
            "hangover.process.time.sleep"
        ) as backoff:
            with self.assertRaises(PermissionError) as caught:
                _terminate_group(process, 12345, Mock(settled=True), 0.05)
        self.assertIs(denied, caught.exception)
        self.assertGreaterEqual(killpg.call_count, 4)
        self.assertLessEqual(killpg.call_count, 10)
        self.assertTrue(backoff.called)
        self.assertTrue(all(0 < entry.args[0] <= 0.005 for entry in backoff.call_args_list))

    def test_darwin_persistent_probe_eperm_exhausts_grace_without_raising(self):
        process = Mock()
        process.poll.return_value = 0
        with patch("sys.platform", "darwin"), patch(
            "hangover.process.os.killpg", side_effect=PermissionError()
        ) as killpg, patch("hangover.process.time.monotonic", side_effect=count(10, 0.01)), patch(
            "hangover.process.time.sleep"
        ):
            _wait_for_group(process, 12345, Mock(settled=True), 10.1)
        self.assertGreaterEqual(killpg.call_count, 2)
        self.assertLessEqual(killpg.call_count, 10)

    def test_signalling_reaps_exited_leader_before_retrying_permission_error(self):
        process = Mock()
        process.poll.return_value = 0
        pump = Mock(settled=True)
        with patch("sys.platform", "darwin"), patch(
            "hangover.process.os.killpg", side_effect=[PermissionError(), ProcessLookupError(),
                                                    ProcessLookupError(), ProcessLookupError()]
        ) as killpg:
            _terminate_group(process, 12345, pump, 1)
        self.assertEqual([call(12345, signal.SIGTERM)] * 2, killpg.call_args_list[:2])
        process.poll.assert_called()
        process.wait.assert_called_once_with()

    def test_group_probe_reaps_exited_leader_before_retrying_permission_error(self):
        process = Mock()
        process.poll.return_value = 0
        with patch("sys.platform", "darwin"), patch(
            "hangover.process.os.killpg", side_effect=[PermissionError(), ProcessLookupError()]
        ) as killpg:
            _wait_for_group(process, 12345, Mock(settled=True), time.monotonic() + 1)
        self.assertEqual([call(12345, 0)] * 2, killpg.call_args_list)

    def test_live_group_permission_error_is_not_swallowed(self):
        process = Mock()
        process.poll.return_value = None
        with patch("sys.platform", "linux"), patch("hangover.process.os.killpg", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                _terminate_group(process, 12345, Mock(settled=True), 1)

    def test_permission_error_after_reaping_is_not_swallowed(self):
        process = Mock()
        process.poll.return_value = 0
        with patch("sys.platform", "linux"), patch("hangover.process.os.killpg", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                _wait_for_group(process, 12345, Mock(settled=True), time.monotonic() + 1)


@unittest.skipUnless(sys.platform == "darwin", "Darwin libproc group inspection")
class DarwinGroupInspectionTests(unittest.TestCase):
    def test_inspection_distinguishes_live_zombie_and_reaped_owned_group(self):
        from hangover.process import _darwin_group_has_live_members

        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            self.assertIs(True, _darwin_group_has_live_members(child.pid))
            child.kill()
            deadline = time.monotonic() + 15
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                self.assertLess(time.monotonic(), deadline, "child never became waitable")
                time.sleep(0.01)
            self.assertIs(False, _darwin_group_has_live_members(child.pid))
            child.wait()
            self.assertIs(False, _darwin_group_has_live_members(child.pid))
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()

    def test_zombie_only_signal_eperm_is_not_a_permission_failure(self):
        child = subprocess.Popen([PYTHON, "-c", "pass"], start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                self.assertLess(time.monotonic(), deadline, "child never became waitable")
                time.sleep(0.01)
            # Keep a real zombie as the precondition; the first poll reaps it.
            # EPERM can outlive that reap while the kernel drops the group.
            with patch("hangover.process.os.killpg", side_effect=PermissionError()):
                _terminate_group(child, child.pid, Mock(settled=True), 0)
            self.assertIsNotNone(child.returncode)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()

    def test_inspection_failure_is_unknown_not_proof_of_death(self):
        from hangover.process import _darwin_group_has_live_members

        with patch("ctypes.CDLL", side_effect=OSError("inspection unavailable")):
            self.assertIsNone(_darwin_group_has_live_members(os.getpgrp()))

    def test_live_unsignalable_owned_group_raises_without_backoff(self):
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            with patch("hangover.process.os.killpg", side_effect=PermissionError()), patch(
                "hangover.process.time.sleep", side_effect=AssertionError("live denial must be prompt")
            ):
                with self.assertRaises(PermissionError):
                    _terminate_group(child, child.pid, Mock(settled=True), 10)
        finally:
            child.kill()
            child.wait()


class RunLoggedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.stdout_path = self.root / "stdout.log"
        self.stderr_path = self.root / "stderr.log"
        self.marker = self.root / "marker.txt"
        self.ready = self.root / "ready.txt"
        # An unrelated process in the test's own process group; a runner that
        # signals anything but its own group would kill it.
        self.sentinel = subprocess.Popen(["sleep", "30"])

    def tearDown(self) -> None:
        if self.sentinel.poll() is None:
            self.sentinel.kill()
            self.sentinel.wait()
        self._tmp.cleanup()

    def run_shell(self, script: str, **kwargs):
        kwargs.setdefault("cwd", self.root)
        kwargs.setdefault("env", {**os.environ, "MARK": str(self.marker)})
        kwargs.setdefault("stdout_path", self.stdout_path)
        kwargs.setdefault("timeout_seconds", 10)
        return run_logged(["sh", "-c", script], **kwargs)

    def test_timeout_terminates_descendant_and_spares_unrelated_sentinel(self) -> None:
        with _after_ready(self.marker) as timing:
            result = self.run_shell(DESCENDANT_WRITER, timeout_seconds=0.5, grace_seconds=0.5)
        elapsed = time.monotonic() - timing["ready_at"]
        self.assertEqual("timeout", result.status)
        self.assertIsNone(result.exit_code)
        self.assertLess(elapsed, 5)
        _wait_for_file(self.marker)
        _assert_stops_growing(self, self.marker)
        self.assertIsNone(self.sentinel.poll(), "unrelated sentinel was killed")

    def test_timeout_kills_child_that_ignores_sigterm(self) -> None:
        with _after_ready(self.ready) as timing:
            result = self.run_shell(
                f"trap '' TERM; echo ready > {str(self.ready)!r}; echo alive; sleep 60",
                timeout_seconds=0.3,
                grace_seconds=0.3,
            )
        elapsed = time.monotonic() - timing["ready_at"]
        self.assertEqual("timeout", result.status)
        self.assertLess(elapsed, 5)
        self.assertEqual(b"alive\n", self.stdout_path.read_bytes())
        self.assertEqual("alive\n", result.stdout_tail)

    def test_sigterm_handler_gets_its_grace_after_stdio_closes(self) -> None:
        # The leader has closed both pipes, so there is nothing left to pump.
        # The grace is a promise to the process, not to the pipes: a handler
        # that needs a moment to clean up must not be SIGKILLed the instant
        # SIGTERM lands just because I/O has already settled.
        script = (
            "import os, signal, sys, time\n"
            "def handler(signum, frame):\n"
            "    time.sleep(0.1)\n"
            f"    open({str(self.marker)!r}, 'w').write('cleaned')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, handler)\n"
            "os.close(1); os.close(2)\n"
            f"open({str(self.ready)!r}, 'w').write('ready')\n"
            "time.sleep(60)\n"
        )
        with _after_ready(self.ready):
            result = run_logged(
                [PYTHON, "-c", script],
                cwd=self.root,
                env=dict(os.environ),
                stdout_path=self.stdout_path,
                stderr_path=self.stderr_path,
                timeout_seconds=0.3,
                grace_seconds=2,
            )
        self.assertEqual("timeout", result.status)
        self.assertIsNone(result.exit_code)
        self.assertTrue(self.marker.exists(), "SIGTERM handler was killed before its grace")
        self.assertEqual("cleaned", self.marker.read_text())

    def test_descendant_keeps_its_grace_when_leader_exits_first_on_timeout(self) -> None:
        # On timeout the leader dies to SIGTERM at once, but a grandchild with a
        # cleanup handler is still in the owned group. Its grace must not be
        # cut short merely because the leader went first.
        grandchild = (
            "import signal, sys, time\n"
            "def handler(signum, frame):\n"
            "    time.sleep(0.1)\n"
            f"    open({str(self.marker)!r}, 'w').write('cleaned')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, handler)\n"
            f"open({str(self.ready)!r}, 'w').write('ready')\n"
            "time.sleep(60)\n"
        )
        leader = (
            "import subprocess, sys, time\n"
            f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "time.sleep(60)\n"
        )
        with _after_ready(self.ready):
            result = run_logged(
                [PYTHON, "-c", leader], cwd=self.root, env=dict(os.environ),
                stdout_path=self.stdout_path, timeout_seconds=0.3, grace_seconds=2,
            )
        self.assertEqual("timeout", result.status)
        self.assertTrue(self.marker.exists(), "grandchild was killed before its grace")
        self.assertEqual("cleaned", self.marker.read_text())
        self.assertIsNone(self.sentinel.poll())

    def test_output_limit_flags_truncation_and_terminates_writer(self) -> None:
        late = self.root / "late.txt"
        returned = self.root / "returned"
        script = (
            "import sys, time\n"
            "from pathlib import Path\n"
            "sys.stdout.write('x' * 200000)\n"
            "sys.stdout.flush()\n"
            f"while not Path({str(returned)!r}).exists(): time.sleep(0.01)\n"
            f"open({str(late)!r}, 'w').write('late')\n"
        )
        result = run_logged(
            [PYTHON, "-c", script],
            cwd=self.root,
            env=dict(os.environ),
            stdout_path=self.stdout_path,
            timeout_seconds=10,
            max_output_bytes=4096,
            grace_seconds=0.5,
        )
        self.assertEqual("output_limit", result.status)
        self.assertTrue(result.truncated)
        self.assertIsNone(result.exit_code)
        self.assertLessEqual(self.stdout_path.stat().st_size, 4096)
        self.assertEqual(4096, result.stdout_bytes)
        returned.write_text("run_logged returned")
        time.sleep(0.4)
        self.assertFalse(late.exists(), "writer survived the output limit")
        self.assertIsNone(self.sentinel.poll(), "unrelated sentinel was killed")

    def test_output_limit_is_combined_across_streams(self) -> None:
        script = (
            "import sys, time\n"
            "sys.stdout.write('o' * 3000); sys.stdout.flush()\n"
            "sys.stderr.write('e' * 3000); sys.stderr.flush()\n"
            "time.sleep(5)\n"
        )
        result = run_logged(
            [PYTHON, "-c", script],
            cwd=self.root,
            env=dict(os.environ),
            stdout_path=self.stdout_path,
            stderr_path=self.stderr_path,
            timeout_seconds=10,
            max_output_bytes=4096,
            grace_seconds=0.5,
        )
        self.assertEqual("output_limit", result.status)
        self.assertTrue(result.truncated)
        self.assertLessEqual(
            self.stdout_path.stat().st_size + self.stderr_path.stat().st_size, 4096
        )
        self.assertLessEqual(result.stdout_bytes + result.stderr_bytes, 4096)

    def test_fast_exit_past_the_cap_is_still_output_limit(self) -> None:
        # The child is gone before the reader hits the cap; the result must not
        # look like a clean exit with a quietly truncated artifact.
        result = run_logged(
            [PYTHON, "-c", "import sys; sys.stdout.buffer.write(b'x' * 10000)"],
            cwd=self.root,
            env=dict(os.environ),
            stdout_path=self.stdout_path,
            timeout_seconds=5,
            max_output_bytes=100,
            grace_seconds=0.2,
        )
        self.assertEqual("output_limit", result.status)
        self.assertTrue(result.truncated)
        self.assertIsNone(result.exit_code)
        self.assertEqual(100, result.stdout_bytes)
        self.assertEqual(100, self.stdout_path.stat().st_size)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin unreaped-group semantics")
    def test_output_limit_handles_exited_unreaped_leader(self) -> None:
        real_killpg = os.killpg
        observed_unreaped = False

        def signal_after_exit(pgid, signum):
            nonlocal observed_unreaped
            if not observed_unreaped:
                # Do not reap: establish the real Darwin EPERM precondition,
                # instead of hoping a fast child exits before the output cap.
                deadline = time.monotonic() + 15
                while True:
                    try:
                        real_killpg(pgid, 0)
                    except PermissionError:
                        # EPERM also covers a leader mid-exit: establish that
                        # it is actually waitable, without consuming the exit.
                        exited = os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if exited is not None:
                            observed_unreaped = True
                            break
                    if time.monotonic() >= deadline:
                        self.fail("child never became an exited, unreaped group leader")
                    time.sleep(0.01)
            return real_killpg(pgid, signum)

        with patch("hangover.process.os.killpg", side_effect=signal_after_exit):
            result = run_logged(
                [PYTHON, "-c", "import sys; sys.stdout.buffer.write(b'x' * 10000)"],
                cwd=self.root, env=dict(os.environ), stdout_path=self.stdout_path,
                timeout_seconds=15, max_output_bytes=100, grace_seconds=0.5,
            )
        self.assertTrue(observed_unreaped)
        self.assertEqual("output_limit", result.status)
        self.assertIsNone(result.exit_code)
        self.assertEqual(100, result.stdout_bytes)
        self.assertTrue(result.truncated)

    def test_zero_tail_is_empty(self) -> None:
        result = self.run_shell("echo a bounded diagnostic", tail_bytes=0)
        self.assertEqual("exited", result.status)
        self.assertEqual("", result.stdout_tail)
        self.assertEqual(b"a bounded diagnostic\n", self.stdout_path.read_bytes())

    def test_exact_cap_is_not_truncation(self) -> None:
        result = self.run_shell("printf 'abcd'", max_output_bytes=4)
        self.assertEqual("exited", result.status)
        self.assertEqual(0, result.exit_code)
        self.assertFalse(result.truncated)
        self.assertEqual(4, result.stdout_bytes)
        self.assertEqual(b"abcd", self.stdout_path.read_bytes())

    def test_both_streams_and_nonzero_exit_are_retained(self) -> None:
        result = self.run_shell(
            "echo out; echo err >&2; exit 3", stderr_path=self.stderr_path
        )
        self.assertIsInstance(result, RunResult)
        self.assertEqual("exited", result.status)
        self.assertEqual(3, result.exit_code)
        self.assertFalse(result.truncated)
        self.assertEqual(b"out\n", self.stdout_path.read_bytes())
        self.assertEqual(b"err\n", self.stderr_path.read_bytes())
        self.assertEqual(4, result.stdout_bytes)
        self.assertEqual(4, result.stderr_bytes)
        self.assertEqual("out\n", result.stdout_tail)
        self.assertEqual("err\n", result.stderr_tail)
        self.assertEqual(str(self.stdout_path), result.stdout_path)
        self.assertEqual(str(self.stderr_path), result.stderr_path)
        self.assertGreater(result.duration_seconds, 0)

    def test_submillisecond_duration_is_not_rounded_to_zero(self) -> None:
        with patch("hangover.process.time.monotonic", side_effect=count(10.0, 0.000001)):
            result = self.run_shell("exit 0")
        self.assertGreater(result.duration_seconds, 0)
        self.assertLess(result.duration_seconds, 0.001)

    def test_signal_death_reports_negative_exit_code(self) -> None:
        result = self.run_shell("kill -KILL $$")
        self.assertEqual("exited", result.status)
        self.assertEqual(-signal.SIGKILL, result.exit_code)

    def test_stderr_merges_into_stdout_when_not_separated(self) -> None:
        result = self.run_shell("echo out; echo err >&2")
        self.assertEqual("exited", result.status)
        self.assertIsNone(result.stderr_path)
        self.assertIsNone(result.stderr_bytes)
        self.assertIsNone(result.stderr_tail)
        self.assertEqual({b"out", b"err"}, set(self.stdout_path.read_bytes().split()))
        self.assertEqual(8, result.stdout_bytes)

    def test_tail_is_bounded_and_decoded_leniently(self) -> None:
        result = self.run_shell("printf 'abcdefghij\\377'", tail_bytes=4)
        self.assertEqual(11, result.stdout_bytes)
        self.assertEqual("hij\ufffd", result.stdout_tail)
        self.assertEqual(b"abcdefghij\xff", self.stdout_path.read_bytes())

    def test_large_input_text_with_chatty_stderr_does_not_deadlock(self) -> None:
        prompt = "".join(f"line {index} " + "p" * 80 + "\n" for index in range(40000))
        self.assertGreater(len(prompt), 3 * 1024 * 1024)
        script = (
            "import sys\n"
            "data = sys.stdin.read()\n"
            "for _ in range(20000): sys.stderr.write('noise ' * 20 + '\\n')\n"
            "sys.stdout.write(data)\n"
        )
        result = run_logged(
            [PYTHON, "-c", script],
            cwd=self.root,
            env=dict(os.environ),
            stdout_path=self.stdout_path,
            stderr_path=self.stderr_path,
            timeout_seconds=30,
            input_text=prompt,
        )
        self.assertEqual("exited", result.status)
        self.assertEqual(0, result.exit_code)
        self.assertEqual(prompt, self.stdout_path.read_text())
        self.assertEqual(len(prompt.encode()), result.stdout_bytes)
        self.assertGreater(result.stderr_bytes, 2 * 1024 * 1024)

    def test_input_text_survives_child_that_exits_without_reading(self) -> None:
        result = self.run_shell("exit 7", input_text="q" * (4 * 1024 * 1024))
        self.assertEqual("exited", result.status)
        self.assertEqual(7, result.exit_code)

    def test_stdin_is_closed_by_default(self) -> None:
        # Hold a real, never-closed pipe on fd 0 so an inherited stdin would
        # make `cat` block instead of seeing EOF from the harness's own stdin.
        read_end, write_end = os.pipe()
        saved_stdin = os.dup(0)
        os.dup2(read_end, 0)
        try:
            with _after_ready(self.ready) as timing:
                result = self.run_shell(
                    f"echo ready > {str(self.ready)!r}; cat; echo done",
                    timeout_seconds=2, grace_seconds=0.2,
                )
            elapsed = time.monotonic() - timing["ready_at"]
        finally:
            os.dup2(saved_stdin, 0)
            for fd in (saved_stdin, read_end, write_end):
                os.close(fd)
        self.assertLess(elapsed, 1.5)
        self.assertEqual("exited", result.status)
        self.assertEqual(0, result.exit_code)
        self.assertEqual(b"done\n", self.stdout_path.read_bytes())

    def test_cwd_and_env_are_applied(self) -> None:
        sub = self.root / "sub"
        sub.mkdir()
        result = self.run_shell(
            "pwd; printf '%s\\n' \"$HANGOVER_PROBE\"",
            cwd=sub,
            env={"PATH": os.environ["PATH"], "HANGOVER_PROBE": "probe-value"},
        )
        self.assertEqual(0, result.exit_code)
        lines = self.stdout_path.read_text().splitlines()
        self.assertEqual(str(sub.resolve()), str(Path(lines[0]).resolve()))
        self.assertEqual("probe-value", lines[1])

    def test_missing_executable_raises_oserror(self) -> None:
        with self.assertRaises(OSError):
            run_logged(
                [str(self.root / "no-such-binary")],
                cwd=self.root,
                env=dict(os.environ),
                stdout_path=self.stdout_path,
                timeout_seconds=5,
            )
        self.assertIsNone(self.sentinel.poll())

    def test_unwritable_log_path_raises_oserror(self) -> None:
        with self.assertRaises(OSError):
            self.run_shell("echo hi", stdout_path=self.root / "missing" / "out.log")
        self.assertFalse(self.marker.exists())

    def test_exit_with_lingering_background_child_returns_and_reaps_group(self) -> None:
        with _after_ready(self.marker) as timing:
            result = self.run_shell(
                "( while :; do echo tick >> \"$MARK\"; sleep 0.05; done ) &"
                " while [ ! -s \"$MARK\" ]; do sleep 0.02; done; echo started",
                grace_seconds=0.5,
            )
        elapsed = time.monotonic() - timing["ready_at"]
        self.assertEqual("exited", result.status)
        self.assertEqual(0, result.exit_code)
        self.assertLess(elapsed, 5)
        self.assertEqual(b"started\n", self.stdout_path.read_bytes())
        _assert_stops_growing(self, self.marker)
        self.assertIsNone(self.sentinel.poll())

    def test_descendant_outliving_leader_without_pipes_is_swept(self) -> None:
        # Leader exits first; the grandchild has closed both pipes, so nothing
        # holds the reader open. It is still in the owned group and must not
        # keep writing after run_logged returns.
        result = self.run_shell(
            "( exec >/dev/null 2>&1; while :; do echo tick >> \"$MARK\"; sleep 0.05; done ) &"
            " while [ ! -s \"$MARK\" ]; do sleep 0.02; done; echo started",
            grace_seconds=0.3,
        )
        self.assertEqual("exited", result.status)
        self.assertEqual(0, result.exit_code)
        self.assertEqual(b"started\n", self.stdout_path.read_bytes())
        _wait_for_file(self.marker)
        _assert_stops_growing(self, self.marker)
        self.assertIsNone(self.sentinel.poll())

    def test_artifact_writer_failure_raises_and_terminates_group(self) -> None:
        if not Path("/dev/full").exists():
            self.skipTest("/dev/full unavailable")
        started = time.monotonic()
        with self.assertRaises(OSError):
            self.run_shell(
                "echo evidence; " + DESCENDANT_WRITER,
                stdout_path=Path("/dev/full"),
                timeout_seconds=30,
                grace_seconds=0.3,
            )
        self.assertLess(time.monotonic() - started, 5)
        if self.marker.exists():
            _assert_stops_growing(self, self.marker)
        self.assertIsNone(self.sentinel.poll())

    def test_escaped_descendant_holding_pipe_returns_incomplete_and_stops_capture(self) -> None:
        # A descendant that leaves the owned group via setsid is outside the
        # termination guarantee. It must not pin the caller forever by keeping
        # stdout open, and the run must not be reported as a clean, final exit
        # while our own capture of that pipe is still live: the artifact stops
        # growing when run_logged returns.
        pidfile = self.root / "escapee.pid"
        outcome: dict = {}
        escapee_code = (
            "import os, time\n"
            "os.setsid()\n"
            f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
            "while True:\n"
            "    print('tick', flush=True)\n"
            "    time.sleep(0.02)\n"
        )
        leader_code = (
            "import subprocess, sys, time\n"
            "from pathlib import Path\n"
            "print('started', flush=True)\n"
            f"subprocess.Popen([sys.executable, '-c', {escapee_code!r}])\n"
            f"while not Path({str(pidfile)!r}).exists(): time.sleep(0.01)\n"
        )

        def call() -> None:
            try:
                outcome["result"] = run_logged(
                    [PYTHON, "-c", leader_code], cwd=self.root, env=dict(os.environ),
                    stdout_path=self.stdout_path, timeout_seconds=20, grace_seconds=0.3,
                )
            except BaseException as exc:  # surfaced by the assertion below
                outcome["error"] = exc

        worker = threading.Thread(target=call, daemon=True)
        worker.start()
        worker.join(timeout=25)
        finished = not worker.is_alive()
        size_at_return = self.stdout_path.stat().st_size
        _wait_for_file(pidfile)
        escapee = int(pidfile.read_text().strip())
        try:
            os.kill(escapee, 0)
            escaped_alive = True
        except ProcessLookupError:
            escaped_alive = False
        try:
            self.assertNotIn("error", outcome, repr(outcome.get("error")))
            self.assertTrue(finished, "run_logged hung on an escaped descendant holding the pipe")
            self.assertTrue(escaped_alive, "escapee died, so the test did not exercise the escape path")
            time.sleep(0.3)
            self.assertEqual(size_at_return, self.stdout_path.stat().st_size, "artifact grew after return")
        finally:
            try:
                os.kill(escapee, signal.SIGKILL)
            except ProcessLookupError:
                pass
            worker.join(timeout=5)
        result = outcome["result"]
        self.assertEqual("incomplete", result.status)
        self.assertIsNone(result.exit_code)
        self.assertFalse(result.truncated)
        self.assertTrue(self.stdout_path.read_bytes().startswith(b"started\n"))

    def test_signalling_failure_still_closes_capture_resources(self) -> None:
        import builtins

        files = []
        children = []
        real_popen = subprocess.Popen

        def open_artifact(*args, **kwargs):
            handle = builtins.open(*args, **kwargs)
            files.append(handle)
            return handle

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        try:
            with patch("hangover.process.open", side_effect=open_artifact, create=True), patch(
                "hangover.process.subprocess.Popen", side_effect=spawn
            ), patch("hangover.process.os.killpg", side_effect=PermissionError()):
                with self.assertRaises(PermissionError):
                    self.run_shell("sleep 60", timeout_seconds=0.1, grace_seconds=0.05)
            self.assertEqual(1, len(files))
            self.assertTrue(files[0].closed, "artifact leaked when group signalling failed")
            self.assertEqual(1, len(children))
            for pipe in (children[0].stdout, children[0].stderr):
                if pipe is not None:
                    self.assertTrue(pipe.closed, "capture pipe leaked when signalling failed")
        finally:
            # The simulated permission failure deliberately prevented runner
            # cleanup. These are only the children/groups this test created.
            for child in children:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
                for pipe in (child.stdin, child.stdout, child.stderr):
                    if pipe is not None:
                        pipe.close()
            for handle in files:
                handle.close()

    def test_interruption_during_post_spawn_setup_reaps_the_child(self) -> None:
        # Anything that can fail between spawn and the wait loop must leave the
        # owned group cleaned up; the interruption lands while the runner is
        # still wiring up the pipes.
        children: list = []
        real_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        try:
            with patch("hangover.process.subprocess.Popen", side_effect=spawn), patch(
                "hangover.process.os.set_blocking", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    self.run_shell("sleep 30", grace_seconds=0.2)
            self.assertEqual(1, len(children))
            self.assertIsNotNone(children[0].poll(), "child survived the setup interruption")
            self.assertIsNone(self.sentinel.poll(), "unrelated sentinel was killed")
        finally:
            for child in children:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()

    def test_interruption_survives_sigterm_permission_error_and_still_kills_group(self) -> None:
        children = []
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        interrupt = KeyboardInterrupt("original interrupt")

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def signal_group(pgid, signum):
            if signum == signal.SIGTERM:
                raise PermissionError("synthetic SIGTERM denial")
            return real_killpg(pgid, signum)

        def interrupt_when_ready(*args, **kwargs):
            _wait_for_file(self.marker)
            raise interrupt

        try:
            with patch("hangover.process.subprocess.Popen", side_effect=spawn), patch(
                "hangover.process._supervise", side_effect=interrupt_when_ready
            ), patch("hangover.process.os.killpg", side_effect=signal_group) as killpg:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.run_shell(DESCENDANT_WRITER, grace_seconds=0.05)
            self.assertIs(interrupt, caught.exception)
            self.assertEqual(1, len(children))
            self.assertIn(call(children[0].pid, signal.SIGKILL), killpg.call_args_list)
            self.assertIsNotNone(children[0].returncode, "child was not waited after SIGKILL")
            self.assertTrue(any("synthetic SIGTERM denial" in note for note in caught.exception.__notes__))
            _assert_stops_growing(self, self.marker)
            self.assertIsNone(self.sentinel.poll())
        finally:
            for child in children:
                if child.poll() is None:
                    real_killpg(child.pid, signal.SIGKILL)
                    child.wait()
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()

    def test_interruption_during_pipe_setup_closes_the_partial_selector(self) -> None:
        # The pump that fails mid-construction is never handed back to the
        # caller, so it has to release its own selector rather than wait on GC.
        import selectors

        created: list = []
        real_selector = selectors.DefaultSelector

        class Recording(real_selector):
            def __init__(self) -> None:
                super().__init__()
                self.closed = False
                created.append(self)

            def close(self) -> None:
                self.closed = True
                super().close()

        with patch("hangover.process.selectors.DefaultSelector", Recording), patch(
            "hangover.process.os.set_blocking", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.run_shell("sleep 30", grace_seconds=0.2)
        self.assertEqual(1, len(created))
        self.assertTrue(created[0].closed, "partially built selector was left open")

    def test_interruption_cleans_up_owned_group_and_reraises(self) -> None:
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        cancelled = threading.Event()

        def interrupt_when_ready():
            while not cancelled.wait(0.02):
                if self.marker.exists() and self.marker.stat().st_size:
                    os.kill(os.getpid(), signal.SIGINT)
                    return

        interrupter = threading.Thread(target=interrupt_when_ready)
        interrupter.start()
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.run_shell(DESCENDANT_WRITER, timeout_seconds=30, grace_seconds=0.5)
        finally:
            cancelled.set()
            interrupter.join()
            signal.signal(signal.SIGINT, previous)
        _wait_for_file(self.marker)
        _assert_stops_growing(self, self.marker)
        self.assertIsNone(self.sentinel.poll(), "unrelated sentinel was killed")


if __name__ == "__main__":
    unittest.main()
