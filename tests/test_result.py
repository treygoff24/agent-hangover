import json
import unittest
from io import StringIO

from hangover.result import (
    EXIT_CODES,
    FRESHNESS,
    STATES,
    DriverResult,
    exit_code,
)


class DriverResultTests(unittest.TestCase):
    def test_state_enum_covers_exactly_the_agreed_outcomes(self) -> None:
        self.assertEqual(
            (
                "ready",
                "in_progress",
                "review_pending",
                "resolved",
                "passed",
                "blocked",
                "tool_error",
                "no_open_work",
            ),
            STATES,
        )

    def test_an_unknown_state_is_refused(self) -> None:
        with self.assertRaises(RuntimeError):
            DriverResult(command="next", state="done", repo="/repo")

    def test_an_unknown_proof_freshness_is_refused(self) -> None:
        self.assertEqual(("not_checked", "checked"), FRESHNESS)
        with self.assertRaises(RuntimeError):
            DriverResult(
                command="next", state="ready", repo="/repo", proof_freshness="fresh"
            )

    def test_a_blocked_or_failed_outcome_must_name_its_blockers(self) -> None:
        for state in ("blocked", "tool_error"):
            with self.assertRaises(RuntimeError):
                DriverResult(command="verify", state=state, repo="/repo")
        result = DriverResult(
            command="verify", state="blocked", repo="/repo", blockers=["a reason"]
        )
        self.assertEqual(["a reason"], result.payload()["blockers"])

    def test_payload_carries_the_common_driver_fields(self) -> None:
        result = DriverResult(
            command="verify",
            state="resolved",
            repo="/repo",
            run="20260101T000000Z-verify-abc123",
            proof="deadbeef",
            review_run="20260101T000000Z-post-review-abc123",
            issue_id="hang-0123456789",
            batch=["hang-0123456789", "hang-9876543210"],
            artifacts={"snapshot": "/repo/.hangover/runs/x/snapshot.json"},
            proof_freshness="checked",
            next_action="hangover next",
            data={"verdict": "pass"},
        )

        payload = result.payload()

        self.assertEqual(
            {
                "schema_version",
                "command",
                "state",
                "repo",
                "run",
                "proof",
                "review_run",
                "issue_id",
                "batch",
                "blockers",
                "artifacts",
                "proof_freshness",
                "next_action",
                "data",
            },
            set(payload),
        )
        self.assertEqual("20260101T000000Z-verify-abc123", payload["run"])
        self.assertEqual("deadbeef", payload["proof"])
        self.assertEqual({"verdict": "pass"}, payload["data"])

    def test_emit_writes_exactly_one_json_value(self) -> None:
        stream = StringIO()

        DriverResult(command="next", state="no_open_work", repo="/repo").emit(stream)

        decoded = json.loads(stream.getvalue())
        self.assertEqual("no_open_work", decoded["state"])
        self.assertEqual(1, decoded["schema_version"])


    def test_one_mapping_gives_every_state_its_documented_exit(self) -> None:
        # README: 0 completed, 1 a blocking verdict, 2 a setup, tool or review failure.
        self.assertEqual(set(STATES), set(EXIT_CODES))
        self.assertEqual({"blocked": 1, "tool_error": 2},
                         {state: code for state, code in EXIT_CODES.items() if code})
        self.assertEqual(2, DriverResult(command="audit", state="tool_error", repo="/repo",
                                         blockers=["Fallow did not complete"]).exit_code)
        self.assertEqual(1, exit_code("blocked"))
        self.assertEqual(0, exit_code("review_pending"))
        with self.assertRaises(RuntimeError):
            exit_code("done")


if __name__ == "__main__":
    unittest.main()
