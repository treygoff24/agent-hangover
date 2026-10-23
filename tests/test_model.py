import copy
import itertools
import tempfile
import unittest
from pathlib import Path

from hangover.model import (
    ISSUE_ID,
    add_to_batch,
    begin_fix,
    focus_remediation,
    open_batches,
    dedupe_open_subjective_issues,
    defer_issue,
    issue_id,
    load_state,
    merge_findings,
    mutate_state,
    new_state,
    next_issue,
    obsolete_issue,
    paths,
    resolve_issue,
    release_issues,
    save_state,
    subjective_duplicate,
    subjective_related,
    suppress_issue,
)
from hangover.oracles import review_findings

TEAM_FILES = ["src/content/team.ts", "src/content/authors.ts"]
TEAM_FILES_WIDER = ["src/content/team.ts", "src/content/authors.ts", "src/lib/seo.ts"]
TEAM_SYMBOLS = ["team", "authors"]
TEAM_SYMBOLS_WIDER = ["team", "authors", "getTeamMember"]


def finding(title: str, priority: str = "P2", **overrides) -> dict:
    item = {
        "fingerprint": ["test", title],
        "source": "test",
        "source_version": "1",
        "category": "dead_code",
        "title": title,
        "evidence": ["evidence"],
        "files": ["src/example.ts"],
        "symbols": [],
        "harm": "harm",
        "proposed_change": "change",
        "invariants": ["behavior"],
        "risk": "low",
        "priority": priority,
        "confidence": "high",
        "verification": ["test"],
        "chesterton": "reason",
    }
    item.update(overrides)
    return item


def subjective(title: str, **overrides) -> dict:
    item = {
        "source": "subjective-review",
        "source_version": None,
        "category": "duplication",
        "title": title,
        "evidence": ["team and authors overlap"],
        "files": list(TEAM_FILES),
        "symbols": list(TEAM_SYMBOLS),
        "harm": "two sources of truth for people",
        "proposed_change": "consolidate the content modules",
        "invariants": ["rendered people stay the same"],
        "risk": "low",
        "priority": "P2",
        "confidence": "high",
        "verification": ["compare the people pages"],
        "chesterton": "authors was added later",
    }
    item.update(overrides)
    return item


def full_scan(**statuses: str) -> dict:
    commands = {
        name: {"status": statuses.get(name, "completed")}
        for name in ("dead_code", "dupes", "flags", "health")
    }
    return {"kind": "scan", "fallow": {"commands": commands}}


class ModelTests(unittest.TestCase):
    def test_card_ids_keep_their_fingerprint_digest_under_the_hang_prefix(self) -> None:
        # Pinned literals: a campaign's cards keep their identities across releases, so the
        # ten hex digits after the prefix must never change for the same fingerprint.
        self.assertEqual("hang-22ff43e68a", issue_id(
            {"fingerprint": ["fallow", "unused_exports", "src/format.js", "formatNameLegacy"]}))
        self.assertEqual("hang-bd363caa1e", issue_id(
            {"source": "review", "category": "naming", "title": "Rename x", "files": ["b.ts", "a.ts"]}))
        self.assertTrue(ISSUE_ID.fullmatch(issue_id(finding("any claim"))))
        self.assertIsNone(ISSUE_ID.fullmatch("dead-22ff43e68a"))

    def test_closed_duplicate_reimport_routes_to_its_recorded_canonical(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("Canonical wording")
        twin = subjective("Restated wording")
        first_id, twin_id = issue_id(first), issue_id(twin)
        for stamp, item, identifier in (("one", first, first_id), ("two", twin, twin_id)):
            state["issues"][identifier] = {**item, "id": identifier, "status": "open",
                                            "first_seen": stamp, "history": []}
        dedupe_open_subjective_issues(state, apply=True)
        self.assertEqual("closed", state["issues"][twin_id]["status"])
        self.assertEqual([first_id], merge_findings(state, [twin], "reported-again")["ids"])
        self.assertEqual("reported-again", state["issues"][first_id]["last_seen_run"])
        self.assertEqual("closed", state["issues"][twin_id]["status"])

    def test_duplicate_alias_chain_routes_to_the_surviving_canonical(self) -> None:
        state = new_state(Path("/synthetic"))
        claims = [subjective(title) for title in ("One", "Two", "Three")]
        ids = [issue_id(item) for item in claims]
        for index, (identifier, item) in enumerate(zip(ids, claims)):
            state["issues"][identifier] = {**item, "id": identifier, "status": "open" if index == 2 else "closed",
                                            "first_seen": str(index), "history": [] if index == 2 else [
                                                {"event": "closed_duplicate", "of": ids[index + 1]}]}
        self.assertEqual([ids[2]], merge_findings(state, [claims[0]], "reported-again")["ids"])
        self.assertEqual(["closed", "closed", "open"], [state["issues"][item]["status"] for item in ids])

    def test_uncertain_rewordings_link_prior_dispositions_without_overruling_them(self) -> None:
        for disposition in ("resolved", "suppressed", "deferred", "obsolete", "closed"):
            with self.subTest(disposition=disposition):
                state = new_state(Path("/synthetic"))
                original = subjective("Same title")
                old_id = merge_findings(state, [original], "old")["ids"][0]
                state["issues"][old_id]["status"] = disposition
                state["issues"][old_id]["history"].append({"event": disposition, "reason": "Prior decision"})
                reworded = {**original, "harm": original["harm"] + " (restated)"}
                new_id = merge_findings(state, [reworded], "new")["ids"][0]
                self.assertNotEqual(old_id, new_id)
                self.assertIn(old_id, state["issues"][new_id].get("possible_duplicates", []))
                self.assertEqual(disposition, state["issues"][old_id]["status"])
                self.assertEqual("Prior decision", state["issues"][old_id]["history"][-1]["reason"])

    def test_refined_identity_ignores_scope_list_order_after_resolution(self) -> None:
        state = new_state(Path("/synthetic"))
        original = subjective("Same title", files=["a.ts", "b.ts"], symbols=["a", "b"], invariants=["one", "two"])
        merge_findings(state, [original], "old")
        distinct = {**original, "proposed_change": "A different coherent change"}
        identifier = merge_findings(state, [distinct], "distinct")["ids"][0]
        resolve_issue(state, identifier, "verified", "reviewed")
        reordered = {**distinct, **{field: list(reversed(distinct[field])) for field in ("files", "symbols", "invariants")}}
        self.assertEqual([identifier], merge_findings(state, [reordered], "reappeared")["ids"])
        self.assertEqual("reopened", state["issues"][identifier]["status"])

    def test_old_coarse_duplicate_alias_cannot_swallow_a_different_scope(self) -> None:
        state = new_state(Path("/synthetic"))
        narrow = subjective("Narrow", files=["a.ts"])
        broad = subjective("Broad", files=["a.ts", "b.ts"], priority="P0")
        narrow_id, broad_id = issue_id(narrow), issue_id(broad)
        state["issues"][narrow_id] = {**narrow, "id": narrow_id, "status": "open", "first_seen": "one", "history": []}
        state["issues"][broad_id] = {**broad, "id": broad_id, "status": "closed", "first_seen": "two",
                                     "history": [{"event": "closed_duplicate", "of": narrow_id}]}
        self.assertEqual([broad_id], merge_findings(state, [broad], "reported-again")["ids"])
        self.assertEqual("reopened", state["issues"][broad_id]["status"])
        self.assertEqual(["a.ts"], state["issues"][narrow_id]["files"])
        self.assertEqual("P2", state["issues"][narrow_id]["priority"])

    def test_same_title_same_function_can_have_independent_remediation_claims(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("Simplify request processing", category="complexity", files=["process.ts"], symbols=["process"],
                           harm="Duplicated normalization obscures data flow", proposed_change="Reuse the existing normalizer",
                           evidence=["Normalization repeats on both branches"])
        second = {**first, "harm": "An unreachable compatibility fallback obscures control flow",
                  "proposed_change": "Remove the unreachable compatibility fallback",
                  "evidence": ["The compatibility fallback has no reachable caller"]}
        self.assertFalse(subjective_duplicate(first, second))
        ids = merge_findings(state, [first, second], "review")["ids"]
        self.assertEqual(2, len(set(ids)))
        resolve_issue(state, ids[0], "verified-first", "reviewed-first")
        self.assertEqual("resolved", state["issues"][ids[0]]["status"])
        self.assertEqual("open", state["issues"][ids[1]]["status"])
        self.assertEqual(second["evidence"], state["issues"][ids[1]]["evidence"])
        self.assertEqual(second["proposed_change"], state["issues"][ids[1]]["proposed_change"])

    def test_exact_deferred_match_is_not_redirected_to_an_arbitrary_open_match(self) -> None:
        state = new_state(Path("/synthetic"))
        deferred = subjective("Deferred wording")
        opened = subjective("Open wording")
        deferred_id, open_id = issue_id(deferred), issue_id(opened)
        for identifier, claim, status in ((deferred_id, deferred, "deferred"), (open_id, opened, "open")):
            state["issues"][identifier] = {**claim, "id": identifier, "status": status,
                                            "first_seen": "first", "history": []}
        result = merge_findings(state, [deferred], "reported-again")
        self.assertEqual([deferred_id], result["ids"])
        self.assertEqual("deferred", state["issues"][deferred_id]["status"])
        self.assertNotIn("last_seen_run", state["issues"][open_id])

    def test_duplicate_alias_cycle_reopens_the_reported_issue(self) -> None:
        state = new_state(Path("/synthetic"))
        claims = [subjective("First wording"), subjective("Second wording")]
        ids = [issue_id(item) for item in claims]
        for index, (identifier, claim) in enumerate(zip(ids, claims)):
            state["issues"][identifier] = {**claim, "id": identifier, "status": "closed", "first_seen": str(index),
                                            "history": [{"event": "closed_duplicate", "of": ids[1 - index]}]}
        self.assertEqual([ids[0]], merge_findings(state, [claims[0]], "new")["ids"])
        self.assertEqual("reopened", state["issues"][ids[0]]["status"])
        self.assertEqual([ids[0]], merge_findings(state, [claims[1]], "newer")["ids"])

    def test_malformed_duplicate_alias_is_not_a_canonical_route(self) -> None:
        state = new_state(Path("/synthetic"))
        claim = subjective("Same claim")
        identifier = issue_id(claim)
        state["issues"][identifier] = {**claim, "id": identifier, "status": "closed", "first_seen": "first",
                                        "history": [{"event": "closed_duplicate", "of": ["invalid"]}]}
        self.assertEqual([identifier], merge_findings(state, [claim], "new")["ids"])
        self.assertEqual("reopened", state["issues"][identifier]["status"])

    def test_dedupe_apply_transfers_stronger_evidence_to_the_canonical_issue(self) -> None:
        state = new_state(Path("/synthetic"))
        for identifier, claim in (("hang-aaaaaaaaaa", subjective("First wording", evidence=["first"])),
                                   ("hang-bbbbbbbbbb", subjective("Second wording", evidence=["second"], priority="P0"))):
            state["issues"][identifier] = {**claim, "id": identifier, "status": "open",
                                            "first_seen": "first", "history": []}
        dedupe_open_subjective_issues(state, apply=True)
        canonical = state["issues"]["hang-aaaaaaaaaa"]
        self.assertEqual("P0", canonical["priority"])
        self.assertEqual(["first", "second"], canonical["evidence"])
        self.assertEqual("P0", canonical["history"][-1]["finding"]["priority"])
        self.assertEqual("closed", state["issues"]["hang-bbbbbbbbbb"]["status"])

    def test_dedupe_does_not_equate_parent_or_absolute_paths_with_repo_paths(self) -> None:
        inside = subjective("Same claim", files=["src/parser.ts"], symbols=["parse"])
        for path in ("../src/parser.ts", "/src/parser.ts"):
            with self.subTest(path=path):
                outside = {**inside, "files": [path]}
                self.assertFalse(subjective_duplicate(inside, outside))

    def test_coarse_legacy_review_fingerprint_cannot_collapse_different_claims(self) -> None:
        first = subjective("Simplify this module", files=["src/parser.ts"], symbols=["parseA"])
        second = {**first, "symbols": ["parseB"], "proposed_change": "Replace a different mechanism"}
        for item in (first, second):
            item.pop("source")
            item.pop("source_version")
        normalized = review_findings({"findings": [first, second]}, "subjective-review", None)
        state = new_state(Path("/synthetic"))
        identifiers = merge_findings(state, normalized, "review")["ids"]
        self.assertEqual(2, len(set(identifiers)))
        self.assertEqual(identifiers, merge_findings(state, normalized, "again")["ids"])

    def test_dedupe_identical_claims_keeps_history_entries_well_formed(self) -> None:
        state = new_state(Path("/synthetic"))
        for identifier in ("hang-aaaaaaaaaa", "hang-bbbbbbbbbb"):
            state["issues"][identifier] = {**subjective("Same claim"), "id": identifier,
                                            "status": "open", "first_seen": "first", "history": []}
        dedupe_open_subjective_issues(state, apply=True)
        self.assertTrue(all(isinstance(event, dict) for event in state["issues"]["hang-aaaaaaaaaa"]["history"]))

    def test_distinct_same_file_review_concerns_are_not_duplicates(self) -> None:
        first = subjective("Simplify parsing", files=["src/parser.ts"], symbols=["parse"],
                           harm="Unclear token state", proposed_change="Replace fallback guessing")
        second = subjective("Remove copied parser branches", files=["src/parser.ts"], symbols=["parse"],
                            harm="Maintenance divergence", proposed_change="Share the parser primitive")
        self.assertFalse(subjective_duplicate(first, second))

    def test_expanded_review_scope_and_severity_survive_as_related_work(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("Simplify one wrapper", files=["a.ts"], symbols=[])
        first_id = merge_findings(state, [first], "first")["ids"][0]
        second = subjective("Fix cross-module behavior", files=["a.ts", "b.ts"], symbols=[], priority="P0")
        second_id = merge_findings(state, [second], "second")["ids"][0]
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(2, len(state["issues"]))
        self.assertEqual("P0", state["issues"][second_id]["priority"])
        self.assertEqual(["a.ts", "b.ts"], state["issues"][second_id]["files"])
        self.assertIn(first_id, state["issues"][second_id]["possible_duplicates"])

    def test_true_rewording_preserves_added_evidence_and_stronger_severity(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("Consolidate the people data", evidence=["original evidence"])
        identifier = merge_findings(state, [first], "first")["ids"][0]
        second = subjective("One canonical people module", evidence=["additional evidence"],
                             priority="P0", risk="high", confidence="low", chesterton="New caller evidence")
        self.assertEqual([identifier], merge_findings(state, [second], "second")["ids"])
        issue = state["issues"][identifier]
        self.assertEqual("P0", issue["priority"])
        self.assertEqual("high", issue["risk"])
        self.assertEqual("low", issue["confidence"])
        self.assertEqual(["original evidence", "additional evidence"], issue["evidence"])
        self.assertEqual(second["proposed_change"], issue["history"][-1]["finding"]["proposed_change"])
        self.assertEqual(first["chesterton"], issue["history"][-1]["previous"]["chesterton"])

    def test_exact_review_match_does_not_downgrade_or_discard_prior_evidence(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("One issue", priority="P0", risk="high", confidence="low", evidence=["strong evidence"])
        identifier = merge_findings(state, [first], "first")["ids"][0]
        second = {**first, "priority": "P3", "risk": "low", "confidence": "high", "evidence": ["later evidence"]}
        self.assertEqual([identifier], merge_findings(state, [second], "second")["ids"])
        issue = state["issues"][identifier]
        self.assertEqual("P0", issue["priority"])
        self.assertEqual("high", issue["risk"])
        self.assertEqual("low", issue["confidence"])
        self.assertEqual(["strong evidence", "later evidence"], issue["evidence"])

    def test_review_findings_from_different_parent_remediations_stay_separate(self) -> None:
        state = new_state(Path("/synthetic"))
        first = subjective("Same title", source="post-review", parent_issue="parent-a", fingerprint=["a"])
        second = subjective("Same title", source="post-review", parent_issue="parent-b", fingerprint=["b"])
        first_id = merge_findings(state, [first], "first")["ids"][0]
        second_id = merge_findings(state, [second], "second")["ids"][0]
        self.assertNotEqual(first_id, second_id)

    def test_dedupe_apply_keeps_overlap_only_suggestions_open(self) -> None:
        state = new_state(Path("/synthetic"))
        for identifier, finding_value in (("hang-aaaaaaaaaa", subjective("First scope")),
                                           ("hang-bbbbbbbbbb", subjective("Expanded scope", files=TEAM_FILES_WIDER))):
            state["issues"][identifier] = {**finding_value, "id": identifier, "status": "open",
                                            "first_seen": "first", "history": []}
        dedupe_open_subjective_issues(state, apply=True)
        self.assertEqual("open", state["issues"]["hang-bbbbbbbbbb"]["status"])

    def test_begin_fix_refuses_to_reset_an_active_attempt(self) -> None:
        state = new_state(Path("/synthetic"))
        identifiers = merge_findings(state, [
            finding("one", files=["one.ts"]), finding("two", files=["two.ts"]),
        ], "scan")["ids"]
        begin_fix(state, identifiers[0], "scan", "base", identifiers[1:])
        original = copy.deepcopy(state)

        with self.assertRaisesRegex(RuntimeError, "already in progress"):
            begin_fix(state, identifiers[0], "new-scan", "new-base")
        self.assertEqual(original, state)

    def test_disposition_sequences_preserve_batch_invariants(self) -> None:
        operations = ("defer", "obsolete", "release", "suppress", "resolve")
        for sequence in itertools.product(itertools.product(operations, (0, 1)), repeat=3):
            state = new_state(Path("/synthetic"))
            identifiers = merge_findings(state, [
                finding("one", files=["one.ts"]), finding("two", files=["two.ts"]),
            ], "scan")["ids"]
            begin_fix(state, identifiers[0], "scan", "base", identifiers[1:])
            for operation, index in sequence:
                identifier = identifiers[index]
                original = copy.deepcopy(state)
                try:
                    if operation == "defer":
                        defer_issue(state, identifier, "later")
                    elif operation == "obsolete":
                        obsolete_issue(state, identifier, "purpose removed")
                    elif operation == "suppress":
                        suppress_issue(state, identifier, "policy", ".fallowrc.json")
                    elif operation == "resolve":
                        resolve_issue(state, identifier, "verify", "review")
                    else:
                        release_issues(state, [identifier])
                except RuntimeError:
                    self.assertEqual(original, state, sequence)
                active = state["active_batch"]
                in_progress = {key for key, issue in state["issues"].items() if issue["status"] == "in_progress"}
                self.assertEqual(in_progress, set(active), sequence)
                self.assertEqual(len(active), len(set(active)), sequence)
                self.assertEqual(active[0] if active else None, state["active_issue"], sequence)

    def test_batch_materializes_finding_ids_once(self) -> None:
        state = new_state(Path("/synthetic"))
        identifiers = merge_findings(state, [
            finding("one", files=["one.ts"]), finding("two", files=["two.ts"]),
        ], "scan")["ids"]

        begin_fix(state, identifiers[0], "scan", "base", identifiers[1:], finding_ids=iter(identifiers))

        record = state["remediations"][state["active_remediation"]]
        self.assertEqual(identifiers, record["fix_finding_ids"])

    def test_malformed_remediation_is_a_controlled_state_error(self) -> None:
        for records in (
            [],
            {"attempt": {"id": "attempt", "members": [{}], "primary": None}},
            {"attempt": {"id": "attempt", "members": [], "primary": None}},
        ):
            with self.subTest(records=records), tempfile.TemporaryDirectory() as directory:
                repo = Path(directory)
                state = new_state(repo)
                state.update(active_remediation="attempt", remediations=records)
                save_state(repo, state)
                with self.assertRaisesRegex(RuntimeError, "invalid active remediation"):
                    load_state(repo)

    def test_archived_remediation_does_not_reproject_settled_issue_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            state = new_state(repo)
            identifier = merge_findings(state, [finding("one")], "scan")["ids"][0]
            begin_fix(state, identifier, "scan", "original-base", fix_dir="original-fix")
            record = state["remediations"][state["active_remediation"]]
            resolve_issue(state, identifier, "verified", "reviewed")
            self.assertIsNone(state["active_remediation"])
            # Even changed historical metadata must not overwrite settled records.
            record["fix_dir"] = "archived-other-fix"
            save_state(repo, state)

            loaded = load_state(repo)
            self.assertEqual("original-fix", loaded["issues"][identifier]["fix_dir"])
            self.assertEqual("verified", loaded["issues"][identifier]["verified_run"])

    def test_mutate_state_applies_a_stale_commands_delta_to_fresh_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            save_state(repo, new_state(repo))
            command_a_state = load_state(repo)

            mutate_state(
                repo,
                lambda state: state.__setitem__("active_issue", "command-b"),
            )
            command_a_review = command_a_state.get("latest_review") or "review-a"
            mutate_state(
                repo,
                lambda state: state.__setitem__("latest_review", command_a_review),
            )

            state = load_state(repo)
            self.assertEqual("command-b", state["active_issue"])
            self.assertEqual("review-a", state["latest_review"])
            self.assertEqual(2, state["revision"])

    def test_full_scan_marks_absent_open_fallow_issue_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding(
                "Remove unused export",
                source="fallow",
                category="unused_exports",
            )
            identifier = merge_findings(
                state, [item], "scan-1", scan_result=full_scan()
            )["ids"][0]

            merged = merge_findings(
                state, [], "scan-2", scan_result=full_scan()
            )

            issue = state["issues"][identifier]
            self.assertEqual(1, merged["stale"])
            self.assertEqual("stale", issue["status"])
            self.assertEqual(
                {
                    "event": "stale",
                    "run": "scan-2",
                    "reason": "not reported by the latest scan",
                },
                {key: issue["history"][-1][key] for key in ("event", "run", "reason")},
            )

    def test_full_scan_does_not_stale_active_or_review_sourced_issues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            fallow = finding(
                "Active deterministic issue",
                source="fallow",
                category="unused_exports",
            )
            review = subjective("Review issue")
            identifiers = merge_findings(
                state, [fallow, review], "scan-1", scan_result=full_scan()
            )["ids"]
            state["issues"][identifiers[0]]["status"] = "in_progress"

            merge_findings(state, [], "scan-2", scan_result=full_scan())

            self.assertEqual("in_progress", state["issues"][identifiers[0]]["status"])
            self.assertEqual("open", state["issues"][identifiers[1]]["status"])

    def test_full_scan_obsoletes_review_issue_when_every_file_is_gone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            state = new_state(repo)
            item = subjective("Removed review target", files=["src/removed.ts"])
            identifier = merge_findings(state, [item], "review-1")["ids"][0]

            merge_findings(state, [], "scan-2", scan_result=full_scan(), repo=repo)

            issue = state["issues"][identifier]
            self.assertEqual("obsolete", issue["status"])
            self.assertEqual(
                {
                    "event": "obsolete",
                    "run": "scan-2",
                    "reason": "every referenced file was removed",
                },
                {key: issue["history"][-1][key] for key in ("event", "run", "reason")},
            )

    def test_full_scan_keeps_review_issue_when_any_file_survives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "src").mkdir()
            (repo / "src/live.ts").write_text("export const live = true;\n")
            state = new_state(repo)
            item = subjective(
                "Partially removed review target",
                files=["src/removed.ts", "src/live.ts"],
            )
            identifier = merge_findings(state, [item], "review-1")["ids"][0]

            merge_findings(state, [], "scan-2", scan_result=full_scan(), repo=repo)

            self.assertEqual("open", state["issues"][identifier]["status"])

    def test_matching_review_reopens_an_obsolete_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            state = new_state(repo)
            original = subjective("Removed review target", files=["src/removed.ts"])
            identifier = merge_findings(state, [original], "review-1")["ids"][0]
            merge_findings(state, [], "scan-2", scan_result=full_scan(), repo=repo)
            restated = subjective(
                "The review target came back",
                files=["src/removed.ts"],
            )

            merged = merge_findings(state, [restated], "review-3")

            self.assertEqual([identifier], merged["ids"])
            self.assertEqual("reopened", state["issues"][identifier]["status"])
            self.assertEqual("seen_again", state["issues"][identifier]["history"][-1]["event"])

    def test_begin_fix_refuses_obsolete_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            identifier = merge_findings(
                state, [subjective("Removed review target")], "review-1"
            )["ids"][0]
            state["issues"][identifier]["status"] = "obsolete"

            with self.assertRaisesRegex(
                RuntimeError,
                "the files this issue names no longer exist; rescan if they came back",
            ):
                begin_fix(state, identifier, "scan-1", "abc123")

    def test_next_issue_skips_obsolete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            obsolete = subjective("Higher obsolete issue", priority="P0")
            live = subjective(
                "Lower live issue", priority="P3", files=["src/live.ts"]
            )
            identifiers = merge_findings(state, [obsolete, live], "review-1")["ids"]
            state["issues"][identifiers[0]]["status"] = "obsolete"

            self.assertEqual("Lower live issue", next_issue(state)["title"])

    def test_stale_fallow_issue_seen_again_reopens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding(
                "Remove unused export",
                source="fallow",
                category="unused_exports",
            )
            identifier = merge_findings(
                state, [item], "scan-1", scan_result=full_scan()
            )["ids"][0]
            merge_findings(state, [], "scan-2", scan_result=full_scan())

            merge_findings(state, [item], "scan-3", scan_result=full_scan())

            issue = state["issues"][identifier]
            self.assertEqual("reopened", issue["status"])
            self.assertEqual("reopened", issue["history"][-1]["event"])
            self.assertEqual("scan-3", issue["history"][-1]["run"])

    def test_disabled_fallow_rule_obsoletes_an_open_issue_and_reopens_on_sight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding(
                "Private type escapes",
                source="fallow",
                category="private_type_leaks",
            )
            identifier = merge_findings(
                state, [item], "scan-1", scan_result=full_scan()
            )["ids"][0]

            merged = merge_findings(
                state,
                [],
                "scan-2",
                scan_result=full_scan(),
                obsolete_fallow_rules={"private_type_leaks": "private-type-leaks"},
            )

            issue = state["issues"][identifier]
            self.assertEqual(1, merged["obsolete"])
            self.assertEqual("obsolete", issue["status"])
            self.assertEqual(
                "rule private-type-leaks is off in the resolved Fallow config",
                issue["history"][-1]["reason"],
            )

            merge_findings(state, [item], "scan-3", scan_result=full_scan())
            self.assertEqual("reopened", state["issues"][identifier]["status"])

    def test_scan_detaches_disabled_rule_batch_members_without_resolving_fixes(self) -> None:
        for disabled_index in (0, 1):
            with self.subTest(disabled_index=disabled_index):
                state = new_state(Path("/repo"))
                items = [
                    finding("Private leak", source="fallow", category="private_type_leaks"),
                    finding("Actual fix", source="fallow", category="unused_exports"),
                ]
                if disabled_index:
                    items.reverse()
                identifiers = merge_findings(state, items, "scan-1")["ids"]
                begin_fix(state, identifiers[0], "scan-1", "abc123", identifiers[1:])
                disabled, survivor = identifiers[disabled_index], identifiers[1 - disabled_index]
                merge_findings(state, [], "scan-2", scan_result=full_scan(),
                               obsolete_fallow_rules={"private_type_leaks": "private-type-leaks"})
                self.assertEqual("obsolete", state["issues"][disabled]["status"])
                self.assertEqual("in_progress", state["issues"][survivor]["status"])
                self.assertEqual([survivor], state["active_batch"])
                self.assertEqual(survivor, state["active_issue"])

    def test_scan_repairs_legacy_settled_batch_membership(self) -> None:
        for status in ("stale", "suppressed", "obsolete", "deferred", "resolved"):
            with self.subTest(status=status):
                state = new_state(Path("/repo"))
                identifiers = merge_findings(state, [
                    finding("One", source="fallow"), finding("Two", source="fallow")
                ], "scan-1")["ids"]
                begin_fix(state, identifiers[0], "scan-1", "abc123", identifiers[1:])
                state["issues"][identifiers[0]]["status"] = status
                merge_findings(state, [], "scan-2", scan_result=full_scan())
                self.assertEqual([identifiers[1]], state["active_batch"])
                self.assertEqual(identifiers[1], state["active_issue"])
                state["issues"][identifiers[1]]["status"] = status
                merge_findings(state, [], "scan-3", scan_result=full_scan())
                self.assertEqual([], state["active_batch"])
                self.assertIsNone(state["active_issue"])

    def test_incomplete_fallow_section_does_not_stale_its_issues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            dead_code = finding(
                "Remove unused export",
                source="fallow",
                category="unused_exports",
            )
            duplication = finding(
                "Consolidate clone group",
                source="fallow",
                category="duplication",
            )
            identifiers = merge_findings(
                state, [dead_code, duplication], "scan-1", scan_result=full_scan()
            )["ids"]

            merged = merge_findings(
                state,
                [],
                "scan-2",
                scan_result=full_scan(dead_code="unavailable"),
            )

            self.assertEqual(1, merged["stale"])
            self.assertEqual("open", state["issues"][identifiers[0]]["status"])
            self.assertEqual("stale", state["issues"][identifiers[1]]["status"])

    def test_next_issue_skips_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            fallow = finding(
                "Higher stale issue",
                "P0",
                source="fallow",
                category="unused_exports",
            )
            review = subjective("Lower live issue", priority="P3")
            merge_findings(
                state, [fallow, review], "scan-1", scan_result=full_scan()
            )
            merge_findings(state, [], "scan-2", scan_result=full_scan())

            self.assertEqual("Lower live issue", next_issue(state)["title"])

    def test_begin_fix_records_the_base_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding("Record the fix base")
            identifier = merge_findings(state, [item], "scan-1")["ids"][0]

            issue = begin_fix(state, identifier, "scan-1", "abc123")

            self.assertEqual("abc123", issue["fix_base_commit"])
            self.assertEqual("abc123", issue["history"][-1]["fix_base_commit"])

    def test_begin_fix_records_null_without_a_base_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding("Record a missing fix base")
            identifier = merge_findings(state, [item], "scan-1")["ids"][0]

            issue = begin_fix(state, identifier, "scan-1", None)

            self.assertIsNone(issue["fix_base_commit"])

    def test_stable_ids_and_verified_finding_reopens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding("Remove unused export")
            identifier = issue_id(item)
            self.assertEqual([identifier], merge_findings(state, [item], "scan-1")["ids"])
            resolve_issue(state, identifier, "verify-1", "review-1")

            merge_findings(state, [item], "scan-2")

            self.assertEqual("reopened", state["issues"][identifier]["status"])
            self.assertEqual("reopened", state["issues"][identifier]["history"][-1]["event"])

    def test_next_prioritizes_high_confidence_high_leverage_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            merge_findings(
                state,
                [
                    finding("Lower", "P3", files=["src/lower.ts"]),
                    finding("Higher", "P1", files=["src/higher.ts"]),
                ],
                "scan-1",
            )
            self.assertEqual("Higher", next_issue(state)["title"])

    def test_merge_preserves_active_fix_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            item = finding("Still present")
            identifier = merge_findings(state, [item], "scan-1")["ids"][0]
            state["issues"][identifier]["fix_finding_ids"] = [identifier]

            merge_findings(state, [item], "verify-1")

            self.assertEqual([identifier], state["issues"][identifier]["fix_finding_ids"])

    def test_state_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            repo = Path(directory)
            (repo / ".hangover").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "outside the repository"):
                paths(repo)

    def test_overlapping_team_authors_findings_are_related_not_duplicates(self) -> None:
        original = subjective("Consolidate team.ts and authors.ts")
        restated = subjective(
            "team.ts and authors.ts are the same people list",
            files=list(TEAM_FILES_WIDER),
            symbols=list(TEAM_SYMBOLS_WIDER),
        )
        self.assertFalse(subjective_duplicate(restated, original))
        self.assertFalse(subjective_duplicate(original, restated))
        self.assertTrue(subjective_related(restated, original))
        self.assertTrue(subjective_related(original, restated))

    def test_subjective_duplicate_rejects_same_files_different_category(self) -> None:
        original = subjective("Consolidate team.ts and authors.ts")
        other = subjective(
            "team.ts and authors.ts are the same people list",
            category="dead_code",
        )
        self.assertFalse(subjective_duplicate(other, original))

    def test_subjective_duplicate_rejects_same_category_disjoint_files(self) -> None:
        original = subjective("Consolidate team.ts and authors.ts")
        other = subjective(
            "Unused compat re-exports",
            files=["src/lib/compat.ts", "src/index.ts"],
            symbols=["compat"],
        )
        self.assertFalse(subjective_duplicate(other, original))

    def test_subjective_duplicate_rejects_disjoint_nonempty_symbols(self) -> None:
        original = subjective("Consolidate team.ts and authors.ts")
        other = subjective(
            "Different symbols in the same files",
            symbols=["getPage", "metadata"],
        )
        self.assertFalse(subjective_duplicate(other, original))

    def test_empty_symbol_overlap_is_only_a_suggestion(self) -> None:
        original = subjective("Consolidate team.ts and authors.ts", symbols=[])
        restated = subjective(
            "team.ts and authors.ts are the same people list",
            files=list(TEAM_FILES_WIDER),
            symbols=list(TEAM_SYMBOLS_WIDER),
        )
        self.assertFalse(subjective_duplicate(restated, original))
        self.assertFalse(subjective_duplicate(original, restated))
        self.assertTrue(subjective_related(restated, original))
        self.assertTrue(subjective_related(original, restated))

    def test_merge_reworded_subjective_finding_updates_history_instead_of_creating(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            original = subjective("Consolidate team.ts and authors.ts")
            first = merge_findings(state, [original], "review-1")
            identifier = first["ids"][0]

            restated = subjective(
                "team.ts and authors.ts are the same people list",
                files=list(TEAM_FILES),
                symbols=list(TEAM_SYMBOLS),
            )
            second = merge_findings(state, [restated], "review-2")

            self.assertEqual(1, len(state["issues"]))
            self.assertEqual([identifier], second["ids"])
            self.assertEqual(
                {"ids": [identifier], "new": 0, "already_tracked": 1, "stale": 0},
                second,
            )
            issue = state["issues"][identifier]
            self.assertEqual("Consolidate team.ts and authors.ts", issue["title"])
            self.assertEqual("review-2", issue["last_seen_run"])
            self.assertEqual("seen_again", issue["history"][-1]["event"])
            self.assertEqual("review-2", issue["history"][-1]["run"])
            self.assertEqual(
                "team.ts and authors.ts are the same people list",
                issue["history"][-1]["as"],
            )

    def test_merge_post_review_finding_uses_the_same_subjective_matcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            original = subjective(
                "Follow-up leftover compat export",
                source="post-review",
                category="dead_code",
                files=["src/lib/compat.ts"],
                symbols=["compat"],
            )
            identifier = merge_findings(state, [original], "verify-1")["ids"][0]
            restated = subjective(
                "compat.ts is still unused",
                source="post-review",
                category="dead_code",
                files=["src/lib/compat.ts"],
                symbols=["compat"],
            )

            merged = merge_findings(state, [restated], "verify-2")

            self.assertEqual(1, len(state["issues"]))
            self.assertEqual([identifier], merged["ids"])
            self.assertEqual("seen_again", state["issues"][identifier]["history"][-1]["event"])

    def test_merge_does_not_fuzzy_reopen_a_resolved_subjective_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            original = subjective("Consolidate team.ts and authors.ts")
            identifier = merge_findings(state, [original], "review-1")["ids"][0]
            resolve_issue(state, identifier, "verify-1", "review-1")
            restated = subjective(
                "team.ts and authors.ts are the same people list",
                files=list(TEAM_FILES_WIDER),
                symbols=list(TEAM_SYMBOLS_WIDER),
            )

            merged = merge_findings(state, [restated], "review-2")

            self.assertEqual(2, len(state["issues"]))
            self.assertEqual("resolved", state["issues"][identifier]["status"])
            self.assertEqual(1, merged["new"])
            new_id = merged["ids"][0]
            self.assertNotEqual(identifier, new_id)
            self.assertEqual("open", state["issues"][new_id]["status"])

    def test_resolution_history_keeps_fix_notes_and_declared_change_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            identifier = merge_findings(state, [subjective("Declared adjustment")], "review-1")["ids"][0]
            state["issues"][identifier]["fix_notes"] = [
                {"at": "2026-09-07T10:00:00+00:00", "text": "intentional behavior change"}
            ]
            assessments = [{
                "note": "intentional behavior change", "verdict": "accepted",
                "evidence": ["covered by focused test"],
            }]
            resolve_issue(state, identifier, "verify-1", "review-2", assessments)
            event = state["issues"][identifier]["history"][-1]
            self.assertEqual(state["issues"][identifier]["fix_notes"], event["fix_notes"])
            self.assertEqual(assessments, event["declared_changes_assessed"])

    def test_merge_does_not_match_a_fallow_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            fallow_item = subjective(
                "Fallow clone group",
                source="fallow",
                fingerprint=["fallow", "clone"],
            )
            fallow_id = merge_findings(state, [fallow_item], "scan-1")["ids"][0]
            restated = subjective("team.ts and authors.ts are the same people list")

            merged = merge_findings(state, [restated], "review-1")

            self.assertEqual(2, len(state["issues"]))
            self.assertNotEqual(fallow_id, merged["ids"][0])
            self.assertEqual(1, merged["new"])

    def test_dedupe_selects_earlier_first_seen_as_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            earlier = subjective("Consolidate team.ts and authors.ts")
            later = subjective(
                "team.ts and authors.ts are the same people list",
                files=list(TEAM_FILES),
                symbols=list(TEAM_SYMBOLS),
            )
            earlier_id = "hang-aaaaaaaaaa"
            later_id = "hang-bbbbbbbbbb"
            state["issues"] = {
                earlier_id: {
                    **earlier,
                    "id": earlier_id,
                    "status": "open",
                    "first_seen": "2026-08-26T17:33:00+00:00",
                    "last_seen": "2026-08-26T17:33:00+00:00",
                    "last_seen_run": "review-1",
                    "history": [],
                },
                later_id: {
                    **later,
                    "id": later_id,
                    "status": "open",
                    "first_seen": "2026-08-26T18:00:00+00:00",
                    "last_seen": "2026-08-26T18:00:00+00:00",
                    "last_seen_run": "review-2",
                    "history": [],
                },
            }

            dry = dedupe_open_subjective_issues(state, apply=False)
            self.assertEqual(
                [
                    {
                        "duplicate": later_id,
                        "canonical": earlier_id,
                        "duplicate_title": later["title"],
                        "canonical_title": earlier["title"],
                        "match": "same_remediation",
                    }
                ],
                dry,
            )
            self.assertEqual("open", state["issues"][later_id]["status"])

            applied = dedupe_open_subjective_issues(state, apply=True)
            self.assertEqual(dry, applied)
            self.assertEqual("open", state["issues"][earlier_id]["status"])
            self.assertEqual("closed", state["issues"][later_id]["status"])
            self.assertEqual("closed_duplicate", state["issues"][later_id]["history"][-1]["event"])
            self.assertEqual(earlier_id, state["issues"][later_id]["history"][-1]["of"])

    def test_merge_preserves_an_exact_id_deferred_subjective_issue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            finding = subjective("Consolidate team.ts and authors.ts")
            identifier = merge_findings(state, [finding], "review-1")["ids"][0]
            defer_issue(state, identifier, "risky dynamic usage")

            merged = merge_findings(state, [dict(finding)], "review-2")

            self.assertEqual([identifier], merged["ids"])
            self.assertEqual(0, merged["new"])
            self.assertEqual(1, merged["already_tracked"])
            issue = state["issues"][identifier]
            self.assertEqual("deferred", issue["status"])
            events = [entry["event"] for entry in issue["history"]]
            self.assertIn("deferred", events)
            self.assertEqual("review-2", issue["last_seen_run"])

    def test_dedupe_overlap_chains_remain_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = new_state(Path(directory))
            base = {
                "status": "open",
                "last_seen_run": "review-1",
                "history": [],
            }
            first = subjective("People list v1")
            second = subjective(
                "People list v2",
                files=list(TEAM_FILES_WIDER),
                symbols=list(TEAM_SYMBOLS_WIDER),
            )
            # Third overlaps second's extra files but not first's set enough to match it.
            third = subjective(
                "SEO helpers duplicate people lookups",
                files=["src/lib/seo.ts", "src/lib/people.ts"],
                symbols=["getTeamMember"],
            )
            state["issues"] = {
                identifier: {
                    **item,
                    "id": identifier,
                    **base,
                    "first_seen": stamp,
                    "last_seen": stamp,
                }
                for identifier, item, stamp in (
                    ("hang-aaaaaaaaaa", first, "2026-08-26T17:33:00+00:00"),
                    ("hang-bbbbbbbbbb", second, "2026-08-26T18:00:00+00:00"),
                    ("hang-cccccccccc", third, "2026-08-26T18:00:01+00:00"),
                )
            }
            self.assertTrue(subjective_related(third, second))
            self.assertFalse(subjective_duplicate(third, second))
            self.assertFalse(subjective_duplicate(third, first))

            applied = dedupe_open_subjective_issues(state, apply=True)

            self.assertEqual(2, len(applied))
            self.assertEqual("hang-bbbbbbbbbb", applied[0]["duplicate"])
            self.assertEqual("hang-aaaaaaaaaa", applied[0]["canonical"])
            self.assertTrue(all(pair["match"] == "overlap_only" for pair in applied))
            self.assertTrue(all(issue["status"] == "open" for issue in state["issues"].values()))


class OpenBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = new_state(Path("/tmp/repo"))
        self.ids = merge_findings(
            self.state, [finding(name, files=[f"src/{name}.ts"]) for name in "abcd"], "scan"
        )["ids"]

    def start(self, identifiers, branch=None):
        return begin_fix(self.state, identifiers[0], "scan", "base", identifiers[1:], fix_dir="d", branch=branch)

    def test_second_batch_needs_a_branch_and_first_is_parked(self) -> None:
        a, b, c, d = self.ids
        self.start([a, b])
        with self.assertRaisesRegex(RuntimeError, "--branch"):
            self.start([c])
        self.start([c, d], branch="lane-2")
        self.assertEqual(c, self.state["active_issue"])
        self.assertEqual([[c, d], [a, b]], [r["members"] for r in open_batches(self.state)])
        self.assertEqual("lane-2", open_batches(self.state)[0]["branch"])
        self.assertTrue(all(self.state["issues"][i]["status"] == "in_progress" for i in self.ids))

    def test_card_is_in_at_most_one_open_batch_and_branch_is_unique(self) -> None:
        a, b, c, d = self.ids
        self.start([a, b])
        with self.assertRaisesRegex(RuntimeError, "companions must be open"):
            self.start([c, b], branch="x")
        self.start([c], branch="x")
        with self.assertRaisesRegex(RuntimeError, "already belongs to an open batch"):
            self.start([d], branch="x")

    def test_resolving_one_batch_leaves_the_other_open_and_focused(self) -> None:
        a, b, c, _ = self.ids
        self.start([a, b])
        self.start([c], branch="lane")
        resolve_issue(self.state, c, "run", "review")
        self.assertEqual(a, self.state["active_issue"])
        self.assertEqual([a, b], self.state["active_batch"])
        self.assertEqual(1, len(open_batches(self.state)))
        resolve_issue(self.state, a, "run", "review")
        self.assertEqual([b], self.state["active_batch"])

    def test_release_reaches_a_parked_batch_and_focus_switches(self) -> None:
        a, b, c, _ = self.ids
        self.start([a, b])
        self.start([c], branch="lane")
        release_issues(self.state, [b])
        self.assertEqual("open", self.state["issues"][b]["status"])
        focus_remediation(self.state, a)
        self.assertEqual(a, self.state["active_issue"])
        self.assertEqual([a], self.state["active_batch"])
        release_issues(self.state, [a])
        self.assertEqual(c, self.state["active_issue"])

    def test_legacy_single_batch_becomes_one_open_batch(self) -> None:
        a, b, *_ = self.ids
        self.start([a, b])
        legacy = copy.deepcopy(self.state)
        legacy.pop("open_remediations")
        self.assertEqual([[a, b]], [r["members"] for r in open_batches(legacy)])
        begin_fix(legacy, self.ids[2], "scan", "base", fix_dir="d", branch="lane")
        self.assertEqual([[self.ids[2]], [a, b]], [r["members"] for r in open_batches(legacy)])

    def test_add_to_batch_extends_members_and_drops_the_proof(self) -> None:
        a, b, c, d = self.ids
        self.start([a, b])
        record = open_batches(self.state)[0]
        record["verification"] = {"id": "v", "status": "passed"}
        add_to_batch(self.state, a, [c])
        self.assertEqual([a, b, c], self.state["active_batch"])
        self.assertNotIn("verification", record)
        self.assertEqual("base", self.state["issues"][c]["fix_base_commit"])
        with self.assertRaisesRegex(RuntimeError, "already in this batch"):
            add_to_batch(self.state, a, [c])
        self.start([d], branch="lane")
        with self.assertRaisesRegex(RuntimeError, "not a member of an open batch"):
            add_to_batch(self.state, "hang-0000000000", [d])
        with self.assertRaisesRegex(RuntimeError, "companions must be open"):
            add_to_batch(self.state, a, [d])


if __name__ == "__main__":
    unittest.main()
