import copy
import json
import shutil
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from hangover.model import begin_fix, defer_issue, issue_id, merge_findings, new_state, ordered_issues
from hangover.oracles import _function_inventory, extract_fallow_findings
from hangover.cli import _verification_blockers, _resolve_side_effect_fallow_issues


SOURCE = """class One {
  handler(value: number) {
    return value + 1;
  }
}
class Two {
  handler(value: number) {
    return value - 1;
  }
}
"""


def health(*lines):
    return {"status": "completed", "commands": {"health": {"status": "completed", "data": {
        "findings": [{"path": "src/handlers.ts", "name": "handler", "line": line, "col": 2,
                      "line_count": 3, "param_count": 1, "cyclomatic": 28, "cognitive": 22,
                      "exceeded": "both", "severity": "critical" if index == 0 else "moderate"}
                     for index, line in enumerate(lines)],
    }}}}


def legacy_finding():
    return {"source": "fallow", "category": "complexity", "title": "Legacy handler",
            "files": ["src/handlers.ts"], "symbols": ["handler"], "evidence": ["Original evidence"],
            "priority": "P1", "risk": "medium", "confidence": "high",
            "fingerprint": ["fallow", "complexity", "src/handlers.ts", "handler"]}


class ComplexityIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        (self.repo / "src").mkdir()
        self.source = self.repo / "src/handlers.ts"
        self.source.write_text(SOURCE)

    def tearDown(self):
        self.temp.cleanup()

    def test_unavailable_source_still_preserves_distinct_reported_locations(self):
        findings = extract_fallow_findings(health(2, 7))
        self.assertEqual(2, len({issue_id(item) for item in findings}))
        self.assertTrue(all(item["complexity_identity"]["ambiguous"] for item in findings))
        state = new_state(self.repo)
        ids = merge_findings(state, findings, "scan")["ids"]
        self.assertEqual(["P1", "P3"], [state["issues"][identifier]["priority"] for identifier in ids])

    def test_source_hashing_bounds_even_one_large_minified_line(self):
        payload = b"function handler() { return '" + b"x" * (4 * 1024 * 1024) + b"'; }\n"
        self.source.write_bytes(payload)
        testcase = self

        class BoundedReader(BytesIO):
            def readline(self, size=-1):
                testcase.assertGreater(size, 0)
                testcase.assertLessEqual(size, 64 * 1024)
                return super().readline(size)

        result = health(1)
        result["commands"]["health"]["data"]["findings"][0]["line_count"] = 1
        with patch.object(Path, "open", return_value=BoundedReader(payload)):
            findings = extract_fallow_findings(result, repo=self.repo)
        self.assertFalse(findings[0]["complexity_identity"]["ambiguous"])

    def test_symlinked_source_is_not_read_as_an_in_repository_span(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside.ts"
            outside.write_text(SOURCE)
            self.source.unlink()
            self.source.symlink_to(outside)
            with patch.object(Path, "open", side_effect=AssertionError("read external source")):
                findings = extract_fallow_findings(health(2, 7), repo=self.repo)
            self.assertTrue(all(item["complexity_identity"]["ambiguous"] for item in findings))

    def test_parent_relative_source_cannot_escape_the_requested_repository(self):
        nested = self.repo / "nested"
        nested.mkdir()
        result = health(2)
        result["commands"]["health"]["data"]["findings"][0]["path"] = "../src/handlers.ts"
        with patch.object(Path, "open", side_effect=AssertionError("read outside requested root")):
            findings = extract_fallow_findings(result, repo=nested)
        self.assertTrue(findings[0]["complexity_identity"]["ambiguous"])

    def test_directory_symlinks_are_not_followed_even_within_the_repository(self):
        (self.repo / "alias").symlink_to(self.repo / "src", target_is_directory=True)
        result = health(2)
        result["commands"]["health"]["data"]["findings"][0]["path"] = "alias/handlers.ts"
        with patch.object(Path, "open", side_effect=AssertionError("followed source symlink")):
            findings = extract_fallow_findings(result, repo=self.repo)
        self.assertTrue(findings[0]["complexity_identity"]["ambiguous"])

    def test_ambiguous_ids_do_not_depend_on_native_result_order(self):
        self.source.write_text(SOURCE.replace("value - 1", "value + 1"))
        result = health(2, 7)
        before = extract_fallow_findings(result, repo=self.repo)
        result["commands"]["health"]["data"]["findings"].reverse()
        after = extract_fallow_findings(result, repo=self.repo)
        self.assertEqual({issue_id(item) for item in before}, {issue_id(item) for item in after})

    def test_distinct_spans_keep_ids_when_unrelated_lines_move_them(self):
        before = extract_fallow_findings(health(2, 7), repo=self.repo)
        self.assertEqual(2, len({issue_id(item) for item in before}))
        self.assertTrue(all(not item["complexity_identity"]["ambiguous"] for item in before))
        self.source.write_text("// unrelated prefix\n" + SOURCE)
        after = extract_fallow_findings(health(3, 8), repo=self.repo)
        self.assertEqual([issue_id(item) for item in before], [issue_id(item) for item in after])

    def test_removing_an_earlier_same_name_function_preserves_the_remaining_card_by_exact_span(self):
        before = extract_fallow_findings(health(2, 7), repo=self.repo)
        state = new_state(self.repo)
        ids = merge_findings(state, before, "before")["ids"]
        defer_issue(state, ids[1], "keep Two")
        self.source.write_text("".join(SOURCE.splitlines(keepends=True)[5:]))
        result = health(2)
        result["function_inventory"] = {"complete": True, "functions": [
            {"path": "src/handlers.ts", "name": "handler", "positions": [[2, 2]]}]}  # Fallow lists one handler now
        after = extract_fallow_findings(result, repo=self.repo)
        self.assertEqual(["fallow", "complexity", "src/handlers.ts", "handler", "fn-v3"], after[0]["fingerprint"])
        merged = merge_findings(state, after, "after", scan_result={"kind": "scan", "fallow": result})
        card = state["issues"][merged["ids"][0]]
        self.assertEqual(ids[1], card["identity_from"])
        self.assertEqual("deferred", card["status"])


    def test_literal_whitespace_is_part_of_the_span_identity(self):
        source = SOURCE.replace("value + 1", '"one space"').replace("value - 1", '"one  space"')
        self.source.write_text(source)
        findings = extract_fallow_findings(health(2, 7), repo=self.repo)
        self.assertEqual(2, len({issue_id(item) for item in findings}))
        self.assertTrue(all(not item["complexity_identity"]["ambiguous"] for item in findings))

    def test_identical_spans_are_explicitly_ambiguous_and_cannot_inherit_by_order(self):
        identical = SOURCE.replace("value - 1", "value + 1")
        self.source.write_text(identical)
        before = extract_fallow_findings(health(2, 7), repo=self.repo)
        before_ids = {issue_id(item) for item in before}
        self.assertEqual(2, len(before_ids))
        self.assertTrue(all(item["complexity_identity"]["ambiguous"] for item in before))
        self.source.write_text("".join(identical.splitlines(keepends=True)[5:]))
        after = extract_fallow_findings(health(2), repo=self.repo)
        self.assertNotIn(issue_id(after[0]), before_ids)

    def test_ambiguous_id_cannot_move_to_another_identical_body_after_removal(self):
        identical = SOURCE.replace("value - 1", "value + 1")
        third = "".join(identical.splitlines(keepends=True)[:5]).replace("One", "Three")
        self.source.write_text(identical + third)
        before = extract_fallow_findings(health(2, 7, 12), repo=self.repo)
        self.source.write_text("".join((identical + third).splitlines(keepends=True)[5:]))
        after = extract_fallow_findings(health(2, 7), repo=self.repo)
        self.assertTrue({issue_id(item) for item in before}.isdisjoint({issue_id(item) for item in after}))

    def test_ambiguous_member_cannot_close_while_its_family_is_still_reported(self):
        issue = {**legacy_finding(), "id": "hang-aaaaaaaaaa",
                 "complexity_identity": {"family": ["src/handlers.ts", "handler"], "ambiguous": True}}
        snapshot = {"fallow": {"status": "completed"}, "fallow_comparison": {"comparable": True},
                    "complexity_families_seen": [["src/handlers.ts", "handler"]]}
        blockers = _verification_blockers(snapshot, issue, [])
        self.assertTrue(any("ambiguous" in reason for reason in blockers))

    def test_ambiguous_collateral_does_not_get_automatic_resolution_credit(self):
        state = new_state(self.repo)
        item = {**legacy_finding(), "complexity_identity": {
            "family": ["src/handlers.ts", "handler"], "ambiguous": True}}
        identifier = merge_findings(state, [item], "old")["ids"][0]
        _resolve_side_effect_fallow_issues(state, "primary", [identifier], "verify",
                                          complexity_families=[["src/handlers.ts", "handler"]])
        self.assertEqual("open", state["issues"][identifier]["status"])

    def test_legacy_disposition_history_is_linked_not_copied_into_new_anchors(self):
        state = new_state(self.repo)
        old_id = merge_findings(state, [legacy_finding()], "legacy")["ids"][0]
        old = state["issues"][old_id]
        old["status"] = "resolved"
        old["history"].append({"event": "resolved", "run": "old-proof"})
        original_history = copy.deepcopy(old["history"])
        findings = extract_fallow_findings(health(2, 7), repo=self.repo)
        ids = merge_findings(state, findings, "anchored", scan_result={"kind": "scan", "fallow": health(2, 7)})["ids"]
        self.assertNotIn(old_id, ids)
        self.assertTrue(all(state["issues"][identifier]["status"] in {"open", "reopened"} for identifier in ids))
        self.assertTrue(all(state["issues"][identifier]["identity_from"] == old_id for identifier in ids))
        self.assertEqual(original_history, old["history"][:len(original_history)])
        self.assertEqual("resolved", old["status"])

    def test_deferred_legacy_ruling_carries_forward_to_its_single_anchored_replacement(self):
        state = new_state(self.repo)
        old_id = merge_findings(state, [legacy_finding()], "legacy")["ids"][0]
        defer_issue(state, old_id, "JSX skeleton; too risky to split")
        findings = extract_fallow_findings(health(2), repo=self.repo)
        merged = merge_findings(state, findings, "anchored", scan_result={"kind": "scan", "fallow": health(2)})
        (identifier,) = merged["ids"]
        issue = state["issues"][identifier]
        self.assertEqual("deferred", issue["status"])
        self.assertEqual(old_id, issue["identity_from"])
        inherited = [entry for entry in issue["history"] if entry.get("event") == "deferred"]
        self.assertEqual(1, len(inherited))
        self.assertEqual("JSX skeleton; too risky to split", inherited[0]["reason"])
        self.assertEqual(old_id, inherited[0]["inherited_from"])
        self.assertEqual("obsolete", state["issues"][old_id]["status"])
        self.assertEqual(1, merged["obsolete"])
        self.assertEqual([], [issue["id"] for issue in ordered_issues(state, open_only=True)])
        self.assertEqual(["deferred"], [item["inherited_status"] for item in merged["identity_migrations"]])

    def test_deferred_legacy_collision_split_starts_open_and_keeps_the_legacy_ruling(self):
        state = new_state(self.repo)
        old_id = merge_findings(state, [legacy_finding()], "legacy")["ids"][0]
        defer_issue(state, old_id, "JSX skeleton; too risky to split")
        findings = extract_fallow_findings(health(2, 7), repo=self.repo)
        merged = merge_findings(state, findings, "anchored", scan_result={"kind": "scan", "fallow": health(2, 7)})
        self.assertEqual(2, len(merged["ids"]))
        for identifier in merged["ids"]:
            issue = state["issues"][identifier]
            self.assertEqual("open", issue["status"])
            self.assertEqual(old_id, issue["identity_from"])
            self.assertFalse(any(entry.get("event") == "deferred" for entry in issue["history"]))
        self.assertEqual("deferred", state["issues"][old_id]["status"])
        self.assertEqual(0, merged["obsolete"])
        self.assertNotIn("inherited_status", merged["identity_migrations"][0])

    def test_deferred_legacy_keeps_its_ruling_when_the_anchored_card_already_exists(self):
        state = new_state(self.repo)
        anchored = extract_fallow_findings(health(2), repo=self.repo)
        (existing_id,) = merge_findings(state, anchored, "earlier")["ids"]
        old_id = merge_findings(state, [legacy_finding()], "legacy")["ids"][0]
        defer_issue(state, old_id, "JSX skeleton; too risky to split")
        merged = merge_findings(state, anchored, "anchored", scan_result={"kind": "scan", "fallow": health(2)})
        self.assertEqual([existing_id], merged["ids"])
        self.assertEqual("open", state["issues"][existing_id]["status"])
        self.assertFalse(any(entry.get("event") == "deferred" for entry in state["issues"][existing_id]["history"]))
        self.assertEqual("deferred", state["issues"][old_id]["status"])
        self.assertEqual(0, merged["obsolete"])
        self.assertNotIn("inherited_status", merged["identity_migrations"][0])

    def test_active_legacy_identity_requires_explicit_release_before_migration(self):
        state = new_state(self.repo)
        old_id = merge_findings(state, [legacy_finding()], "legacy")["ids"][0]
        begin_fix(state, old_id, "legacy", "base")
        before = copy.deepcopy(state)
        findings = extract_fallow_findings(health(2, 7), repo=self.repo)
        with self.assertRaisesRegex(RuntimeError, "release"):
            merge_findings(state, findings, "anchored")
        self.assertEqual(before, state)


FIXTURES = Path(__file__).parent / "fixtures/fallow-3.31.0"


def real_health(drop=(), **changes):
    """Fallow 3.31.0 `health` output captured from the sample project in fixtures/.../src."""
    data = json.loads((FIXTURES / "health.json").read_text())
    data["findings"] = [item for item in data["findings"] if item["name"] not in drop]
    for item in data["findings"]:
        if item["name"] == "complexOne":
            item.update(changes)
    result = {"status": "completed", "commands": {"health": {"status": "completed", "data": data}}}
    result["function_inventory"] = inventory(result)
    return result


def inventory(result, listing=None):
    """What a scan stores: `_function_inventory` over a real zero-threshold `health` listing."""
    listing = listing or json.loads((FIXTURES / "functions.json").read_text())
    with patch("hangover.oracles._run_fallow", return_value={"status": "completed", "data": listing}):
        return _function_inventory(Path("/unused"), Path("/unused"), result["commands"]["health"])


def v2_card(state, span, path="src/index.ts", name="complexOne", status="open", run="old"):
    """A pre-upgrade span-anchored card, built the way the earlier release built it."""
    finding = {**legacy_finding(), "title": f"Reduce complexity of {name} in {path}",
               "files": [path], "symbols": [name],
               "fingerprint": ["fallow", "complexity", path, name, "span-v2", span],
               "complexity_identity": {"family": [path, name], "version": 2, "ambiguous": False,
                                       "span_sha256": span}}
    identifier = merge_findings(state, [finding], run)["ids"][0]
    state["issues"][identifier]["status"] = status
    return identifier


class FunctionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        shutil.copytree(FIXTURES / "src", self.repo / "src")
        self.state = new_state(self.repo)
        self.span = next(f for f in extract_fallow_findings(real_health(), repo=self.repo)
                         if f["symbols"] == ["complexOne"])["complexity_identity"]["span_sha256"]

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, result, run, **scan_extra):
        findings = extract_fallow_findings(result, repo=self.repo)
        return merge_findings(self.state, findings, run,
                              scan_result={"kind": "scan", "fallow": result, **scan_extra})

    def one(self, merged):
        return next(i for i in merged["ids"] if self.state["issues"][i]["symbols"] == ["complexOne"])

    def test_the_real_sample_is_keyed_by_function_and_carries_its_span(self):
        findings = extract_fallow_findings(real_health(), repo=self.repo)
        self.assertEqual({("src/index.ts", "complexOne"), ("src/dup_a.ts", "fna"), ("src/dup_b.ts", "fnb"),
                          ("src/dup_c.ts", "fnc")}, {tuple(f["complexity_identity"]["family"]) for f in findings})
        self.assertTrue(all(f["fingerprint"][-1] == "fn-v3" for f in findings))
        self.assertEqual(64, len(self.span))

    def test_editing_inside_a_function_keeps_its_card_and_records_the_drift(self):
        first = self.scan(real_health(), "one")["ids"]
        (self.repo / "src/index.ts").write_text((self.repo / "src/index.ts").read_text().replace("r += 5", "r += 55"))
        merged = self.scan(real_health(cyclomatic=12, cognitive=9, line_count=3), "two")
        self.assertEqual(sorted(first), sorted(merged["ids"]))
        self.assertEqual((0, 0), (merged["new"], merged["stale"]))
        drift = [e for e in self.state["issues"][self.one(merged)]["history"] if e["event"] == "metrics_changed"]
        self.assertEqual(1, len(drift))
        self.assertEqual((19, 31), (drift[0]["from"]["cyclomatic"], drift[0]["from"]["cognitive"]))
        self.assertEqual((12, 9), (drift[0]["to"]["cyclomatic"], drift[0]["to"]["cognitive"]))

    def amb_health(self, name, line, col):
        item = {"path": "src/amb.ts", "name": name, "line": line, "col": col, "line_count": 1,
                "param_count": 0, "cyclomatic": 1, "cognitive": 0, "exceeded": "both", "severity": "high"}
        result = {"status": "completed", "commands": {"health": {"status": "completed", "data": {
            "summary": {"max_cyclomatic_threshold": 0, "max_cognitive_threshold": 0}, "findings": [item]}}}}
        result["function_inventory"] = inventory(result)
        return result

    def test_two_handlers_on_one_line_are_not_mistaken_for_one(self):
        # Real Fallow output for `class One { handler() {} }` / `class Two { handler() {} }`:
        # a line- or regex-based count sees these as inline methods; Fallow lists both.
        (src,) = [i for i in [self.repo / "src/amb.ts"] if i.exists()]
        first = extract_fallow_findings(self.amb_health("handler", 1, 19), repo=self.repo)[0]
        second = extract_fallow_findings(self.amb_health("handler", 2, 19), repo=self.repo)[0]
        self.assertEqual("span-v2", first["fingerprint"][4])
        self.assertNotEqual(issue_id(first), issue_id(second))

    def test_a_comma_declared_arrow_is_still_named_when_fallow_lists_it_once(self):
        # `const other = 1, handler2 = () => 2;` defeats line regexes; the listing is exact.
        finding = extract_fallow_findings(self.amb_health("handler2", 3, 28), repo=self.repo)[0]
        self.assertEqual("fn-v3", finding["fingerprint"][4])

    def test_unavailable_or_incomplete_listing_never_grants_the_name_key(self):
        result = self.amb_health("handler2", 3, 28)
        result.pop("function_inventory")
        self.assertEqual("span-v2", extract_fallow_findings(result, repo=self.repo)[0]["fingerprint"][4])
        result["function_inventory"] = {"complete": False, "functions": [
            {"path": "src/amb.ts", "name": "handler2", "positions": [[3, 28]]}]}
        self.assertEqual("span-v2", extract_fallow_findings(result, repo=self.repo)[0]["fingerprint"][4])
        listing = json.loads((FIXTURES / "functions.json").read_text())
        listing["summary"]["functions_analyzed"] += 1  # Fallow analyzed more than it listed
        self.assertIsNone(inventory(self.amb_health("handler2", 3, 28), listing))

    def test_inventory_stores_only_reported_names_and_positions(self):
        stored = inventory(self.amb_health("handler", 1, 19))
        self.assertEqual({"complete": True, "functions": [
            {"path": "src/amb.ts", "name": "handler", "positions": [[1, 19], [2, 19]]}]}, stored)

    def test_exact_surviving_span_migrates_the_whole_card(self):
        old = v2_card(self.state, self.span)
        defer_issue(self.state, old, "domain policy; leave")
        history = copy.deepcopy(self.state["issues"][old]["history"])
        merged = self.scan(real_health(), "upgrade")
        card = self.state["issues"][self.one(merged)]
        self.assertEqual(("deferred", old), (card["status"], card["identity_from"]))
        self.assertEqual(history, card["history"][:len(history)])
        self.assertEqual("identity_migrated", card["history"][len(history)]["event"])
        self.assertEqual(("obsolete", True), (self.state["issues"][old]["status"],
                                              self.state["issues"][old]["identity_migrated"]))

    def test_the_only_card_for_an_edited_function_migrates(self):
        old = v2_card(self.state, "e" * 64)
        merged = self.scan(real_health(), "upgrade")
        self.assertEqual(old, self.state["issues"][self.one(merged)]["identity_from"])

    def test_settled_cards_migrate_then_reopen_on_sight(self):
        for status in ("resolved", "suppressed"):
            with self.subTest(status=status):
                self.state = new_state(self.repo)
                old = v2_card(self.state, self.span, status=status)
                merged = self.scan(real_health(), "upgrade")
                card = self.state["issues"][self.one(merged)]
                self.assertEqual("reopened", card["status"])
                self.assertEqual(old, card["identity_from"])
                self.assertEqual(status, self.state["issues"][old]["status"])

    def test_a_removed_siblings_ruling_is_never_inherited_by_a_stale_survivor(self):
        sibling = v2_card(self.state, "b" * 64)
        defer_issue(self.state, sibling, "ruling about the removed sibling")
        stale = v2_card(self.state, "c" * 64, status="stale")
        merged = self.scan(real_health(), "upgrade")
        card = self.state["issues"][self.one(merged)]
        self.assertEqual("open", card["status"])
        self.assertNotIn("identity_from", card)
        self.assertEqual(sorted([sibling, stale]), card["history"][-1]["candidates"])
        self.assertEqual("deferred", self.state["issues"][sibling]["status"])

    def test_an_exact_span_picks_its_card_among_several_same_name_cards(self):
        sibling = v2_card(self.state, "b" * 64)
        defer_issue(self.state, sibling, "ruling about the removed sibling")
        survivor = v2_card(self.state, self.span, status="stale")
        merged = self.scan(real_health(), "upgrade")
        card = self.state["issues"][self.one(merged)]
        self.assertEqual(survivor, card["identity_from"])
        self.assertEqual("reopened", card["status"])
        self.assertEqual("deferred", self.state["issues"][sibling]["status"])

    def test_active_span_anchored_card_requires_release(self):
        old = v2_card(self.state, self.span)
        begin_fix(self.state, old, "run", "base")
        with self.assertRaisesRegex(RuntimeError, "release"):
            self.scan(real_health(), "upgrade")

    def test_degraded_scan_does_not_seed_a_destination_that_strands_the_old_ruling(self):
        old = v2_card(self.state, self.span)
        defer_issue(self.state, old, "domain policy; leave")
        cards = set(self.state["issues"])
        merged = self.scan(real_health(), "degraded",
                           fallow_comparison={"comparable": False, "kind": "type_aware_degraded"})
        self.assertEqual(cards | {i for i in self.state["issues"] if self.state["issues"][i]["symbols"] != ["complexOne"]},
                         set(self.state["issues"]))
        self.assertIn(old, merged["ids"])
        self.assertFalse(any(c.get("identity_from") == old for c in self.state["issues"].values()))
        merged = self.scan(real_health(), "complete")
        card = self.state["issues"][self.one(merged)]
        self.assertEqual(("deferred", old), (card["status"], card["identity_from"]))

    def test_inherited_deferral_keeps_its_pre_scan_record_so_verify_does_not_call_it_introduced(self):
        legacy = {**legacy_finding(), "fingerprint": ["fallow", "complexity", "src/index.ts", "complexOne"],
                  "title": "Legacy", "files": ["src/index.ts"], "symbols": ["complexOne"]}
        old = merge_findings(self.state, [legacy], "legacy")["ids"][0]
        defer_issue(self.state, old, "domain policy; leave")
        legacy_first_seen = self.state["issues"][old]["first_seen"]
        merged = self.scan(real_health(), "upgrade")
        target = self.one(merged)
        self.assertEqual("deferred", self.state["issues"][target]["status"])
        self.assertEqual(("deferred", legacy_first_seen),
                         (merged["pre_scan"][target]["status"], merged["pre_scan"][target]["first_seen"]))
        issue = {"id": "hang-fixed", "source": "fallow", "fix_started_at": "2999-01-01T00:00:00+00:00",
                 "fix_finding_ids": []}
        snapshot = {"fallow": {"status": "completed"}, "fallow_comparison": {"comparable": True},
                    "pre_scan_cards": merged["pre_scan"]}
        blockers = _verification_blockers(snapshot, issue, merged["ids"], self.state["issues"])
        self.assertNotIn(target, " ".join(blockers))

    def snapshot_for(self, started_before_card):
        self.scan(real_health(cyclomatic=7, cognitive=6), "base")
        target = self.one({"ids": list(self.state["issues"])})
        card = self.state["issues"][target]
        card["status"] = "deferred" if started_before_card else "open"
        if not started_before_card:
            card["first_seen"] = "2999-01-01T00:00:00+00:00"  # created after the fix began
        merged = self.scan(real_health(cyclomatic=25, cognitive=30), "after")
        snapshot = {"fallow": {"status": "completed"}, "fallow_comparison": {"comparable": True},
                    "pre_scan_cards": merged["pre_scan"]}
        issue = {"id": "hang-fixed", "source": "fallow", "fix_started_at": "2500-01-01T00:00:00+00:00",
                 "fix_finding_ids": [i for i in merged["ids"] if i != target]}
        return target, _verification_blockers(snapshot, issue, merged["ids"], self.state["issues"])

    def test_a_card_deferred_before_the_fix_is_not_introduced_when_it_returns(self):
        _, blockers = self.snapshot_for(True)
        self.assertEqual([], [b for b in blockers if "introduced" in b])

    def test_a_card_created_after_the_fix_began_stays_introduced_with_its_pre_scan_metrics(self):
        target, blockers = self.snapshot_for(False)
        self.assertEqual("the fix introduced new deterministic finding(s): " + target, blockers[0])
        (line,) = blockers[1:]
        self.assertTrue(line.startswith(f"introduced {target}: Reduce complexity of complexOne"))
        # The metrics just before this scan (7/6), not an older history event.
        self.assertIn("cyclomatic 7, cognitive 6 -> cyclomatic 25, cognitive 30", line)
        self.assertIn("thresholds 5/5", line)

    def test_a_function_with_no_prior_card_is_reported_as_new(self):
        self.scan(real_health(drop=("complexOne",)), "base")
        merged = self.scan(real_health(), "after")
        snapshot = {"fallow": {"status": "completed"}, "fallow_comparison": {"comparable": True},
                    "pre_scan_cards": merged["pre_scan"]}
        issue = {"id": "hang-fixed", "source": "fallow", "fix_started_at": "2026-01-01T00:00:00+00:00",
                 "fix_finding_ids": [i for i in merged["ids"] if i != self.one(merged)]}
        blockers = _verification_blockers(snapshot, issue, merged["ids"], self.state["issues"])
        self.assertIn("not previously tracked -> cyclomatic 19, cognitive 31", blockers[1])


if __name__ == "__main__":
    unittest.main()
