import copy
import unittest
from pathlib import Path

from hangover.model import defer_issue, merge_findings, new_state
from hangover.oracles import extract_fallow_findings


def findings(fingerprint, spans=(('a.ts', 1, 8), ('b.ts', 2, 9))):
    return extract_fallow_findings({'commands': {'dupes': {'data': {'clone_groups': [{
        'fingerprint': fingerprint, 'instances': [dict(file=f, start_line=s, end_line=e) for f, s, e in spans]
    }]}}}})


class DuplicationIdentityTests(unittest.TestCase):
    def test_incomplete_legacy_span_evidence_cannot_transfer_ruling(self):
        self.state['issues'][self.old]['evidence'] = ['Instance: a.ts:1-8', 'Instance: b.ts']
        defer_issue(self.state, self.old, 'Uncertain spans')
        merged = self.merge(findings('new', (('a.ts', 1, 8),)))
        self.assertEqual('open', self.state['issues'][merged['ids'][0]]['status'])
        self.assertEqual('deferred', self.state['issues'][self.old]['status'])
    def setUp(self):
        self.state = new_state(Path('/unused'))
        self.old = merge_findings(self.state, findings('old'), 'old')['ids'][0]
        self.state['issues'][self.old].pop('duplication_identity', None)

    def merge(self, items):
        return merge_findings(self.state, items, 'new', scan_result={
            'kind': 'scan', 'fallow': {'commands': {'dupes': {'status': 'completed'}}}})

    def test_exact_deferral_inherits_only_ruling_and_links_history(self):
        defer_issue(self.state, self.old, 'Intentional skeleton')
        self.state['issues'][self.old]['history'].append({'event': 'unverifiable', 'reason': 'Not a ruling'})
        self.state['issues'][self.old]['first_seen'] = 'legacy-time'
        history = copy.deepcopy(self.state['issues'][self.old]['history'])
        merged = self.merge(findings('new'))
        card = self.state['issues'][merged['ids'][0]]
        self.assertEqual('deferred', card['status'])
        self.assertEqual(self.old, card['identity_from'])
        self.assertEqual(history, self.state['issues'][self.old]['history'][:len(history)])
        self.assertFalse(any(e['event'] == 'unverifiable' for e in card['history']))
        self.assertEqual('legacy-time', card['first_seen'])
        self.assertEqual(self.old, next(e['from_issue'] for e in card['history'] if e['event'] == 'identity_refined'))
        self.assertEqual('Intentional skeleton', card['history'][-1]['reason'])
        self.assertEqual(self.old, card['history'][-1]['inherited_from'])
        self.assertTrue(self.state['issues'][self.old]['identity_migrated'])
        self.assertEqual('obsolete', self.state['issues'][self.old]['status'])
        self.assertEqual(1, merged['obsolete'])

    def test_open_reopened_and_stale_exact_matches_start_open(self):
        for status in ('open', 'reopened', 'stale'):
            with self.subTest(status=status):
                self.setUp()
                self.state['issues'][self.old]['status'] = status
                self.state['issues'][self.old]['history'].append({'event': 'unverifiable', 'reason': 'Not a ruling'})
                card = self.state['issues'][self.merge(findings('new'))['ids'][0]]
                self.assertEqual('open', card['status'])
                self.assertFalse(any(e.get('reason') for e in card['history']))
                self.assertEqual('obsolete', self.state['issues'][self.old]['status'])
                self.assertEqual([{'file': 'a.ts', 'start_line': 1, 'end_line': 8},
                                  {'file': 'b.ts', 'start_line': 2, 'end_line': 9}], card['duplication_identity']['spans'])

    def test_partial_overlap_records_durable_legacy_disposition(self):
        for status in ('open', 'reopened', 'stale', 'deferred'):
            with self.subTest(status=status):
                self.setUp()
                self.state['issues'][self.old]['status'] = status
                items = findings('new', (('a.ts', 1, 8), ('c.ts', 2, 9)))
                merged = self.merge(items)
                card = self.state['issues'][merged['ids'][0]]
                legacy = self.state['issues'][self.old]
                self.assertEqual('open', card['status'])
                self.assertEqual(self.old, card['identity_from'])
                expected = 'deferred' if status == 'deferred' else 'obsolete'
                self.assertEqual(expected, legacy['status'])
                self.assertTrue(legacy['identity_migrated'])
                event = legacy['history'][-1]
                self.assertEqual('identity_refined', event['event'])
                self.assertEqual(self.old, event['from_issue'])
                self.assertEqual([card['id']], event['replacements'])
                self.assertNotIn('inherited_status', event)
                history = copy.deepcopy(legacy['history'])
                self.merge(items)
                self.assertEqual(expected, legacy['status'])
                self.assertEqual(history, legacy['history'])

    def test_preexisting_card_excluded(self):
        # Seed without migration, as if this card already had its own history.
        other = new_state(Path('/unused'))
        identifier = merge_findings(other, findings('new'), 'earlier')['ids'][0]
        self.state['issues'][identifier] = other['issues'][identifier]
        defer_issue(self.state, self.old, 'Legacy policy')
        self.merge(findings('new'))
        self.assertEqual('deferred', self.state['issues'][self.old]['status'])
        self.assertNotIn('identity_from', self.state['issues'][identifier])

    def test_split_and_many_to_one_do_not_inherit(self):
        defer_issue(self.state, self.old, 'Legacy policy')
        merged = self.merge(findings('new') + findings('other'))
        self.assertEqual(['open', 'open'], [self.state['issues'][i]['status'] for i in merged['ids']])
        self.assertEqual('deferred', self.state['issues'][self.old]['status'])
        self.setUp()
        duplicate = copy.deepcopy(self.state['issues'][self.old])
        duplicate['id'] = 'dslp-other'
        self.state['issues']['dslp-other'] = duplicate
        merged = self.merge(findings('new'))
        self.assertEqual('open', self.state['issues'][merged['ids'][0]]['status'])
        linked = self.state['issues'][merged['ids'][0]]['identity_from']
        self.assertEqual('obsolete', self.state['issues'][linked]['status'])
        unlinked = next(i for i in (self.old, 'dslp-other') if i != linked)
        self.assertEqual('stale', self.state['issues'][unlinked]['status'])

    def test_distinct_exact_groups_can_share_one_instance(self):
        # Independent clone groups can share one span while retaining different rule dispositions.
        spans = (('a.ts', 1, 8), ('c.ts', 2, 9))
        other_state = new_state(Path('/unused'))
        second = merge_findings(other_state, findings('old-second', spans), 'old')['ids'][0]
        self.state['issues'][second] = other_state['issues'][second]
        defer_issue(self.state, self.old, 'First ruling')
        defer_issue(self.state, second, 'Second ruling')
        merged = self.merge(findings('new') + findings('new-second', spans))
        self.assertEqual(2, len(merged.get('identity_migrations', [])))
        self.assertEqual(['deferred', 'deferred'], [self.state['issues'][i]['status'] for i in merged['ids']])


class RankedFingerprintReassignmentTests(unittest.TestCase):
    """Fallow reassigns `dup:<hash>-rN` to other groups as code changes."""
    RANKED = 'dup:6f87acd9b3e1c402-r31'

    def setUp(self):
        self.state = new_state(Path('/unused'))
        self.scan = {'kind': 'scan', 'fallow': {'commands': {'dupes': {'status': 'completed'}}}}
        self.first = merge_findings(self.state, findings(self.RANKED), 'one')['ids'][0]
        defer_issue(self.state, self.first, 'generated code; leave')

    def merge(self, items, run='two'):
        return merge_findings(self.state, items, run, scan_result=self.scan)

    def test_unrelated_group_under_the_same_ranked_fingerprint_gets_a_fresh_card(self):
        merged = self.merge(findings(self.RANKED, (('x.ts', 5, 20), ('y.ts', 7, 22))))
        (fresh,) = merged['ids']
        self.assertNotEqual(self.first, fresh)
        card = self.state['issues'][fresh]
        self.assertEqual('open', card['status'])
        self.assertEqual(self.first, card['reassigned_from'])
        self.assertEqual([('opened', 'two')], [(e['event'], e['run']) for e in card['history']])
        old = self.state['issues'][self.first]
        self.assertEqual('deferred', old['status'])  # its ruling stays with the group it was made about

    def test_fresh_card_is_found_again_by_its_complete_span_set(self):
        (fresh,) = self.merge(findings(self.RANKED, (('x.ts', 5, 20), ('y.ts', 7, 22))))['ids']
        (again,) = self.merge(findings(self.RANKED, (('x.ts', 5, 20), ('y.ts', 7, 22))), 'three')['ids']
        self.assertEqual(fresh, again)
        self.assertEqual(1, sum(1 for c in self.state['issues'].values() if c.get('reassigned_from')))

    def test_a_partial_overlap_never_takes_over_a_fresh_cards_ruling(self):
        (fresh,) = self.merge(findings(self.RANKED, (('x.ts', 5, 20), ('y.ts', 7, 22))))['ids']
        defer_issue(self.state, fresh, 'ruling about the x/y group')
        (other,) = self.merge(findings(self.RANKED, (('x.ts', 5, 20), ('z.ts', 3, 18))), 'three')['ids']
        self.assertNotEqual(fresh, other)
        card = self.state['issues'][other]
        self.assertEqual('open', card['status'])
        self.assertEqual(fresh, card['identity_from'])
        self.assertFalse(any(e.get('event') == 'deferred' for e in card['history']))
        self.assertEqual('deferred', self.state['issues'][fresh]['status'])

    def test_overlapping_group_keeps_its_card_and_history(self):
        (same,) = self.merge(findings(self.RANKED, (('a.ts', 3, 12), ('b.ts', 2, 9))))['ids']
        self.assertEqual(self.first, same)
        self.assertEqual('deferred', self.state['issues'][same]['status'])

    def test_plain_fingerprint_without_a_rank_suffix_is_not_reassigned(self):
        state = new_state(Path('/unused'))
        first = merge_findings(state, findings('dup:6f87acd9'), 'one')['ids'][0]
        (same,) = merge_findings(state, findings('dup:6f87acd9', (('x.ts', 1, 8), ('y.ts', 1, 8))), 'two',
                                 scan_result=self.scan)['ids']
        self.assertEqual(first, same)


class DuplicationHoldTests(unittest.TestCase):
    def setUp(self):
        self.state = new_state(Path('/unused'))
        self.scan = {'kind': 'scan', 'fallow': {'commands': {'dupes': {'status': 'completed'}}}}
        self.first = merge_findings(self.state, findings('old'), 'one')['ids'][0]
        defer_issue(self.state, self.first, 'ruling')

    def merge(self, items, run='two'):
        return merge_findings(self.state, items, run, scan_result=self.scan)

    def test_degraded_scan_holds_a_group_that_would_inherit_a_deferral(self):
        degraded = {'kind': 'scan', 'fallow': {'status': 'completed'},
                    'fallow_comparison': {'comparable': False, 'kind': 'type_aware_degraded'}}
        cards = set(self.state['issues'])
        merged = merge_findings(self.state, findings('renamed-by-fallow'), 'degraded', scan_result=degraded)
        self.assertEqual(cards, set(self.state['issues']))
        self.assertEqual([self.first], merged['ids'])
        (held,) = merged['held']
        self.assertEqual(([self.first], 'duplication'), (held['candidates'], held['category']))
        merged = self.merge(findings('renamed-by-fallow'), 'complete')
        card = self.state['issues'][merged['ids'][0]]
        self.assertEqual(('deferred', self.first), (card['status'], card['identity_from']))
        self.assertNotIn('held', merged)

    def test_exactly_inherited_deferral_is_not_reported_as_introduced_by_verify(self):
        from hangover.cli import _verification_blockers
        started = '2999-01-01T00:00:00+00:00'  # after every card's first_seen
        merged = self.merge(findings('renamed-by-fallow'), 'complete')
        issue = {'id': 'dslp-x', 'source': 'fallow', 'fix_started_at': started, 'fix_finding_ids': []}
        snapshot = {'fallow': {'status': 'completed'}, 'fallow_comparison': {'comparable': True},
                    'pre_scan_cards': merged['pre_scan']}
        self.assertEqual([], [b for b in _verification_blockers(snapshot, issue, merged['ids'], self.state['issues'])
                              if 'introduced' in b])
        snapshot['pre_scan_cards'] = {}
        self.assertTrue([b for b in _verification_blockers(snapshot, issue, merged['ids'], self.state['issues'])
                         if 'introduced' in b])


if __name__ == '__main__':
    unittest.main()
