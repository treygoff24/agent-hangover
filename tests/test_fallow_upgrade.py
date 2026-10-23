import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
from hangover.cli import _print_scan

from hangover.model import begin_fix, defer_issue, issue_id, merge_findings, new_state
from hangover.oracles import _fallow_finding_gaps, extract_fallow_findings, run_fallow_scan


class FallowUpgradeTests(unittest.TestCase):
    def test_self_scan_excludes_fixture_sources(self):
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / '.fallowrc.json').read_text())
        self.assertIn('tests/fixtures/**', config.get('ignorePatterns', []))

    def test_self_scan_keeps_ast_grep_cli_dependency(self):
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / '.fallowrc.json').read_text())
        package = json.loads((root / 'package.json').read_text())
        self.assertIn('@ast-grep/cli', package['dependencies'])
        self.assertIn('@ast-grep/cli', config.get('ignoreDependencies', []))

    def test_invalid_dead_summary_does_not_hide_dupe_omissions(self):
        data = self.dupes()
        data['clone_groups_omitted'] = 1
        gaps = _fallow_finding_gaps({'dead_code': {'data': {'summary': []}}, 'dupes': {'data': data}})
        self.assertTrue(any(g.startswith('dead-code:') for g in gaps))
        self.assertTrue(any(g.startswith('dupes:') for g in gaps))
    def test_scan_error_line_keeps_structured_code_and_help(self):
        output = StringIO()
        with redirect_stdout(output):
            _print_scan({'id': 'scan', 'kind': 'scan', 'fallow': {'status': 'partial', 'commands': {
                'health': {'status': 'error', 'data': {'error': True, 'code': 'bad_config',
                    'message': 'Bad value', 'help': 'Use a list'}}}}})
        self.assertIn('bad_config: Bad value; Use a list', output.getvalue())
    def test_spread_replaces_optional_suggested_name(self):
        data = {'commands': {'dupes': {'data': {'clone_groups': [{
            'fingerprint': 'dup:55572694', 'spread': 0,
            'instances': [{'file': 'a.ts', 'start_line': 1, 'end_line': 9}]}]}}}}
        self.assertIn('Fallow clone spread: 0 (maximum directory-tree or same-file line distance between instances).', extract_fallow_findings(data)[0]['evidence'])
    def dupes(self):
        return {'stats': {'clone_groups': 1, 'clone_families': 1},
                'clone_groups': [{}], 'clone_families': [{}],
                'clone_groups_shown': 1, 'clone_groups_omitted': 0,
                'clone_families_shown': 1, 'clone_families_omitted': 0}

    def test_dupe_omissions_and_inconsistent_counts_are_incomplete(self):
        self.assertEqual([], _fallow_finding_gaps({'dupes': {'data': self.dupes()}}))
        for field in ('clone_groups', 'clone_families'):
            for mutation in ('omitted', 'shown', 'records'):
                with self.subTest(field=field, mutation=mutation):
                    data = self.dupes()
                    if mutation == 'omitted':
                        data[field + '_omitted'] = 1
                        data['stats'][field] = 2
                    elif mutation == 'shown':
                        data[field + '_shown'] = 0
                    else:
                        data[field] = []
                    self.assertTrue(_fallow_finding_gaps({'dupes': {'data': data}}))

    def test_dupe_gap_marks_dupes_not_dead_code_incomplete(self):
        data = self.dupes()
        data['clone_groups_omitted'] = 1
        def run(repo, directory, name, args):
            return {'status': 'completed', 'data': data if name == 'dupes' else {}}
        with patch('hangover.oracles._run_fallow', side_effect=run), patch('hangover.oracles.fallow_version', return_value='fallow 3.31.0'):
            result = run_fallow_scan(Path('/unused'), Path('/unused'), {'javascript': True})
        self.assertEqual('inconsistent', result['commands']['dupes']['status'])
        self.assertEqual('completed', result['commands']['dead_code']['status'])
        self.assertEqual('partial', result['status'])


def dead_code(strip_ids=False):
    """Fallow 3.31.0 `dead-code` output captured from a sample project."""
    data = json.loads((Path(__file__).parent / 'fixtures/fallow-3.31.0/dead-code.json').read_text())
    if strip_ids:
        for value in data.values():
            for item in value if isinstance(value, list) else []:
                if isinstance(item, dict):
                    item.pop('finding_id', None)
    return {'commands': {'dead_code': {'status': 'completed', 'data': data}}}


def by_symbol(findings, symbol):
    return next(item for item in findings if symbol in item['symbols'])


class FindingIdIdentityTests(unittest.TestCase):
    def setUp(self):
        self.state = new_state(Path('/unused'))
        self.scan = {'kind': 'scan', 'fallow': {'status': 'completed'}}

    def seed_legacy(self):
        legacy = extract_fallow_findings(dead_code(strip_ids=True))
        return {item['symbols'][0] if item['symbols'] else item['category']: issue_id(item) for item in legacy}, legacy

    def test_card_identity_is_the_stable_finding_id_and_ignores_line_moves(self):
        before = extract_fallow_findings(dead_code())
        moved = dead_code()
        for item in moved['commands']['dead_code']['data']['unused_exports']:
            item['line'] += 40
            item['col'] += 2
            item['span_start'] += 900
        after = extract_fallow_findings(moved)
        target = by_symbol(before, 'unusedExport')
        self.assertEqual('dc1:unused-export:9b605bb79c849a67', target['finding_id'])
        self.assertEqual(['fallow', 'unused_exports', 'finding-id', 'dc1:unused-export:9b605bb79c849a67'], target['fingerprint'])
        self.assertEqual([issue_id(item) for item in before], [issue_id(item) for item in after])

    def test_output_without_finding_ids_keeps_the_path_and_symbol_key(self):
        findings = extract_fallow_findings(dead_code(strip_ids=True))
        self.assertTrue(findings)
        self.assertTrue(all('finding_id' not in item and 'finding-id' not in item['fingerprint'] for item in findings))

    def test_malformed_finding_id_is_ignored_not_trusted(self):
        data = dead_code()
        data['commands']['dead_code']['data']['unused_exports'][0]['finding_id'] = 'not an id'
        self.assertNotIn('finding_id', by_symbol(extract_fallow_findings(data), 'unusedExport'))

    def test_every_status_migrates_losslessly_by_exact_match(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        issues = self.state['issues']
        defer_issue(self.state, ids['unusedExport'], 'public API; keep')
        issues[ids['unusedConst']]['status'] = 'resolved'
        issues[ids['unusedConst']]['history'].append({'event': 'resolved', 'run': 'proof'})
        saved = {key: copy.deepcopy(issues[value]) for key, value in ids.items()}
        merged = merge_findings(self.state, extract_fallow_findings(dead_code()), 'upgrade', scan_result=self.scan)
        self.assertEqual(0, merged['new'])
        for key, old_id in ids.items():
            new = next(i for i in merged['ids'] if issues[i]['title'] == saved[key]['title'])
            card = issues[new]
            self.assertEqual(old_id, card['identity_from'])
            self.assertEqual(saved[key]['first_seen'], card['first_seen'])
            self.assertEqual(saved[key]['history'], card['history'][:len(saved[key]['history'])])
            self.assertTrue(issues[old_id]['identity_migrated'])
        deferred = issues[next(i for i in merged['ids'] if 'unusedExport' in issues[i]['symbols'])]
        self.assertEqual('deferred', deferred['status'])
        reopened = issues[next(i for i in merged['ids'] if 'unusedConst' in issues[i]['symbols'])]
        self.assertEqual('reopened', reopened['status'])  # resolved cards reopen on sight, as before
        self.assertEqual('obsolete', issues[ids['unusedExport']]['status'])
        self.assertEqual('resolved', issues[ids['unusedConst']]['status'])

    def test_one_legacy_key_split_by_fallow_stays_explicitly_ambiguous(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        data = dead_code()
        twin = copy.deepcopy(data['commands']['dead_code']['data']['unused_exports'][0])
        twin['finding_id'] += '~1'
        data['commands']['dead_code']['data']['unused_exports'].append(twin)
        merged = merge_findings(self.state, extract_fallow_findings(data), 'upgrade', scan_result=self.scan)
        twins = [self.state['issues'][i] for i in merged['ids'] if 'unusedExport' in self.state['issues'][i]['symbols']]
        self.assertEqual(2, len(twins))
        self.assertEqual({'open'}, {card['status'] for card in twins})
        self.assertEqual({ids['unusedExport']}, {card['identity_from'] for card in twins})
        self.assertEqual('obsolete', self.state['issues'][ids['unusedExport']]['status'])

    def test_active_legacy_card_requires_release(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        begin_fix(self.state, ids['unusedExport'], 'old', 'base')
        with self.assertRaisesRegex(RuntimeError, 'release'):
            merge_findings(self.state, extract_fallow_findings(dead_code()), 'upgrade', scan_result=self.scan)

    def test_existing_finding_id_card_blocks_migration(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        merge_findings(self.state, extract_fallow_findings(dead_code()), 'first', scan_result=self.scan)
        issues_after_first = copy.deepcopy(self.state['issues'])
        merge_findings(self.state, extract_fallow_findings(dead_code()), 'second', scan_result=self.scan)
        self.assertEqual(set(issues_after_first), set(self.state['issues']))

    def twin_data(self):
        data = dead_code()
        twin = copy.deepcopy(data['commands']['dead_code']['data']['unused_exports'][0])
        twin['finding_id'] += '~1'
        data['commands']['dead_code']['data']['unused_exports'].append(twin)
        return data

    def test_an_existing_destination_does_not_hide_a_split_family(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        defer_issue(self.state, ids['unusedExport'], 'public API; keep')
        base = next(f for f in extract_fallow_findings(self.twin_data()) if f['finding_id'].endswith('a67'))
        self.state['issues'][issue_id(base)] = {**copy.deepcopy(self.state['issues'][ids['unusedExport']]),
                                                'id': issue_id(base), 'status': 'open', 'history': []}
        merged = merge_findings(self.state, extract_fallow_findings(self.twin_data()), 'upgrade', scan_result=self.scan)
        twin = next(self.state['issues'][i] for i in merged['ids'] if self.state['issues'][i].get('finding_id', '').endswith('~1'))
        self.assertEqual('open', twin['status'])
        self.assertFalse(any(e.get('event') == 'deferred' for e in twin['history']))
        self.assertEqual('deferred', self.state['issues'][ids['unusedExport']]['status'])

    def test_degraded_scan_creates_no_destination_and_the_next_one_still_migrates(self):
        ids, legacy = self.seed_legacy()
        merge_findings(self.state, legacy, 'old')
        defer_issue(self.state, ids['unusedExport'], 'public API; keep')
        cards = set(self.state['issues'])
        degraded = {'kind': 'scan', 'fallow': {'status': 'completed'},
                    'fallow_comparison': {'comparable': False, 'kind': 'type_aware_degraded'}}
        merged = merge_findings(self.state, extract_fallow_findings(dead_code()), 'degraded', scan_result=degraded)
        self.assertEqual(cards, set(self.state['issues']))
        self.assertTrue(set(ids.values()) <= set(merged['ids']))
        merged = merge_findings(self.state, extract_fallow_findings(dead_code()), 'complete', scan_result=self.scan)
        card = next(self.state['issues'][i] for i in merged['ids'] if 'unusedExport' in self.state['issues'][i]['symbols'])
        self.assertEqual(('deferred', ids['unusedExport']), (card['status'], card['identity_from']))

    def test_scan_stores_a_complete_function_listing_for_reported_names_only(self):
        fixtures = Path(__file__).parent / 'fixtures/fallow-3.31.0'
        health = json.loads((fixtures / 'health.json').read_text())
        listing = json.loads((fixtures / 'functions.json').read_text())
        calls = []
        def run(repo, directory, name, args, *rest, **options):
            calls.append((name, args))
            return {'status': 'completed', 'data': {'functions': listing, 'health': health}.get(name, {})}
        with patch('hangover.oracles._run_fallow', side_effect=run), patch('hangover.oracles.fallow_version', return_value='fallow 3.31.0'):
            result = run_fallow_scan(Path('/unused'), Path('/unused'), {'javascript': True})
        (functions_call,) = [args for name, args in calls if name == 'functions']
        self.assertEqual(['health', '--complexity', '--max-cyclomatic', '0', '--max-cognitive', '0', '--max-crap', '0'], functions_call)
        self.assertEqual({'complexOne', 'fna', 'fnb', 'fnc'}, {f['name'] for f in result['function_inventory']['functions']})
        self.assertNotIn('functions', result['commands'])


if __name__ == '__main__':
    unittest.main()
