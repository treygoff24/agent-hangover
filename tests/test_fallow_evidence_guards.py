import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hangover.cli import _fallow_comparison, _verification_blockers, _resolve_side_effect_fallow_issues
from hangover.model import merge_findings, new_state
from hangover.oracles import extract_fallow_findings, run_fallow_scan


def degraded(path='unused.ts', kind='skipped-large-file'):
    return {'version': 'fallow 3.31.0', 'status': 'completed', 'commands': {'dead_code': {
        'status': 'completed', 'data': {'unused_files': [{'path': 'unused.ts',
        'reachability_caveats': ['incomplete-import-graph']}], 'workspace_diagnostics': [
        {'path': path, 'kind': kind}]}}}}


class EvidenceGuardTests(unittest.TestCase):
    def test_caveat_lookup_indexes_once_and_preserves_output_bytes(self):
        import json
        from unittest.mock import patch
        from hangover.fallow_evidence import degrading_diagnostics, _covers
        result = {'commands': {'dead_code': {'data': {
            'unused_exports': [{'path': path, 'name': 'unused'} for path in
                               ('src/a.ts', 'src/nested/b.ts', 'other.ts', 'src')],
            'workspace_diagnostics': [
                {'path': 'src/', 'kind': 'skipped-large-file'},
                {'path': 'src/nested', 'kind': 'custom-degraded', 'degrades_analysis': True},
                {'path': 'src/nested/b.ts', 'kind': 'source-read-failure'},
                {'path': 'src/', 'kind': 'skipped-large-file'},
                {'path': '.', 'kind': 'source-read-failure'},
                {'path': 'src-neighbor', 'kind': 'source-read-failure'}]}}}}
        def reference(run, files, *_):
            return [f"{item['kind']}: {item['path']} was not fully analyzed"
                    for item in degrading_diagnostics(run) if _covers(item['path'], files)]
        with patch('hangover.oracles.caveat_reasons', side_effect=reference):
            expected = json.dumps(extract_fallow_findings(result)).encode()
        self.assertEqual(4, len(json.loads(expected)))
        self.assertIn(b'custom-degraded', expected)
        with patch('hangover.fallow_evidence.degrading_diagnostics', wraps=degrading_diagnostics) as diagnostics:
            actual = json.dumps(extract_fallow_findings(result)).encode()
            self.assertEqual(expected, actual)
            self.assertEqual(1, diagnostics.call_count)

    def test_missing_findings_share_one_caveat_index(self):
        from hangover.fallow_evidence import degrading_diagnostics
        run = degraded()
        data = run['commands']['dead_code']['data']
        data['unused_files'] = [{'path': f'src/{index}.ts'} for index in range(20)]
        data['workspace_diagnostics'] = [{'path': 'src/', 'kind': 'source-read-failure'}]
        state = new_state(Path('/unused'))
        identifiers = merge_findings(state, extract_fallow_findings(run), 'before')['ids']
        self.assertEqual(20, len(identifiers))
        data['unused_files'] = []
        with patch('hangover.fallow_evidence.degrading_diagnostics', wraps=degrading_diagnostics) as diagnostics:
            merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': run})
            self.assertEqual(1, diagnostics.call_count)
        for identifier in identifiers:
            card = state['issues'][identifier]
            self.assertEqual('open', card['status'])
            self.assertEqual('source-read-failure: src/ was not fully analyzed', card['history'][-1]['reason'])

    def test_comparison_kinds_do_not_depend_on_reason_text(self):
        base = {'fallow': {'version': 'same', 'dead_code_mode': 'syntactic'}}
        cases = [(None, base, 'no_baseline'),
                 (base, {'fallow': {'version': 'different'}}, 'version_changed'),
                 (base, {'fallow': {'version': 'same', 'dead_code_mode': 'type-aware'}}, 'mode_changed'),
                 (base, {'fallow': {'version': 'same', 'summary': {'resolved_config_sha256': 'changed'}}}, 'config_changed')]
        for before, after, kind in cases:
            with self.subTest(kind=kind):
                self.assertEqual(kind, _fallow_comparison(before, after).get('kind'))
        state = new_state(Path('/unused'))
        merge_findings(state, extract_fallow_findings(degraded()), 'before')
        original = repr(state)
        merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': degraded(),
                       'fallow_comparison': {'comparable': False, 'kind': 'version_changed', 'reason': 'New wording'}})
        self.assertEqual(original, repr(state))

    def test_hold_preserves_status_and_deduplicates_last_reason(self):
        for status in ('open', 'reopened', 'stale'):
            for cause in ('caveat', 'comparison'):
                with self.subTest(status=status, cause=cause):
                    state = new_state(Path('/unused'))
                    identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
                    card = state['issues'][identifier]
                    card['status'] = status
                    history = list(card['history'])
                    snapshot = {'kind': 'scan', 'fallow': degraded() if cause == 'caveat' else degraded('other.ts')}
                    if cause == 'comparison':
                        snapshot['fallow_comparison'] = {'comparable': False, 'kind': 'mode_changed', 'reason': 'mode changed'}
                    for run in ('one', 'two'):
                        merge_findings(state, [], run, scan_result=snapshot,
                                       obsolete_fallow_rules={'unused_files': 'unused-file'})
                    self.assertEqual(status, card['status'])
                    self.assertEqual(len(history) + (status != 'stale'), len(card['history']))
                    if status != 'stale':
                        self.assertEqual('unverifiable', card['history'][-1]['event'])
                        snapshot['fallow'] = degraded('unused.ts', 'source-read-failure')
                        merge_findings(state, [], 'new-reason', scan_result=snapshot)
                        self.assertEqual(len(history) + 2, len(card['history']))

    def test_caveated_finding_names_only_own_file_diagnostics(self):
        run = degraded()
        run['commands']['dead_code']['data']['workspace_diagnostics'].append(
            {'path': 'index.ts', 'kind': 'source-parse-degraded'})
        item = extract_fallow_findings(run)[0]
        self.assertEqual('low', item['confidence'])
        self.assertTrue(any('skipped-large-file' in e and 'unused.ts' in e for e in item['evidence']))
        self.assertFalse(any('index.ts' in e for e in item['evidence']))
        self.assertTrue(any('incomplete-import-graph' in e for e in item['evidence']))

    def test_missing_finding_under_caveat_stays_open(self):
        state = new_state(Path('/unused'))
        identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
        run = degraded()
        run['commands']['dead_code']['data']['unused_files'] = []
        merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': run})
        card = state['issues'][identifier]
        self.assertEqual('open', card['status'])
        self.assertEqual('unverifiable', card['history'][-1]['event'])
        self.assertIn('unused.ts', card['history'][-1]['reason'])

    def test_touched_unread_file_blocks_verification(self):
        snapshot = {'fallow': degraded('index.ts', 'source-parse-degraded'), 'fallow_comparison': {'comparable': True},
                    'changed_files': ['index.ts']}
        blockers = _verification_blockers(snapshot, {'id': 'x', 'source': 'fallow', 'files': ['unused.ts']}, [])
        self.assertTrue(any('source-parse-degraded' in b and 'index.ts' in b for b in blockers))

    def test_caveated_collateral_cannot_resolve(self):
        state = new_state(Path('/unused'))
        identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
        _resolve_side_effect_fallow_issues(state, 'primary', [identifier], 'verify', fallow=degraded())
        self.assertEqual('open', state['issues'][identifier]['status'])
        _resolve_side_effect_fallow_issues(state, 'primary', [identifier], 'verify', fallow=degraded('other.ts'))
        self.assertEqual('resolved', state['issues'][identifier]['status'])

    def test_unrelated_unread_file_does_not_hold_absent_finding(self):
        state = new_state(Path('/unused'))
        identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
        merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': degraded('other.ts')})
        self.assertEqual('stale', state['issues'][identifier]['status'])
        snapshot = {'fallow': degraded('other.ts'), 'fallow_comparison': {'comparable': True}}
        self.assertEqual([], _verification_blockers(snapshot, state['issues'][identifier], []))

    def test_unknown_kind_marked_degrading_holds_its_file(self):
        # Fallow 3.27+ marks degrading diagnostics; a kind hangover has never seen still counts.
        run = degraded('unused.ts', 'future-degrading-kind')
        run['commands']['dead_code']['data']['workspace_diagnostics'][0]['degrades_analysis'] = True
        item = extract_fallow_findings(run)[0]
        self.assertEqual('low', item['confidence'])
        self.assertTrue(any('future-degrading-kind' in e for e in item['evidence']))
        quiet = degraded('unused.ts', 'boundaries-not-configured')
        self.assertFalse(any('boundaries-not-configured' in e for e in extract_fallow_findings(quiet)[0]['evidence']))

    def test_empty_analysis_is_incomparable_and_holds_the_ledger(self):
        before = {'fallow': {'version': 'fallow 3.31.0', 'dead_code_mode': 'syntactic'}}
        run = degraded('.', 'no-source-files-analyzed')
        run['commands']['dead_code']['data']['unused_files'] = []
        current = {'fallow': {**run, 'dead_code_mode': 'syntactic'}}
        comparison = _fallow_comparison(before, current)
        self.assertFalse(comparison['comparable'])
        self.assertEqual('empty_analysis', comparison['kind'])
        state = new_state(Path('/unused'))
        identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
        merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': run,
                       'fallow_comparison': comparison})
        self.assertEqual('open', state['issues'][identifier]['status'])

    def partial_run(self, decision='retained-abstained', decisions=True):
        semantic = {'query_id': 0, 'decision': decision, 'status': 'partial', 'reason_code': 'dynamic-behavior',
                    'explanation': 'mount is retained because dynamic runtime behavior makes deletion unsafe.'}
        meta = {'identity': {'mode': 'type-aware', 'completeness': 'partial'}, 'warning_count': 0, 'warnings': [],
                'queries': [{'query_id': 0, 'status': 'partial'}, {'query_id': 1, 'status': 'complete'}]}
        if decisions:
            meta['candidate_decisions'] = [semantic, {'query_id': 1, 'decision': 'confirmed-used', 'status': 'complete'}]
        data = {'_meta': {'type_aware': meta},
                'unused_exports': [{'path': 'piece.js', 'export_name': 'mount', 'line': 4, 'semantic': semantic}]}
        return {'version': 'fallow 3.31.0', 'dead_code_mode': 'type-aware',
                'commands': {'dead_code': {'status': 'completed', 'data': data}}}

    def test_partial_type_aware_run_that_only_retained_candidates_stays_comparable(self):
        before = {'fallow': {'version': 'fallow 3.31.0', 'dead_code_mode': 'type-aware'}}
        self.assertTrue(_fallow_comparison(before, {'fallow': self.partial_run()})['comparable'])
        bare = self.partial_run(decisions=False)
        del bare['commands']['dead_code']['data']['_meta']['type_aware']['queries']
        no_queries = self.partial_run()
        no_queries['commands']['dead_code']['data']['_meta']['type_aware']['queries'] = []
        uncovered = self.partial_run()
        uncovered['commands']['dead_code']['data']['_meta']['type_aware']['queries'].append(
            {'query_id': 7, 'status': 'partial'})
        for run in (self.partial_run('confirmed-used'), self.partial_run(decisions=False), bare,
                    no_queries, uncovered):
            with self.subTest(run=run['commands']['dead_code']['data']['_meta']['type_aware'].get('candidate_decisions')):
                result = _fallow_comparison(before, {'fallow': run})
                self.assertEqual('type_aware_degraded', result.get('kind'))

    def test_partial_run_needs_settled_api_surface_evidence(self):
        before = {'fallow': {'version': 'fallow 3.31.0', 'dead_code_mode': 'type-aware'}}
        run = self.partial_run()
        run['commands']['dead_code']['data']['_meta']['type_aware']['identity']['capabilities'] = ['symbol-use', 'api-surface']
        self.assertEqual('type_aware_degraded', _fallow_comparison(before, {'fallow': run}).get('kind'))
        run['commands']['config'] = {'data': {'rules': {'private-type-leaks': 'off'}}}
        self.assertTrue(_fallow_comparison(before, {'fallow': run})['comparable'])
        with tempfile.TemporaryDirectory() as folder:
            raw = Path(folder) / 'config.json'
            raw.write_text('{"rules": {"private-type-leaks": "off"}}')
            run['commands']['config'] = {'raw': str(raw)}
            self.assertTrue(_fallow_comparison(before, {'fallow': run})['comparable'])
        run['commands']['config'] = {'data': {'rules': {'private-type-leaks': 'error'}}}
        run['commands']['dead_code']['data']['_meta']['type_aware']['api_surface'] = {'status': 'complete'}
        self.assertTrue(_fallow_comparison(before, {'fallow': run})['comparable'])
        run['commands']['dead_code']['data']['_meta']['type_aware']['identity']['capabilities'].append('future-capability')
        self.assertEqual('type_aware_degraded', _fallow_comparison(before, {'fallow': run}).get('kind'))

    def test_folder_diagnostic_holds_cards_beneath_it_but_root_does_not(self):
        held = degraded('.', 'undeclared-workspace')
        held['commands']['dead_code']['data']['workspace_diagnostics'][0].update(path='packages/app', degrades_analysis=True)
        held['commands']['dead_code']['data']['unused_files'] = [{'path': 'packages/app/unused.ts'}]
        self.assertTrue(any('undeclared-workspace' in e for e in extract_fallow_findings(held)[0]['evidence']))
        sibling = degraded('packages/application', 'undeclared-workspace')
        sibling['commands']['dead_code']['data']['workspace_diagnostics'][0]['degrades_analysis'] = True
        sibling['commands']['dead_code']['data']['unused_files'] = [{'path': 'packages/app/unused.ts'}]
        self.assertFalse(any('undeclared-workspace' in e for e in extract_fallow_findings(sibling)[0]['evidence']))
        root = degraded('.', 'malformed-tsconfig')
        root['commands']['dead_code']['data']['workspace_diagnostics'][0]['degrades_analysis'] = True
        root['commands']['dead_code']['data']['unused_files'] = [{'path': 'unused.ts'}]
        self.assertFalse(any('malformed-tsconfig' in e for e in extract_fallow_findings(root)[0]['evidence']))

    def test_abstained_candidate_is_low_confidence_with_the_reason(self):
        item = extract_fallow_findings(self.partial_run())[0]
        self.assertEqual('low', item['confidence'])
        self.assertTrue(any('dynamic-behavior' in e and 'mount is retained' in e for e in item['evidence']))

    def test_type_aware_warning_is_incomparable_even_with_mode_marker(self):
        before = {'fallow': {'version': 'fallow 3.31.0', 'dead_code_mode': 'type-aware'}}
        current = {'fallow': {'version': 'fallow 3.31.0', 'dead_code_mode': 'type-aware',
                    'commands': {'dead_code': {'data': {'_meta': {'type_aware': {
                        'identity': {'mode': 'type-aware', 'completeness': 'partial'},
                        'warnings': ['semantic sidecar timed out; using syntactic findings'], 'warning_count': 1}}}}}}}
        result = _fallow_comparison(before, current)
        self.assertFalse(result['comparable'])
        self.assertEqual('type_aware_degraded', result.get('kind'))
        self.assertIn('timed out', result['reason'])

    def test_incomparable_scan_cannot_stale_or_obsolete(self):
        state = new_state(Path('/unused'))
        identifier = merge_findings(state, extract_fallow_findings(degraded()), 'before')['ids'][0]
        merge_findings(state, [], 'after', scan_result={'kind': 'scan', 'fallow': degraded(),
            'fallow_comparison': {'comparable': False, 'kind': 'mode_changed', 'reason': 'dead-code analysis mode changed'}},
            obsolete_fallow_rules={'unused_files': 'unused-file'})
        self.assertEqual('open', state['issues'][identifier]['status'])

    def test_nonreproducible_clock_suppresses_hotspot_priority_and_names_reason(self):
        health = {'hotspot_summary': {'clock': {'source': 'wall_clock', 'epoch_secs': 123, 'reproducible': False}},
            'hotspots': [{'path': 'a.ts', 'score': 90, 'commits': 10, 'trend': 'heating'}],
            'vital_signs': {'hotspot_top_pct_count': 1},
            'findings': [{'path': 'a.ts', 'name': 'a', 'cyclomatic': 30, 'cognitive': 25,
                          'severity': 'high', 'exceeded': 'both'}]}
        item = extract_fallow_findings({'commands': {'health': {'data': health}}})[0]
        self.assertEqual('P2', item['priority'])
        self.assertTrue(any('not reproducible' in e for e in item['evidence']))


if __name__ == '__main__':
    unittest.main()
