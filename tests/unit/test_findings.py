# -*- coding: utf-8 -*-
"""Unit tests for stable finding identity and evidence merging."""
from pathlib import Path

import libsast
from libsast.findings import (
    FindingStore,
    make_evidence_id,
    make_finding_id,
    normalize_severity,
    rulepack_name,
    severity_rank,
)


BASE_DIR = Path(__file__).parents[1]
RULES_DIR = BASE_DIR / 'assets' / 'rules' / 'duplicate_packs'
SAMPLE = BASE_DIR / 'assets' / 'files' / 'duplicate_sample.test'


def _scan():
    options = {
        'match_rules': RULES_DIR.as_posix(),
        'match_extensions': ['.test'],
        'multiprocessing': 'thread',
    }
    return libsast.Scanner(options, [SAMPLE.as_posix()]).scan()


def test_finding_id_is_stable_and_order_independent():
    first = make_finding_id('shared_vuln')
    second = make_finding_id('shared_vuln')
    assert first == second
    assert first.startswith('LS-')
    # Different rule ids must never collide.
    assert make_finding_id('a') != make_finding_id('b')


def test_evidence_id_is_stable_across_rescans():
    evidence_id = make_evidence_id(
        'shared_vuln', 'sample.test', (1, 1), (0, 10), 'DANGEROUS')
    assert evidence_id.startswith('LE-')
    assert evidence_id == make_evidence_id(
        'shared_vuln', 'sample.test', (1, 1), (0, 10), 'DANGEROUS')


def test_duplicate_rule_ids_merge_into_one_finding():
    result = _scan()['pattern_matcher']
    # Two rulepacks define shared_vuln; the result stays a single finding.
    assert list(result).count('shared_vuln') == 1
    finding = result['shared_vuln']
    assert finding['rule_id'] == 'shared_vuln'
    assert finding['finding_id'] == make_finding_id('shared_vuln')
    # Both rulepacks are attributed on the finding and its evidence.
    assert finding['rulepacks'] == ['pack_alpha', 'pack_beta']
    assert finding['matchers'] == ['Regex']


def test_merged_evidence_dedupes_locations_and_keeps_provenance():
    finding = _scan()['pattern_matcher']['shared_vuln']
    # Two distinct match locations in the sample file.
    assert len(finding['files']) == 2
    assert len(finding['evidence']) == 2
    lines = sorted(
        evidence['match_lines'] for evidence in finding['evidence'])
    assert lines == [(1, 1), (2, 3)]
    for evidence in finding['evidence']:
        assert evidence['rulepacks'] == ['pack_alpha', 'pack_beta']
        packs = {item['rulepack'] for item in evidence['provenance']}
        assert packs == {'pack_alpha', 'pack_beta'}
        assert all(
            item['matcher_engine'] == 'pattern_matcher'
            for item in evidence['provenance'])


def test_severity_is_deterministic_highest_wins():
    # alpha says warning, beta says error: error must win regardless of
    # the (non-deterministic) file/rule processing order.
    finding = _scan()['pattern_matcher']['shared_vuln']
    assert finding['metadata']['severity'] == 'error'


def test_rescan_produces_identical_identity_and_evidence():
    first = _scan()['pattern_matcher']
    second = _scan()['pattern_matcher']
    for rule_id in first:
        assert first[rule_id]['finding_id'] == second[rule_id]['finding_id']
        assert (
            [ev['evidence_id'] for ev in first[rule_id]['evidence']]
            == [ev['evidence_id'] for ev in second[rule_id]['evidence']]
        )


def test_severity_helpers():
    assert normalize_severity('ERROR') == 'error'
    assert severity_rank('error') < severity_rank('warning')
    assert severity_rank('warning') < severity_rank('info')
    assert rulepack_name('/rules/pack_alpha.yaml') == 'pack_alpha'
    assert rulepack_name('/rules/some_dir') == 'some_dir'
    assert rulepack_name(
        'https://example.com/rules.yaml').endswith('rules.yaml')


def test_store_merges_same_location_from_two_rulepacks():
    store = FindingStore('pattern_matcher')
    rule_a = {
        'id': 'rid',
        'type': 'Regex',
        'severity': 'info',
        'message': 'a',
        '_rulepack': 'pack_a',
    }
    rule_b = {
        'id': 'rid',
        'type': 'Regex',
        'severity': 'high',
        'message': 'b',
        '_rulepack': 'pack_b',
    }
    match = ('DANGEROUS_API(', (0, 15), (1, 1))
    store.add_evidence(rule_a, match, file_path='f.test')
    store.add_evidence(rule_b, match, file_path='f.test')
    findings = store.finalize()
    entry = findings['rid']
    # Same location merged into one evidence entry with both provenances.
    assert len(entry['evidence']) == 1
    assert entry['evidence'][0]['rulepacks'] == ['pack_a', 'pack_b']
    assert len(entry['files']) == 1
    assert entry['metadata']['severity'] == 'high'
    assert entry['rulepacks'] == ['pack_a', 'pack_b']


def test_choice_findings_carry_locations_and_provenance():
    from tests.unit.setup_test import scanner

    result = scanner({}).scan()['choice_matcher']
    entry = result['rule1']
    assert entry['finding_id'].startswith('LS-')
    assert entry['rulepacks'] == ['choice']
    assert entry['matchers'] == ['code']
    assert entry['evidence']
    for evidence in entry['evidence']:
        assert evidence['evidence_id'].startswith('LE-')
        assert evidence['provenance'][0]['matcher_engine'] == (
            'choice_matcher')
    # Choice-specific metadata remains available and has no private keys.
    assert entry['metadata']['choice']
    assert all(not key.startswith('_') for key in entry['metadata'])


def test_semgrep_findings_are_merged_with_stable_identity(monkeypatch):
    import libsast.core_sgrep.semantic_sgrep as sgrep_module
    from libsast.core_sgrep.semantic_sgrep import SemanticGrep

    def fake_invoke(paths, rules):
        return {
            'results': [
                {
                    'path': 'app.py',
                    'start': {'line': 4, 'col': 24},
                    'end': {'line': 4, 'col': 31},
                    'check_id': 'boto-client-ip',
                    'extra': {
                        'message': 'boto client using IP address',
                        'severity': 'ERROR',
                        'metadata': {'cwe': 'cwe-1050'},
                        'lines': "c = boto3.client(host='8.8.8.8')",
                    },
                },
                {
                    'path': 'other.py',
                    'start': {'line': 9, 'col': 1},
                    'end': {'line': 9, 'col': 8},
                    'check_id': 'boto-client-ip',
                    'extra': {
                        'message': 'boto client using IP address',
                        'severity': 'WARNING',
                        'metadata': {},
                        'lines': 'dangerous()',
                    },
                },
            ],
            'errors': [],
        }

    monkeypatch.setattr(sgrep_module, 'invoke_semgrep', fake_invoke)
    scanner = SemanticGrep({
        'sgrep_rules': (
            BASE_DIR / 'assets' / 'rules' / 'semantic_grep').as_posix(),
    })
    report = scanner.scan([Path('app.py'), Path('other.py')])
    match = report['matches']['boto-client-ip']
    assert match['finding_id'] == make_finding_id('boto-client-ip')
    # Two locations stay distinct and both carry stable evidence ids.
    assert len(match['evidence']) == 2
    assert all(
        evidence['evidence_id'].startswith('LE-')
        for evidence in match['evidence'])
    # Highest severity wins deterministically.
    assert match['metadata']['severity'] == 'error'
    assert match['metadata']['cwe']
