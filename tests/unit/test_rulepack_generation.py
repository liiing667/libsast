"""Rulepack immutability, refresh recovery and report provenance."""
import hashlib
import json

import libsast
from libsast import rulepack
from libsast.core_matcher.pattern_matcher import PatternMatcher


def _write_rule(path, rule_id, pattern):
    text = (
        f'- id: {rule_id}\n'
        f'  message: rule {rule_id}\n'
        f'  pattern: {pattern}\n'
        '  severity: info\n'
        '  type: Regex\n'
        '  input_case: exact\n'
    )
    path.write_text(text)
    return text


def _scan(rule_path, files_dir, **extra):
    options = {
        'match_rules': rule_path.as_posix(),
        'multiprocessing': 'thread',
        **extra,
    }
    return libsast.Scanner(options, [files_dir.as_posix()]).scan()


def test_admission_freezes_source_version_and_identity(tmp_path):
    rulepack.reset_rulepack_store()
    rules = tmp_path / 'rules'
    rules.mkdir()
    _write_rule(rules / 'rule.yaml', 'frozen_rule', 'ALPHA')
    files = tmp_path / 'files'
    files.mkdir()
    (files / 'a.test').write_text('ALPHA\n')

    result = _scan(rules, files)

    finding = result['pattern_matcher']['frozen_rule']
    assert finding['files']
    assert finding['metadata']['description']
    info = result['rulepack']
    assert info['source'] == rules.as_posix()
    assert info['version']
    assert info['identity']
    assert info['generation']
    assert info['rule_ids'] == ['frozen_rule']
    assert finding['rule_id'] == 'frozen_rule'
    assert finding['rule_source'] == rules.as_posix()
    assert finding['rule_version'] == info['version']
    assert finding['rulepack_id'] == info['identity']


def test_hot_update_during_scan_does_not_mix_rule_versions(
        tmp_path, monkeypatch):
    rulepack.reset_rulepack_store()
    rules = tmp_path / 'rules'
    rules.mkdir()
    rule_file = rules / 'rule.yaml'
    _write_rule(rule_file, 'before_admission', 'ALPHA')
    files = tmp_path / 'files'
    files.mkdir()
    (files / 'a.test').write_text('ALPHA\nBETA\n')

    original_scan = PatternMatcher.scan

    def scan_after_update(self, paths):
        # The scanner has already admitted the rulepack before constructing
        # the matcher; this rewrite must not affect the in-flight scan.
        _write_rule(rule_file, 'after_admission', 'BETA')
        return original_scan(self, paths)

    monkeypatch.setattr(PatternMatcher, 'scan', scan_after_update)
    result = _scan(rules, files)

    assert 'before_admission' in result['pattern_matcher']
    assert 'after_admission' not in result['pattern_matcher']
    assert result['rule_metadata']['before_admission']['generation'] == (
        result['generation'])


def test_failed_refresh_keeps_previous_complete_generation(tmp_path):
    rulepack.reset_rulepack_store()
    rules = tmp_path / 'rules'
    rules.mkdir()
    rule_file = rules / 'rule.yaml'
    _write_rule(rule_file, 'stable_rule', 'ALPHA')
    files = tmp_path / 'files'
    files.mkdir()
    (files / 'a.test').write_text('ALPHA\nBETA\n')

    first = _scan(rules, files)
    old_version = first['rulepack']['version']
    old_generation = first['generation']

    # A failed refresh leaves a malformed candidate.  The complete previous
    # snapshot must remain visible, with its original identity.
    rule_file.write_text('- id: [broken\n')
    second = _scan(rules, files)

    assert 'stable_rule' in second['pattern_matcher']
    assert second['rulepack']['version'] == old_version
    assert second['generation'] == old_generation

    # A complete valid refresh is admitted as one new generation.
    _write_rule(rule_file, 'refreshed_rule', 'BETA')
    third = _scan(rules, files)
    assert 'refreshed_rule' in third['pattern_matcher']
    assert 'stable_rule' not in third['pattern_matcher']
    assert third['rulepack']['version'] != old_version
    assert third['generation'] != old_generation


def test_explicit_matcher_override_wins_over_rulepack_base(tmp_path):
    rulepack.reset_rulepack_store()
    base = tmp_path / 'pack'
    pattern_dir = base / 'pattern_matcher'
    pattern_dir.mkdir(parents=True)
    _write_rule(pattern_dir / 'base.yaml', 'base_rule', 'ALPHA')

    custom = tmp_path / 'custom.yaml'
    _write_rule(custom, 'custom_rule', 'BETA')
    files = tmp_path / 'files'
    files.mkdir()
    (files / 'a.test').write_text('ALPHA\nBETA\n')

    result = libsast.Scanner({
        'rulepack': base.as_posix(),
        'match_rules': custom.as_posix(),
        'multiprocessing': 'thread',
    }, [files.as_posix()]).scan()

    assert list(result['pattern_matcher']) == ['custom_rule']
    assert result['rulepack']['source'] == custom.as_posix()


def test_report_keeps_legacy_fields_and_is_json_serializable(tmp_path):
    rulepack.reset_rulepack_store()
    rules = tmp_path / 'rules'
    rules.mkdir()
    rule_file = rules / 'rule.yaml'
    text = _write_rule(rule_file, 'legacy_rule', 'ALPHA')
    digest = hashlib.sha256(text.encode()).hexdigest()
    (rules / 'rulepack.yaml').write_text(
        'version: rules-v1\n'
        'files:\n'
        f'  rule.yaml: {digest}\n')
    files = tmp_path / 'files'
    files.mkdir()
    (files / 'a.test').write_text('ALPHA\n')

    result = _scan(rules, files)

    assert result['rulepack']['version'] == 'rules-v1'
    finding = result['pattern_matcher']['legacy_rule']
    assert finding['files']
    assert finding['metadata']['severity'] == 'info'
    assert finding['rulepack']['rule_id'] == 'legacy_rule'
    assert result['rule_metadata']['legacy_rule']['version'] == 'rules-v1'
    encoded = json.dumps(result)
    assert 'legacy_rule' in encoded
