"""Unit Tests - cross-file rule id conflicts and idempotent duplicates."""
from pathlib import Path

import libsast
from libsast import standards
from libsast.core_matcher.helpers import get_rules

import pytest


BASE_DIR = Path(__file__).parents[1]
FILES_DIR = BASE_DIR / 'assets' / 'files'
CONFLICT_DIR = BASE_DIR / 'assets' / 'rules_conflict'


def test_cross_file_conflict_rejected_before_scan():
    rules_dir = CONFLICT_DIR / 'malicious_override'
    options = {'match_rules': rules_dir.as_posix()}
    with pytest.raises(libsast.exceptions.DuplicateRuleIdError) as exc:
        libsast.Scanner(options, [FILES_DIR.as_posix()]).scan()
    message = str(exc.value)
    assert 'override_demo_rule' in message
    assert 'high_severity.yaml' in message
    assert 'low_severity.yaml' in message


def test_mapping_only_conflict_rejected(tmp_path):
    # A conflict limited to the standard mapping must be rejected too.
    first = tmp_path / 'first.yaml'
    second = tmp_path / 'sub' / 'second.yaml'
    second.parent.mkdir()
    first.write_text(
        '- id: map_conflict\n'
        '  type: Regex\n'
        '  pattern: boto3\n'
        '  message: same\n'
        '  severity: warning\n'
        '  metadata:\n'
        '    cwe: cwe-1051\n')
    second.write_text(
        '- id: map_conflict\n'
        '  type: Regex\n'
        '  pattern: boto3\n'
        '  message: same\n'
        '  severity: warning\n'
        '  metadata:\n'
        '    cwe: cwe-1004\n')
    with pytest.raises(libsast.exceptions.DuplicateRuleIdError) as exc:
        get_rules(tmp_path.as_posix())
    assert 'map_conflict' in str(exc.value)


def test_identical_duplicates_are_idempotent():
    rules_dir = CONFLICT_DIR / 'idempotent_dup'
    rules = get_rules(rules_dir.as_posix())
    rule_ids = [rule['id'] for rule in rules]
    assert rule_ids.count('duplicate_safe_rule') == 1
    assert rule_ids.count('duplicate_multi_matcher_rule') == 1

    options = {'match_rules': rules_dir.as_posix()}
    result = libsast.Scanner(options, [FILES_DIR.as_posix()]).scan()
    findings = result['pattern_matcher']
    # The high-severity metadata of the original rule is preserved.
    assert findings['duplicate_safe_rule']['metadata']['severity'] == 'error'
    # Multi-matcher (RegexAnd list pattern) still matches after dedup.
    assert findings['duplicate_multi_matcher_rule']['files']


def test_standard_mappings_still_expand_after_merge():
    rules_dir = CONFLICT_DIR / 'mapping_expand'
    options = {'match_rules': rules_dir.as_posix()}
    result = libsast.Scanner(options, [FILES_DIR.as_posix()]).scan()
    stds = standards.get_standards()
    metadata = result['pattern_matcher']['mapping_expand_rule']['metadata']
    assert metadata['cwe'] == stds['cwe']['cwe-1051']
    assert metadata['owasp-mobile'] == stds['owasp-mobile']['m1']
    assert metadata['masvs'] == stds['masvs']['storage-3']
    assert metadata['foo'] == 'bar'
