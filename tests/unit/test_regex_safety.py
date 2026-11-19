"""Unit Tests - regex resource boundaries for untrusted rules."""
import time
from pathlib import Path

import libsast
from libsast import exceptions
from libsast.core_matcher import matchers
from libsast.core_matcher.pattern_matcher import PatternMatcher

import pytest


ASSETS = Path(__file__).parents[1] / 'assets'
RULES_DIR = ASSETS / 'rules' / 'regex_safety'
SAMPLE_FILE = ASSETS / 'regex_safety' / 'sample.java'
EVIL_PATTERN = r'(a|aa)+$'


@pytest.fixture
def long_attack_input(tmp_path):
    """Long input that triggers catastrophic backtracking."""
    attack_file = tmp_path / 'attack.java'
    attack_file.write_text(
        'SENSITIVE_MARKER\n' + 'a' * 50000 + 'b', 'utf-8')
    return attack_file


def scan(rule_file, paths, **options):
    options['match_rules'] = str(RULES_DIR / rule_file)
    return libsast.Scanner(options, paths).scan()


def test_safe_complex_rules_preserved():
    """Legit complex rules keep working with consistent evidence."""
    result = scan('safe_patterns.yaml', [SAMPLE_FILE.as_posix()])
    findings = result['pattern_matcher']
    for rule_id in (
            'safe_complex_url',
            'safe_regex_and',
            'safe_regex_or',
            'safe_regex_and_not',
            'safe_regex_and_or'):
        assert findings[rule_id], rule_id

    url_files = findings['safe_complex_url']['files']
    assert url_files[0]['file_path'] == SAMPLE_FILE.as_posix()
    assert url_files[0]['match_string'] == (
        'https://api.example.com/v1/users')
    assert url_files[0]['match_lines'] == (3, 3)

    and_strings = {
        f['match_string'] for f in findings['safe_regex_and']['files']}
    assert and_strings == {'token = "abc123def456"', 'Authorization'}

    or_strings = {
        f['match_string'] for f in findings['safe_regex_or']['files']}
    assert or_strings == {'password = "hunter2"'}

    and_not = findings['safe_regex_and_not']['files']
    assert and_not[0]['match_string'] == 'BEGIN PRIVATE KEY'

    and_or_strings = {
        f['match_string'] for f in findings['safe_regex_and_or']['files']}
    assert and_or_strings == {'api.example.com', 'GET'}


def test_invalid_regex_rejected_at_load():
    """Rules with regex that does not compile fail closed at load."""
    options = {'match_rules': str(RULES_DIR / 'evil_invalid_regex.yaml')}
    matcher = PatternMatcher(options)
    with pytest.raises(exceptions.InvalidRegexError):
        matcher.validate_rules()
    with pytest.raises(exceptions.InvalidRegexError):
        scan('evil_invalid_regex.yaml', [SAMPLE_FILE.as_posix()])


def test_oversized_pattern_rejected():
    """Patterns beyond the length limit fail closed."""
    oversized = 'a' * (matchers.MAX_PATTERN_LENGTH + 1)
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_regex_pattern(oversized)
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_rule_patterns([oversized])
    # Boundary: exactly at the limit is accepted.
    matchers.validate_rule_patterns(['a' * matchers.MAX_PATTERN_LENGTH])


def test_too_many_patterns_rejected(monkeypatch):
    """Rules combining too many patterns fail closed."""
    monkeypatch.setattr(matchers, 'MAX_PATTERNS_PER_RULE', 2)
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_rule_patterns(['a', 'b', 'c'])
    matchers.validate_rule_patterns(['a', 'b'])


def test_non_string_pattern_rejected():
    """Non string patterns fail closed."""
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_regex_pattern(123)
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_rule_patterns(123)
    with pytest.raises(exceptions.InvalidRegexError):
        matchers.validate_rule_patterns([])


def test_runtime_timeout_fail_closed(monkeypatch):
    """A backtracking pattern times out instead of blocking."""
    monkeypatch.setattr(matchers, 'REGEX_TIMEOUT', 0.5)
    command = matchers.MatchCommand()
    content = 'a' * 50000 + 'b'
    start = time.monotonic()
    matches = command._find_match(
        'Regex', content, {'pattern': EVIL_PATTERN})
    elapsed = time.monotonic() - start
    assert matches == set()
    assert elapsed < 10


def test_combined_matchers_timeout_fail_closed(monkeypatch):
    """RegexAnd/Or/AndNot/AndOr fail closed on timing out patterns."""
    monkeypatch.setattr(matchers, 'REGEX_TIMEOUT', 0.5)
    command = matchers.MatchCommand()
    content = 'a' * 50000 + 'b'
    start = time.monotonic()
    assert command._find_match(
        'RegexAnd', content, {'pattern': [EVIL_PATTERN, 'x']}) == set()
    assert command._find_match(
        'RegexOr', content, {'pattern': [EVIL_PATTERN]}) == set()
    assert command._find_match(
        'RegexAndNot', content, {'pattern': ['a+', EVIL_PATTERN]}) == set()
    assert command._find_match(
        'RegexAndOr', content, {'pattern': ['a+', [EVIL_PATTERN]]}) == set()
    assert time.monotonic() - start < 30


def test_scan_completes_on_attack_input(long_attack_input, monkeypatch):
    """Untrusted rule on attack input cannot block the scan."""
    monkeypatch.setattr(matchers, 'REGEX_TIMEOUT', 0.5)
    start = time.monotonic()
    result = scan(
        'evil_runtime.yaml',
        [long_attack_input.as_posix()],
        multiprocessing='thread')
    elapsed = time.monotonic() - start
    assert elapsed < 30

    findings = result['pattern_matcher']
    # Evil rule fails closed: no findings, no evidence fabricated.
    assert 'evil_backtracking' not in findings
    # Legit rule on the same file still matches with intact evidence.
    companion = findings['safe_companion']['files']
    assert companion[0]['file_path'] == long_attack_input.as_posix()
    assert companion[0]['match_string'] == 'SENSITIVE_MARKER'
    assert companion[0]['match_position'] == (1, 16)
    assert companion[0]['match_lines'] == (1, 1)
