# -*- coding: utf_8 -*-
"""Unit tests for scan cancellation, atomic publication and retries."""
from pathlib import Path

import pytest

import libsast
from libsast.common import CancellationToken
from libsast.exceptions import ScanCancelledError

ASSETS = Path(__file__).parents[1] / 'assets'
FILES_DIR = ASSETS / 'files'
RULES_DIR = ASSETS / 'rules' / 'pattern_matcher'
CHOICE_DIR = ASSETS / 'rules' / 'choice_matcher'


def _options(token=None, **extra):
    options = {
        'match_rules': RULES_DIR.as_posix(),
        'choice_rules': CHOICE_DIR.as_posix(),
        'choice_extensions': {'.python'},
        'alternative_path': (FILES_DIR / 'alternate.python').as_posix(),
        'multiprocessing': 'thread',
    }
    if token is not None:
        options['cancel_token'] = token
    options.update(extra)
    return options


def _finding_counts(result):
    return {
        rule_id: len(details['files'])
        for rule_id, details in result['pattern_matcher'].items()
    }


def test_retry_does_not_count_files_twice():
    scanner = libsast.Scanner(_options(), [FILES_DIR.as_posix()])
    first = scanner.scan()
    second = scanner.scan()
    assert _finding_counts(first) == _finding_counts(second)
    # Retrying must not append the previous attempt's findings again.
    for rule_id, details in first['pattern_matcher'].items():
        first_entries = details['files']
        second_entries = second['pattern_matcher'][rule_id]['files']
        assert len(second_entries) == len(first_entries)
        assert second_entries == first_entries


def test_reused_matcher_retry_does_not_duplicate_findings():
    """Re-running a matcher instance used to append to its old findings."""
    matcher = libsast.PatternMatcher(
        _options(multiprocessing='thread'))
    target = FILES_DIR / 'test_matcher.test'
    file_contents = matcher.read_file_contents([target])
    matcher.regex_scan(file_contents)
    first = {
        rule_id: len(details['files'])
        for rule_id, details in matcher.findings.items()}

    matcher.regex_scan(file_contents)
    second = {
        rule_id: len(details['files'])
        for rule_id, details in matcher.findings.items()}
    assert first == second


def test_cancelled_scan_raises_and_publishes_nothing():
    token = CancellationToken()
    token.cancel()
    scanner = libsast.Scanner(
        _options(token), [FILES_DIR.as_posix()])
    with pytest.raises(ScanCancelledError):
        scanner.scan()
    # No partial findings are left behind on freshly built matcher instances.
    assert scanner.options['cancel_token'] is token
    assert libsast.PatternMatcher(scanner.options).findings == {}
    assert libsast.ChoiceMatcher(scanner.options).findings == {}


def test_scanner_cancel_matches_token_cancel():
    scanner = libsast.Scanner(_options(), [FILES_DIR.as_posix()])
    assert isinstance(scanner.cancel_token, CancellationToken)
    scanner.cancel()
    assert scanner.cancel_token.cancelled is True
    with pytest.raises(ScanCancelledError):
        scanner.scan()


def test_retry_after_cancellation_returns_complete_results():
    token = CancellationToken()
    token.cancel()
    cancelled = libsast.Scanner(
        _options(token), [FILES_DIR.as_posix()])
    with pytest.raises(ScanCancelledError):
        cancelled.scan()

    # A fresh scan over the same paths yields the full, clean report.
    retry = libsast.Scanner(_options(), [FILES_DIR.as_posix()])
    result = retry.scan()
    assert result['pattern_matcher']['test_regex']
    assert result['choice_matcher']['rule1']
    counts = _finding_counts(result)
    again = retry.scan()
    assert _finding_counts(again) == counts


def test_cancelled_choice_scan_keeps_empty_findings():
    token = CancellationToken()
    token.cancel()
    matcher = libsast.ChoiceMatcher(_options(token))
    with pytest.raises(ScanCancelledError):
        matcher.scan([FILES_DIR])
    assert matcher.findings == {}


def test_cancellation_during_processing_publishes_no_partial_batch(
        monkeypatch):
    """Cancelling after some files are processed still hides partial data."""
    token = CancellationToken()
    matcher = libsast.PatternMatcher(
        _options(token, multiprocessing='thread'))
    original = matcher.pattern_matcher
    calls = 0

    def cancelling_worker(file_data):
        nonlocal calls
        calls += 1
        if calls == 1:
            token.cancel()
        return original(file_data)

    monkeypatch.setattr(matcher, 'pattern_matcher', cancelling_worker)
    paths = sorted(
        libsast.Scanner(
            _options(), [FILES_DIR.as_posix()]).get_scan_files(),
        key=lambda p: p.as_posix())
    file_contents = matcher.read_file_contents(paths)

    with pytest.raises(ScanCancelledError):
        matcher.regex_scan(file_contents)
    assert matcher.findings == {}


def test_all_matchers_share_the_same_file_snapshot():
    scanner = libsast.Scanner(_options(), [FILES_DIR.as_posix()])
    snapshot = scanner.get_scan_files()
    expected = sorted(p.as_posix() for p in snapshot)
    seen = {}

    original = libsast.PatternMatcher.scan

    def spy_scan(self, paths):
        seen[type(self).__name__] = [p.as_posix() for p in paths]
        return original(self, paths)

    libsast.PatternMatcher.scan = spy_scan
    try:
        scanner.scan()
    finally:
        libsast.PatternMatcher.scan = original
    assert seen['PatternMatcher'] == expected


def test_token_is_picklable_for_process_workers():
    import pickle

    token = CancellationToken()
    restored = pickle.loads(pickle.dumps(token))
    assert restored.cancelled is False
    token.cancel()
    cancelled = pickle.loads(pickle.dumps(token))
    assert cancelled.cancelled is True
    with pytest.raises(ScanCancelledError):
        cancelled.raise_if_cancelled()
