# -*- coding: utf_8 -*-
"""Unit tests for Semgrep argv batching (MobSF/mobsfscan#98)."""
import errno
import os
import stat
import textwrap
from pathlib import Path

from libsast.core_sgrep.semantic_sgrep import SemanticGrep
from libsast.core_sgrep.helpers import (
    BatchReport,
    _invoke_semgrep_batched,
    batch_paths,
    merge_semgrep_reports,
)
from libsast.exceptions import SemgrepError

BASE_COMMAND = [
    'semgrep', 'scan', '--metrics=off', '--disable-version-check',
    '--quiet', '--no-rewrite-rule-ids', '--json', '--config', 'r', '--',
]


def make_finding(check_id, path, line=1, col=1, end_line=1, end_col=5):
    return {
        'check_id': check_id,
        'path': path,
        'start': {'line': line, 'col': col},
        'end': {'line': end_line, 'col': end_col},
        'extra': {'metadata': {}, 'message': 'm', 'severity': 'INFO'},
    }


def test_batch_paths_respects_byte_budget():
    base = ['semgrep', 'scan', '--json', '--config', 'rules.yaml']
    paths = [f'/tmp/project/file_{i}.java' for i in range(50)]
    batches = batch_paths(base, paths, max_bytes=400)
    assert len(batches) > 1
    assert sum(len(batch) for batch in batches) == len(paths)
    for batch in batches:
        size = sum(len(p) + 1 for p in base + batch)
        # First path in a batch may exceed alone; later ones must fit budget
        # when batch has multiple entries.
        if len(batch) > 1:
            assert size <= 400


def test_batch_paths_empty():
    assert batch_paths(['semgrep'], [], max_bytes=100) == [[]]


def test_merge_semgrep_reports():
    find_a = make_finding('a', 'f1.java')
    find_b = make_finding('b', 'f2.java')
    merged = merge_semgrep_reports(
        [
            BatchReport(['f1.java'], {'results': [find_a], 'errors': ['e1']},
                        None),
            BatchReport(['f2.java'], {'results': [find_b], 'errors': []},
                        None),
            BatchReport(['f3.java'], None, 'boom'),
            BatchReport(['f4.java'], {'results': [], 'errors': 'e2'}, None),
        ],
        requested_paths=['f1.java', 'f2.java', 'f3.java', 'f4.java'])
    assert [r['check_id'] for r in merged['results']] == ['a', 'b']
    assert merged['errors'] == ['e1', 'boom', 'e2']
    assert merged['complete'] is False
    assert merged['scanned_paths'] == ['f1.java', 'f2.java', 'f4.java']
    assert merged['missing_paths'] == ['f3.java']


def test_merge_dedupes_findings_and_errors():
    dup = make_finding('a', 'shared.java')
    merged = merge_semgrep_reports(
        [
            BatchReport(['f1.java'], {'results': [dup], 'errors': ['e']},
                        None),
            # Overlapping batch reports the same finding and error again.
            BatchReport(['f1.java'], {'results': [dict(dup)], 'errors': ['e']},
                        None),
        ],
        requested_paths=['f1.java'])
    assert merged['results'] == [dup]
    assert merged['errors'] == ['e']
    assert merged['complete'] is True


def test_merge_distinct_positions_are_not_deduped():
    first = make_finding('a', 'f1.java', line=1)
    second = make_finding('a', 'f1.java', line=9)
    merged = merge_semgrep_reports(
        [BatchReport(['f1.java'], {'results': [first, second], 'errors': []},
                     None)],
        requested_paths=['f1.java'])
    assert merged['results'] == [first, second]
    assert merged['complete'] is True


def test_invoke_single_batch_complete(monkeypatch):
    def fake_run(command):
        paths = command[len(BASE_COMMAND):]
        return {
            'results': [make_finding('r', p) for p in paths],
            'errors': [],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)
    report = _invoke_semgrep_batched(
        BASE_COMMAND, ['a.java', 'b.java'], max_bytes=10 ** 9)
    assert report['complete'] is True
    assert report['missing_paths'] == []
    assert len(report['results']) == 2
    assert report['errors'] == []


def test_invoke_bisects_on_e2big(monkeypatch):
    """When argv is too long, bisect batches until calls succeed."""
    calls = []

    def fake_run(command):
        calls.append(list(command))
        paths = command[len(BASE_COMMAND):]
        # Fail if more than 2 paths (simulate ARG_MAX)
        if len(paths) > 2:
            raise OSError(errno.E2BIG, 'Argument list too long')
        return {
            'results': [make_finding('r', p) for p in paths],
            'errors': [],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)

    paths = [f'f{i}.java' for i in range(5)]
    # Force a single oversized batch so bisect path is exercised
    report = _invoke_semgrep_batched(BASE_COMMAND, paths, max_bytes=10 ** 9)
    assert len(report['results']) == 5
    assert report['errors'] == []
    assert report['complete'] is True
    assert report['missing_paths'] == []
    # At least one call must have split (more than one successful run)
    assert len(calls) >= 3


def test_invoke_single_path_e2big_is_incomplete(monkeypatch):
    """A path that alone exceeds ARG_MAX is a coverage gap."""

    def fake_run(command):
        raise OSError(errno.E2BIG, 'Argument list too long')

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)
    report = _invoke_semgrep_batched(
        BASE_COMMAND, ['huge.java'], max_bytes=10 ** 9)
    assert report['results'] == []
    assert report['complete'] is False
    assert report['missing_paths'] == ['huge.java']
    assert any('Argument list too long' in e for e in report['errors'])


def test_invoke_failed_batch_keeps_partial_findings(monkeypatch):
    """Truncated JSON in one batch must not hide good batches, and the
    merged report must flag the uncovered paths."""

    def fake_run(command):
        paths = command[len(BASE_COMMAND):]
        if 'bad.java' in paths:
            raise SemgrepError('semgrep output was not valid JSON: x')
        return {
            'results': [make_finding('r', p) for p in paths],
            'errors': [],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)
    paths = ['a.java', 'bad.java', 'c.java']
    # One path per batch so the failure is isolated to bad.java
    report = _invoke_semgrep_batched(BASE_COMMAND, paths, max_bytes=1)
    assert [r['path'] for r in report['results']] == ['a.java', 'c.java']
    assert report['complete'] is False
    assert report['missing_paths'] == ['bad.java']
    assert report['scanned_paths'] == ['a.java', 'c.java']
    assert any('not valid JSON' in e for e in report['errors'])


def test_invoke_cross_batch_duplicates_not_double_counted(monkeypatch):
    """Overlapping batches reporting the same finding count it once."""
    shared = make_finding('r', 'shared.java')

    def fake_run(command):
        paths = command[len(BASE_COMMAND):]
        return {
            'results': [make_finding('r', p) for p in paths] + [dict(shared)],
            'errors': [],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)
    report = _invoke_semgrep_batched(
        BASE_COMMAND, ['a.java', 'b.java'], max_bytes=1)
    paths = sorted(r['path'] for r in report['results'])
    assert paths == ['a.java', 'b.java', 'shared.java']
    assert report['complete'] is True


FAKE_SEMGREP = textwrap.dedent(
    '''\
    #!/usr/bin/env python3
    """Fixed fake semgrep for acceptance tests.

    Emits one finding per path argument, plus a finding for shared.java
    in every invocation to simulate overlapping cross-batch duplicates.
    A batch containing a path with "truncated" in its name emits
    truncated JSON, simulating a cut-off semgrep run.
    """
    import json
    import sys

    paths = sys.argv[sys.argv.index('--') + 1:] if '--' in sys.argv else []
    if any('truncated' in p for p in paths):
        sys.stdout.write('{"results": [')
        sys.exit(0)

    def finding(path):
        return {
            'check_id': 'fake-rule',
            'path': path,
            'start': {'line': 1, 'col': 1},
            'end': {'line': 1, 'col': 5},
            'extra': {'metadata': {}, 'message': 'm', 'severity': 'INFO'},
        }

    results = [finding(p) for p in paths]
    results.append(finding('shared.java'))
    json.dump({'results': results, 'errors': []}, sys.stdout)
    ''')


def install_fake_semgrep(tmp_path, monkeypatch):
    """Place the fixed fake semgrep first on PATH."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'semgrep'
    fake.write_text(FAKE_SEMGREP)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv(
        'PATH', f'{bin_dir}{os.pathsep}{os.environ.get("PATH", "")}')
    return fake


def run_fake_semgrep(paths, max_bytes):
    return _invoke_semgrep_batched(BASE_COMMAND, paths, max_bytes=max_bytes)


def test_fake_semgrep_cross_batch_hits_and_dedup(tmp_path, monkeypatch):
    install_fake_semgrep(tmp_path, monkeypatch)
    report = run_fake_semgrep(['a.java', 'b.java', 'c.java'], max_bytes=1)
    assert report['complete'] is True
    assert report['missing_paths'] == []
    paths = sorted(r['path'] for r in report['results'])
    # Legitimate hits from every batch survive; the shared finding that
    # every batch repeats is counted once.
    assert paths == ['a.java', 'b.java', 'c.java', 'shared.java']
    assert report['errors'] == []


def test_fake_semgrep_truncated_batch_marks_incomplete(tmp_path, monkeypatch):
    install_fake_semgrep(tmp_path, monkeypatch)
    report = run_fake_semgrep(
        ['a.java', 'truncated.java', 'b.java'], max_bytes=1)
    assert report['complete'] is False
    assert report['missing_paths'] == ['truncated.java']
    # Partial findings from successful batches are still returned.
    paths = sorted(r['path'] for r in report['results'])
    assert paths == ['a.java', 'b.java', 'shared.java']
    assert any('not valid JSON' in e for e in report['errors'])


def test_semantic_grep_surfaces_incomplete_findings(monkeypatch):
    """Callers can tell the scan is incomplete from the findings dict."""

    def fake_invoke_semgrep(paths, rules):
        return {
            'results': [make_finding('r', 'a.java')],
            'errors': ['boom'],
            'complete': False,
            'missing_paths': ['bad.java'],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.semantic_sgrep.invoke_semgrep',
        fake_invoke_semgrep)
    scanner = SemanticGrep({'sgrep_rules': 'synthetic-rules'})
    findings = scanner.scan([Path('a.java'), Path('bad.java')])
    assert findings['complete'] is False
    assert 'r' in findings['matches']
    assert any('incomplete' in e for e in findings['errors'])
    assert 'boom' in findings['errors']
