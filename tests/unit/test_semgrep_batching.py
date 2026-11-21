# -*- coding: utf_8 -*-
"""Unit tests for Semgrep argv batching (MobSF/mobsfscan#98)."""
import errno
import subprocess

from libsast.core_sgrep.helpers import (
    SemgrepTransportError,
    _invoke_semgrep_batched,
    batch_paths,
    merge_semgrep_reports,
)
from libsast.core_sgrep.semantic_sgrep import SemanticGrep


def _recording_fake(calls, fail_on=()):
    """Fake _run_semgrep_command recording each invoked batch."""
    def fake_run(command, timeout=None):
        batch = command[command.index('--') + 1:]
        calls.append(list(batch))
        if any(path in fail_on for path in batch):
            raise SemgrepTransportError('boom')
        return {
            'results': [{'path': path} for path in batch],
            'errors': [],
        }
    return fake_run


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
    merged = merge_semgrep_reports([
        {'results': [{'check_id': 'a'}], 'errors': ['e1']},
        {'results': [{'check_id': 'b'}], 'errors': []},
        None,
        {'results': [], 'errors': 'e2'},
    ])
    assert [r['check_id'] for r in merged['results']] == ['a', 'b']
    assert merged['errors'] == ['e1', 'e2']


def test_merge_semgrep_reports_propagates_failed_batches():
    failed = {'batch': 0, 'batches': 1, 'paths': ['x.py'], 'error': 'boom'}
    merged = merge_semgrep_reports([
        {'results': [], 'errors': [], 'failed_batches': [failed]},
        {'results': [{'check_id': 'a'}]},
    ])
    assert merged['failed_batches'] == [failed]
    assert [r['check_id'] for r in merged['results']] == ['a']


def test_invoke_bisects_on_e2big(monkeypatch):
    """When argv is too long, bisect batches until calls succeed."""
    calls = []

    def fake_run(command, timeout=None):
        calls.append(list(command))
        paths = command[len([
            'semgrep', 'scan', '--metrics=off', '--disable-version-check',
            '--quiet', '--no-rewrite-rule-ids', '--json', '--config', 'r',
        ]):]
        # Fail if more than 2 paths (simulate ARG_MAX)
        if len(paths) > 2:
            raise OSError(errno.E2BIG, 'Argument list too long')
        return {
            'results': [{'path': p} for p in paths],
            'errors': [],
        }

    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command', fake_run)

    base = [
        'semgrep', 'scan', '--metrics=off', '--disable-version-check',
        '--quiet', '--no-rewrite-rule-ids', '--json', '--config', 'r',
    ]
    paths = [f'f{i}.java' for i in range(5)]
    # Force a single oversized batch so bisect path is exercised
    report = _invoke_semgrep_batched(base, paths, max_bytes=10 ** 9)
    assert len(report['results']) == 5
    assert report['errors'] == []
    # At least one call must have split (more than one successful run)
    assert len(calls) >= 3


def test_batch_plan_is_deterministic_for_same_file_set(monkeypatch):
    """Input order must not change the batch plan (resume relies on it)."""
    calls = []
    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command',
        _recording_fake(calls))
    base = ['semgrep', 'scan', '--']
    paths = [f'f{i}.py' for i in range(10)]

    _invoke_semgrep_batched(base, paths, max_bytes=20)
    first_plan = list(calls)
    calls.clear()
    _invoke_semgrep_batched(base, list(reversed(paths)), max_bytes=20)

    assert calls == first_plan
    assert sum(len(batch) for batch in first_plan) == len(paths)


def test_failed_batch_is_recorded_not_clean(monkeypatch):
    """A batch that does not return must not be merged as clean."""
    calls = []
    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command',
        _recording_fake(calls, fail_on={'b.py'}))
    base = ['semgrep', 'scan', '--']

    report = _invoke_semgrep_batched(
        base, ['c.py', 'a.py', 'b.py'], max_bytes=12)

    # Successful batches are merged, the failed one is missing.
    assert [hit['path'] for hit in report['results']] == ['a.py', 'c.py']
    assert len(report['failed_batches']) == 1
    failed = report['failed_batches'][0]
    # Sorted plan: ['a.py'], ['b.py'], ['c.py'] -> b.py is batch index 1.
    assert failed['batch'] == 1
    assert failed['batches'] == 3
    assert failed['paths'] == ['b.py']
    assert failed['error'] == 'boom'
    # The merged errors must name the unscanned files explicitly.
    assert any(
        'b.py' in err and 'not scanned' in err for err in report['errors'])


def test_retry_with_same_file_set_reproduces_failed_batch(monkeypatch):
    """A retry computes the same plan, so missing batches stay comparable."""
    calls = []
    monkeypatch.setattr(
        'libsast.core_sgrep.helpers._run_semgrep_command',
        _recording_fake(calls, fail_on={'b2.py'}))
    base = ['semgrep', 'scan', '--']
    paths = [f'b{i}.py' for i in range(6)]

    first = _invoke_semgrep_batched(base, paths, max_bytes=16)
    first_plan = list(calls)
    missing = {
        path
        for failed in first['failed_batches']
        for path in failed['paths']
    }
    assert missing == {'b2.py'}

    # Retry with the same files in a different order: same plan, same gap.
    calls.clear()
    second = _invoke_semgrep_batched(base, list(reversed(paths)), max_bytes=16)
    assert calls == first_plan
    assert second['failed_batches'] == first['failed_batches']


def test_timeout_marks_batch_failed(monkeypatch):
    """A timed out batch is recorded with its files, not treated as clean."""
    def fake_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd='semgrep', timeout=1)

    monkeypatch.setattr(
        'subprocess.run', fake_subprocess_run)

    report = _invoke_semgrep_batched(
        ['semgrep', 'scan', '--'], ['a.py'], max_bytes=10 ** 9, timeout=1)

    assert report['results'] == []
    assert len(report['failed_batches']) == 1
    assert report['failed_batches'][0]['paths'] == ['a.py']
    assert 'timed out' in report['failed_batches'][0]['error']
    assert any('a.py' in err for err in report['errors'])


def test_missing_semgrep_binary_marks_batch_failed(monkeypatch):
    """A missing semgrep binary must not look like a clean scan."""
    def fake_subprocess_run(*args, **kwargs):
        raise FileNotFoundError('semgrep')

    monkeypatch.setattr(
        'subprocess.run', fake_subprocess_run)

    report = _invoke_semgrep_batched(
        ['semgrep', 'scan', '--'], ['a.py'], max_bytes=10 ** 9)

    assert report['results'] == []
    assert report['failed_batches'][0]['paths'] == ['a.py']
    assert 'semgrep not found' in report['failed_batches'][0]['error']


def test_format_output_surfaces_failed_batches():
    """SemanticGrep findings must expose batches that never returned."""
    sgrep = SemanticGrep({'sgrep_rules': 'rules.yaml'})
    sgrep.format_output({
        'results': [],
        'errors': [
            'Semgrep batch 2/2 did not return results (boom);'
            ' 1 file(s) not scanned: x.py',
        ],
        'failed_batches': [
            {'batch': 1, 'batches': 2, 'paths': ['x.py'], 'error': 'boom'},
        ],
    })
    assert sgrep.findings['errors']
    assert sgrep.findings['failed_batches'][0]['paths'] == ['x.py']
