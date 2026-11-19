# -*- coding: utf_8 -*-
"""Acceptance tests: unreadable source must never count as an empty file.

An unreadable or vanished scannable file fails the scan with
machine-readable diagnostics instead of producing a successful
"no findings" result. Legitimate empty files and explicitly filtered
files remain non-errors, and existing findings structures are unchanged.
"""
import os
from pathlib import Path

import pytest

from libsast import Scanner, exceptions

ASSETS_DIR = Path(__file__).parents[1] / 'assets'
PATTERN_RULES = ASSETS_DIR / 'rules' / 'pattern_matcher' / 'patterns.yaml'
TS_RULES = ASSETS_DIR / 'rules' / 'treesitter_matcher' / 'ts_rules.yaml'
SGREP_RULES = ASSETS_DIR / 'rules' / 'semantic_grep'


def _unreadable(path):
    """Render a file unreadable for the current (non-root) user."""
    path.chmod(0o000)
    assert not os.access(path, os.R_OK)


pytestmark = pytest.mark.skipif(
    os.geteuid() == 0,
    reason='chmod 000 does not block reads for root',
)


def test_regex_path_fails_on_unreadable_file(tmp_path):
    bad = tmp_path / 'unreadable.test'
    bad.write_text('engine.close()')
    _unreadable(bad)

    scanner = Scanner({
        'match_rules': PATTERN_RULES.as_posix(),
        'match_extensions': ['.test'],
    }, [tmp_path.as_posix()])

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        scanner.scan()

    diagnostics = exc_info.value.diagnostics
    assert len(diagnostics) == 1
    assert diagnostics[0]['file_path'] == bad.as_posix()
    assert diagnostics[0]['reason']


def test_regex_path_fails_when_file_vanishes(tmp_path, monkeypatch):
    vanish = tmp_path / 'vanishes.test'
    vanish.write_text('engine.close()')

    from libsast import source_reader

    original = source_reader.read_source_text

    def flaky_read(file_path):
        if file_path == vanish:
            os.unlink(vanish)
        return original(file_path)

    monkeypatch.setattr(source_reader, 'read_source_text', flaky_read)

    scanner = Scanner({
        'match_rules': PATTERN_RULES.as_posix(),
        'match_extensions': ['.test'],
    }, [tmp_path.as_posix()])

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        scanner.scan()

    assert exc_info.value.diagnostics[0]['file_path'] == vanish.as_posix()


def test_treesitter_path_fails_on_unreadable_file(tmp_path):
    bad = tmp_path / 'unreadable.ts'
    bad.write_text('eval("danger")\n')
    _unreadable(bad)

    scanner = Scanner({
        'ts_rules': TS_RULES.as_posix(),
        'ts_extensions': ['.ts'],
        'multiprocessing': 'thread',
    }, [tmp_path.as_posix()])

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        scanner.scan()

    assert exc_info.value.diagnostics[0]['file_path'] == bad.as_posix()


def test_semgrep_path_fails_on_unreadable_file(tmp_path):
    bad = tmp_path / 'unreadable.py'
    bad.write_text("import boto3\nboto3.client(host='8.8.8.8')\n")
    _unreadable(bad)

    scanner = Scanner({
        'sgrep_rules': SGREP_RULES.as_posix(),
        'sgrep_extensions': ['.py'],
    }, [tmp_path.as_posix()])

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        scanner.scan()

    assert exc_info.value.diagnostics[0]['file_path'] == bad.as_posix()


def test_semgrep_path_fails_on_engine_side_vanish(tmp_path, monkeypatch):
    vanished = tmp_path / 'vanishes.py'
    vanished.write_text('x = 1\n')

    monkeypatch.setattr(
        'libsast.core_sgrep.semantic_sgrep.invoke_semgrep',
        lambda paths, rules: {
            'results': [],
            'errors': [{
                'code': 2,
                'level': 'error',
                'type': 'SemgrepError',
                'message': f'Invalid scanning root: {vanished.as_posix()}',
                'path': vanished.as_posix(),
            }],
        },
    )

    from libsast.core_sgrep.semantic_sgrep import SemanticGrep

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        SemanticGrep({
            'sgrep_rules': 'synthetic-rules',
            'sgrep_extensions': ['.py'],
        }).scan([vanished])

    diagnostic = exc_info.value.diagnostics[0]
    assert diagnostic['file_path'] == vanished.as_posix()
    assert 'SemgrepError' in diagnostic['reason']


def test_legitimate_empty_file_is_not_an_error(tmp_path):
    empty = tmp_path / 'empty.test'
    empty.write_text('')
    good = tmp_path / 'good.test'
    good.write_text('engine.close()')

    result = Scanner({
        'match_rules': PATTERN_RULES.as_posix(),
        'match_extensions': ['.test'],
    }, [tmp_path.as_posix()]).scan()

    assert result['pattern_matcher']['test_regex']['files']


def test_filtered_file_is_not_an_error(tmp_path):
    ignored = tmp_path / 'ignored.test'
    ignored.write_text('engine.close()')

    result = Scanner({
        'match_rules': PATTERN_RULES.as_posix(),
        'match_extensions': ['.java'],
    }, [tmp_path.as_posix()]).scan()

    assert result == {'pattern_matcher': {}}


def test_existing_findings_structure_is_preserved(tmp_path):
    good = tmp_path / 'good.test'
    good.write_text('engine.close()')

    result = Scanner({
        'match_rules': PATTERN_RULES.as_posix(),
        'match_extensions': ['.test'],
    }, [tmp_path.as_posix()]).scan()

    finding = result['pattern_matcher']['test_regex']
    assert set(finding.keys()) == {'files', 'metadata'}
    detail = finding['files'][0]
    assert set(detail.keys()) == {
        'file_path',
        'match_string',
        'match_position',
        'match_lines',
    }
    assert detail['file_path'] == good.as_posix()


def test_all_three_paths_share_diagnostic_shape(tmp_path):
    bad = tmp_path / 'unreadable.shared'
    bad.write_text('content')
    _unreadable(bad)

    from libsast.source_reader import load_source_files

    with pytest.raises(exceptions.SourceReadError) as exc_info:
        load_source_files([bad])

    diagnostic = exc_info.value.diagnostics[0]
    assert set(diagnostic.keys()) == {'file_path', 'reason'}
    assert diagnostic['file_path'] == bad.as_posix()


def test_semgrep_warning_level_errors_remain_non_fatal(tmp_path, monkeypatch):
    good = tmp_path / 'warn.py'
    good.write_text('x = 1\n')

    monkeypatch.setattr(
        'libsast.core_sgrep.semantic_sgrep.invoke_semgrep',
        lambda paths, rules: {
            'results': [],
            'errors': [{
                'code': 3,
                'level': 'warn',
                'message': 'Lexical error in file warn.py',
                'path': good.as_posix(),
                'type': 'Lexical error',
            }],
        },
    )

    from libsast.core_sgrep.semantic_sgrep import SemanticGrep

    result = SemanticGrep({
        'sgrep_rules': 'synthetic-rules',
        'sgrep_extensions': ['.py'],
    }).scan([good])

    assert result['errors']
    assert result['matches'] == {}
