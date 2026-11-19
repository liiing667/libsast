"""Tests for SemanticGrep input filtering."""
from pathlib import Path

from libsast.core_sgrep.semantic_sgrep import SemanticGrep


def test_scan_skips_semgrep_when_no_paths_match_requested_extensions(monkeypatch):
    invoked = []

    def fake_invoke_semgrep(paths, rules):
        invoked.append((paths, rules))
        return {'results': [], 'errors': []}

    monkeypatch.setattr(
        'libsast.core_sgrep.semantic_sgrep.invoke_semgrep',
        fake_invoke_semgrep,
    )
    scanner = SemanticGrep({
        'sgrep_rules': 'synthetic-rules',
        'sgrep_extensions': ['.py'],
    })

    result = scanner.scan([Path('synthetic-benign.txt')])

    assert invoked == []
    assert result == {'matches': {}, 'errors': []}


def test_scan_only_passes_matching_extensions_to_semgrep(
        monkeypatch, tmp_path):
    invoked = []

    def fake_invoke_semgrep(paths, rules):
        invoked.append((paths, rules))
        return {'results': [], 'errors': []}

    monkeypatch.setattr(
        'libsast.core_sgrep.semantic_sgrep.invoke_semgrep',
        fake_invoke_semgrep,
    )
    scanner = SemanticGrep({
        'sgrep_rules': 'synthetic-rules',
        'sgrep_extensions': ['.py'],
    })
    paths = [tmp_path / 'synthetic-benign.txt',
             tmp_path / 'synthetic-benign.py']
    for sfile in paths:
        sfile.write_text('')

    scanner.scan(paths)

    assert invoked == [([tmp_path / 'synthetic-benign.py'],
                        'synthetic-rules')]
