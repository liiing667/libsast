"""Unit Tests - versioned snapshots, symlinks and empty files."""
import os
from pathlib import Path

import pytest

import libsast
from libsast.exceptions import FileSnapshotError
from libsast.file_snapshot import (
    SnapshotRegistry,
    create_snapshot,
    get_file_version,
    is_finding_current,
)

from .setup_test import scanner


def _make_symlink(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip('Symlinks not supported')


def test_valid_symlinked_file_is_scanned(tmp_path):
    """A symlink pointing at a regular file must still be scanned."""
    outside = tmp_path / 'outside'
    outside.mkdir()
    secret = outside / 'secret.test'
    secret.write_text('.close()')
    root = tmp_path / 'root'
    root.mkdir()
    real = root / 'real.test'
    real.write_text('real')
    _make_symlink(root / 'link.test', secret)

    scan = libsast.Scanner({}, [root.as_posix()])
    files = scan.get_scan_files()
    assert real in files
    assert root / 'link.test' in files
    assert scan.validate_file(root / 'link.test')


def test_symlinked_directories_are_not_traversed(tmp_path):
    """A linked directory must not pull outside files into the scan."""
    root = tmp_path / 'root'
    root.mkdir()
    nested = root / 'nested'
    nested.mkdir()
    (nested / 'inside.test').write_text('.close()')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'outside.test').write_text('.close()')
    _make_symlink(root / 'escape', outside)

    names = {
        p.name for p in libsast.Scanner(
            {}, [root.as_posix()]).get_scan_files()
    }
    assert names == {'inside.test'}


def test_broken_symlink_and_symlinked_dir_are_rejected(tmp_path):
    """Broken links fail; symlinked directories must not be traversed."""
    root = tmp_path / 'root'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret.test').write_text('.close()')
    _make_symlink(root / 'broken.test', tmp_path / 'missing')
    _make_symlink(root / 'linked_dir', outside)

    scan = libsast.Scanner({}, [root.as_posix()])
    # The symlinked directory itself is not collected as a file and its
    # contents (outside the scan root) are never traversed.
    assert scan.get_scan_files() == set()
    assert not any(
        p.name == 'secret.test' for p in scan.get_scan_files())
    assert not scan.validate_file(root / 'broken.test')
    assert not scan.validate_file(root / 'linked_dir')
    with pytest.raises(FileSnapshotError):
        create_snapshot(root / 'broken.test')


def test_snapshot_follows_symlink_target(tmp_path):
    target = tmp_path / 'target.test'
    target.write_text('version one')
    link = tmp_path / 'link.test'
    _make_symlink(link, target)

    snapshot = create_snapshot(link)
    assert snapshot.data == 'version one'
    assert snapshot.version.is_symlink is True
    assert snapshot.resolved_path == target.resolve()
    assert snapshot.digest == create_snapshot(target).digest


def test_registry_rescans_when_symlink_target_changes(tmp_path):
    first = tmp_path / 'first.test'
    second = tmp_path / 'second.test'
    first.write_text('first content')
    second.write_text('second content')
    link = tmp_path / 'link.test'
    _make_symlink(link, first)

    registry = SnapshotRegistry()
    snapshot_one = registry.get(link)
    assert snapshot_one.data == 'first content'

    # Re-point the symlink at another file with different content.
    link.unlink()
    _make_symlink(link, second)
    snapshot_two = registry.get(link)

    assert snapshot_two.data == 'second content'
    assert snapshot_two.digest != snapshot_one.digest
    assert snapshot_two.version.target != snapshot_one.version.target


def test_registry_rescans_when_target_content_changes(tmp_path):
    target = tmp_path / 'target.test'
    target.write_text('original')
    registry = SnapshotRegistry()
    before = registry.get(target)

    # Rewrite with different content; ensure mtime moves forward even on
    # coarse-grained filesystems.
    target.write_text('rewritten-with-different-content')
    os.utime(target, ns=(target.stat().st_atime_ns,
                          target.stat().st_mtime_ns + 10_000_000))
    after = registry.get(target)

    assert after.data == 'rewritten-with-different-content'
    assert after.digest != before.digest


def test_registry_reuses_snapshot_while_unchanged(tmp_path):
    target = tmp_path / 'target.test'
    target.write_text('stable content')
    registry = SnapshotRegistry()
    first = registry.get(target)
    second = registry.get(target)
    assert first is second


def test_empty_file_has_a_snapshot_and_version(tmp_path):
    empty = tmp_path / 'empty.test'
    empty.write_text('')
    snapshot = create_snapshot(empty)
    assert snapshot.data == ''
    assert snapshot.size_bytes == 0
    # SHA-256 of the empty byte string.
    assert snapshot.digest == (
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    assert get_file_version(empty) is not None


def test_empty_file_is_scanned_without_crashing(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'empty.test').write_text('')
    rules = (
        Path(__file__).parents[1]
        / 'assets' / 'rules' / 'pattern_matcher' / 'patterns.yaml'
    )
    scan = libsast.Scanner(
        {'match_rules': rules.as_posix()}, [root.as_posix()])
    # The empty file produces no matches but the scan must complete and
    # still return the matcher section.
    result = scan.scan()
    assert 'pattern_matcher' in result


def test_findings_are_bound_to_file_versions(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'hit.test').write_text('resource.close()')
    rules = (
        Path(__file__).parents[1]
        / 'assets' / 'rules' / 'pattern_matcher' / 'patterns.yaml'
    )
    result = libsast.Scanner(
        {'match_rules': rules.as_posix()},
        [root.as_posix()]).scan()
    files = result['pattern_matcher']['test_regex']['files']
    assert files
    version = files[0]['file_version']
    assert version['digest']
    assert 'mtime_ns' in version and 'size' in version

    # The bound digest matches a fresh snapshot of the same content.
    assert create_snapshot(root / 'hit.test').digest == version['digest']


def test_matcher_results_unaffected():
    options = {'match_extensions': ['.test']}
    assert scanner(options).scan()['pattern_matcher']['test_regex']


def test_persisted_finding_is_stale_after_content_changes(tmp_path):
    """A finding bound to an old file version must not survive a rewrite."""
    target = tmp_path / 'target.test'
    target.write_text('resource.close()')
    snapshot = create_snapshot(target)
    version_dict = snapshot.version.as_dict()

    assert is_finding_current(target, version_dict) is True

    # Different content with a newer mtime: the stale finding must be
    # detected instead of silently reused on the next run.
    target.write_text('completely different content after rewrite')
    os.utime(target, ns=(target.stat().st_atime_ns,
                          target.stat().st_mtime_ns + 5_000_000))
    assert is_finding_current(target, version_dict) is False

    # A fresh snapshot's version is current again.
    new_version = create_snapshot(target).version.as_dict()
    assert is_finding_current(target, new_version) is True

    # Missing files and malformed version metadata are never current.
    target.unlink()
    assert is_finding_current(target, new_version) is False
    assert is_finding_current(tmp_path, {}) is False


def test_persisted_finding_is_stale_after_symlink_repoint(tmp_path):
    first = tmp_path / 'first.test'
    second = tmp_path / 'second.test'
    first.write_text('shared symlink content v1')
    second.write_text('shared symlink content v2')
    link = tmp_path / 'link.test'
    _make_symlink(link, first)

    version_dict = create_snapshot(link).version.as_dict()
    assert is_finding_current(link, version_dict) is True

    link.unlink()
    _make_symlink(link, second)
    # Even with identical size/mtime the symlink target changed.
    assert is_finding_current(link, version_dict) is False
