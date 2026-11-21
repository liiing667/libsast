# -*- coding: utf_8 -*-
"""The libsast Scanner module."""
import os
from fnmatch import fnmatch
from pathlib import Path

from libsast.common import get_worker_count
from libsast.file_snapshot import SnapshotRegistry
from libsast.core_matcher.pattern_matcher import PatternMatcher
from libsast.core_matcher.choice_matcher import ChoiceMatcher
from libsast.core_sgrep.semantic_sgrep import SemanticGrep
from libsast.core_treesitter.ts_matcher import TreeSitterMatcher
from libsast.exceptions import InvalidPathError


class Scanner:
    def __init__(self, options: dict, paths: list) -> None:
        # Set options with default values where missing
        self.options = {
            'sgrep_rules': None,
            'sgrep_extensions': None,
            'ts_rules': None,
            'ts_extensions': None,
            'ts_extension_map': None,
            'ts_max_file_size_mb': 15,
            'ts_max_match_length': 300,
            'match_rules': None,
            'match_extensions': None,
            'choice_rules': None,
            'choice_extensions': None,
            'alternative_path': None,
            'ignore_filenames': [],
            'ignore_extensions': [],
            'ignore_paths': [],
            'show_progress': False,
            'cpu_core': 1,
            'multiprocessing': 'default',
            # Overwrite with options from invocation
            **(options or {}),
        }

        # Cache frequently used settings
        if options.get('ignore_extensions'):
            self.ignore_extensions = set(options.get('ignore_extensions'))
        else:
            self.ignore_extensions = set()
        if options.get('ignore_filenames'):
            self.ignore_filenames = set(options.get('ignore_filenames'))
        else:
            self.ignore_filenames = set()
        if options.get('ignore_paths'):
            self.ignore_paths = {
                Path(p).as_posix() for p in self.options['ignore_paths']}
        else:
            self.ignore_paths = set()
        if options.get('cpu_core') and isinstance(options['cpu_core'], int):
            self.options['cpu_core'] = options['cpu_core']
        else:
            self.options['cpu_core'] = get_worker_count()
        self.paths = paths
        # One registry per scan so every matcher analyses the exact same
        # version of every file, including when symlinks are re-pointed.
        self.snapshots = SnapshotRegistry()

    def scan(self) -> dict:
        """Start Scan."""
        results = {}
        valid_paths = self.get_scan_files()

        if not valid_paths:
            return {}

        # Snapshot every file once up front. The snapshots bind the content
        # to a file version; if a file (or symlink target) changes later in
        # the scan, the registry detects it and the affected file is
        # explicitly re-read/rescanned with the new content.
        scan_snapshots = self.snapshots.get_many(valid_paths)
        if not scan_snapshots:
            return {}

        if self.options['match_rules']:
            results['pattern_matcher'] = PatternMatcher(
                self.options).scan(scan_snapshots)
        if self.options['ts_rules']:
            results['treesitter_matcher'] = TreeSitterMatcher(
                self.options).scan(scan_snapshots)
        if self.options['choice_rules']:
            results['choice_matcher'] = ChoiceMatcher(
                self.options).scan(scan_snapshots)
        if self.options['sgrep_rules']:
            results['semantic_grep'] = SemanticGrep(
                self.options).scan(valid_paths)

        self._bind_file_versions(results, scan_snapshots)
        return results

    def _bind_file_versions(self, results, snapshots):
        """Attach the file version each finding was produced from.

        Persisting this fingerprint alongside the findings lets the next
        run tell whether an on-disk file still matches the scanned
        version: a different fingerprint means the old findings are stale
        and the file must be rescanned.
        """
        versions = {
            snapshot.path.as_posix(): snapshot.version.as_dict()
            for snapshot in snapshots
        }
        self._annotate(results, versions)

    def _annotate(self, node, versions):
        """Walk arbitrary finding structures and tag file entries."""
        if isinstance(node, dict):
            files = node.get('files')
            if isinstance(files, list):
                for file_details in files:
                    if not isinstance(file_details, dict):
                        continue
                    version = versions.get(file_details.get('file_path'))
                    if version is not None:
                        file_details['file_version'] = dict(version)
            for value in node.values():
                self._annotate(value, versions)
        elif isinstance(node, list):
            for item in node:
                self._annotate(item, versions)

    def get_scan_files(self):
        """Get files valid for scanning."""
        if not isinstance(self.paths, list):
            raise InvalidPathError('Path should be a list')

        all_files = set()
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                self._collect_files(pobj, all_files)
            elif pobj.is_file() and self.validate_file(pobj):
                all_files.add(pobj)

        return all_files

    def _collect_files(self, root, all_files):
        """Walk ``root`` without following symlinked directories.

        Symlinked files inside the tree are still collected (their target
        is resolved safely in the snapshot layer), but a symlinked
        directory is never traversed so a scan cannot silently leave the
        requested root or loop forever on a directory cycle.
        """
        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)
            # Drop symlinked sub-directories in place so os.walk does not
            # descend into them.
            dirnames[:] = [
                name for name in dirnames
                if not (current / name).is_symlink()
            ]
            for name in filenames:
                candidate = current / name
                if self.validate_file(candidate):
                    all_files.add(candidate)

    def validate_file(self, path):
        """Check if we should scan the file."""
        # Early exit if the path does not exist or is not a regular file.
        # Valid symlinks are followed (their target is resolved by the
        # snapshot layer); only broken links, symlink loops and non-file
        # targets are rejected.
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return False
        if not resolved.is_file():
            return False

        # Validate against ignore conditions
        ignore_conditions = any([
            any(pp in path.as_posix() for pp in self.ignore_paths),
            any(fnmatch(path.name, pattern) for pattern in self.ignore_filenames),
            path.suffix.lower() in self.ignore_extensions,
        ])

        return not ignore_conditions
