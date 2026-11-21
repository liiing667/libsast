# -*- coding: utf_8 -*-
"""Versioned file snapshots.

A :class:`FileSnapshot` pairs the content read for one scan with a version
fingerprint of that exact content. Every matcher (regex, tree-sitter,
choice and sgrep) consumes the same snapshot, so a symlink that is
re-pointed, or a file that is rewritten while a scan is in progress, can
never make two matchers analyse two different versions of the same path.

The fingerprint (content SHA-256 plus size/mtime metadata) also lets
callers bind persisted findings to a file version: when the fingerprint
changes, stale findings must be discarded and the file rescanned.
"""
from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path

from libsast.exceptions import FileSnapshotError

# A file is re-read at most this many times when it keeps changing
# underneath us, instead of looping forever on an actively written file.
_MAX_READ_ATTEMPTS = 3


@dataclass(frozen=True)
class FileVersion:
    """Fingerprint of one immutable version of a file.

    ``digest`` is the SHA-256 of the captured content and is what findings
    should be bound to. The remaining fields are cheap stat-based change
    indicators used to detect rewrites and symlink re-points without
    re-reading every file.
    """

    digest: str
    size: int
    mtime_ns: int
    inode: int
    device: int
    is_symlink: bool
    target: str | None

    def as_dict(self) -> dict:
        """Return a JSON-serialisable representation of the version."""
        return {
            'digest': self.digest,
            'size': self.size,
            'mtime_ns': self.mtime_ns,
            'inode': self.inode,
            'device': self.device,
            'is_symlink': self.is_symlink,
            'target': self.target,
        }

    def stat_signature(self) -> tuple:
        """Stat identity that changes whenever the file version changes."""
        return (
            self.device,
            self.inode,
            self.size,
            self.mtime_ns,
            self.is_symlink,
            self.target,
        )


@dataclass(frozen=True)
class FileSnapshot:
    """Content captured for a single path together with its version.

    ``path`` is the scanned path as presented by the caller (a symlink path
    stays a symlink path in the findings), while ``resolved_path`` is the
    regular file the content was read from. ``data`` and ``version`` are
    guaranteed to describe the same on-disk bytes.
    """

    path: Path
    resolved_path: Path
    data: str
    version: FileVersion
    size_bytes: int = field(compare=False)

    @property
    def digest(self) -> str:
        """SHA-256 hex digest of the captured content."""
        return self.version.digest

    def matches_version(self, version: FileVersion | None) -> bool:
        """Return True when ``version`` still describes this snapshot.

        Stat fields are compared instead of content hashes so cache
        validation never has to re-read the file. A different inode, size,
        mtime or symlink target means the content changed and a rescan is
        required.
        """
        return (
            version is not None
            and version.stat_signature() == self.version.stat_signature()
        )


def _lstat_info(path: Path):
    """Return lstat info and symlink target metadata for ``path``."""
    lst = path.lstat()
    is_symlink = stat.S_ISLNK(lst.st_mode)
    target = os.readlink(path) if is_symlink else None
    return lst, is_symlink, target


def _build_version(digest: str, st, is_symlink: bool,
                   target: str | None) -> FileVersion:
    return FileVersion(
        digest=digest,
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        inode=st.st_ino,
        device=st.st_dev,
        is_symlink=is_symlink,
        target=target,
    )


def create_snapshot(path: os.PathLike | str) -> FileSnapshot:
    """Read ``path`` once and bind the content to its file version.

    The target file is stat'd before and after the read and the content is
    checksummed, so a swap (including a symlink re-pointing to another
    target) that happens while reading is detected and the read is retried
    against the new version. Empty files and valid symlinks are captured
    like any other file.

    Raises:
        FileSnapshotError: when the file disappears, is not a regular file
            (after symlink resolution) or keeps changing while being read.
    """
    sfile = Path(path)
    last_error: Exception | None = None
    for _ in range(_MAX_READ_ATTEMPTS):
        try:
            _, is_symlink, target = _lstat_info(sfile)
            # Resolve symlinks so the content is always read from the
            # currently referenced target.
            resolved = sfile.resolve(strict=True)
            pre = resolved.stat()
            if not stat.S_ISREG(pre.st_mode):
                raise FileSnapshotError(
                    f'Not a regular file and cannot be scanned: {sfile}')
            raw = resolved.read_bytes()
            post = resolved.stat()
        except FileSnapshotError:
            raise
        except (OSError, ValueError) as exp:
            # Broken symlink, deleted file, permission problem, ...
            raise FileSnapshotError(
                f'Unable to snapshot {sfile}: {exp}') from exp

        if (pre.st_mtime_ns != post.st_mtime_ns
                or pre.st_size != post.st_size
                or pre.st_ino != post.st_ino
                or pre.st_dev != post.st_dev):
            # The target was rewritten or the symlink was re-pointed while
            # we were reading. Loop and capture the new version.
            last_error = FileSnapshotError(
                f'{sfile} changed while it was being read')
            continue

        digest = hashlib.sha256(raw).hexdigest()
        version = _build_version(digest, post, is_symlink, target)
        return FileSnapshot(
            path=sfile,
            resolved_path=resolved,
            data=raw.decode('utf-8', 'ignore'),
            version=version,
            size_bytes=len(raw),
        )

    raise FileSnapshotError(
        f'{sfile} changed repeatedly while it was being read'
    ) from last_error


def get_file_version(path: os.PathLike | str) -> FileVersion | None:
    """Return the current file version without reading the whole file.

    Uses lstat/stat only, so it is cheap enough for cache validation.
    Returns ``None`` when the path no longer resolves to a regular file.
    The digest is left empty: the stat signature is sufficient for change
    detection, callers needing the content digest use
    :func:`create_snapshot`.
    """
    sfile = Path(path)
    try:
        _, is_symlink, target = _lstat_info(sfile)
        resolved = sfile.resolve(strict=True)
        st = resolved.stat()
        if not stat.S_ISREG(st.st_mode):
            return None
    except (OSError, ValueError):
        return None
    return _build_version('', st, is_symlink, target)


class SnapshotRegistry:
    """Cache of versioned snapshots shared by the matchers of one scan.

    All matchers in a scan share one registry so each file is read a
    single time and regex/tree-sitter (and any other consumer) are
    guaranteed the identical content version.
    """

    def __init__(self) -> None:
        self._snapshots: dict[Path, FileSnapshot] = {}
        self._lock = threading.Lock()

    def get(self, path: os.PathLike | str) -> FileSnapshot:
        """Return a current snapshot for ``path``.

        A cached snapshot is only reused while the on-disk file version is
        unchanged. Any modification (including a symlink pointing at a new
        target) invalidates the cache and triggers an explicit re-read,
        i.e. a rescan of the new content.
        """
        sfile = Path(path)
        with self._lock:
            cached = self._snapshots.get(sfile)
        current = get_file_version(sfile)
        if cached is not None and cached.matches_version(current):
            return cached
        snapshot = create_snapshot(sfile)
        with self._lock:
            self._snapshots[sfile] = snapshot
        return snapshot

    def get_many(self, paths) -> list[FileSnapshot]:
        """Snapshot every path, dropping entries that cannot be read."""
        snapshots: list[FileSnapshot] = []
        for sfile in paths:
            try:
                snapshots.append(self.get(sfile))
            except FileSnapshotError:
                continue
        return snapshots

    def version_of(self, path: os.PathLike | str) -> FileVersion | None:
        """Return the cached version for ``path`` if still current."""
        sfile = Path(path)
        with self._lock:
            cached = self._snapshots.get(sfile)
        if cached is None:
            return None
        current = get_file_version(sfile)
        if cached.matches_version(current):
            return cached.version
        return None

    def clear(self) -> None:
        """Drop every cached snapshot (starts a new scan)."""
        with self._lock:
            self._snapshots.clear()


def is_finding_current(path, file_version: dict) -> bool:
    """Check whether a persisted finding is still valid for ``path``.

    Consumers that store findings between runs should call this before
    reusing them. ``file_version`` is the ``file_version`` dict attached
    to a finding by the scanner. A ``False`` result means the on-disk
    file (or symlink target) changed and the file must be rescanned.
    """
    if not isinstance(file_version, dict):
        return False
    required = (
        'device', 'inode', 'size', 'mtime_ns', 'is_symlink', 'target')
    if any(key not in file_version for key in required):
        return False
    current = get_file_version(path)
    if current is None:
        return False
    return current.stat_signature() == (
        file_version.get('device'),
        file_version.get('inode'),
        file_version.get('size'),
        file_version.get('mtime_ns'),
        file_version.get('is_symlink'),
        file_version.get('target'),
    )
