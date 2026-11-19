# -*- coding: utf_8 -*-
"""Shared source file reading and read-failure diagnostics.

Every scan path (regex, tree-sitter and semgrep) must reach the same
coverage conclusion: a file selected for scanning that cannot be read is a
scan-completeness failure, never an empty file. Legitimate empty files and
files filtered out by extension, size or ignore rules are not errors.
"""
from concurrent.futures import ThreadPoolExecutor

from libsast.exceptions import SourceReadError


def read_diagnostic(file_path, reason):
    """Build one machine-readable unreadable-source diagnostic."""
    return {
        'file_path': file_path.as_posix() if hasattr(
            file_path, 'as_posix') else str(file_path),
        'reason': reason,
    }


def check_source_readable(file_path):
    """Raise SourceReadError when a scannable file cannot be opened.

    A lightweight open/close probe used before handing paths to engines
    that read files themselves (semgrep). Permission-denied and vanished
    files are both reported with their errno reason.
    """
    try:
        with open(file_path, 'rb'):
            pass
    except OSError as exc:
        raise SourceReadError.from_diagnostics(
            'Source file is not readable.',
            [
                read_diagnostic(file_path, f'{type(exc).__name__}: {exc}'),
            ])


def read_source_text(file_path):
    """Read one file as text, surfacing read failures as diagnostics."""
    try:
        return file_path, file_path.read_text('utf-8', 'ignore'), None
    except OSError as exc:
        return file_path, None, read_diagnostic(
            file_path, f'{type(exc).__name__}: {exc}')


def load_source_files(paths, allowed_extensions=None, max_size_mb=5):
    """Read scannable files in parallel and fail closed on read errors.

    Extension and size filtering happens here so filtered files and
    legitimate empty files are simply absent from the result instead of
    being reported as errors. All unreadable files are collected into one
    SourceReadError so a single failure report covers the whole batch.
    """
    exts = {ext.lower() for ext in (allowed_extensions or [])}
    max_size_bytes = max_size_mb * 1024 * 1024

    selected = set()
    for sfile in paths:
        ext = sfile.suffix.lower()
        if exts and ext not in exts:
            continue
        try:
            if sfile.stat().st_size > max_size_bytes:
                continue
        except OSError as exc:
            raise SourceReadError.from_diagnostics(
                'Source file is not readable.',
                [
                    read_diagnostic(sfile, f'{type(exc).__name__}: {exc}'),
                ])
        selected.add(sfile)

    if not selected:
        return []

    with ThreadPoolExecutor() as io_executor:
        loaded = list(io_executor.map(read_source_text, selected))

    diagnostics = [diag for _, _, diag in loaded if diag is not None]
    if diagnostics:
        raise SourceReadError.from_diagnostics(
            'Failed to read source files; scan is incomplete.',
            diagnostics,
        )
    return [(file_path, data) for file_path, data, _ in loaded]
