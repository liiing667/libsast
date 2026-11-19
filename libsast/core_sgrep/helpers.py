# -*- coding: utf_8 -*-
"""Semantic Grep Helpers."""
import errno
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import NamedTuple

from libsast.exceptions import SemgrepError

# Semgrep CE redacts some JSON fields unless logged into Semgrep App.
_REDACTED = 'requires login'


class BatchReport(NamedTuple):
    """Outcome of one semgrep batch bound to the paths it scanned."""

    paths: list
    report: dict | None
    error: str | None

    @property
    def ok(self):
        """A batch is complete only when semgrep returned usable JSON."""
        return self.report is not None


def _max_arg_bytes():
    """Conservative argv budget so we stay under OS ARG_MAX."""
    try:
        arg_max = os.sysconf('SC_ARG_MAX')
    except (ValueError, OSError, AttributeError):
        arg_max = 256 * 1024
    # Environment + interpreter overhead; keep a large safety margin.
    return max(32 * 1024, arg_max // 4)


def _command_nbytes(command):
    """Approximate argv byte size (strings + NUL separators)."""
    return sum(len(part) + 1 for part in command)


def batch_paths(base_command, paths, max_bytes=None):
    """Split paths into argv-safe batches for Semgrep."""
    if max_bytes is None:
        max_bytes = _max_arg_bytes()
    base_size = _command_nbytes(base_command)
    if not paths:
        return [[]]

    batches = []
    current = []
    size = base_size
    for path in paths:
        extra = len(path) + 1
        # Always allow a single path even if huge; caller handles E2BIG.
        if current and size + extra > max_bytes:
            batches.append(current)
            current = []
            size = base_size
        current.append(path)
        size += extra
    if current:
        batches.append(current)
    return batches


def _result_fingerprint(result):
    """Stable identity of a finding so duplicates are not double counted."""
    start = result.get('start') or {}
    end = result.get('end') or {}
    return (
        result.get('check_id'),
        result.get('path'),
        start.get('line'),
        start.get('col'),
        end.get('line'),
        end.get('col'),
    )


def _error_key(error):
    """Hashable key for de-duplicating semgrep error entries."""
    try:
        return json.dumps(error, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(error)


def merge_semgrep_reports(batches, requested_paths=None):
    """Merge per-batch semgrep reports and assess completeness.

    Each BatchReport binds the paths of its batch to the batch outcome.
    Findings are de-duplicated across batches, and any requested path not
    covered by a successful batch marks the merged report incomplete.
    """
    merged = {
        'results': [],
        'errors': [],
        'complete': True,
        'scanned_paths': [],
        'missing_paths': [],
    }
    seen_results = set()
    seen_errors = set()
    scanned = set()

    def add_error(error):
        key = _error_key(error)
        if key not in seen_errors:
            seen_errors.add(key)
            merged['errors'].append(error)

    for batch in batches:
        if batch.error:
            add_error(batch.error)
        report = batch.report
        if not report:
            continue
        scanned.update(batch.paths)
        for result in report.get('results') or []:
            fingerprint = _result_fingerprint(result)
            if fingerprint in seen_results:
                continue
            seen_results.add(fingerprint)
            merged['results'].append(result)
        errors = report.get('errors')
        if not errors:
            continue
        if not isinstance(errors, list):
            errors = [errors]
        for error in errors:
            add_error(error)
    merged['scanned_paths'] = sorted(scanned)
    if requested_paths is not None:
        merged['missing_paths'] = [
            path for path in requested_paths if path not in scanned]
    merged['complete'] = not merged['missing_paths'] and all(
        batch.ok for batch in batches)
    return merged


def incomplete_note(missing_paths):
    """Human-readable summary of paths missing from a merged report."""
    count = len(missing_paths)
    if not count:
        return 'semgrep scan is incomplete: some batches failed'
    shown = ', '.join(str(path) for path in missing_paths[:5])
    more = f' and {count - 5} more' if count > 5 else ''
    return (
        f'semgrep scan is incomplete: {count} file(s) not scanned: '
        f'{shown}{more}')


def _run_semgrep_command(command):
    """Run one semgrep command and return the parsed JSON report.

    Raises SemgrepError when no usable report was produced and OSError
    with E2BIG when the argument list is too long.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise SemgrepError(
            'semgrep not found. Install with: pip install semgrep',
        ) from None
    except OSError as exc:
        # Errno 7 / E2BIG: Argument list too long
        if exc.errno in {errno.E2BIG, 7}:
            raise
        raise SemgrepError(str(exc)) from exc

    raw = result.stdout or ''
    if not raw:
        err = (result.stderr or '').strip()
        raise SemgrepError(err or 'semgrep produced no output')
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepError(
            f'semgrep output was not valid JSON: {exc}') from exc


def _invoke_semgrep_batched(base_command, paths, max_bytes=None):
    """Run semgrep in argv-safe batches; bisect on E2BIG.

    The merged report is marked incomplete when any requested path was
    not covered by a successful batch.
    """
    if max_bytes is None:
        max_bytes = _max_arg_bytes()
    if not paths:
        return merge_semgrep_reports([], requested_paths=[])
    batches = []

    def run_batch(batch):
        command = base_command + batch
        try:
            report = _run_semgrep_command(command)
        except OSError as exc:
            if exc.errno not in {errno.E2BIG, 7}:
                batches.append(BatchReport(batch, None, str(exc)))
                return
            if len(batch) <= 1:
                path = batch[0] if batch else ''
                batches.append(BatchReport(
                    batch,
                    None,
                    'Argument list too long when invoking semgrep'
                    f' on path: {path}'))
                return
            mid = len(batch) // 2
            run_batch(batch[:mid])
            run_batch(batch[mid:])
            return
        except SemgrepError as exc:
            batches.append(BatchReport(batch, None, str(exc)))
            return
        batches.append(BatchReport(batch, report, None))

    for batch in batch_paths(base_command, paths, max_bytes):
        run_batch(batch)
    return merge_semgrep_reports(batches, requested_paths=paths)


def invoke_semgrep(paths, scan_rules):
    """Call Semgrep and return the parsed JSON report."""
    if platform.system() == 'Windows':
        return None
    ps = [pt.as_posix() for pt in paths]
    base_command = [
        'semgrep',
        'scan',
        '--metrics=off',
        '--disable-version-check',
        '--quiet',
        '--no-rewrite-rule-ids',
        '--json',
        '--config',
        scan_rules,
        # A scanned file named like an option, such as `--output=x`, must
        # still be read as a path.
        '--',
    ]
    return _invoke_semgrep_batched(base_command, ps)


def get_match_string(path, start_line, end_line, fallback=''):
    """Return matched source text, recovering it when Semgrep redacts lines."""
    if fallback and fallback != _REDACTED:
        return fallback
    try:
        lines = Path(path).read_text(
            encoding='utf-8', errors='ignore').splitlines()
        snippet = lines[start_line - 1:end_line]
        return '\n'.join(snippet)
    except (OSError, ValueError, IndexError, TypeError):
        return '' if fallback == _REDACTED else fallback
