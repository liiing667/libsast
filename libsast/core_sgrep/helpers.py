# -*- coding: utf_8 -*-
"""Semantic Grep Helpers."""
import errno
import json
import os
import platform
import subprocess
from pathlib import Path

# Semgrep CE redacts some JSON fields unless logged into Semgrep App.
_REDACTED = 'requires login'


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


def merge_semgrep_reports(reports):
    """Merge Semgrep JSON reports from multiple invocations."""
    merged = {'results': [], 'errors': []}
    for report in reports:
        if not report:
            continue
        merged['results'].extend(report.get('results') or [])
        errors = report.get('errors')
        if not errors:
            continue
        if isinstance(errors, list):
            merged['errors'].extend(errors)
        else:
            merged['errors'].append(errors)
    return merged


def _run_semgrep_command(command):
    """Run one Semgrep command and return parsed JSON or an error report."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return {
            'results': [],
            'errors': ['semgrep not found. Install with: pip install semgrep'],
        }
    except OSError as exc:
        # Errno 7 / E2BIG: Argument list too long
        if exc.errno in {errno.E2BIG, 7}:
            raise
        return {'results': [], 'errors': [str(exc)]}

    raw = result.stdout or ''
    if not raw:
        err = (result.stderr or '').strip()
        return {'results': [], 'errors': [err] if err else []}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        return {'results': [], 'errors': [str(exc)]}


def _invoke_semgrep_batched(base_command, paths, max_bytes=None):
    """Run Semgrep in argv-safe batches; bisect on E2BIG."""
    if max_bytes is None:
        max_bytes = _max_arg_bytes()
    # Reports are collected locally and published only once at the end. On a
    # retry (E2BIG bisect or an outer scan retry) the failing batch's report
    # is discarded, so the same files can never be counted twice.
    reports = []

    def run_batch(batch):
        command = base_command + batch
        try:
            report = _run_semgrep_command(command)
        except OSError as exc:
            if exc.errno not in {errno.E2BIG, 7}:
                reports.append({'results': [], 'errors': [str(exc)]})
                return
            if len(batch) <= 1:
                path = batch[0] if batch else ''
                reports.append({
                    'results': [],
                    'errors': [
                        'Argument list too long when invoking semgrep'
                        f' on path: {path}',
                    ],
                })
                return
            # Do not append a report for the failed oversized batch: retry
            # its halves instead so each path appears in exactly one report.
            mid = len(batch) // 2
            run_batch(batch[:mid])
            run_batch(batch[mid:])
            return
        reports.append(report)

    for batch in batch_paths(base_command, paths, max_bytes):
        run_batch(batch)
    return merge_semgrep_reports(reports)


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
