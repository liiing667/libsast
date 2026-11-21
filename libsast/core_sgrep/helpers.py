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

# Env var (in seconds) capping a single Semgrep batch run; unset = no limit.
_TIMEOUT_ENV = 'LIBSAST_SGREP_TIMEOUT'


class SemgrepTransportError(Exception):
    """A Semgrep batch did not return a usable report at all."""


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
        if errors:
            if isinstance(errors, list):
                merged['errors'].extend(errors)
            else:
                merged['errors'].append(errors)
        failed = report.get('failed_batches')
        if failed:
            merged.setdefault('failed_batches', []).extend(failed)
    return merged


def _run_semgrep_command(command, timeout=None):
    """Run one Semgrep command and return the parsed JSON report.

    Raises SemgrepTransportError when the batch did not return a usable
    report (missing binary, timeout, empty or invalid output). An E2BIG
    OSError still propagates so the caller can bisect the batch.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise SemgrepTransportError(
            'semgrep not found. Install with: pip install semgrep') from exc
    except subprocess.TimeoutExpired as exc:
        raise SemgrepTransportError(
            f'semgrep timed out after {exc.timeout}s') from exc
    except OSError as exc:
        # Errno 7 / E2BIG: Argument list too long
        if exc.errno in {errno.E2BIG, 7}:
            raise
        raise SemgrepTransportError(str(exc)) from exc

    raw = result.stdout or ''
    if not raw:
        err = (result.stderr or '').strip()
        raise SemgrepTransportError(
            err or f'semgrep exited with code {result.returncode}'
            ' and produced no output')
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepTransportError(
            f'invalid semgrep JSON output: {exc}') from exc


def _invoke_semgrep_batched(base_command, paths, max_bytes=None, timeout=None):
    """Run Semgrep in argv-safe batches; bisect on E2BIG.

    The batch plan is deterministic: paths are sorted before splitting,
    so the same set of files always maps to the same batch numbers across
    runs and a retry reproduces the exact same plan. Batches that do not
    return a usable report are recorded under 'failed_batches' (with the
    files they covered) instead of being silently merged as clean.
    """
    if max_bytes is None:
        max_bytes = _max_arg_bytes()
    reports = []
    failed_batches = []
    batches = batch_paths(base_command, sorted(paths), max_bytes)
    total = len(batches)

    def record_failure(batch, index, error):
        failed_batches.append({
            'batch': index,
            'batches': total,
            'paths': list(batch),
            'error': error,
        })

    def run_batch(batch, index):
        command = base_command + batch
        try:
            reports.append(_run_semgrep_command(command, timeout=timeout))
            return
        except SemgrepTransportError as exc:
            record_failure(batch, index, str(exc))
            return
        except OSError as exc:
            if exc.errno not in {errno.E2BIG, 7}:
                record_failure(batch, index, str(exc))
                return
            if len(batch) <= 1:
                path = batch[0] if batch else ''
                record_failure(
                    batch,
                    index,
                    'Argument list too long when invoking semgrep'
                    f' on path: {path}',
                )
                return
            mid = len(batch) // 2
            run_batch(batch[:mid], index)
            run_batch(batch[mid:], index)

    for index, batch in enumerate(batches):
        run_batch(batch, index)
    merged = merge_semgrep_reports(reports)
    if failed_batches:
        merged['failed_batches'] = failed_batches
        for failed in failed_batches:
            files = ', '.join(failed['paths'])
            merged['errors'].append(
                f"Semgrep batch {failed['batch'] + 1}/{failed['batches']}"
                f' did not return results ({failed["error"]});'
                f" {len(failed['paths'])} file(s) not scanned: {files}")
    return merged


def _timeout_from_env():
    """Read optional per-batch Semgrep timeout (seconds) from the env."""
    raw = os.environ.get(_TIMEOUT_ENV)
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def invoke_semgrep(paths, scan_rules, timeout=None):
    """Call Semgrep and return the parsed JSON report."""
    if platform.system() == 'Windows':
        return None
    if timeout is None:
        timeout = _timeout_from_env()
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
    return _invoke_semgrep_batched(base_command, ps, timeout=timeout)


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
