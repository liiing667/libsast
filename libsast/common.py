# -*- coding: utf_8 -*-
"""Common Helpers."""
import os
import sys
from concurrent.futures import (
    ProcessPoolExecutor,
    ThreadPoolExecutor,
)
from threading import (
    Event,
    Thread,
)

from libsast.exceptions import ScanCancelledError
from libsast.exceptions import (
    YamlRuleLoadError,
    YamlRuleParseError,
)

import yaml


class CancellationToken:
    """Cooperative cancellation signal shared by every matcher.

    The token is intentionally a plain ``threading.Event`` wrapper so it can
    be passed to worker processes and checked from any thread or process
    without changing the scanner's rule format or JSON output.
    """

    def __init__(self):
        self._event = Event()

    def cancel(self):
        """Request cancellation of an in-progress scan."""
        self._event.set()

    @property
    def cancelled(self):
        """Return ``True`` once cancellation has been requested."""
        return self._event.is_set()

    def raise_if_cancelled(self):
        """Raise :class:`ScanCancelledError` when cancellation was requested."""
        if self._event.is_set():
            raise ScanCancelledError('Scan cancelled before completion.')

    def __getstate__(self):
        """A fresh, already-set event is recreated inside worker processes."""
        return {'cancelled': self._event.is_set()}

    def __setstate__(self, state):
        self._event = Event()
        if state.get('cancelled'):
            self._event.set()


class ProgressBar:
    def __init__(self, prefix, expected_time, size=60, output=sys.stderr):
        self.prefix = prefix
        self.expected_time = expected_time
        self.size = size
        self.output = output

    def progress_print(self, index):
        """Print progress bar."""
        if self.expected_time:
            prog_length = int(self.size * index / self.expected_time)
        else:
            prog_length = self.size
        prog = '█' * prog_length
        self.output.write(f'- {self.prefix} {prog} {index}\r')
        self.output.flush()

    def progress_loop(self, iterator):
        """Show progress for loop."""
        self.progress_print(0)
        for index, item in enumerate(iterator):
            yield item
            self.progress_print(index + 1)
        self.output.write('\n')
        self.output.flush()

    def iter_progress(self, iterator, total=None, token=None):
        """Iterate ``iterator``, updating progress as each item is consumed.

        Unlike :meth:`progress_loop`, progress is driven by the caller's
        consumption, so the bar tracks the files or rules that have actually
        been processed instead of racing ahead of the scan. When ``token`` is
        cancelled, iteration stops with :class:`ScanCancelledError` and the
        bar is left unfinished, making the incomplete state visible.
        """
        if total is None:
            total = self.expected_time
        index = 0
        self.progress_print(0)
        for item in iterator:
            if token is not None:
                token.raise_if_cancelled()
            yield item
            index += 1
            self.progress_print(index)
        if token is not None:
            token.raise_if_cancelled()
        if index >= total:
            self.output.write('\n')
            self.output.flush()

    def progress_function(self, function, args=None, kwargs=None):
        """Show progress for function."""
        ret = [None]
        index = 0
        # Hack determined by size of rule files
        self.expected_time = self.expected_time * 350

        def myrunner(function, ret, *args, **kwargs):
            ret[0] = function(*args, **kwargs)
        self.progress_print(0)
        thread = Thread(
            target=myrunner,
            args=(function, ret) + tuple(args),
            kwargs=kwargs)
        thread.start()
        while thread.is_alive():
            thread.join(timeout=0.2)
            index += 1
            self.progress_print(index)
        self.output.write('\n')
        self.output.flush()
        return ret[0]


def read_yaml(file_obj, text=False):
    try:
        if text:
            return yaml.safe_load(file_obj)
        return yaml.safe_load(file_obj.read_text('utf-8', 'ignore'))
    except yaml.YAMLError as exp:
        raise YamlRuleParseError(
            f'YAML Parse Error: {repr(exp)}')
    except Exception as gen:
        raise YamlRuleLoadError(
            f'Failed to load YAML file: {repr(gen)}')


def get_worker_count():
    """Get worker count for pool."""
    libsast_workers = os.getenv('LIBSAST_WORKERS')
    if libsast_workers:
        try:
            return int(libsast_workers)
        except ValueError:
            return 1
    try:
        worker_count = os.cpu_count()
    except Exception:
        worker_count = 1

    # Adjust worker count for Windows
    if sys.platform == 'win32':
        worker_count = min(worker_count, 61)
    return worker_count


def cancellable_map(executor_kind, max_workers, function, items,
                    chunksize=1, token=None):
    """Map ``function`` over ``items`` with cooperative cancellation.

    Results are only returned once *every* item has been processed. When the
    ``token`` is cancelled mid-scan, scheduled work is abandoned and
    :class:`ScanCancelledError` is raised instead of returning partial
    results, so callers can never publish an incomplete batch.
    """
    if not items:
        return []
    if executor_kind == 'billiard':
        from billiard import Pool
        with Pool(processes=max_workers) as pool:
            results = []
            for result in pool.imap(
                    function, items, chunksize=chunksize):
                if token is not None:
                    token.raise_if_cancelled()
                results.append(result)
        if token is not None:
            token.raise_if_cancelled()
        return results
    if token is None:
        # Hot path without cancellation: keep the original pool.map behaviour
        # including chunksize-based IPC batching for process pools.
        if executor_kind == 'thread':
            with ThreadPoolExecutor() as executor:
                return list(executor.map(function, items))
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            return list(executor.map(
                function, items, chunksize=chunksize))

    executor_cls = (
        ThreadPoolExecutor if executor_kind == 'thread'
        else ProcessPoolExecutor)
    executor_kwargs = (
        {'max_workers': max_workers} if executor_kind != 'thread' else {})
    results = []
    with executor_cls(**executor_kwargs) as executor:
        if executor_kind == 'thread':
            iterator = executor.map(function, items)
        else:
            # ProcessPoolExecutor.map honours chunksize for IPC efficiency.
            iterator = executor.map(
                function, items, chunksize=chunksize)
        for result in iterator:
            token.raise_if_cancelled()
            results.append(result)
    if token is not None:
        token.raise_if_cancelled()
    return results
