# -*- coding: utf_8 -*-
"""Semantic Grep Core."""
from libsast.core_sgrep.helpers import get_match_string, invoke_semgrep
from libsast.exceptions import SourceReadError
from libsast.source_reader import check_source_readable, read_diagnostic
from libsast import (
    common,
    standards,
)


class SemanticGrep:
    def __init__(self, options: dict) -> None:
        self.scan_rules = options.get('sgrep_rules')
        self.show_progress = options.get('show_progress')
        exts = options.get('sgrep_extensions')
        if exts:
            self.exts = [ext.lower() for ext in exts]
        else:
            self.exts = []
        self.findings = {
            'matches': {},
            'errors': [],
        }
        self.standards = standards.get_standards()

    def scan(self, paths: list) -> dict:
        """Do sgrep scan."""
        if self.exts:
            paths = [sfile for sfile in paths if sfile.suffix.lower() in self.exts]
            if not paths:
                return self.findings
        # Shared coverage conclusion: an unreadable scannable file fails
        # the scan instead of being silently skipped by the engine.
        for sfile in paths:
            check_source_readable(sfile)
        if self.show_progress:
            pbar = common.ProgressBar('Semantic Grep', len(paths))
            sgrep_out = pbar.progress_function(
                invoke_semgrep,
                (paths, self.scan_rules))
        else:
            sgrep_out = invoke_semgrep(paths, self.scan_rules)
        self.raise_on_unreadable_source(sgrep_out, paths)
        self.format_output(sgrep_out)
        return self.findings

    @staticmethod
    def raise_on_unreadable_source(results, paths):
        """Convert engine-side read failures into SourceReadError.

        Files that vanish after the preflight (or engines refusing an
        unreadable scanning root) surface here as error entries, so they
        reach the same machine-readable diagnostic as the other paths.
        Non-fatal engine warnings (for example lexical warnings) keep the
        legacy behavior of being recorded in the findings report.
        """
        if not results or not results.get('errors'):
            return
        diagnostics = []
        by_posix = {sfile.as_posix(): sfile for sfile in paths}
        for err in results['errors']:
            if isinstance(err, dict):
                reason = f"{err.get('type', 'error')}: {err.get('message', '')}"
                file_name = err.get('path') or err.get('message') or ''
                level = str(err.get('level', '')).lower()
                err_type = str(err.get('type', '')).lower()
                message = str(err.get('message', '')).lower()
                read_failure = any(token in err_type for token in (
                    'semgreperror', 'oserror', 'ioerror', 'filenotfound',
                    'permission',
                )) or any(token in message for token in (
                    'not readable',
                    'invalid scanning root',
                    'no such file',
                    'permission denied',
                ))
                if level == 'warn' or not read_failure:
                    continue
            else:
                reason = str(err)
                file_name = str(err)
            sfile = by_posix.get(file_name)
            diagnostics.append(read_diagnostic(sfile or file_name, reason))
        if not diagnostics:
            return
        raise SourceReadError.from_diagnostics(
            'Semgrep could not read source files; scan is incomplete.',
            diagnostics,
        )

    def format_output(self, results):
        """Format sgrep results."""
        if not results:
            return
        errs = results.get('errors')
        if errs:
            self.findings['errors'] = errs
        if not results.get('results'):
            return
        smatches = self.findings['matches']
        for find in results['results']:
            file_path = find['path']
            start_line = find['start']['line']
            end_line = find['end']['line']
            file_details = {
                'file_path': file_path,
                'match_position': (find['start']['col'], find['end']['col']),
                'match_lines': (start_line, end_line),
                'match_string': get_match_string(
                    file_path,
                    start_line,
                    end_line,
                    find.get('extra', {}).get('lines', ''),
                ),
            }
            rule_id = find['check_id']
            if rule_id in smatches:
                smatches[rule_id]['files'].append(file_details)
            else:
                metadata = find['extra']['metadata']
                metadata['description'] = find['extra']['message']
                metadata['severity'] = find['extra']['severity']
                smatches[rule_id] = {
                    'files': [file_details],
                    'metadata': metadata,
                }
                self.expand_mappings(smatches[rule_id])

    def expand_mappings(self, meta):
        """Expand libsast standard mappings."""
        meta_keys = meta['metadata'].keys()
        for mkey in meta_keys:
            if mkey not in self.standards.keys():
                continue
            to_expand = meta['metadata'][mkey]
            expanded = self.standards[mkey].get(to_expand)
            if expanded:
                meta['metadata'][mkey] = expanded
