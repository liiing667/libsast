# -*- coding: utf_8 -*-
"""Semantic Grep Core."""
from libsast.core_sgrep.helpers import get_match_string, invoke_semgrep
from libsast import (
    common,
    standards,
)


class SemanticGrep:
    def __init__(self, options: dict) -> None:
        self.scan_rules = options.get('sgrep_rules')
        self.show_progress = options.get('show_progress')
        self.token = options.get('cancel_token')
        exts = options.get('sgrep_extensions')
        if exts:
            self.exts = [ext.lower() for ext in exts]
        else:
            self.exts = []
        self.findings = self._empty_findings()
        self.standards = standards.get_standards()

    @staticmethod
    def _empty_findings():
        return {'matches': {}, 'errors': []}

    def scan(self, paths: list) -> dict:
        """Do sgrep scan."""
        # Reset state so a retry never appends to a previous attempt.
        self.findings = self._empty_findings()
        paths = sorted(paths, key=lambda p: p.as_posix())
        if self.token is not None:
            self.token.raise_if_cancelled()
        if self.exts:
            paths = [sfile for sfile in paths if sfile.suffix.lower() in self.exts]
            if not paths:
                return self.findings
        if self.show_progress:
            pbar = common.ProgressBar('Semantic Grep', len(paths))
            sgrep_out = pbar.progress_function(
                invoke_semgrep,
                (paths, self.scan_rules))
        else:
            sgrep_out = invoke_semgrep(paths, self.scan_rules)
        if self.token is not None:
            self.token.raise_if_cancelled()
        self.format_output(sgrep_out)
        return self.findings

    def format_output(self, results):
        """Format sgrep results."""
        if not results:
            return
        # Build the new report locally and publish the complete batch in one
        # assignment; cancelled or failed scans never expose partial state.
        findings = self._empty_findings()
        errs = results.get('errors')
        if errs:
            findings['errors'] = errs
        if not results.get('results'):
            self.findings = findings
            return
        smatches = findings['matches']
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
        self.findings = findings

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
