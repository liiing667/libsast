# -*- coding: utf_8 -*-
"""Semantic Grep Core."""
from libsast.core_sgrep.helpers import (
    _report_generation,
    get_match_string,
    invoke_semgrep,
)
from libsast.rulepack import (
    attach_rulepack_evidence,
    coerce_rulepack,
)
from libsast.exceptions import RulePackGenerationError
from libsast import (
    common,
    standards,
)


class SemanticGrep:
    def __init__(self, options: dict, rulepack=None) -> None:
        self.scan_rules = options.get('sgrep_rules')
        self.show_progress = options.get('show_progress')
        self.scan_generation = options.get('scan_generation')
        snapshot = (
            rulepack
            or options.get('sgrep_rulepack')
        )
        if snapshot is not None:
            self.rulepack = coerce_rulepack(
                snapshot, raw=True, allow_stale=False)
        else:
            self.rulepack = None
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

    @property
    def rule_source(self):
        """Rule source used by this matcher."""
        return self.rulepack.source if self.rulepack else self.scan_rules

    @property
    def rules_version(self):
        """Rule version used by this matcher."""
        return self.rulepack.version if self.rulepack else None

    @property
    def rulepack_id(self):
        """Rulepack identity used by this matcher."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def rule_generation(self):
        """Rulepack generation used by this matcher."""
        return self.rulepack.generation if self.rulepack else None

    def semgrep_config(self):
        """Return the frozen config path when a snapshot is attached."""
        if self.rulepack is not None:
            return self.rulepack.materialize()
        return self.scan_rules

    def scan(self, paths: list) -> dict:
        """Do sgrep scan."""
        self.findings = {
            'matches': {},
            'errors': [],
        }
        if self.exts:
            paths = [sfile for sfile in paths if sfile.suffix.lower() in self.exts]
            if not paths:
                return self.findings
        config = self.semgrep_config()
        if self.show_progress:
            pbar = common.ProgressBar('Semantic Grep', len(paths))
            sgrep_out = pbar.progress_function(
                invoke_semgrep,
                (paths, config))
        else:
            sgrep_out = invoke_semgrep(paths, config)
        if isinstance(sgrep_out, dict):
            reported = _report_generation(sgrep_out)
            expected = {
                str(value) for value in (
                    self.scan_generation,
                    self.rulepack.generation if self.rulepack else None,
                    self.rulepack.version if self.rulepack else None,
                    self.rulepack.identity if self.rulepack else None,
                )
                if value
            }
            if reported and expected and str(reported) not in expected:
                raise RulePackGenerationError(
                    'Semgrep report generation does not match the frozen '
                    f'rulepack: {reported} not in {sorted(expected)}')
        self.format_output(sgrep_out)
        return self.findings

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
                attach_rulepack_evidence(
                    smatches[rule_id],
                    self.rulepack,
                    rule_id=rule_id,
                    scan_generation=self.scan_generation)
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
