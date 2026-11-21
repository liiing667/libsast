# -*- coding: utf_8 -*-
"""Semantic Grep Core."""
from pathlib import Path

import yaml

from libsast.core_sgrep.helpers import get_match_string, invoke_semgrep
from libsast.findings import (
    FindingStore,
    rulepack_name,
)
from libsast import (
    common,
    standards,
)


class SemanticGrep:
    def __init__(self, options: dict) -> None:
        self.scan_rules = options.get('sgrep_rules')
        self.rulepack = rulepack_name(self.scan_rules)
        self.show_progress = options.get('show_progress')
        exts = options.get('sgrep_extensions')
        if exts:
            self.exts = [ext.lower() for ext in exts]
        else:
            self.exts = []
        # Map check_id -> originating rule so findings can be attributed to
        # the rulepack even when several rule files share an id.
        self.rule_index = self._index_rules()
        self.findings = {
            'matches': FindingStore('semantic_grep'),
            'errors': [],
        }
        self.standards = standards.get_standards()

    def _index_rules(self):
        """Build a check_id -> rule dict from the configured sgrep rules."""
        index = {}
        rules = self._load_sgrep_rules()
        for rule in rules or ():
            if isinstance(rule, dict) and rule.get('id'):
                enriched = dict(rule)
                enriched.setdefault('_rulepack', self.rulepack)
                enriched.setdefault('_matcher_engine', 'semantic_grep')
                index.setdefault(rule['id'], enriched)
        return index

    def _load_sgrep_rules(self):
        """Load Semgrep rules (file or directory, with top-level rules key)."""
        if not self.scan_rules:
            return []
        location = Path(self.scan_rules)
        yaml_files = []
        if location.is_file():
            yaml_files = [location]
        elif location.is_dir():
            yaml_files = sorted(location.glob('**/*.yaml'))
        loaded = []
        for yfile in yaml_files:
            try:
                data = yaml.safe_load(yfile.read_text('utf-8', 'ignore'))
            except yaml.YAMLError:
                continue
            if isinstance(data, dict):
                data = data.get('rules') or []
            if isinstance(data, list):
                pack = rulepack_name(yfile)
                for item in data:
                    if isinstance(item, dict):
                        item.setdefault('_rulepack', pack)
                        item['_rule_loc'] = str(yfile)
                loaded.extend(data)
        return loaded

    def scan(self, paths: list) -> dict:
        """Do sgrep scan."""
        if self.exts:
            paths = [sfile for sfile in paths if sfile.suffix.lower() in self.exts]
            if not paths:
                return self.finalize()
        if self.show_progress:
            pbar = common.ProgressBar('Semantic Grep', len(paths))
            sgrep_out = pbar.progress_function(
                invoke_semgrep,
                (paths, self.scan_rules))
        else:
            sgrep_out = invoke_semgrep(paths, self.scan_rules)
        self.format_output(sgrep_out)
        return self.finalize()

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
            rule = self.rule_index.get(rule_id, {
                'id': rule_id,
                'type': 'semantic_grep',
                'message': find['extra'].get('message', ''),
                'severity': find['extra'].get('severity'),
                'metadata': find['extra'].get('metadata', {}),
                '_rulepack': self.rulepack,
                '_matcher_engine': 'semantic_grep',
            })
            smatches.add_evidence(rule, file_details)

    def finalize(self):
        """Resolve standard mappings and return the serializable report."""
        matches = self.findings['matches'].finalize()
        for entry in matches.values():
            self.expand_mappings(entry)
        self.findings['matches'] = matches
        return self.findings

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
