# -*- coding: utf_8 -*-
"""Stable finding identity and deterministic evidence merging.

The same vulnerability can be reported more than once when several rule
packs ship rules that share an id, or when more than one matcher type
matches the same location. This module centralises the bookkeeping so
that:

* every finding carries a stable ``finding_id`` derived from intrinsic
  rule/location data (rescan results never depend on scan order);
* duplicate evidence for the same rule/location is merged instead of
  being appended twice;
* every piece of evidence records which rulepack, matcher type and
  location produced it;
* severity and metadata are resolved with a deterministic rule rather
  than whichever rule happened to be processed first.
"""
import hashlib
import json
from operator import itemgetter

# Deterministic severity ordering, highest priority first. Both the
# lowercase libsast values and Semgrep's uppercase spellings are covered.
SEVERITY_ORDER = (
    'critical',
    'high',
    'error',
    'medium',
    'warning',
    'low',
    'info',
    'informational',
)
SEVERITY_RANK = {
    name: index for index, name in enumerate(SEVERITY_ORDER)
}

def normalize_severity(severity):
    """Return a lowercase severity string for stable comparisons."""
    if not severity:
        return ''
    return str(severity).strip().lower()


def severity_rank(severity):
    """Rank a severity value; unknown severities sort after known ones."""
    return SEVERITY_RANK.get(normalize_severity(severity), len(SEVERITY_ORDER))


def _stable_hash(payload):
    """Hash a JSON-serialisable payload into a stable hex digest."""
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def make_finding_id(rule_id):
    """Stable, order-independent identifier for a rule id."""
    return 'LS-' + _stable_hash({'rule_id': str(rule_id)})[:16]


def make_evidence_id(rule_id, file_path, match_lines,
                     match_position, match_string):
    """Stable identifier for a single match location."""
    return 'LE-' + _stable_hash({
        'rule_id': str(rule_id),
        'file_path': file_path,
        'match_lines': list(match_lines),
        'match_position': list(match_position),
        'match_string': match_string,
    })[:16]


def location_key(file_path, match_lines, match_position, match_string):
    """Dedup key for evidence that points at the exact same location."""
    return (
        file_path,
        tuple(match_lines),
        tuple(match_position),
        match_string,
    )


def rulepack_name(rule_loc):
    """Derive a stable rulepack name from a rule file/dir/URL location."""
    if not rule_loc:
        return 'unknown_rulepack'
    location = str(rule_loc)
    if location.startswith(('http://', 'https://')):
        return location.rstrip('/')
    from pathlib import Path

    path = Path(location)
    if path.suffix:
        return path.stem
    return path.name or 'unknown_rulepack'


class FindingStore:
    """Collect findings while keeping identity and evidence stable."""

    def __init__(self, matcher_engine):
        self.matcher_engine = matcher_engine
        self.findings = {}

    def _entry(self, rule):
        rule_id = rule['id']
        entry = self.findings.get(rule_id)
        if entry is None:
            entry = {
                'finding_id': make_finding_id(rule_id),
                'rule_id': rule_id,
                'files': [],
                'evidence': [],
                'metadata': {},
                'rulepacks': [],
                'matchers': [],
            }
            self.findings[rule_id] = entry
        return entry

    @staticmethod
    def _record_provenance(entry, key, value):
        """Append a provenance value once, preserving first-seen order."""
        if value and value not in entry[key]:
            entry[key].append(value)

    def _merge_metadata(self, entry, rule):
        """Merge rule metadata deterministically.

        Severity is always the highest among the contributing rules;
        other metadata keys are filled in rulepack/rule order and never
        overwritten, so the result cannot depend on scan scheduling.
        """
        metadata = entry['metadata']
        rule_metadata = dict(rule.get('metadata') or {})

        incoming_severity = rule.get('severity', '')
        if (not metadata.get('severity')
                or severity_rank(incoming_severity)
                < severity_rank(metadata.get('severity'))):
            if incoming_severity:
                metadata['severity'] = normalize_severity(incoming_severity)

        if rule.get('message') and not metadata.get('description'):
            metadata['description'] = rule['message']

        for key, value in rule_metadata.items():
            if key.startswith('_'):
                continue
            if key not in ('severity', 'description') and key not in metadata:
                metadata[key] = value

    def add_evidence(self, rule, match, file_path=None,
                     extra_fields=None):
        """Add one match location, merging duplicates at the same spot.

        ``match`` follows the matcher tuple convention
        ``(match_string, match_position, match_lines)``. For engines that
        already build a file-details dict, pass it via ``match`` and leave
        ``file_path`` unset.
        """
        entry = self._entry(rule)
        rule_id = rule['id']

        if file_path is None and isinstance(match, dict):
            file_details = dict(match)
        else:
            match_string, match_position, match_lines = match
            file_details = {
                'file_path': file_path,
                'match_string': match_string,
                'match_position': tuple(match_position),
                'match_lines': tuple(match_lines),
            }
        if extra_fields:
            for key, value in extra_fields.items():
                file_details.setdefault(key, value)

        file_path = file_details['file_path']
        match_lines = tuple(file_details['match_lines'])
        match_position = tuple(file_details['match_position'])
        match_string = file_details['match_string']

        rulepack = rule.get('_rulepack') or rulepack_name(
            rule.get('_rule_loc'))
        matcher_type = rule.get('type', self.matcher_engine)
        provenance = {
            'rulepack': rulepack,
            'matcher': matcher_type,
            'matcher_engine': self.matcher_engine,
            'rule_id': rule_id,
        }

        dedup = location_key(
            file_path, match_lines, match_position, match_string)
        for existing in entry['evidence']:
            if existing['_location_key'] == dedup:
                self._merge_provenance(existing, provenance)
                break
        else:
            evidence = {
                'evidence_id': make_evidence_id(
                    rule_id,
                    file_path,
                    match_lines,
                    match_position,
                    match_string),
                'file_path': file_path,
                'match_string': match_string,
                'match_position': match_position,
                'match_lines': match_lines,
                'rulepacks': [rulepack] if rulepack else [],
                'matchers': [matcher_type] if matcher_type else [],
                'provenance': [provenance],
                '_location_key': dedup,
            }
            entry['evidence'].append(evidence)

        # Backward-compatible flat file list, also deduped.
        flat = {
            key: value for key, value in file_details.items()
        }
        if flat not in entry['files']:
            entry['files'].append(flat)

        self._record_provenance(entry, 'rulepacks', rulepack)
        self._record_provenance(entry, 'matchers', matcher_type)
        self._merge_metadata(entry, rule)

    @staticmethod
    def _merge_provenance(evidence, provenance):
        """Fold a contributing rule into an existing evidence entry."""
        rulepack = provenance['rulepack']
        matcher_type = provenance['matcher']
        if rulepack and rulepack not in evidence['rulepacks']:
            evidence['rulepacks'].append(rulepack)
        if matcher_type and matcher_type not in evidence['matchers']:
            evidence['matchers'].append(matcher_type)
        if provenance not in evidence['provenance']:
            evidence['provenance'].append(provenance)

    def finalize(self):
        """Return findings with deterministic ordering and clean fields."""
        file_sort = itemgetter(
            'file_path', 'match_string', 'match_lines', 'match_position')
        for entry in self.findings.values():
            entry['files'].sort(key=file_sort)
            entry['evidence'].sort(
                key=lambda ev: (
                    ev['file_path'],
                    ev['match_lines'],
                    ev['match_position'],
                    ev['match_string'],
                ))
            for evidence in entry['evidence']:
                evidence.pop('_location_key', None)
                evidence['rulepacks'].sort()
                evidence['matchers'].sort()
                evidence['provenance'].sort(
                    key=lambda prov: (
                        prov.get('rulepack') or '',
                        prov.get('matcher') or '',
                    ))
            entry['rulepacks'].sort()
            entry['matchers'].sort()
        return self.findings
