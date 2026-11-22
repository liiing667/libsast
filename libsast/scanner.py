# -*- coding: utf_8 -*-
"""The libsast Scanner module."""
from pathlib import Path
from fnmatch import fnmatch
import uuid

from libsast.common import get_worker_count
from libsast.core_matcher import helpers as matcher_helpers
from libsast.core_matcher.pattern_matcher import PatternMatcher
from libsast.core_matcher.choice_matcher import ChoiceMatcher
from libsast.core_sgrep.semantic_sgrep import SemanticGrep
from libsast.core_treesitter.ts_matcher import TreeSitterMatcher
from libsast.exceptions import (
    InvalidPathError,
    LibsastError,
)
from libsast.rulepack import (
    RulePack,
    RuleSet,
    build_rule_metadata,
    coerce_rulepack,
    finding_rulepack,
    rulepack_from_rules,
    rulepack_metadata,
    source_key,
)

RULEPACK_OPTION_KEYS = {
    'match_rules': 'match_rulepack',
    'ts_rules': 'ts_rulepack',
    'choice_rules': 'choice_rulepack',
    'sgrep_rules': 'sgrep_rulepack',
}


class Scanner:
    def __init__(self, options: dict, paths: list) -> None:
        # Set options with default values where missing
        provided_options = options or {}
        self.options = {
            'sgrep_rules': None,
            'sgrep_extensions': None,
            'ts_rules': None,
            'ts_extensions': None,
            'ts_extension_map': None,
            'ts_max_file_size_mb': 15,
            'ts_max_match_length': 300,
            'match_rules': None,
            'match_extensions': None,
            'choice_rules': None,
            'choice_extensions': None,
            'alternative_path': None,
            'ignore_filenames': [],
            'ignore_extensions': [],
            'ignore_paths': [],
            'show_progress': False,
            'cpu_core': 1,
            'multiprocessing': 'default',
            # A rulepack can be a base rule directory/URL or a mapping of
            # matcher options.  Explicit *_rules options always win.
            'rulepack': None,
            'rulepack_version': None,
            'rulepack_allow_stale': True,
            'fresh_rulepack': False,
            # Overwrite with options from invocation
            **provided_options,
        }
        self._provided_options = set(provided_options)

        # Cache frequently used settings
        if provided_options.get('ignore_extensions'):
            self.ignore_extensions = set(
                provided_options.get('ignore_extensions'))
        else:
            self.ignore_extensions = set()
        if provided_options.get('ignore_filenames'):
            self.ignore_filenames = set(
                provided_options.get('ignore_filenames'))
        else:
            self.ignore_filenames = set()
        if provided_options.get('ignore_paths'):
            self.ignore_paths = {
                Path(p).as_posix() for p in self.options['ignore_paths']}
        else:
            self.ignore_paths = set()
        if (
                provided_options.get('cpu_core')
                and isinstance(provided_options['cpu_core'], int)):
            self.options['cpu_core'] = provided_options['cpu_core']
        else:
            self.options['cpu_core'] = get_worker_count()
        self.paths = paths
        self.rulepacks = {}
        self.rulepack = None
        self.rule_metadata = {}
        self.scan_generation = None
        self.generation = None
        self.scan_id = None
        self.last_scan_result = None
        self._inline_rulepack_version = None
        self._source_versions = {}

    def scan(self) -> dict:
        """Start Scan."""
        results = {}
        self.rulepacks = {}
        self.rulepack = None
        self.rule_metadata = {}
        self.last_scan_result = None
        self._inline_rulepack_version = None
        self._source_versions = {}
        valid_paths = self.get_scan_files()

        if not valid_paths:
            return {}

        # Admission: freeze every configured rule source exactly once,
        # before any file is matched.  All matchers in this scan receive the
        # same immutable snapshot(s).
        self.scan_id = uuid.uuid4().hex
        matcher_options = self._admit_rulepacks()
        # ``generation`` identifies the rulepack state, not merely this
        # process invocation: unchanged rules keep the same value across
        # restarts, while a complete refresh gets a new one.
        self.scan_generation = (
            self.rulepack.generation if self.rulepack else self.scan_id)
        self.generation = self.scan_generation
        matcher_options['scan_generation'] = self.scan_generation

        if (
                matcher_options.get('match_rulepack')
                or matcher_options.get('match_rules')):
            results['pattern_matcher'] = PatternMatcher(
                matcher_options).scan(valid_paths)
        if (
                matcher_options.get('ts_rulepack')
                or matcher_options.get('ts_rules')):
            results['treesitter_matcher'] = TreeSitterMatcher(
                matcher_options).scan(valid_paths)
        if (
                matcher_options.get('choice_rulepack')
                or matcher_options.get('choice_rules')):
            results['choice_matcher'] = ChoiceMatcher(
                matcher_options).scan(valid_paths)
        if (
                matcher_options.get('sgrep_rulepack')
                or matcher_options.get('sgrep_rules')):
            results['semantic_grep'] = SemanticGrep(
                matcher_options).scan(valid_paths)

        self._add_rulepack_metadata(results)
        self.last_scan_result = results
        return results

    @property
    def rule_source(self):
        """Primary rule source frozen for the most recent scan."""
        return self.rulepack.source if self.rulepack else None

    @property
    def rulepack_source(self):
        """Primary rule source frozen for the most recent scan."""
        return self.rule_source

    @property
    def rules_version(self):
        """Primary rule version frozen for the most recent scan."""
        return self.rulepack.version if self.rulepack else None

    @property
    def rulepack_version(self):
        """Primary rule version frozen for the most recent scan."""
        return self.rules_version

    @property
    def rulepack_id(self):
        """Primary rulepack identity frozen for the most recent scan."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def rulepack_identity(self):
        """Primary rulepack identity frozen for the most recent scan."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def collection_id(self):
        """Primary rule collection identity (alias)."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def ruleset_id(self):
        """Primary rule collection identity (alias)."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def rule_generation(self):
        """Primary rulepack generation frozen for the most recent scan."""
        return self.rulepack.generation if self.rulepack else None

    @property
    def scan_rulepack(self):
        """Primary frozen rulepack (alias)."""
        return self.rulepack

    @property
    def rule_snapshot(self):
        """Primary frozen rulepack (alias)."""
        return self.rulepack

    @property
    def rule_snapshots(self):
        """All frozen rulepacks in the most recent scan."""
        return self.rulepacks

    @property
    def ruleset(self):
        """Primary frozen rulepack (alias)."""
        return self.rulepack

    @property
    def rule_set(self):
        """Primary frozen rulepack (alias)."""
        return self.rulepack

    @property
    def snapshot(self):
        """Primary frozen rulepack (alias)."""
        return self.rulepack

    def _rulepack_option(self):
        """Return the generic rulepack option in either accepted spelling."""
        for key in ('rulepack', 'rule_pack', 'ruleset'):
            value = self.options.get(key)
            if value is not None:
                return value
        return None

    def _derive_rule_sources(self):
        """Resolve explicit matcher options over an optional rulepack base."""
        keys = (
            'match_rules',
            'ts_rules',
            'choice_rules',
            'sgrep_rules',
        )
        sources = {
            key: self.options.get(key)
            for key in keys
        }
        explicit = {
            key: bool(self.options.get(key))
            for key in keys
        }
        base = self._rulepack_option()
        if not base:
            return sources, explicit

        if isinstance(base, dict):
            base_version = (
                base.get('version') or base.get('rulepack_version'))
            aliases = {
                'match': 'match_rules',
                'pattern': 'match_rules',
                'pattern_matcher': 'match_rules',
                'treesitter': 'ts_rules',
                'tree_sitter': 'ts_rules',
                'ts': 'ts_rules',
                'choice': 'choice_rules',
                'choice_matcher': 'choice_rules',
                'sgrep': 'sgrep_rules',
                'semantic_grep': 'sgrep_rules',
                'semgrep': 'sgrep_rules',
            }
            if isinstance(base.get('rules'), list):
                # An in-memory rulepack document.
                if not explicit['match_rules']:
                    sources['match_rules'] = base
                    self._inline_rulepack_version = base_version
                    if base_version:
                        self._source_versions['match_rules'] = base_version
                return sources, explicit
            for raw_key, value in base.items():
                key = aliases.get(raw_key, raw_key)
                if key in sources and not explicit[key]:
                    sources[key] = value
                    if base_version:
                        self._source_versions[key] = base_version
            return sources, explicit

        if isinstance(base, (RulePack, RuleSet, list, tuple)):
            if not explicit['match_rules']:
                sources['match_rules'] = base
            return sources, explicit

        text = str(base)
        path = Path(text)
        if path.is_dir():
            candidates = {
                'match_rules': (
                    'pattern_matcher', 'patterns', 'regex', 'rules'),
                'ts_rules': (
                    'treesitter_matcher', 'tree_sitter', 'tree-sitter',
                    'treesitter', 'ts'),
                'choice_rules': ('choice_matcher', 'choice', 'choices'),
                'sgrep_rules': ('semantic_grep', 'semgrep', 'sgrep'),
            }
            for key, names in candidates.items():
                if explicit[key]:
                    continue
                for name in names:
                    candidate = path / name
                    if candidate.is_dir():
                        sources[key] = candidate.as_posix()
                        break
            if not explicit['match_rules'] and not sources['match_rules']:
                # Only treat a flat rulepack directory as a pattern rule
                # source when no matcher-specific subdirectory was found.
                # Otherwise a semantic-grep/choice-only pack would be parsed
                # as pattern rules as well.
                if not any(
                        sources[key] for key in keys
                        if key != 'match_rules'):
                    if any(path.rglob('*.yaml')) or any(path.rglob('*.yml')):
                        sources['match_rules'] = path.as_posix()
        elif not explicit['match_rules']:
            # A single rule file or URL is a pattern rulepack.
            sources['match_rules'] = text
        return sources, explicit

    def _version_for(self, key):
        """Return an explicit version override for one matcher source."""
        pack_option = RULEPACK_OPTION_KEYS.get(key, f'{key}_rulepack')
        return (
            self.options.get(f'{key}_version')
            or self.options.get(f'{pack_option}_version')
            or self.options.get('rulepack_version')
            or self.options.get('rule_pack_version')
            or self.options.get('rule_version')
            or self.options.get('rules_version')
            or self.options.get('ruleset_version')
            or self._source_versions.get(key)
            or self._inline_rulepack_version
        )

    def _allow_stale(self):
        """Whether a refresh failure may return the previous complete pack."""
        fresh = bool(self.options.get('fresh_rulepack'))
        return bool(self.options.get('rulepack_allow_stale', True)) and not fresh

    def _resolve_rulepack(self, key, source, raw=False, cache=None):
        """Resolve one source into an immutable snapshot (or ``None``)."""
        if source is None:
            return None
        if isinstance(source, RulePack):
            return source
        if isinstance(source, RuleSet):
            return source.rulepack or rulepack_from_rules(source)
        cache_key = (source_key(source), raw)
        if cache is not None and cache_key in cache:
            return cache[cache_key]

        pack_option = RULEPACK_OPTION_KEYS.get(key, f'{key}_rulepack')
        direct = self.options.get(pack_option)
        if direct is not None:
            pack = coerce_rulepack(
                direct, raw=raw, allow_stale=self._allow_stale())
        else:
            pack = None

        if pack is None:
            version = self._version_for(key)
            if raw:
                try:
                    pack = matcher_helpers.get_semgrep_rulepack(
                        source,
                        version=version,
                        allow_stale=self._allow_stale(),
                    )
                except LibsastError:
                    # Semgrep also accepts registry aliases, policy names
                    # and other non-filesystem configs; leave those to
                    # Semgrep itself exactly as before.
                    pack = None
                if pack is not None and not pack.files:
                    # Empty directories have nothing to freeze; let Semgrep
                    # report its own config error as before.
                    pack = None
            else:
                try:
                    rules = matcher_helpers.get_rules(
                        source,
                        version=version,
                        allow_stale=self._allow_stale(),
                    )
                except LibsastError:
                    # A custom/old get_rules implementation may raise
                    # instead of using the rulepack store.  Preserve the
                    # same last-known-good boundary here.
                    if not self._allow_stale():
                        raise
                    pack = matcher_helpers.get_last_known_good_rulepack(
                        source)
                    if pack is None:
                        raise
                    rules = pack.rule_set()
                if rules is None:
                    pack = None
                else:
                    pack = getattr(rules, 'rulepack', None)
                    if pack is None:
                        pack = rulepack_from_rules(
                            rules, source=source, version=version)
        if cache is not None and pack is not None:
            cache[cache_key] = pack
        return pack

    def _admit_rulepacks(self):
        """Freeze all rule sources and build per-scan matcher options."""
        sources, explicit = self._derive_rule_sources()
        matcher_options = dict(self.options)
        matcher_options['scan_generation'] = self.scan_id
        cache = {}

        for key in (
                'match_rules',
                'ts_rules',
                'choice_rules',
                'sgrep_rules',
        ):
            source = sources.get(key)
            pack_option = RULEPACK_OPTION_KEYS[key]
            if not source and not self.options.get(pack_option):
                continue
            if not source and self.options.get(pack_option):
                source = self.options.get(pack_option)
            pack = self._resolve_rulepack(
                key,
                source,
                raw=(key == 'sgrep_rules'),
                cache=cache,
            )
            if pack is None:
                # Preserve non-filesystem Semgrep configs and empty legacy
                # rule files exactly as before.
                continue
            self.rulepacks[key] = pack
            matcher_options[pack_option] = pack
            matcher_options[key] = pack.source

        if self.rulepacks:
            # Primary pack follows matcher execution precedence.
            for key in (
                    'match_rules',
                    'ts_rules',
                    'choice_rules',
                    'sgrep_rules',
            ):
                if key in self.rulepacks:
                    self.rulepack = self.rulepacks[key]
                    break
        return matcher_options

    def _add_rulepack_metadata(self, results):
        """Attach immutable rule provenance to the scan report."""
        if not self.rulepacks:
            return
        matcher_names = {
            'match_rules': 'PatternMatcher',
            'ts_rules': 'TreeSitterMatcher',
            'choice_rules': 'ChoiceMatcher',
            'sgrep_rules': 'SemanticGrep',
        }
        infos = {}
        metadata_inputs = []
        for key, pack in self.rulepacks.items():
            matcher = matcher_names.get(key, key)
            infos[key] = rulepack_metadata(
                pack,
                scan_generation=self.scan_generation,
                matcher=matcher,
                option=key,
            )
            metadata_inputs.append((pack, matcher, key))

        self.rule_metadata = build_rule_metadata(
            metadata_inputs, scan_generation=self.scan_generation)
        result_packs = {
            'pattern_matcher': ('match_rules', 'PatternMatcher'),
            'treesitter_matcher': ('ts_rules', 'TreeSitterMatcher'),
            'choice_matcher': ('choice_rules', 'ChoiceMatcher'),
        }
        for result_key, (option_key, matcher_name) in result_packs.items():
            pack = self.rulepacks.get(option_key)
            if pack is None:
                continue
            for rule_id in results.get(result_key, {}).keys():
                self.rule_metadata.setdefault(rule_id, {
                    'id': rule_id,
                    'rule_id': rule_id,
                    'source': pack.source,
                    'rule_source': pack.source,
                    'version': pack.version,
                    'rule_version': pack.version,
                    'identity': pack.identity,
                    'rulepack_id': pack.identity,
                    'generation': pack.generation,
                    'rulepack_generation': pack.generation,
                    'scan_generation': self.scan_generation,
                    'matchers': [matcher_name],
                    'options': [option_key],
                    'rulepack': finding_rulepack(
                        pack,
                        rule_id,
                        scan_generation=self.scan_generation),
                })
        # Semgrep parses its own rule ids; bind those findings to the same
        # frozen generation even though libsast did not decode them.
        semantic_pack = self.rulepacks.get('sgrep_rules')
        if semantic_pack is not None:
            for rule_id in (
                    results.get('semantic_grep', {})
                    .get('matches', {})
                    .keys()):
                self.rule_metadata.setdefault(rule_id, {
                    'id': rule_id,
                    'rule_id': rule_id,
                    'source': semantic_pack.source,
                    'rule_source': semantic_pack.source,
                    'version': semantic_pack.version,
                    'rule_version': semantic_pack.version,
                    'identity': semantic_pack.identity,
                    'rulepack_id': semantic_pack.identity,
                    'generation': semantic_pack.generation,
                    'rulepack_generation': semantic_pack.generation,
                    'scan_generation': self.scan_generation,
                    'matchers': ['SemanticGrep'],
                    'options': ['sgrep_rules'],
                    'rulepack': finding_rulepack(
                        semantic_pack,
                        rule_id,
                        scan_generation=self.scan_generation),
                })

        results['rulepacks'] = infos
        # Common singular spelling always names the primary rulepack (the
        # same object precedence used for ``Scanner.rulepack``).
        primary_key = next(
            key for key in (
                'match_rules', 'ts_rules', 'choice_rules', 'sgrep_rules')
            if key in infos)
        results['rulepack'] = infos[primary_key]
        results['rule_pack'] = results['rulepack']
        results['ruleset'] = results['rulepack']
        results['rulepack_id'] = self.rulepack.identity
        results['rulepack_identity'] = self.rulepack.identity
        results['collection_id'] = self.rulepack.identity
        results['ruleset_id'] = self.rulepack.identity
        results['rulepack_source'] = self.rulepack.source
        results['rulepack_version'] = self.rulepack.version
        results['rule_metadata'] = self.rule_metadata
        results['scan_generation'] = self.scan_generation
        results['generation'] = self.scan_generation
        results['scan_id'] = self.scan_id

    def get_scan_files(self):
        """Get files valid for scanning."""
        if not isinstance(self.paths, list):
            raise InvalidPathError('Path should be a list')

        all_files = set()
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                all_files.update({
                    pfile
                    for pfile in pobj.rglob('*')
                    if self.validate_file(pfile)
                })
            elif pobj.is_file() and self.validate_file(pobj):
                all_files.add(pobj)

        return all_files

    def validate_file(self, path):
        """Check if we should scan the file."""
        # Early exit if the path is not a file or does not exist.
        # Symlinks are skipped: one in the scanned tree can point outside it.
        if path.is_symlink() or not path.exists() or not path.is_file():
            return False

        # Validate against ignore conditions
        ignore_conditions = any([
            any(pp in path.as_posix() for pp in self.ignore_paths),
            any(fnmatch(path.name, pattern) for pattern in self.ignore_filenames),
            path.suffix.lower() in self.ignore_extensions,
        ])

        return not ignore_conditions
