# -*- coding: utf_8 -*-
"""Immutable rulepack snapshots used by every matcher in one scan.

Rules can live in a local file, a directory or behind an HTTP endpoint.  A
scan must never observe two versions of that rule source.  :class:`RulePack`
captures the complete rule set at scan admission and binds it to a stable
content version/identity.  :class:`RuleSet` keeps the historical list API
used by the matchers while carrying that snapshot as metadata.

The module deliberately does not import the matcher helpers at import time:
``libsast.core_matcher.helpers`` imports this module, and only the download
helper is needed lazily.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import threading
import time
import weakref
from dataclasses import (
    dataclass,
    field,
    replace,
)
from pathlib import Path

from libsast.common import read_yaml
from libsast.exceptions import (
    InvalidRuleError,
    InvalidRuleFormatError,
    MissingRuleError,
    RulePackChangedError,
    RulePackIntegrityError,
    StaleRulePackError,
    YamlRuleLoadError,
    YamlRuleParseError,
)
from libsast.standards import get_mapping


RULEPACK_FORMAT = 'libsast-rulepack-v1'
MANIFEST_NAMES = (
    'rulepack.yaml',
    'rulepack.yml',
    'rulepack.json',
    '.rulepack.yaml',
    '.rulepack.yml',
    '.rulepack.json',
    'ruleset.yaml',
    'ruleset.yml',
    'manifest.yaml',
    'manifest.yml',
    'manifest.json',
)
RULE_EXTENSIONS = ('.yaml', '.yml')
# A rule source that is actively being rewritten is retried this many times
# before the snapshot is rejected.  We never publish a partial read.
MAX_SOURCE_READ_ATTEMPTS = 3


def _json_default(value):
    """Best-effort canonical value for YAML types not known to JSON."""
    if isinstance(value, (set, tuple)):
        return list(value)
    if isinstance(value, bytes):
        return value.decode('utf-8', 'ignore')
    return str(value)


def _canonical_json(value):
    """Return a stable JSON representation with sorted object keys."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=_json_default,
    )


def _sha256(data) -> str:
    """Return a SHA-256 hex digest for bytes or text."""
    if isinstance(data, str):
        data = data.encode('utf-8', 'ignore')
    return hashlib.sha256(data).hexdigest()


def _normalise_source(source) -> str:
    """Return the caller-facing source string for a rule location."""
    if isinstance(source, Path):
        return source.as_posix()
    return str(source)


def source_key(source) -> str:
    """Return a stable cache key for a rule source.

    Local paths are resolved so ``rules``, ``./rules`` and an absolute path
    share one snapshot.  URLs are kept verbatim and in-memory snapshots are
    keyed by their identity.
    """
    if isinstance(source, RulePack):
        return f'memory:{source.identity}'
    if isinstance(source, RuleSet):
        if source.rulepack is not None:
            return f'memory:{source.rulepack.identity}'
        source = list(source)
    if isinstance(source, (list, tuple)):
        return f'memory:{_rules_identity(source)}'
    if isinstance(source, dict):
        return f'memory:{_rules_identity([source])}'
    text = _normalise_source(source)
    if text.startswith(('http://', 'https://')):
        return text
    path = Path(text)
    try:
        return path.expanduser().resolve(strict=False).as_posix()
    except (OSError, RuntimeError):
        return path.absolute().as_posix()


@dataclass(frozen=True)
class RuleFile:
    """One immutable file that belongs to a rulepack snapshot."""

    path: str
    digest: str
    size: int
    content: bytes = field(
        default=b'', repr=False, compare=False, metadata={'json': False})
    mtime_ns: int | None = None

    def as_dict(self):
        """Return a JSON-serialisable file record (content excluded)."""
        return {
            'path': self.path,
            'digest': self.digest,
            'size': self.size,
        }


@dataclass(frozen=True)
class RuleRecord:
    """Provenance for one decoded rule."""

    rule_id: str | None
    rule_type: str | None
    source_file: str
    digest: str
    version: str
    identity: str
    generation: str

    def as_dict(self):
        """Return a JSON-serialisable rule record."""
        return {
            'id': self.rule_id,
            'rule_id': self.rule_id,
            'type': self.rule_type,
            'source': self.source_file,
            'rule_source': self.source_file,
            'source_file': self.source_file,
            'digest': self.digest,
            'version': self.version,
            'rulepack_version': self.version,
            'identity': self.identity,
            'rulepack_id': self.identity,
            'generation': self.generation,
        }


@dataclass(frozen=True)
class RulePack:
    """An immutable, versioned snapshot of a complete rule source.

    ``source`` is the location supplied by the caller, ``version`` is either
    an explicit manifest/option version or the content digest, ``identity``
    is the digest of the complete rule collection and ``generation`` is the
    value consumers should use to attribute findings to one rulepack state.
    Re-scanning unchanged content reuses the same object through
    :data:`default_store`.
    """

    source: str
    version: str
    identity: str
    generation: str
    rules: tuple = ()
    files: tuple = ()
    rule_records: tuple = ()
    source_kind: str = 'memory'
    manifest_version: str | None = None
    raw: bool = False
    loaded_at: float = field(default_factory=time.time, compare=False)
    stale: bool = field(default=False, compare=False)

    # -- identity aliases -------------------------------------------------
    @property
    def id(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def rulepack_id(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def rulepack_identity(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def fingerprint(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def digest(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def checksum(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def collection_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def collection_identity(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def ruleset_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def ruleset_identity(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def set_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def rule_source(self):
        """Rule source (alias)."""
        return self.source

    @property
    def source_path(self):
        """Local source path, or ``None`` for remote/memory sources."""
        if self.source_kind in ('file', 'directory'):
            return Path(self.source)
        return None

    @property
    def resolved_source(self):
        """Canonical cache identity for the rule source."""
        return source_key(self.source)

    @property
    def rule_files(self):
        """Immutable file records that make up this snapshot."""
        return self.files

    @property
    def file_paths(self):
        """Relative paths that make up this snapshot."""
        return [item.path for item in self.files]

    @property
    def rules_version(self):
        """Rule version (alias)."""
        return self.version

    @property
    def rulepack_version(self):
        """Rule version (alias)."""
        return self.version

    @property
    def rulepack_generation(self):
        """Rulepack generation (alias)."""
        return self.generation

    @property
    def rule_count(self):
        """Number of decoded rules in this snapshot."""
        return len(self.rules)

    @property
    def rule_ids(self):
        """Rule ids in stable source order."""
        return [
            record.rule_id for record in self.rule_records
            if record.rule_id is not None
        ]

    @property
    def rules_list(self):
        """Return the historical list representation."""
        return list(self.rules)

    def __iter__(self):
        """Iterate over the immutable rules in this snapshot."""
        return iter(self.rules)

    def __len__(self):
        """Number of rules in this snapshot."""
        return len(self.rules)

    def __getitem__(self, index):
        """Index into the immutable rules in this snapshot."""
        return self.rules[index]

    def rule_set(self):
        """Return a list-compatible rule collection bound to this snapshot."""
        return RuleSet(self.rules, self)

    def as_dict(self, include_rules=True):
        """Return a JSON-serialisable, output-safe description."""
        info = {
            'source': self.source,
            'rule_source': self.source,
            'resolved_source': self.resolved_source,
            'source_kind': self.source_kind,
            'version': self.version,
            'rule_version': self.version,
            'rulepack_version': self.version,
            'identity': self.identity,
            'rulepack_id': self.identity,
            'fingerprint': self.identity,
            'collection_id': self.identity,
            'ruleset_id': self.identity,
            'generation': self.generation,
            'rulepack_generation': self.generation,
            'rule_count': self.rule_count,
            'rule_ids': self.rule_ids,
            'files': [item.as_dict() for item in self.files],
            'manifest_version': self.manifest_version,
            'stale': bool(self.stale),
            'fallback': bool(self.stale),
        }
        if include_rules:
            info['rules'] = [
                record.as_dict() for record in self.rule_records]
            info['rule_index'] = {
                record.rule_id: record.as_dict()
                for record in self.rule_records
                if record.rule_id is not None
            }
        return info

    # -- frozen filesystem view (needed by Semgrep) ----------------------
    def materialize(self):
        """Return a stable filesystem path containing this exact snapshot.

        Semgrep takes a rule file or directory path rather than in-memory
        rules.  Writing the already-read bytes to a private temporary tree
        guarantees Semgrep cannot observe a rulepack update that happens
        after scan admission.  The temporary tree is removed when the pack
        is garbage collected.
        """
        cached = self.__dict__.get('_frozen_path')
        if cached:
            return cached
        if not self.files:
            raise StaleRulePackError(
                f'Rulepack {self.source} has no files to materialize.')

        tmpdir = tempfile.mkdtemp(prefix='libsast-rulepack-')
        root = Path(tmpdir)
        try:
            if self.source_kind == 'directory' or len(self.files) > 1:
                for item in self.files:
                    relative = Path(item.path)
                    if relative.is_absolute() or '..' in relative.parts:
                        relative = Path(relative.name)
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(item.content)
                frozen = root
            else:
                item = self.files[0]
                suffix = '.yaml'
                if item.path:
                    suffix = Path(item.path).suffix.lower() or suffix
                target = root / f'rulepack{suffix}'
                target.write_bytes(item.content)
                frozen = target
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

        object.__setattr__(self, '_frozen_path', frozen.as_posix())
        object.__setattr__(self, '_tempdir', tmpdir)
        weakref.finalize(
            self, shutil.rmtree, tmpdir, ignore_errors=True)
        return frozen.as_posix()

    def close(self):
        """Remove the temporary materialized view, if any."""
        tmpdir = self.__dict__.pop('_tempdir', None)
        self.__dict__.pop('_frozen_path', None)
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def __getstate__(self):
        """Exclude cached temporary paths from pickling/worker processes."""
        state = self.__dict__.copy()
        state.pop('_frozen_path', None)
        state.pop('_tempdir', None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __hash__(self):
        """Hash the snapshot by its stable identity fields."""
        return hash((
            self.source,
            self.version,
            self.identity,
            self.generation,
            self.raw,
        ))

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class RuleSet(list):
    """Historical list of rules that also carries its frozen snapshot."""

    def __init__(self, rules=(), rulepack: RulePack | None = None):
        # Keep each consumer's rule dictionaries private.  A matcher or caller
        # that mutates a rule cannot retroactively change the shared snapshot.
        super().__init__(copy.deepcopy(list(rules)))
        self.rulepack = rulepack

    def __reduce__(self):
        """Keep the snapshot metadata when the list crosses processes."""
        return (self.__class__, (list(self), self.rulepack))

    def copy(self):
        """Return another list bound to the same immutable snapshot."""
        return self.__class__(self, self.rulepack)

    @property
    def source(self):
        """Rule source (alias)."""
        return self.rulepack.source if self.rulepack else None

    @property
    def version(self):
        """Rule version (alias)."""
        return self.rulepack.version if self.rulepack else None

    @property
    def identity(self):
        """Rulepack identity (alias)."""
        return self.rulepack.identity if self.rulepack else None

    @property
    def generation(self):
        """Rulepack generation (alias)."""
        return self.rulepack.generation if self.rulepack else None

    @property
    def rulepack_id(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def rulepack_identity(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def fingerprint(self):
        """Rulepack identity (alias)."""
        return self.identity

    @property
    def rules_version(self):
        """Rule version (alias)."""
        return self.version

    @property
    def collection_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def collection_identity(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def ruleset_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def ruleset_identity(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def set_id(self):
        """Rule collection identity (alias)."""
        return self.identity

    @property
    def rule_count(self):
        """Number of rules in the attached snapshot."""
        return self.rulepack.rule_count if self.rulepack else len(self)

    @property
    def rule_ids(self):
        """Rule ids in the attached snapshot."""
        return self.rulepack.rule_ids if self.rulepack else [
            rule.get('id') for rule in self if isinstance(rule, dict)
        ]

    @property
    def files(self):
        """Rule files in the attached snapshot."""
        return self.rulepack.files if self.rulepack else ()

    def as_dict(self, include_rules=True):
        """Return snapshot metadata, if one is attached."""
        if self.rulepack is None:
            return {}
        return self.rulepack.as_dict(include_rules=include_rules)


class RulePackStore:
    """Process-local last-known-good store for complete rulepacks.

    A failed refresh never replaces the previous complete snapshot.  An
    unchanged refresh returns the existing object so all consumers of one
    generation observe the same identity.
    """

    def __init__(self):
        self._packs = {}
        self._lock = threading.RLock()

    def get(self, key):
        """Return a previously admitted pack, if any."""
        with self._lock:
            return self._packs.get(key)

    def put(self, key, pack):
        """Atomically publish ``pack`` and return the authoritative object."""
        with self._lock:
            previous = self._packs.get(key)
            if (
                    previous is not None
                    and previous.identity == pack.identity
                    and previous.version == pack.version
                    and previous.raw == pack.raw):
                return previous
            self._packs[key] = pack
            return pack

    def drop(self, key):
        """Forget one cached snapshot."""
        with self._lock:
            return self._packs.pop(key, None)

    def clear(self):
        """Forget every cached snapshot."""
        with self._lock:
            self._packs.clear()

    def items(self):
        """Return a snapshot of cached ``(key, pack)`` pairs."""
        with self._lock:
            return list(self._packs.items())

    def __len__(self):
        with self._lock:
            return len(self._packs)

    def __contains__(self, key):
        with self._lock:
            return key in self._packs


default_store = RulePackStore()
_STORE = default_store


def reset_rulepack_store():
    """Clear the last-known-good rulepack store (mostly for tests)."""
    _STORE.clear()


def clear_rulepack_cache():
    """Alias for :func:`reset_rulepack_store`."""
    reset_rulepack_store()


def clear_cache():
    """Alias for :func:`reset_rulepack_store`."""
    reset_rulepack_store()


def reset_rulepack_cache():
    """Alias for :func:`reset_rulepack_store`."""
    reset_rulepack_store()


def _rules_identity(rules):
    """Return a deterministic digest over decoded rule dictionaries."""
    canonical = []
    for rule in rules or ():
        if isinstance(rule, dict):
            canonical.append({
                key: rule[key] for key in sorted(rule)
            })
        else:
            canonical.append(rule)
    return _sha256(_canonical_json(canonical))


def _file_identity(files):
    """Return a deterministic digest over the complete source file set."""
    records = sorted(
        (
            item.path,
            item.digest,
            item.size,
        )
        for item in files
    )
    return _sha256(_canonical_json(records))


def _read_stable_bytes(path: Path):
    """Read one file and reject reads that raced a replacement."""
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or getattr(before, 'st_ino', None) != getattr(after, 'st_ino', None)
            or getattr(before, 'st_dev', None) != getattr(after, 'st_dev', None)):
        raise RulePackChangedError(
            f'Rule file changed while it was being read: {path}')
    return content, after


def _local_files(source: Path, raw=False):
    """Read one local file or directory into a stable list of RuleFile."""
    for _ in range(MAX_SOURCE_READ_ATTEMPTS):
        try:
            if source.is_file():
                paths = [source]
                root = source.parent
            elif source.is_dir():
                paths = sorted(
                    (
                        item for item in source.rglob('*')
                        if item.is_file() and not item.is_symlink()
                        and (
                            raw
                            or item.suffix.lower() in RULE_EXTENSIONS
                            or item.name in MANIFEST_NAMES
                        )
                    ),
                    key=lambda item: item.as_posix(),
                )
                root = source
            else:
                raise InvalidRuleError('This path is invalid')

            files = []
            read_stats = {}
            for path in paths:
                content, stat_result = _read_stable_bytes(path)
                relative = path.relative_to(root).as_posix()
                if path.parent != root and path != source:
                    relative = path.relative_to(root).as_posix()
                read_stats[path] = (
                    stat_result.st_size,
                    stat_result.st_mtime_ns,
                    getattr(stat_result, 'st_ino', None),
                    getattr(stat_result, 'st_dev', None),
                )
                files.append(RuleFile(
                    path=relative,
                    digest=_sha256(content),
                    size=len(content),
                    content=content,
                    mtime_ns=stat_result.st_mtime_ns,
                ))

            # Re-list after the read.  A file added or removed while the
            # snapshot was being built means the candidate is incomplete.
            if source.is_dir():
                current = sorted(
                    (
                        item.relative_to(source).as_posix()
                        for item in source.rglob('*')
                        if item.is_file() and not item.is_symlink()
                        and (
                            raw
                            or item.suffix.lower() in RULE_EXTENSIONS
                            or item.name in MANIFEST_NAMES
                        )
                    ),
                )
            else:
                current = [source.name]
            if current != [item.path for item in files]:
                raise RulePackChangedError(
                    f'Rule source changed while it was being read: {source}')
            # Check every file again after the complete set has been read.
            # This catches a writer that updates file A after it was read but
            # before file B, which would otherwise produce a mixed snapshot
            # even though each individual file read was internally stable.
            for path, expected in read_stats.items():
                try:
                    after = path.stat()
                except OSError as exp:
                    raise RulePackChangedError(
                        f'Rule source changed while it was being read: {path}'
                    ) from exp
                actual = (
                    after.st_size,
                    after.st_mtime_ns,
                    getattr(after, 'st_ino', None),
                    getattr(after, 'st_dev', None),
                )
                if actual != expected:
                    raise RulePackChangedError(
                        'Rule source changed while it was being read: '
                        f'{path}')
            return files
        except RulePackChangedError:
            continue
        except (OSError, ValueError) as exp:
            raise InvalidRuleError(
                f'Unable to read rule source: {source}') from exp
    raise RulePackChangedError(
        f'Rule source kept changing while it was being read: {source}')


def _remote_files(source: str):
    """Download a remote rule source as one stable RuleFile."""
    # Imported lazily to avoid a module cycle with core_matcher.helpers.
    from libsast.core_matcher.helpers import download_rule

    text = download_rule(source)
    if text is None:
        return []
    content = text.encode('utf-8', 'ignore')
    name = Path(source.split('?', 1)[0]).name or 'rulepack.yaml'
    return [RuleFile(
        path=name,
        digest=_sha256(content),
        size=len(content),
        content=content,
    )]


def _manifest_for(source: Path, files):
    """Find and parse an optional sidecar manifest for a local source."""
    if source.is_dir():
        base = source
    else:
        base = source.parent
    for name in MANIFEST_NAMES:
        candidate = base / name
        if not candidate.is_file():
            continue
        try:
            parsed = read_yaml(candidate)
        except (YamlRuleParseError, YamlRuleLoadError):
            raise
        if isinstance(parsed, dict):
            parsed['__manifest_file__'] = candidate.name
            return parsed
    for version_name in (
            'VERSION', 'version', 'VERSION.txt', 'version.txt'):
        version_file = base / version_name
        if not version_file.is_file():
            continue
        try:
            version = version_file.read_text('utf-8', 'ignore').strip()
        except OSError:
            version = ''
        if version:
            return {
                'version': version,
                '__manifest_file__': version_file.name,
            }
    return None


def _manifest_for_remote(name, raw_text):
    """Return no sidecar for a remote source; headers/content drive identity."""
    return None


def _drop_raw_sidecars(files):
    """Keep Semgrep-only file sets free of rulepack manifest sidecars."""
    kept = []
    for item in files:
        if Path(item.path).name not in MANIFEST_NAMES:
            kept.append(item)
            continue
        try:
            parsed = read_yaml(item.content.decode('utf-8', 'ignore'), True)
        except (YamlRuleParseError, YamlRuleLoadError):
            kept.append(item)
            continue
        if isinstance(parsed, dict) and 'rules' not in parsed:
            continue
        kept.append(item)
    return kept


def _validate_manifest(source, manifest, files):
    """Validate declared file digests before a manifest version is trusted."""
    if not manifest:
        return
    declared = manifest.get('files')
    if not declared:
        return
    actual = {
        item.path: item.digest for item in files
        if Path(item.path).name not in MANIFEST_NAMES
    }
    checks = {}
    if isinstance(declared, dict):
        checks = {str(path): str(digest) for path, digest in declared.items()}
    elif isinstance(declared, list):
        for item in declared:
            if isinstance(item, dict):
                path = item.get('path') or item.get('name')
                digest = (
                    item.get('sha256')
                    or item.get('digest')
                    or item.get('checksum'))
                if path and digest:
                    checks[str(path)] = str(digest)
    for path, digest in checks.items():
        normalized = Path(path).as_posix()
        if Path(normalized).name in MANIFEST_NAMES:
            continue
        if normalized not in actual:
            raise RulePackIntegrityError(
                f'Rulepack manifest references missing file: {path}')
        if actual[normalized] != digest:
            raise RulePackIntegrityError(
                f'Rulepack file digest mismatch: {path}')
    extra = sorted(set(actual) - set(checks))
    if extra:
        # A manifest that describes a complete generation must not silently
        # accept a partially written file left behind by a failed refresh.
        raise RulePackIntegrityError(
            'Rulepack contains files not declared by its manifest: '
            + ', '.join(extra))


def _decode_rule_files(files):
    """Decode YAML rule files and return ``(rules, records)``."""
    rules = []
    records = []
    for item in files:
        if item.path in MANIFEST_NAMES or Path(item.path).name in MANIFEST_NAMES:
            text = item.content.decode('utf-8', 'ignore')
            try:
                parsed = read_yaml(text, True)
            except (YamlRuleParseError, YamlRuleLoadError):
                raise
            if isinstance(parsed, dict) and 'rules' not in parsed:
                # A sidecar manifest is provenance, not a rule document.
                continue
        text = item.content.decode('utf-8', 'ignore')
        parsed = read_yaml(text, True)
        if not parsed:
            continue
        if isinstance(parsed, dict):
            if isinstance(parsed.get('rules'), list):
                document = parsed['rules']
            else:
                raise InvalidRuleFormatError(
                    'Rule file must contain a list of rules: '
                    f'{item.path}')
        elif isinstance(parsed, list):
            document = parsed
        else:
            raise InvalidRuleFormatError(
                f'Rule file is invalid: {item.path}')

        mapped = get_mapping(document)
        for rule in mapped:
            if not isinstance(rule, dict):
                raise InvalidRuleFormatError(
                    f'Rule format is invalid in: {item.path}')
            rules.append(rule)
            records.append({
                'rule_id': rule.get('id'),
                'rule_type': rule.get('type'),
                'source_file': item.path,
                'digest': item.digest,
            })
    return rules, records


def _make_pack(source, files, rules, records, source_kind, raw=False,
               version_override=None, manifest=None):
    """Build a RulePack and bind every rule to the same identity."""
    # Manifest sidecars describe the pack; they are not rules.  A version
    # label change must not change the rule collection identity.
    identity_files = [
        item for item in files
        if Path(item.path).name not in MANIFEST_NAMES
    ]
    file_identity = _file_identity(identity_files)
    rules_identity = _rules_identity(rules) if rules else file_identity
    identity = _sha256(_canonical_json({
        'format': RULEPACK_FORMAT,
        'files': [
            [item.path, item.digest, item.size]
            for item in sorted(
                identity_files, key=lambda value: value.path)
        ],
        'rules': rules_identity,
    }))
    manifest_version = None
    if manifest:
        manifest_info = manifest.get('rulepack')
        if not isinstance(manifest_info, dict):
            manifest_info = manifest.get('metadata')
        if not isinstance(manifest_info, dict):
            manifest_info = {}
        manifest_version = (
            manifest.get('version')
            or manifest.get('Version')
            or manifest.get('rulepack_version')
            or manifest.get('id')
            or manifest_info.get('version')
            or manifest_info.get('Version')
            or manifest_info.get('id'))
    if version_override is None:
        version = str(manifest_version) if manifest_version else file_identity
    else:
        version = str(version_override)
        if not version:
            version = (
                str(manifest_version) if manifest_version else file_identity)
    generation = _sha256(
        f'{RULEPACK_FORMAT}:{version}:{identity}'.encode('utf-8'))
    records = [
        RuleRecord(
            rule_id=item['rule_id'],
            rule_type=item['rule_type'],
            source_file=item['source_file'],
            digest=item['digest'],
            version=version,
            identity=identity,
            generation=generation,
        )
        for item in records
    ]
    return RulePack(
        source=_normalise_source(source),
        version=version,
        identity=identity,
        generation=generation,
        rules=tuple(rules),
        files=tuple(files),
        rule_records=tuple(records),
        source_kind=source_kind,
        manifest_version=(
            str(manifest_version) if manifest_version else None),
        raw=raw,
    )


def rulepack_from_rules(rules, source='memory', version=None):
    """Create an immutable snapshot from an in-memory rule list."""
    frozen = copy.deepcopy(list(rules or ()))
    records = [
        {
            'rule_id': (
                rule.get('id') if isinstance(rule, dict) else None),
            'rule_type': (
                rule.get('type') if isinstance(rule, dict) else None),
            'source_file': '<memory>',
            'digest': _rules_identity([rule]),
        }
        for rule in frozen
    ]
    pack = _make_pack(
        source=source,
        files=[],
        rules=frozen,
        records=records,
        source_kind='memory',
        version_override=version,
    )
    return pack


def _load_candidate(source, raw=False, version_override=None):
    """Read and decode one complete candidate snapshot."""
    if isinstance(source, RulePack):
        if version_override is None:
            return source
        return replace(
            source,
            version=str(version_override),
            generation=_sha256(
                f'{RULEPACK_FORMAT}:{version_override}:{source.identity}'
                .encode('utf-8')),
        )
    if isinstance(source, RuleSet):
        if source.rulepack is not None:
            return _load_candidate(
                source.rulepack, raw=raw, version_override=version_override)
        source = list(source)
    if isinstance(source, (list, tuple)):
        pack = rulepack_from_rules(source, version=version_override)
        return pack
    if isinstance(source, dict):
        if isinstance(source.get('rules'), list):
            return rulepack_from_rules(
                source['rules'],
                source=str(source.get('source') or 'memory'),
                version=(
                    version_override
                    if version_override is not None
                    else source.get('version')),
            )
        raise InvalidRuleError('This rulepack format is invalid')
    if not source:
        raise MissingRuleError('Rule location is missing.')

    text = _normalise_source(source)
    manifest = None
    if text.startswith(('http://', 'https://')):
        files = _remote_files(text)
        source_kind = 'url'
    else:
        path = Path(text)
        if not path.exists():
            raise InvalidRuleError('This path is invalid')
        files = _local_files(path, raw=raw)
        source_kind = 'directory' if path.is_dir() else 'file'
        manifest = _manifest_for(path, files)
        _validate_manifest(path, manifest, files)
        if raw:
            files = _drop_raw_sidecars(files)

    if not files:
        if source_kind == 'directory':
            # Historical behaviour: an existing but empty rule directory is
            # a valid (empty) rule set, not an invalid path.
            return _make_pack(
                source=text,
                files=[],
                rules=[],
                records=[],
                source_kind=source_kind,
                raw=raw,
                version_override=version_override,
                manifest=manifest,
            )
        if source_kind == 'url':
            # Historical behaviour: an empty downloaded rule document was
            # treated as "no rules" rather than an invalid path.
            return None
        raise InvalidRuleError('This path is invalid')

    rules = []
    records = []
    if not raw:
        rules, records = _decode_rule_files(files)
    return _make_pack(
        source=text,
        files=files,
        rules=rules,
        records=records,
        source_kind=source_kind,
        raw=raw,
        version_override=version_override,
        manifest=manifest,
    )


def get_rulepack(source, raw=False, allow_stale=True, version=None,
                 cache=True):
    """Return a complete immutable rulepack snapshot.

    The candidate is validated in full before it is published.  If a refresh
    fails and a complete previous snapshot exists for the same source, the
    previous snapshot is returned instead of mixing old and new files.  Set
    ``allow_stale=False`` to surface the refresh failure to the caller.
    """
    if source is None:
        raise MissingRuleError('Rule location is missing.')
    key = (source_key(source), bool(raw))
    try:
        candidate = _load_candidate(
            source, raw=raw, version_override=version)
    except Exception:
        # Any failure while building a candidate (download, decode, partial
        # file set, malformed rule dict) means there is no complete new
        # snapshot.  Keep the previous complete generation visible instead
        # of publishing a mixture.  With no previous snapshot the original
        # failure is surfaced unchanged for existing callers/tests.
        if allow_stale:
            previous = _STORE.get(key) if cache else None
            if previous is not None and previous.raw == raw:
                # Keep the previous complete identity/version but surface
                # that this scan is using a last-known-good snapshot.
                return replace(previous, stale=True)
        raise
    if candidate is None:
        if allow_stale and cache:
            previous = _STORE.get(key)
            if previous is not None and previous.raw == raw:
                return replace(previous, stale=True)
        return None
    if not cache:
        return candidate
    return _STORE.put(key, candidate)


def load_rulepack(source, **kwargs):
    """Alias for :func:`get_rulepack`."""
    return get_rulepack(source, **kwargs)


def snapshot_rules(source, **kwargs):
    """Alias for :func:`get_rulepack`."""
    return get_rulepack(source, **kwargs)


def get_rules_snapshot(source, **kwargs):
    """Alias for :func:`get_rulepack`."""
    return get_rulepack(source, **kwargs)


def coerce_rulepack(value, raw=False, allow_stale=True):
    """Coerce a source, RuleSet or RulePack into a RulePack (or ``None``)."""
    if value is None:
        return None
    if isinstance(value, RulePack):
        return value
    if isinstance(value, RuleSet):
        return value.rulepack or get_rulepack(
            list(value), raw=raw, allow_stale=False)
    if isinstance(value, (list, tuple)):
        return rulepack_from_rules(value)
    return get_rulepack(
        value, raw=raw, allow_stale=allow_stale)


def rulepack_metadata(pack, scan_generation=None, matcher=None, option=None):
    """Build output metadata for one pack used by one matcher."""
    if pack is None:
        return None
    info = pack.as_dict(include_rules=True)
    if scan_generation is not None:
        info['scan_generation'] = str(scan_generation)
    if matcher is not None:
        info['matcher'] = matcher
    if option is not None:
        info['option'] = option
    return info


def finding_rulepack(pack, rule_id=None, scan_generation=None):
    """Return compact rulepack evidence attached to one finding."""
    if pack is None:
        return {}
    info = {
        'rule_id': rule_id,
        'source': pack.source,
        'version': pack.version,
        'identity': pack.identity,
        'fingerprint': pack.identity,
        'rulepack_id': pack.identity,
        'rulepack_identity': pack.identity,
        'collection_id': pack.identity,
        'ruleset_id': pack.identity,
        'generation': pack.generation,
        'stale': bool(pack.stale),
        'fallback': bool(pack.stale),
    }
    if scan_generation is not None:
        info['scan_generation'] = str(scan_generation)
    return info


def attach_rulepack_evidence(finding, pack, rule_id=None,
                             scan_generation=None):
    """Attach compact rulepack evidence to one finding dictionary.

    The historical ``files``/``metadata``/``choice`` fields are untouched;
    the additional fields simply make attribution explicit for consumers.
    """
    if pack is None:
        return finding
    info = finding_rulepack(
        pack, rule_id=rule_id, scan_generation=scan_generation)
    finding['rulepack'] = info
    for key in (
            'rule_id',
            'source',
            'version',
            'identity',
            'rulepack_id',
            'collection_id',
            'ruleset_id',
            'generation',
            'scan_generation',
            'stale',
            'fallback'):
        if key not in info:
            continue
        target = 'rule_source' if key == 'source' else key
        if key == 'version':
            finding['rule_version'] = info[key]
            finding['rulepack_version'] = info[key]
        elif key == 'identity':
            finding['rulepack_id'] = info[key]
            finding['rulepack_identity'] = info[key]
        elif key == 'generation':
            finding['rule_generation'] = info[key]
            finding['rulepack_generation'] = info[key]
        elif key == 'stale':
            finding['rule_stale'] = bool(info[key])
        elif key in ('collection_id', 'ruleset_id'):
            finding[key] = info[key]
        else:
            finding[target] = info[key]
            if key == 'source':
                finding['rulepack_source'] = info[key]
    return finding


def build_rule_metadata(packs, scan_generation=None):
    """Build a rule-id to provenance map from ``(pack, matcher, option)``."""
    metadata = {}
    for pack, matcher, option in packs:
        if pack is None:
            continue
        for record in pack.rule_records:
            if record.rule_id is None:
                continue
            entry = metadata.setdefault(record.rule_id, {
                'id': record.rule_id,
                'rule_id': record.rule_id,
                'source': pack.source,
                'rule_source': pack.source,
                'version': pack.version,
                'rule_version': pack.version,
                'identity': pack.identity,
                'rulepack_id': pack.identity,
                'collection_id': pack.identity,
                'ruleset_id': pack.identity,
                'generation': pack.generation,
                'rulepack_generation': pack.generation,
                'source_file': record.source_file,
                'type': record.rule_type,
                'matchers': [],
                'options': [],
            })
            if scan_generation is not None:
                entry['scan_generation'] = str(scan_generation)
            entry['rulepack'] = finding_rulepack(
                pack, record.rule_id, scan_generation=scan_generation)
            if matcher not in entry['matchers']:
                entry['matchers'].append(matcher)
            if option not in entry['options']:
                entry['options'].append(option)
    return metadata


# Compatibility spellings for consumers that prefer different casing or a
# more explicit snapshot name.
Rulepack = RulePack
Ruleset = RuleSet
RulePackSnapshot = RulePack
RuleSnapshot = RulePack
RuleSetSnapshot = RuleSet
load_ruleset = get_rulepack
get_ruleset = get_rulepack
snapshot_rulepack = get_rulepack
