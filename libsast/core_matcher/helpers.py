# -*- coding: utf_8 -*-
"""Helper Functions."""
import re

from libsast.exceptions import (
    MissingRuleError,
    RuleDownloadError,
)
from libsast.rulepack import (
    RulePack,
    RuleSet,
    get_rulepack as _get_rulepack,
    rulepack_from_rules,
)

import requests

# Default Single Line
DEF_SINGLE = re.compile(r'//.+', re.MULTILINE)
DEF_MULTI = re.compile(r'/\*([\S|\s]+?)\*/', re.MULTILINE)
XML_CMT = re.compile(r'<!--([\S|\s]+?)-->', re.MULTILINE)
REPL_REGEX = re.compile(r'\S', re.MULTILINE)


def download_rule(url):
    """Download Pattern File."""
    try:
        with requests.get(
                url,
                allow_redirects=True,
                timeout=10) as r:
            r.raise_for_status()
            return r.text
    except requests.exceptions.RequestException:
        raise RuleDownloadError(f'Failed to download from: {url}')


def get_rulepack(rule_loc, **kwargs):
    """Get an immutable snapshot of a rule location.

    This is the admission point used by :class:`libsast.Scanner` and by the
    individual matchers.  Keeping the historical :func:`get_rules` list API
    means existing callers do not need to change.
    """
    return _get_rulepack(rule_loc, **kwargs)


def get_semgrep_rulepack(rule_loc, **kwargs):
    """Get a raw rulepack snapshot suitable for ``semgrep --config``."""
    kwargs.setdefault('raw', True)
    return _get_rulepack(rule_loc, **kwargs)


def get_last_known_good_rulepack(rule_loc, raw=False):
    """Return the last complete snapshot for a source, if one exists.

    This is intentionally a read-only lookup.  Callers that need a fresh
    candidate must use :func:`get_rulepack`; this accessor is useful for
    auditing and recovery paths that must not trigger a download/read.
    """
    from libsast.rulepack import default_store, source_key

    return default_store.get((source_key(rule_loc), bool(raw)))


def get_rules(rule_loc, version=None, allow_stale=True):  # noqa: R701
    """Get pattern matcher rules.

    The returned object is a list for compatibility, but it also carries the
    frozen :class:`RulePack` snapshot as ``rulepack``/``version``/
    ``identity``/``generation`` attributes.  All matchers that receive the
    same source therefore share one immutable generation.
    """
    if not rule_loc:
        raise MissingRuleError('Rule location is missing.')
    if isinstance(rule_loc, RuleSet):
        return rule_loc
    if isinstance(rule_loc, RulePack):
        return rule_loc.rule_set()
    if isinstance(rule_loc, (list, tuple)):
        pack = rulepack_from_rules(
            rule_loc, version=version)
        return pack.rule_set()
    if isinstance(rule_loc, dict):
        pack = _get_rulepack(
            rule_loc, version=version, allow_stale=allow_stale)
        return pack.rule_set()

    pack = _get_rulepack(
        rule_loc, version=version, allow_stale=allow_stale)
    if pack is None:
        return None
    if not pack.rules and not pack.raw and pack.source_kind in (
            'file', 'url'):
        # Historical behaviour: an empty single rule file yielded None.
        return None
    return RuleSet(pack.rules, pack)


def comment_replacer(matches, data):
    """Replace Comments from data."""
    to_replace = set()
    for match in matches:
        grp = match.group()
        if grp:
            stripm = grp.strip()
            if stripm == '//':
                # ignore comment starters
                continue
            if ':' + stripm in data:
                # possible URLs http://, do not strip
                continue
            if 'ignore:' in stripm:
                # preserve ignore tags
                continue
            to_replace.add(grp)
    for itm in to_replace:
        dummy = REPL_REGEX.sub(' ', itm)
        data = data.replace(itm, dummy)
    return data


def _multi_comment_sub(match):
    """Replace a multiline or XML comment with spaces, preserving newlines."""
    grp = match.group()
    if 'ignore:' in grp:
        return grp
    return REPL_REGEX.sub(' ', grp)


def strip_comments1(data):
    """Remove Comments.

    Replace multiline comments first and
    then replace single line comments.
    """
    if '/*' in data:
        data = DEF_MULTI.sub(_multi_comment_sub, data)
    if '//' in data:
        def _single_sub(match):
            grp = match.group()
            stripm = grp.strip()
            if stripm == '//' or 'ignore:' in stripm:
                return grp
            start = match.start()
            if start > 0 and data[start - 1] == ':':
                return grp
            return REPL_REGEX.sub(' ', grp)

        data = DEF_SINGLE.sub(_single_sub, data)
    return data


def strip_comments2(data):
    """Remove Comments 2.

    Replace comments for HTML/XML
    """
    if '<!--' in data:
        data = XML_CMT.sub(_multi_comment_sub, data)
    return data


def get_match_lines(content, pos):
    """Get Match lines from position in O(1) C-level newline count."""
    start_pos = max(0, pos[0] - 1)
    end_pos = max(start_pos, pos[1] - 1)
    start_line = content.count('\n', 0, start_pos) + 1
    if end_pos == start_pos:
        return (start_line, start_line)
    end_line = start_line + content.count('\n', start_pos, end_pos)
    return (start_line, end_line)


def is_file_valid(sfile, allowed_extensions=None, max_size_mb=5):
    """Check if the file is valid based on its extension and size.

    Args:
        sfile (Path): The file to check.
        allowed_extensions (set): A set of allowed file extensions.
        max_size_mb (int): The maximum file size in MB.

    Returns:
        bool: True if the file is valid, False otherwise.
    """
    ext = sfile.suffix.lower()
    if allowed_extensions and ext not in allowed_extensions:
        return False

    max_size_bytes = max_size_mb * 1024 * 1024
    if sfile.stat().st_size > max_size_bytes:
        return False

    return True


def strip_comments(data, ext):
    """Format content by stripping comments based on file type."""
    if ext in ('.html', '.xml'):
        return strip_comments2(data)
    return strip_comments1(data)
