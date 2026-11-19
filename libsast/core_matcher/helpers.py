# -*- coding: utf_8 -*-
"""Helper Functions."""
import re
from pathlib import Path

from libsast.exceptions import (
    DuplicateRuleIdError,
    InvalidRuleError,
    MissingRuleError,
    RuleDownloadError,
)
from libsast.common import read_yaml
from libsast.standards import get_mapping

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


def get_rules(rule_loc):  # noqa: R701
    """Get pattern matcher rules."""
    if not rule_loc:
        raise MissingRuleError('Rule location is missing.')
    if rule_loc.startswith(('http://', 'https://')):
        pat = download_rule(rule_loc)
        if not pat:
            return
        rules = read_yaml(pat, True)
        if not rules:
            return
        return merge_rules([(rule_loc, get_mapping(rules))])
    rule = Path(rule_loc)
    if rule.is_file() and rule.exists():
        rules = read_yaml(rule)
        if not rules:
            return
        return merge_rules([(rule.as_posix(), get_mapping(rules))])
    elif rule.is_dir() and rule.exists():
        rule_batches = []
        for yfile in sorted(rule.glob('**/*.yaml')):
            rules = read_yaml(yfile)
            if rules:
                rule_batches.append((yfile.as_posix(), get_mapping(rules)))
        return merge_rules(rule_batches)
    else:
        raise InvalidRuleError('This path is invalid')


def merge_rules(rule_batches):
    """Merge rules from multiple YAML files safely.

    Rule ids are unique within a merged rule set. Rules that share an
    id are allowed only when their content is identical, in which case the
    duplicate is dropped to keep loading idempotent. Rules with the same id
    but conflicting content are rejected before scanning so a later file
    cannot silently override another rule's pattern, severity or mappings.
    """
    merged = []
    seen = {}
    for source, rules in rule_batches:
        for rule in rules:
            rule_id = rule.get('id') if isinstance(rule, dict) else None
            if rule_id is None:
                merged.append(rule)
                continue
            if rule_id not in seen:
                seen[rule_id] = (source, rule)
                merged.append(rule)
            elif seen[rule_id][1] != rule:
                raise DuplicateRuleIdError(
                    'Conflicting rules with the same id '
                    f'"{rule_id}" were found in '
                    f'"{seen[rule_id][0]}" and "{source}". '
                    'Deduplicate the id or make the rules identical.')
    return merged


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
