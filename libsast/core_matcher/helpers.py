# -*- coding: utf_8 -*-
"""Helper Functions."""
import re
from pathlib import Path
from urllib.parse import (
    urljoin,
    urlparse,
)

from libsast.exceptions import (
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

# Remote rule download limits
RULE_DOWNLOAD_TIMEOUT = 10
MAX_RULE_SIZE = 5 * 1024 * 1024
MAX_RULE_REDIRECTS = 5
_DEFAULT_PORTS = {'http': 80, 'https': 443}


def _origin(url):
    """Return the normalized (scheme, host, port) origin of a URL."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower()
    port = parsed.port or _DEFAULT_PORTS.get(scheme)
    return (scheme, host, port)


def _validate_redirect(trusted_url, target_url):
    """Validate a redirect target against the trusted rule URL.

    Rejects non-HTTP(S) targets, HTTPS downgrades and cross-origin
    redirects so a trusted rule URL cannot be bounced to an
    untrusted host, internal service or local file handler.
    """
    target = urlparse(target_url)
    if target.scheme.lower() not in ('http', 'https'):
        raise RuleDownloadError(
            f'Redirect to unsupported scheme blocked: {target_url}')
    trusted = _origin(trusted_url)
    if trusted[0] == 'https' and target.scheme.lower() != 'https':
        raise RuleDownloadError(
            f'HTTPS downgrade redirect blocked: {target_url}')
    if _origin(target_url) != trusted:
        raise RuleDownloadError(
            f'Cross-origin redirect blocked: {target_url}')


def _read_response(response, max_size, url):
    """Read a response body, failing if it exceeds max_size bytes."""
    content_length = response.headers.get('Content-Length')
    if content_length and content_length.isdigit():
        if int(content_length) > max_size:
            raise RuleDownloadError(
                f'Rule file too large ({content_length} bytes): {url}')
    chunks = []
    received = 0
    for chunk in response.iter_content(chunk_size=65536):
        received += len(chunk)
        if received > max_size:
            raise RuleDownloadError(
                f'Rule file exceeds {max_size} bytes: {url}')
        chunks.append(chunk)
    encoding = response.encoding or response.apparent_encoding or 'utf-8'
    return b''.join(chunks).decode(encoding, errors='replace')


def download_rule(url, timeout=RULE_DOWNLOAD_TIMEOUT, max_size=MAX_RULE_SIZE):
    """Download Pattern File.

    Redirects are followed manually: every hop must stay on the
    origin of the trusted URL, must not downgrade HTTPS to HTTP and
    must use HTTP(S). Responses larger than max_size are rejected
    before they are parsed.
    """
    current = url
    try:
        for _ in range(MAX_RULE_REDIRECTS + 1):
            with requests.get(
                    current,
                    allow_redirects=False,
                    stream=True,
                    timeout=timeout) as r:
                if r.is_redirect or r.is_permanent_redirect:
                    location = r.headers.get('Location')
                    if not location:
                        raise RuleDownloadError(
                            f'Redirect without Location header: {current}')
                    target = urljoin(current, location)
                    _validate_redirect(url, target)
                    current = target
                    continue
                r.raise_for_status()
                return _read_response(r, max_size, url)
        raise RuleDownloadError(
            f'Too many redirects (>{MAX_RULE_REDIRECTS}): {url}')
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
        return get_mapping(rules)
    rule = Path(rule_loc)
    if rule.is_file() and rule.exists():
        rules = read_yaml(rule)
        if not rules:
            return
        return get_mapping(rules)
    elif rule.is_dir() and rule.exists():
        patterns = []
        for yfile in rule.glob('**/*.yaml'):
            rules = read_yaml(yfile)
            if rules:
                rules = get_mapping(rules)
                patterns.extend(rules)
        return patterns
    else:
        raise InvalidRuleError('This path is invalid')


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
