# -*- coding: utf_8 -*-
"""Optimized Algorithms for Pattern Matching with Caching."""
from abc import ABC, abstractmethod
from functools import lru_cache

from libsast.core_matcher.helpers import get_match_lines
from libsast.exceptions import InvalidRegexError

import regex

# Resource boundaries for untrusted rule patterns.
# Maximum length of a single regex pattern.
MAX_PATTERN_LENGTH = 4000
# Maximum number of patterns a single rule may combine.
MAX_PATTERNS_PER_RULE = 100
# Hard time budget in seconds for a single regex operation.
REGEX_TIMEOUT = 2.0


def get_pos(match):
    """Adjust zero index in match span."""
    start, end = match.span()
    return (1 if start == 0 else start, end)


def validate_regex_pattern(pattern):
    """Validate a single regex pattern against resource limits."""
    if not isinstance(pattern, str) or not pattern:
        raise InvalidRegexError(
            'Regex pattern must be a non-empty string.')
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise InvalidRegexError(
            'Regex pattern exceeds the maximum length of'
            f' {MAX_PATTERN_LENGTH} characters.')


def validate_rule_patterns(pattern):
    """Validate all regex patterns of a rule against resource limits."""
    if isinstance(pattern, str):
        patterns = [pattern]
    elif isinstance(pattern, list):
        patterns = []
        for item in pattern:
            if isinstance(item, list):
                patterns.extend(item)
            else:
                patterns.append(item)
    else:
        raise InvalidRegexError(
            'Rule pattern must be a string or a list of strings.')
    if not patterns:
        raise InvalidRegexError('Rule does not have any pattern.')
    if len(patterns) > MAX_PATTERNS_PER_RULE:
        raise InvalidRegexError(
            'Rule exceeds the maximum of'
            f' {MAX_PATTERNS_PER_RULE} patterns.')
    for pat in patterns:
        # Compiles the pattern, raising InvalidRegexError on failure.
        get_compiled_pattern(pat)


# Cache validated and compiled regex patterns
@lru_cache(maxsize=4096)
def get_compiled_pattern(pattern):
    """Validate, compile and cache regex patterns."""
    validate_regex_pattern(pattern)
    try:
        return regex.compile(pattern)
    except regex.error as err:
        raise InvalidRegexError(f'Invalid regex pattern: {err}')


def safe_search(pattern, content):
    """Search with a hard time budget.

    Raises TimeoutError if the pattern exceeds REGEX_TIMEOUT.
    """
    return pattern.search(content, timeout=REGEX_TIMEOUT)


def safe_finditer(pattern, content):
    """Find all matches with a hard time budget.

    Raises TimeoutError if the pattern exceeds REGEX_TIMEOUT.
    """
    return list(pattern.finditer(content, timeout=REGEX_TIMEOUT))


class MatchCommand:
    def __init__(self):
        self.patterns = {}
        self.available_patterns = {
            'Regex': Regex,
            'RegexAnd': RegexAnd,
            'RegexOr': RegexOr,
            'RegexAndNot': RegexAndNot,
            'RegexAndOr': RegexAndOr,
        }

    def _find_match(self, pattern_name, content, rule):
        pattern_class = self.patterns.get(
            pattern_name) or self._get_pattern_class(pattern_name)
        self.patterns.setdefault(pattern_name, pattern_class)

        case = rule.get('input_case')
        if case == 'lower':
            content = content.lower()
        elif case == 'upper':
            content = content.upper()

        try:
            return pattern_class._perform_search(content, rule)
        except TimeoutError:
            # Fail closed: a pattern that exceeds its time budget
            # yields no matches instead of blocking the scan.
            return set()

    def _get_pattern_class(self, pattern_name):
        """Get pattern class from the available patterns dictionary."""
        if pattern_name in self.available_patterns:
            return self.available_patterns[pattern_name]()
        raise ValueError(f"Pattern '{pattern_name}' is not recognized.")


class MatchStrategy(ABC):
    @abstractmethod
    def _perform_search(self, content, rule):
        """Search for instances of a pattern match in content."""


class Regex(MatchStrategy):
    def _perform_search(self, content, rule):
        pattern = get_compiled_pattern(rule['pattern'])
        return self._find_matches(content, pattern)

    @staticmethod
    def _find_matches(content, pattern):
        """Helper to find all matches in content and extract details."""
        matches = set()
        for match in safe_finditer(pattern, content):
            grp = match.group()
            if grp:
                match_pos = get_pos(match)
                match_lines = get_match_lines(content, match_pos)
                matches.add((grp, match_pos, match_lines))
        return matches


class RegexAnd(MatchStrategy):
    def _perform_search(self, content, rule):
        patterns = rule['pattern'] if isinstance(
            rule['pattern'], list) else [rule['pattern']]
        compiled = [get_compiled_pattern(regex_str) for regex_str in patterns]
        if not all(safe_search(pat, content) for pat in compiled):
            return False
        all_matches = set()
        for pat in compiled:
            matches = Regex._find_matches(content, pat)
            if not matches:
                return False
            all_matches.update(matches)
        return all_matches


class RegexOr(MatchStrategy):
    def _perform_search(self, content, rule):
        patterns = rule['pattern'] if isinstance(
            rule['pattern'], list) else [rule['pattern']]
        matches = set()
        for regex_str in patterns:
            pattern = get_compiled_pattern(regex_str)
            matches.update(Regex._find_matches(content, pattern))
        return matches


class RegexAndNot(MatchStrategy):
    def _perform_search(self, content, rule):
        present_pattern, not_pattern = rule['pattern']
        present_re = get_compiled_pattern(present_pattern)
        if not safe_search(present_re, content):
            return False
        if safe_search(get_compiled_pattern(not_pattern), content) is not None:
            return False
        present_matches = Regex._find_matches(content, present_re)
        return present_matches if present_matches else False


class RegexAndOr(MatchStrategy):
    def _perform_search(self, content, rule):
        and_pattern, or_patterns = rule['pattern']
        and_re = get_compiled_pattern(and_pattern)
        if not safe_search(and_re, content):
            return False
        or_matches = set()
        for regex_str in or_patterns:
            or_pattern = get_compiled_pattern(regex_str)
            or_matches = Regex._find_matches(content, or_pattern)
            if or_matches:
                break
        if not or_matches:
            return False
        and_matches = Regex._find_matches(content, and_re)
        return and_matches.union(or_matches) if and_matches else False
