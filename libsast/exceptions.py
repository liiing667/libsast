# -*- coding: utf_8 -*-
"""The libsast Exceptions."""


class LibsastError(Exception):
    """Base class for all exceptions thrown by libsast."""

    def __init__(self, message=None):
        super().__init__(message)


class InvalidPathError(LibsastError):
    """Invalid Path Supplied to libsast."""

    pass


class YamlRuleParseError(LibsastError):
    """Failed to parse YAML rule."""

    pass


class YamlRuleLoadError(LibsastError):
    """Failed to load YAML rule file."""

    pass


class MissingRuleError(LibsastError):
    """Rule not provided."""

    pass


class InvalidRuleError(LibsastError):
    """No rule directory, file or url specified."""

    pass


class TypeKeyMissingError(LibsastError):
    """Pattern Matcher rule does not have the key 'type'."""

    pass


class InvalidRuleFormatError(LibsastError):
    """Pattern Matcher rule file is invalid."""

    pass


class PatternKeyMissingError(LibsastError):
    """Pattern Matcher rule does not have the key 'pattern'."""

    pass


class RuleDownloadError(LibsastError):
    """Failed to download rule."""

    pass


class RuleProcessingError(LibsastError):
    """Failed to download rule."""

    pass


class MatcherNotFoundError(LibsastError):
    """Pattern Matcher not found."""

    pass


class RulePackError(LibsastError):
    """Base class for immutable rulepack snapshot failures."""

    pass


class RulePackIntegrityError(RulePackError):
    """A rulepack manifest does not match the files on disk."""

    pass


class RulePackChangedError(RulePackError):
    """A rulepack changed while it was being read into a snapshot."""

    pass


class RulePackGenerationError(RulePackError):
    """Reports from different rulepack generations cannot be mixed."""

    pass


class RulePackVersionError(RulePackError):
    """A rulepack version or identity could not be resolved."""

    pass


class StaleRulePackError(RulePackError):
    """A complete rulepack snapshot is not available."""

    pass


# Compatibility spellings used by consumers.
RulepackError = RulePackError
RulepackIntegrityError = RulePackIntegrityError
RulepackChangedError = RulePackChangedError
RulepackGenerationError = RulePackGenerationError
RulepackVersionError = RulePackVersionError
RulePackMismatchError = RulePackGenerationError
RuleSetGenerationError = RulePackGenerationError
RulePackStaleError = StaleRulePackError
RulePackRefreshError = RulePackChangedError
RulepackRefreshError = RulePackChangedError
RuleSetMismatchError = RulePackGenerationError
