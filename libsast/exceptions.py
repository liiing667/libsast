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


class SourceReadError(LibsastError):
    """One or more scannable source files could not be read.

    Treating such files as empty would hide findings, so the scan fails
    closed. Machine-readable diagnostics are attached for tooling.
    """

    diagnostics = []

    @classmethod
    def from_diagnostics(cls, message, diagnostics):
        """Build the error with attached machine-readable diagnostics."""
        error = cls(message)
        error.diagnostics = diagnostics or []
        return error
