"""Errors specific to this package."""

from builtins import list


class PADError(Exception):
    """Base class for all errors."""


class ParsingError(PADError):
    """An error occurred while parsing rules."""


class InvalidRule(ParsingError):
    """The rule syntax seems valid but the usage is incorrect."""
    def __init__(self, rule_name, description=""):
        ParsingError.__init__(self)
        self.name = rule_name
        self.desc = description

    def __str__(self):
        return "Invalid Rule %s: %s" % (self.name, self.desc)


class InvalidSyntax(ParsingError):
    """The rule syntax is invalid."""
    def __init__(self, filename, line_number, line, description=""):
        ParsingError.__init__(self)
        self.filename = filename
        self.line_no = line_number
        self.line = line
        self.desc = description

    def __str__(self):
        return "Invalid Syntax %s:%s: %s in %r" % (self.filename, self.line_no,
                                                   self.desc, self.line)


class MaxRecursionDepthExceeded(ParsingError):
    """The maximum recursion depth has been exceeded while parsing include
    directives.
    """
    def __init__(self):
        ParsingError.__init__(self)
        self._recursion_list = list()

    def add_call(self, filename, line_number, line):
        """Add to the recursion list."""
        self._recursion_list.append((filename, line_number, line))

    @property
    def recursion_list(self):
        """Return the recursion list as a list of tuples:

        (filename, line number, line)
        """
        return self._recursion_list


class PluginError(PADError):
    """Something went wrong with a plugin."""


class PluginLoadError(PluginError):
    """Something went wrong while loading a plugin."""


class InhibitCallbacks(Exception):
    """Stops the processing of the current callback, and prevent other plugins
    callbacks.
    """
