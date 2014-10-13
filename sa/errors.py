"""Errors specific to this package."""


class SAError(Exception):
    """Base class for all errors."""


class ParsingError(SAError):
    """An error occurred while parsing rules."""


class InvalidRule(ParsingError):
    """The rule syntax seems valid but the usage is incorrect."""
    def __init__(self, rule_name, description=""):
        self.name = rule_name
        self.desc = description

    def __str__(self):
        return "Invalid Rule %s: %s" % (self.name, self.desc)


class InvalidSyntax(ParsingError):
    """The rule syntax is invalid."""
    def __init__(self, filename, line_number, line, description=""):
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
    def __init__(self, filename, line_number, line):
        ParsingError.__init__(self)
        self._recursion_list = [(filename, line_number, line)]

    def add_call(self, filename, line_number, line):
        """Add to the recursion list."""
        self._recursion_list.append((filename, line_number, line))

    @property
    def recursion_list(self):
        """Return the recursion list as a list of tuples:

        (filename, line number, line)
        """
        return self._recursion_list


