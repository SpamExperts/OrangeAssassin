"""Handle regex conversions."""

from builtins import object

import re
import operator
from functools import reduce

import oa.errors

# Map of perl flags and the corresponding re ones.
FLAGS = {
    "i": re.IGNORECASE,
    "s": re.DOTALL,
    "m": re.MULTILINE,
    "x": re.VERBOSE,
}

DELIMS = {
    "/": "/",
    "{": "}",
    "%": "%",
    "<": ">",
    "'": "'",
    "~": "~",
    ",": ",",
    "!": "!",
    ";": ";",
}

# Regex substitution for Perl -> Python compatibility
_CONVERTS = (
    (re.compile(r"""
    # Python does not support local extensions so remove those. For example:
    # (?i:test) becomes (?:test)

        (?<=\(\?)                             # Look-behind and match (?
        (([adlupimsx-]*?)|(\^[?^alupimsx]*?)) # Capture the extension
        (?=:)                                 # Look-ahead and match the :
""", re.VERBOSE), r""),

    (re.compile(r"""
    # Python doesn't have support for expression such as \b?
    # Replace it with (\b)?

        (\\b)        # Capture group that matches \b or \B
        (?=\?)       # Look-ahead that matches ?
""", re.VERBOSE | re.IGNORECASE), r"(\1)"),

    (re.compile(r"""
    # Python doesn't have support for "independent" subexpression (?>)
    # Replace those with non capturing groups (?:)

        (?<=\(\?)    # Look-behind and match (?
        (>)          # Match >
""", re.VERBOSE), r":"),
)


class Pattern(object):
    """Abstract class for rule regex matching."""

    def __init__(self, pattern):
        self._pattern = pattern

    def match(self, text):
        raise NotImplementedError()


class MatchPattern(Pattern):
    """This pattern does a search on the text and returns either 1 or 0."""

    def match(self, text):
        return 1 if self._pattern.search(text) else 0


class NotMatchPattern(Pattern):
    """This pattern does a search on the text and returns either 1 or 0."""

    def match(self, text):
        return 0 if self._pattern.search(text) else 1


def perl2re(pattern, match_op="=~"):
    """Convert a Perl type regex to a Python one."""
    # We don't need to consider the pre-flags
    pattern = pattern.strip().lstrip("mgs")
    delim = pattern[0]
    try:
        rev_delim = DELIMS[delim]
    except KeyError:
        raise oa.errors.InvalidRegex("Invalid regex delimiter %r in %r" %
                                     (delim, pattern))
    try:
        pattern, flags_str = pattern.lstrip(delim).rsplit(rev_delim, 1)
    except ValueError:
        raise oa.errors.InvalidRegex("Invalid regex %r. Please make sure you "
                                      "have escaped all the special characters "
                                      "when you defined the regex in "
                                      "configuration file" % pattern)
    for conv_p, repl in _CONVERTS:
        pattern = conv_p.sub(repl, pattern)

    flags = reduce(operator.or_, (FLAGS.get(flag, 0) for flag in flags_str), 0)

    try:
        if match_op == "=~":
            return MatchPattern(re.compile(pattern, flags))
        elif match_op == "!~": return NotMatchPattern(re.compile(pattern, flags))
    except re.error as e:
        raise oa.errors.InvalidRegex("Invalid regex %r: %s" % (pattern, e))


class Regex(object):
    """Customised regex class to work in lazy mode"""
    compiled = None

    def __init__(self, pattern, flags=0):
        self.pattern = pattern
        self.flags = flags

    def compile(self):
        from oa.config import LAZY_MODE
        if LAZY_MODE:
            return re.compile(self.pattern, self.flags)
        elif not self.compiled:
            self.compiled = re.compile(self.pattern, self.flags)
        return self.compiled

    def search(self, string):
        return self.compile().search(string)

    def match(self, string):
        return self.compile().match(string)

    def fullmatch(self, string):
        return self.compile().fullmatch(string)

    def sub(self, repl, string, count=0):
        return self.compile().sub(repl, string, count)

    def subn(self, repl, string, count=0):
        return self.compile().sub(repl, string, count)

    def split(self, string, maxsplit=0):
        return self.compile().split(string, maxsplit)

    def findall(self, string):
        return self.compile().findall(string)

    def finditer(self, string):
        return self.compile().finditer(string)
