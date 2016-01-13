"""Handle regex conversions."""

from builtins import object

import re
import operator
from functools import reduce

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
    rev_delim = DELIMS[delim]
    pattern, flags_str = pattern.lstrip(delim).rsplit(rev_delim, 1)
    for conv_p, repl in _CONVERTS:
        pattern = conv_p.sub(repl, pattern)

    flags = reduce(operator.or_, (FLAGS.get(flag, 0) for flag in flags_str), 0)

    if match_op == "=~":
        return MatchPattern(re.compile(pattern, flags))
    elif match_op == "!~":
        return NotMatchPattern(re.compile(pattern, flags))

