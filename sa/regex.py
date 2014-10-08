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


class CountPattern(Pattern):
    """This pattern does a findall on the text and returns the count of
    matches. Equivalent to the '/g' flag in Perl.
    """
    def match(self, text):
        return len(self._pattern.findall(text) or ())


def perl2re(pattern):
    """Convert a Perl type regex to a Python one."""
    # We don't need to consider the pre-flags
    dummy, pattern = pattern.strip().split("/", 1)
    pattern, flags_str = pattern.rsplit("/", 1)
    pattern = pattern.replace(r"\/", "/")
    pattern = pattern.replace(r"\#", "#")

    flags = reduce(operator.or_, (FLAGS.get(flag, 0) for flag in flags_str), 0)
    if "g" in flags_str:
        return CountPattern(re.compile(pattern, flags))
    else:
        return MatchPattern(re.compile(pattern, flags))



