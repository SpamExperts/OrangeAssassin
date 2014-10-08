"""Rules that check headers."""

import sa.regex
import sa.rules.base


class HeaderRule(sa.rules.base.BaseRule):
    """Matches a header by name and a regular expression for the value. The
    headers are decoded, and the header name is not included.

    If the special header name "ALL" is used then the pattern is checked
    against all headers. In this case the header name IS included in the
    search.
    """
    def __init__(self, name, header_name, pattern, score=None, desc=None):
        super(HeaderRule, self).__init__(name, score=score, desc=desc)
        self._header_name = header_name
        self._all = self._header_name == "ALL"
        self._pattern = pattern

    def match(self, msg):
        if not self._all:
            return self._match(msg)
        else:
            return self._match_all(msg)

    def _match(self, msg):
        for value in msg.headers[self._header_name]:
            if self._pattern.match(value):
                return True
        return False

    def _match_all(self, msg):
        for name, values in msg.header.items():
            for value in values:
                if self._pattern.match("%s: %s" % (name, value)):
                    return True
        return False

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        header_name, pattern = data["value"].split("=~", 1)

        kwargs["header_name"] = header_name.strip()
        kwargs["pattern"] = sa.regex.perl2re(pattern)
        return kwargs



