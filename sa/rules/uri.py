"""Rules that check for URIs."""

import sa.rules.base


class URIRule(sa.rules.base.BaseRule):
    """Match a regular expression against any URI found in all parts of the
    message body.

    Note that this does include the protocol.
    """
    _rule_type = "URI: "

    def __init__(self, name, pattern, score=None, desc=None):
        super(URIRule, self).__init__(name, score=score, desc=desc)
        self._pattern = pattern

    def match(self, msg):
        for uri in msg.uri_list:
            if self._pattern.match(uri):
                return True
        return False

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = sa.regex.perl2re(data["value"])
        return kwargs
