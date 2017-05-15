"""Rules that check for URIs."""

import oa.regex
import oa.rules.base


class URIRule(oa.rules.base.BaseRule):
    """Match a regular expression against any URI found in all parts of the
    message body.

    Note that this does include the protocol.
    """
    _rule_type = "URI: "
    rule_type = 'uri'

    def __init__(self, name, pattern, score=None, desc=None, priority=0,
                 tflags=None):
        super(URIRule, self).__init__(name, score=score, desc=desc,
                                      priority=priority, tflags=tflags)
        self._pattern = pattern

    def match(self, msg):
        for uri in msg.uri_list:
            if self._pattern.match(uri):
                return True
        return False

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = oa.regex.perl2re(data["value"])
        return kwargs
