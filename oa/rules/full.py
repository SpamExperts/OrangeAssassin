"""Matches against the full pristine message."""

import oa.regex
import oa.rules.base


class FullRule(oa.rules.base.BaseRule):
    """Match a regular expression against the full raw message."""
    rule_type = 'full'

    def __init__(self, name, pattern, score=None, desc=None, priority=0,
                 tflags=None):
        super(FullRule, self).__init__(name, score=score, desc=desc,
                                       priority=priority, tflags=tflags)
        self._pattern = pattern

    def match(self, msg):
        return bool(self._pattern.match(msg.raw_msg))

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = oa.regex.perl2re(data["value"])
        return kwargs
