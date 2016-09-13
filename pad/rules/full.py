"""Matches against the full pristine message."""

import pad.regex
import pad.rules.base


class FullRule(pad.rules.base.BaseRule):
    """Match a regular expression against the full raw message."""

    def __init__(self, name, pattern, score=None, desc=None, priority=0,
                 tflags=None):
        super(FullRule, self).__init__(name, score=score, desc=desc,
                                       priority=priority, tflags=tflags)
        self._pattern = pattern

    def match(self, msg):
        return bool(self._pattern.match(msg.raw_msg))

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = pad.regex.perl2re(data["value"])
        return kwargs
