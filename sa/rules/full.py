"""Matches against the full pristine message."""

import sa.regex
import sa.rules.base


class FullRule(sa.rules.base.BaseRule):
    """Match a regular expression against the full raw message."""

    def __init__(self, name, pattern, score=None, desc=None):
        super(FullRule, self).__init__(name, score=score, desc=desc)
        self._pattern = pattern

    def match(self, msg):
        return bool(self._pattern.match(msg.raw_msg))

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = sa.regex.perl2re(data["value"])
        return kwargs

    @classmethod
    def get_rule(cls, name, data):
        if data["value"].startswith("eval:"):
            return sa.rules.base._NOOPRule.get_rule(name, data)
        return super(FullRule, cls).get_rule(name, data)
