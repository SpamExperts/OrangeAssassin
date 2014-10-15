"""Rules that check email body."""

import sa.regex
import sa.rules.base


class BodyRule(sa.rules.base.BaseRule):
    """Match a regular expression against the extracted text of the message.

    The text is:
        - decoded and stripped of any headers
        - all line break replaced with ' '
        - all HTML parts removed.
        - subject headers prepended
    """
    _rule_type = "BODY: "

    def __init__(self, name, pattern, score=None, desc=None):
        super(BodyRule, self).__init__(name, score=score, desc=desc)
        self._pattern = pattern

    def match(self, msg):
        return bool(self._pattern.match(msg.text))

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = sa.regex.perl2re(data["value"])
        return kwargs


class RawBodyRule(BodyRule):
    """Like the BodyRule but matches against the raw body.

    The text is:
        - decoded and stripped of any headers
    """
    _rule_type = "RAW: "

    def match(self, msg):
        return bool(self._pattern.match(msg.raw_text))
