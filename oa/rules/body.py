"""Rules that check email body."""

import oa.regex
import oa.rules.base


class BodyRule(oa.rules.base.BaseRule):
    """Match a regular expression against the extracted text of the message.

    The text is:
        - decoded and stripped of any headers
        - all line break replaced with ' '
        - all HTML parts removed.
        - subject headers prepended
    """
    _rule_type = "BODY: "
    rule_type = "body"

    def __init__(self, name, pattern, score=None, desc=None, priority=0,
                 tflags=None):
        super(BodyRule, self).__init__(name, score=score, desc=desc,
                                       priority=priority, tflags=tflags)
        self._pattern = pattern

    def match(self, msg):
        return bool(self._pattern.match(msg.text))

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = oa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["pattern"] = oa.regex.perl2re(data["value"])
        return kwargs


class RawBodyRule(BodyRule):
    """Like the BodyRule but matches against the raw body.

    The text is:
        - decoded and stripped of any headers
    """
    _rule_type = "RAW: "
    rule_type = "rawbody"

    def match(self, msg):
        return bool(self._pattern.match(msg.raw_text))
