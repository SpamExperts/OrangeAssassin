"""Expose some eval rules that do checks on the body."""

from __future__ import division
from __future__ import absolute_import

import re
import collections

import pad.plugins.base

SPACE_COUNT = re.compile(r"\s")
SPLIT_WORDS = re.compile(r"\s+")
REMOVE_OTHER = re.compile(r"[^\w]")
STOCK_RE = re.compile(r"""
    ^trad(?:e|ing)date|
    company(?:name)?|
    s\w?(?:t\w?o\w?c\w?k|y\w?m(?:\w?b\w?o\w?l)?)|
    t(?:arget|icker)|
    (?:opening|current)p(?:rice)?|
    p(?:rojected|osition)|
    expectations|
    weeks?high|
    marketperformance|
    (?:year|week|month|day|price)(?:target|estimates?)|
    sector|
    r(?:ecommendation|ating)
""", re.I | re.S | re.X | re.M)


class BodyEval(pad.plugins.base.BasePlugin):
    eval_rules = (
        "multipart_alternative_difference",
        "multipart_alternative_difference_count",
        "check_blank_line_ratio",
        "tvd_vertical_words",
        "check_stock_info",
    )

    def check_start(self, msg):
        """Initialize a empty list that will contain all
        the tokens from each multipart/alternative parts.
        """
        super(BodyEval, self).check_start(msg)
        self.set_local(msg, "multiparts", [])
        self.set_local(msg, "text_tokens", collections.Counter())
        self.set_local(msg, "html_tokens", collections.Counter())

    def extract_metadata(self, msg, payload, text, part):
        """Parse each part and extract the relevant tokens."""
        super(BodyEval, self).extract_metadata(msg, payload, text, part)
        multiparts = self.get_local(msg, "multiparts")
        if part.get_content_type() == "multipart/alternative":
            # The actual parts and text will come after
            # get the list of ids for each subpart of this
            # multipart.
            multiparts.extend(id(subpart) for subpart in part.get_payload())
            return

        content_type = part.get_content_type()
        if (id(part) not in multiparts or not text or
                content_type not in ("text/plain", "text/html")):
            # Unknown part or empty part, skip it.
            return

        words = (REMOVE_OTHER.sub('', word)
                 for word in SPLIT_WORDS.split(text))
        if content_type.lower() == "text/plain":
            self.get_local(msg, "text_tokens").update(
                word.lower() for word in words if word
            )
        elif content_type.lower() == "text/html":
            self.get_local(msg, "html_tokens").update(
                word.lower() for word in words if word
            )

    def parsed_metadata(self, msg):
        """Compute the max difference between the html and
        plain tokens of the multipart alternatives parts
        of the message.
        """
        super(BodyEval, self).parsed_metadata(msg)
        text_tokens = self.get_local(msg, "text_tokens")
        html_tokens = self.get_local(msg, "html_tokens")

        valid_count = 0
        for token, count in text_tokens.items():
            # If the token appears at least as many
            # times in the text part as in the html
            # part then it is valid.
            if token in html_tokens and count >= html_tokens[token]:
                valid_count += 1
        try:
            token_count = len(html_tokens)
            diff = abs((token_count - valid_count) / token_count * 100)
        except ZeroDivisionError:
            diff = 0.0
        self.set_local(msg, "madiff", diff)
        self.ctxt.log.debug("Text tokens=%s, HTML tokens=%s, valid count=%s, "
                            "diff=%.2f", len(text_tokens), len(html_tokens),
                            valid_count, diff)

        self.set_local(msg, "line_count", msg.raw_text.count("\n"))
        self.set_local(msg, "blank_line_count", msg.raw_text.count("\n\n"))

    def multipart_alternative_difference(self, msg, minr, maxr, target=None):
        """Check the difference between the text and html parts of
        the message. Every word seen in the text part of the
        message should also exist at least as many times in the
        HTML version.

        This eval rule checks the ratio of difference between
        the two parts between the specified thresholds. If both
        parts are identical this will give a ration of 0%. If
        none of the words seen in the text part are present in
        the HTML part the ratio is 100%.

        Note that this excludes any HTML tags from the count.

        :param msg: the message that's being checked
        :param minr: the inferior value of the threshold
        :param maxr: the superior value of the threshold
        :return: True if the ratio is between the two values
          and False otherwise.

        """
        minr, maxr = float(minr), float(maxr)
        return minr <= self.get_local(msg, "madiff") <= maxr

    def multipart_alternative_difference_count(self, msg, ratio, minhtml,
                                               target=None):
        """Check the ration of unique tokens seen in the text
        and HTML version of the message. This does not take
        into account how many times each token has been seen
        in each part, but only checks the raw ratio.

        If more tokens are seen in the text version. the ratio
        will be larger than 1.0. If more tokens are seen in the
        HTML version, the ration will be smaller then 1.0.

        :param msg: the message that's being checked
        :param ratio: the inferior threshold value of the ratio
        :param minhtml: if there are less than this number
          of HTML tokens, the rule won't match
        :return: True if the ratio is larger than the ratio
          parameter and there are at least `minhtml` tokens

        """
        ratio, minhtml = float(ratio), int(minhtml)

        text_tokens = len(self.get_local(msg, "text_tokens"))
        html_tokens = len(self.get_local(msg, "html_tokens"))

        if html_tokens < minhtml:
            return False
        try:
            return (text_tokens / html_tokens) > ratio
        except ZeroDivisionError:
            return False

    def check_blank_line_ratio(self, msg, minr, maxr, minlines=1, target=None):
        """Check the ratio of blank lines to the number of
        lines in the message body.

        :param msg: the message that's being checked
        :param minr: the inferior value of the threshold
        :param maxr: the superior value of the threshold
        :param minlines: this rule will match only if the
          message has at least this number of lines.
        :return: True if the ratio is between the two values
          and False otherwise.

        """
        minr, maxr, minlines = float(minr), float(maxr), int(minlines)
        minlines = max(minlines, 1)
        line_count = self.get_local(msg, "line_count")
        blank_line_count = self.get_local(msg, "blank_line_count")

        if self.get_local(msg, "line_count") < minlines:
            return False
        ratio = blank_line_count / line_count * 100
        return minr <= ratio <= maxr

    # XXX Strange name?
    def tvd_vertical_words(self, msg, minr, maxr, target=None):
        """Check the ratio of spaces to non-spaces.

        :param msg: the message that's being checked
        :param minr: the inferior value of the threshold
        :param maxr: the superior value of the threshold
        :return: True if the ratio is between the two values
          and False otherwise.

        """
        if target == "rawbody":
            text = msg.raw_text
        else:
            text = msg.text

        space_count = sum(1 for _ in SPACE_COUNT.finditer(text))
        try:
            ratio = space_count / (len(text) - space_count) * 100
        except ZeroDivisionError:
            return False
        return minr <= ratio <= maxr

    def check_stock_info(self, msg, minwords, target=None):
        """Check the message for common stock market words.

        :param msg: the message that's being checked
        :param minwords: the minimum number of words to be
          found for this rule to match.
        :return: True if there are at least `minwords` found
          in the message, and False otherwise.
        """
        minwords = int(minwords)
        if target == "rawbody":
            text = msg.raw_text
        else:
            text = msg.text
        stock_count = sum(1 for _ in STOCK_RE.finditer(text))
        return stock_count >= minwords
