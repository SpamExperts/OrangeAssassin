"""Expose some eval rules that do checks on the body."""

from __future__ import division
from __future__ import absolute_import

import re
import collections

import pad.plugins.base

SPLIT_WORDS = re.compile(r"\s+")
REMOVE_OTHER = re.compile(r"[^\w]")


class BodyEval(pad.plugins.base.BasePlugin):
    eval_rules = (
        "multipart_alternative_difference",
        "multipart_alternative_difference_count",
        # "check_blank_line_ratio",
        # "tvd_vertical_words",
        # "check_stock_info",
    )

    def check_start(self, msg):
        """Initialize a empty list that will contain all
        the tokens from each multipart/alternative parts.
        """
        super(BodyEval, self).check_start(msg)
        self.set_local(msg, "multiparts", [])
        self.set_local(msg, "text_tokens", collections.Counter())
        self.set_local(msg, "html_tokens", collections.Counter())

    def extract_metadata(self, msg, payload, part):
        """Parse each part and extract the relevant tokens."""
        super(BodyEval, self).extract_metadata(msg, payload, part)
        multiparts = self.get_local(msg, "multiparts")
        if part.get_content_type() == "multipart/alternative":
            # The actual parts and text will come after
            # get the list of ids for each subpart of this
            # multipart.
            multiparts.extend(id(subpart) for subpart in part.get_payload())
            return

        content_type = part.get_content_type()
        if (id(part) not in multiparts or not payload or
                content_type not in ("text/plain", "text/html")):
            # Unknown part or empty part, skip it.
            return

        words = (REMOVE_OTHER.sub('', word)
                 for word in SPLIT_WORDS.split(payload))
        if content_type.lower() == "text/plain":
            self.get_local(msg, "text_tokens").update(
                word for word in words if word
            )
        elif content_type.lower() == "text/html":
            self.get_local(msg, "html_tokens").update(
                word for word in words if word
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
            if count >= html_tokens[token]:
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

    def multipart_alternative_difference(self, msg, min, max, target=None):
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
        :param min: the inferior value of the threshold
        :param max: the superior value of the threshold
        :return: True if the ratio is between the two values
          and False otherwise.

        """
        min, max = float(min), float(max)
        return min <= self.get_local(msg, "madiff") <= max

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
