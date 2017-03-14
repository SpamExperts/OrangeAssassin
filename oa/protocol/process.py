"""Implement commands that process the message."""

from __future__ import absolute_import

import oa.protocol
import oa.protocol.check


class ProcessCommand(oa.protocol.check.CheckCommand):
    """Match the messages against the ruleset and
    return the adjusted message.
    """
    has_options = True
    has_message = True

    def extra_details(self, msg, options):
        """Add any extra details to the response."""
        adjusted_msg = self.ruleset.get_adjusted_message(msg)
        yield adjusted_msg


class HeadersCommand(ProcessCommand):
    """Match the messages against the ruleset and
    return the adjusted message (headers only).
    """

    def extra_details(self, msg, options):
        """Add any extra details to the response."""
        adjusted_msg = self.ruleset.get_adjusted_message(msg, header_only=True)
        yield adjusted_msg
