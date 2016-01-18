"""Implement commands that process the message."""

from __future__ import absolute_import

import pad.protocol
import pad.protocol.base


class ProcessCommand(pad.protocol.base.BaseProtocol):
    """Match the messages against the ruleset and
    return the adjusted message.
    """
    has_options = True
    has_message = True

    def handle(self, msg, options):
        self.ruleset.match(msg)
        yield self.ruleset.get_adjusted_message(msg)


class HeadersCommand(ProcessCommand):
    """Match the messages against the ruleset and
    return the adjusted message (headers only).
    """

    def handle(self, msg, options):
        self.ruleset.match(msg)
        yield self.ruleset.get_adjusted_message(msg, header_only=True)
