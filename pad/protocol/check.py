"""Implement a simple CHECK command."""

from __future__ import absolute_import

import pad.protocol.base


class CheckCommand(pad.protocol.base.BaseProtocol):
    """Check if the message is spam and return the score."""
    has_options = True
    has_message = True

    def handle(self, msg, options):
        score = 0
        self.ruleset.match(msg)
        for result in msg.rules_checked.values():
            score += result
        # XXX Need to be read from configuration
        if score >= 5:
            spam = True
        else:
            spam = False
        yield "Spam: %s ; %s / %s\r\n" % (spam, score, 5)
