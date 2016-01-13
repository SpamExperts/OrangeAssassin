"""Implement the REPORT command."""

from __future__ import absolute_import

import pad.protocol.check


class ReportCommand(pad.protocol.check.CheckCommand):
    """Check if the message is spam and return the score.

    Also return a list of symbols and descriptions for each
    rule that matched.
    """

    def handle(self, msg, options):
        for response in super(ReportCommand, self).handle(msg, options):
            yield response
        yield "\r\n"
        for name, result in msg.rules_checked.items():
            if result:
                yield str(self.ruleset.get_rule(name))
