"""Implement the SYMBOLS command."""

from __future__ import absolute_import

import pad.protocol.check


class SymbolsCommand(pad.protocol.check.CheckCommand):
    """Check if the message is spam and return the score.

    Also return a list of symbols that matched.
    """

    def handle(self, msg, options):
        for response in super(SymbolsCommand, self).handle(msg, options):
            yield response
        yield "\r\n"
        yield ",".join(name for name, result in msg.rules_checked.items()
                       if result)

