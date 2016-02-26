"""Implement commands that perform checks on the message."""

from __future__ import absolute_import

import pad.protocol
import pad.protocol.base


class CheckCommand(pad.protocol.base.BaseProtocol):
    """Check if the message is spam and return the score."""
    has_options = True
    has_message = True

    def handle(self, msg, options):
        self.ruleset.match(msg)
        if msg.score >= self.ruleset.conf["required_score"]:
            spam = True
        else:
            spam = False
        yield "Spam: %s ; %s / %s\r\n" % (spam, msg.score,
                                          self.ruleset.conf["required_score"])
        result = "".join(self.extra_details(msg, options))
        yield "Content-length: %s\r\n\r\n" % len(result)
        yield result

    def extra_details(self, msg, options):
        """Add any extra details to the response."""
        yield ""


class SymbolsCommand(CheckCommand):
    """Check if the message is spam and return the score.

    Also return a list of symbols that matched.
    """

    def extra_details(self, msg, options):
        """Return a list of rule names that matched the
        message.
        """
        yield ",".join(name for name, result in msg.rules_checked.items()
                       if result)


class ReportCommand(CheckCommand):
    """Check if the message is spam and return the score.

    Also return a list of symbols and descriptions for each
    rule that matched.
    """

    def extra_details(self, msg, options):
        """Return a full report of rules that matched
        the message.
        """
        yield self.ruleset.get_report(msg)


class ReportIfSpamCommand(ReportCommand):
    """Check if the message is spam and return the score.

    Also return a list of symbols and descriptions for each
    rule that matched only if the message is Spam.
    """

    def extra_details(self, msg, options):
        """Return a full report of rules that matched
        the message, if it's Spam.
        """
        if msg.score < self.ruleset.conf["required_score"]:
            return
        result = super(ReportIfSpamCommand, self).extra_details(msg, options)
        for line in result:
            yield line
