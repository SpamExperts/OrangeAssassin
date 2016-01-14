"""Implement the TELL command."""

from __future__ import absolute_import

import pad.protocol
import pad.protocol.base


class TellCommand(pad.protocol.base.BaseProtocol):
    """Report of revoke spam/ham messages.
    """
    has_options = True
    has_message = True

    def handle(self, msg, options):
        spam = options.get("message-class", "spam").lower() == "spam"
        response = []
        if "set" in options:
            targets = options.get("set").split(",")
            local = "local" in targets
            remote = "remote" in targets
            self.ruleset.ctxt.hook_report(msg, spam, local, remote)
            response.append("DidSet: %s" % options.get("set"))
        if "remove" in options:
            targets = options.get("set").split(",")
            local = "local" in targets
            remote = "remote" in targets
            self.ruleset.ctxt.hook_report(msg, spam, local, remote)
            response.append("DidRemove: %s" % options.get("remove"))
        for action in response:
            yield action