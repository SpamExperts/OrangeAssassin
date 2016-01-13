"""Implement a simple PING command."""

from __future__ import absolute_import

import pad.protocol.base


class PingCommand(pad.protocol.base.BaseProtocol):
    """A simple PING command."""
    ok_code = "PONG"

    def handle(self, msg, options):
        return ""

