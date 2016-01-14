"""Implement general "no operation" commands."""

from __future__ import absolute_import

import pad.protocol.base


class PingCommand(pad.protocol.base.BaseProtocol):
    """A simple PING command."""
    ok_code = "PONG"

    def handle(self, msg, options):
        return ""


class SkipCommand(pad.protocol.base.BaseProtocol):
    """The client changed his mind, do nothing."""

    def get_and_handle(self):
        """Do nothing."""



