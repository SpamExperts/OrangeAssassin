"""Implement general "no operation" commands."""

from __future__ import absolute_import

import oa.protocol.base


class PingCommand(oa.protocol.base.BaseProtocol):
    """A simple PING command."""
    ok_code = "PONG"

    def handle(self, msg, options):
        return ""


class SkipCommand(oa.protocol.base.BaseProtocol):
    """The client changed his mind, do nothing."""

    def handle(self, msg, options):
        pass

    def get_and_handle(self):
        """Do nothing."""
