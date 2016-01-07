""" RelayCountry Plugin. """

from __future__ import absolute_import

import pad.plugins.base

class RelayCountry(pad.plugins.base.BasePlugin):
    
    def check_start(self, msg):
        """ Check the X-Relay-Countries in the message and exposes the 
        countries that a mail was relayed from
        """
        if not msg.get("X-Relay-Countries", None):
            return
        return msg["X-Relay-Countries"]

