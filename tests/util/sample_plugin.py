"""Sample plugin that can be used for testing."""

from __future__ import print_function, absolute_import

import pad.plugins.base


class TestPluginReportRevoke(pad.plugins.base.BasePlugin):
    """Sample plugin that can be used for testing."""
    options = {}
    eval_rules = ()

    def plugin_report(self, msg):
        """Report the message as spam."""
        super(TestPluginReportRevoke, self).plugin_report(msg)
        print("Reporting message.")

    def plugin_revoke(self, msg):
        """Report the message as ham."""
        super(TestPluginReportRevoke, self).plugin_revoke(msg)
        print("Revoking message.")
