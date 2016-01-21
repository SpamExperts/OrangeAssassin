"""Similar to the DumpText demo SA plugin."""

from __future__ import print_function, absolute_import

import sys

import pad.plugins.base


class TestPluginReportRevoke(pad.plugins.base.BasePlugin):
    """Similar to the SA DumpText demo plugin, useful for debugging rulesets.
    """
    options = {}
    eval_rules = ()

    def plugin_report(self, msg):
        """Report the digest to pyzor as spam."""
        super(TestPluginReportRevoke, self).plugin_report(msg)
        print("Reporting message.")

    def plugin_revoke(self, msg):
        """Report the digest to pyzor as ham."""
        super(TestPluginReportRevoke, self).plugin_revoke(msg)
        print("Revoking message.")
