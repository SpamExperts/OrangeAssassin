"""Pyzor check plugin."""

from __future__ import absolute_import

import pyzor.client
import pyzor.digest

import pad.plugins.base


class PyzorPlugin(pad.plugins.base.BasePlugin):
    eval_rules = ("check_pyzor",)
    options = {"use_pyzor": ("bool", True),
               "pyzor_max": ("int", 5),
               "pyzor_timeout": ("float", 3.5),
               "pyzor_servers": ("list", ["public.pyzor.org:24441"])}

    def finish_parsing_end(self, ruleset):
        """Create and store globally a pyzor client."""
        super(PyzorPlugin, self).finish_parsing_end(ruleset)
        # Store a single Pyzor client in the global context at plugin
        # initialization, rather than creating a new one for every message
        self["client"] = pyzor.client.BatchClient(
            timeout=self["pyzor_timeout"]
        )

    def check_pyzor(self, msg, target=None):
        """Check the message with the defined pyzor servers. Stores the
        digest so it can be used
        """
        if not self["use_pyzor"]:
            return False
        digest = pyzor.digest.DataDigester(msg.msg).value
        # Store the digest data in the local message context, so it can be
        # used for reporting later.
        self.set_local(msg, "digest", digest)

        client = self["client"]
        self.ctxt.log.debug("Checking digest %s with Pyzor", digest)
        for server in self["pyzor_servers"]:
            response = client.check(digest, server.rsplit(":", 1))
            r_count = int(response["Count"])
            wl_count = int(response["WL-Count"])
            self.ctxt.log.debug("Response from %s: (%s, %s)", server, r_count,
                                wl_count)
            if r_count >= self["pyzor_max"] and not wl_count:
                return True
        return False

    def plugin_report(self, msg):
        """Report the digest to pyzor as spam."""
        super(PyzorPlugin, self).plugin_report(msg)
        self._pyzor_report(msg, True)

    def plugin_revoke(self, msg):
        """Report the digest to pyzor as ham."""
        super(PyzorPlugin, self).plugin_revoke(msg)
        self._pyzor_report(msg, False)

    def _pyzor_report(self, msg, spam=True):
        """Does the actual work for reporting digests to pyzor."""
        if not self["use_pyzor"]:
            return
        try:
            digest = self.get_local(msg, "digest")
        except KeyError:
            digest = pyzor.digest.DataDigester(msg.msg).value
            self.set_local(msg, "digest", digest)
        client = self["client"]
        self.ctxt.log.debug("Reporting digest %s with Pyzor (%s)", digest,
                            spam)
        for server in self["pyzor_servers"]:
            if spam:
                client.report(digest, server.rsplit(":", 1))
            else:
                client.whitelist(digest, server.rsplit(":", 1))
