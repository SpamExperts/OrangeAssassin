"""Similar to the DumpText demo SA plugin."""

from __future__ import print_function, absolute_import

import sys

import pad.plugins.base


class DumpText(pad.plugins.base.BasePlugin):
    """Similar to the SA DumpText demo plugin, useful for debugging rulesets.
    """

    eval_rules = ("dump_text",
                  "dump_raw_text",
                  "dump_meta_data",)

    def dump_text(self, msg):
        """Dump the decoded parsed text of the message to stderr."""
        self.ctxt.log.debug("Dumping text to STDERR")
        print(msg.text, file=sys.stderr)
        return True

    def dump_raw_text(self, msg):
        """Dump the decoded raw text of the message to stderr."""
        self.ctxt.log.debug("Dumping raw text to STDERR")
        print(msg.raw_text, file=sys.stderr)
        return True

    def dump_meta_data(self, msg):
        """Dump the extracted data of the message to stderr."""
        self.ctxt.log.debug("Dumping metadata to STDERR.")
        print("Decoded Headers:", file=sys.stderr)
        for header in msg.iter_decoded_headers():
            print(header, file=sys.stderr)
        print("", file=sys.stderr)
        print("URI list:", file=sys.stderr)
        for uri in msg.uri_list:
            print(uri, file=sys.stderr)
