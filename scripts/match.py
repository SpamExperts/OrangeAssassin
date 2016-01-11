#! /usr/bin/env python

"""Testing tool that parses PAD rule set files and runs a match against message.

Prints out any matching rules.
"""

from __future__ import print_function

import os
import sys
import glob
import argparse

import pad
import pad.config
import pad.errors
import pad.message
import pad.rules.parser




class MessageList(argparse.FileType):

    def __call__(self, string):
        if string != "-" and os.path.isdir(string):
            items = [
                super(MessageList, self).__call__(
                    open(os.path.join(string, x), self._mode))
                for x in os.listdir(string) 
                if os.path.isfile(os.path.join(string,x))]
            return items
        else:
            return [super(MessageList, self).__call__(string)]


def parse_arguments(args):
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-n", "--nice", type=int, help="set 'nice' level",
                        default=0)
    parser.add_argument("--paranoid", action="store_true",
                        help="If errors are found in the ruleset stop "
                        "processing", default=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--report", action="store_true",
                        help="Report the message as spam", default=False)
    group.add_argument("-k", "--revoke", action="store_true",
                        help="Revoke the message as spam ", default=False)
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debugging output", default=False)
    parser.add_argument("-v", "--version", action="store_true",
                        help="Print version", default=False)
    parser.add_argument("-C", "--configpath", "--config-file", action="store",
                        help="Path to standard configuration directory",
                        default="/usr/share/spamassassin")
    parser.add_argument("--siteconfig", action="store",
                        help="Path to standard configuration directory",
                        default="/etc/mail/spamassassin")
    parser.add_argument("messages", type=MessageList(), nargs="?",
                        metavar="path", help="Paths to messages or "
                        "directories containing messages",
                        default="-")

    return parser.parse_args(args)

def main():

    options = parse_arguments(sys.argv[1:])

    if options.version:
        print(pad.__version__)

    logger = pad.config.setup_logging("pad-logger", debug=options.debug)

    try:
        ruleset = pad.rules.parser.parse_pad_rules(glob.glob(options.siteconfig),
                                                   options.paranoid)
    except pad.errors.MaxRecursionDepthExceeded as e:
        print(e.recursion_list, file=sys.stderr)
        sys.exit(1)
    except pad.errors.ParsingError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for msgf in options.messages:

        raw_msg = msgf.read()
        msg = pad.message.Message(ruleset.ctxt, raw_msg)

        ruleset.match(msg)

        for name, result in msg.rules_checked.items():
            if result:
                print(ruleset.get_rule(name))

        if options.revoke:
            ruleset.context.hook_revoke(raw_msg)
        if options.report:
            ruleset.context.hook_report(raw_msg)

        msgf.close()

if __name__ == "__main__":
    main()

