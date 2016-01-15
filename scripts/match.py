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


CONFIG_PATHS = (
    '/var/lib/spamassassin/3.004001',
    '/usr/local/share/spamassassin',
    '/usr/local/share/spamassassin',
    '/usr/local/share/spamassassin',
    '/usr/share/spamassassin',
    )


SITE_RULES_PATHS = (
    '/etc/mail/spamassassin',
    '/usr/local/etc/mail/spamassassin',
    '/usr/local/etc/spamassassin',
    '/usr/local/etc/spamassassin',
    '/usr/pkg/etc/spamassassin',
    '/usr/etc/spamassassin',
    '/etc/mail/spamassassin',
    '/etc/spamassassin',
    )


class MessageList(argparse.FileType):

    def __call__(self, string):
        if os.path.isdir(string):
            for x in os.listdir(string):
                path = os.path.join(string, x)
                msgf = super(MessageList, self).__call__(path)
                yield msgf
        else:
            yield super(MessageList, self).__call__(string)


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
    parser.add_argument("-D", "--debug", action="store_true",
                        help="Enable debugging output", default=False)
    parser.add_argument("-v", "--version", action="store_true",
                        help="Print version", default=False)


    config_paths = [x for x in CONFIG_PATHS if os.path.exists(x)]

    try:
        default_config = config_paths[0]
        require_config = False
    except (IndexError):
        default_config = None
        require_config = True


    parser.add_argument("-C", "--configpath", "--config-file", action="store",
                        help="Path to standard configuration directory",
                        default=default_config, required=require_config)

    available_siteconfig_paths = [x for x in SITE_RULES_PATHS if os.path.exists(x)]

    try:
        default_siteconfig = available_siteconfig_paths[0]
        require_siteconfig = False
    except (IndexError):
        default_siteconfig = None
        require_siteconfig = True

    parser.add_argument("--siteconfigpath", action="store",
                        help="Path to standard configuration directory",
                        default=default_siteconfig, required=require_siteconfig)



    parser.add_argument("messages", type=MessageList(), nargs="*",
                        metavar="path", help="Paths to messages or "
                        "directories containing messages",
                        default=[[sys.stdin]])

    return parser.parse_args(args)

def main():

    options = parse_arguments(sys.argv[1:])

    if options.version:
        print(pad.__version__)

    logger = pad.config.setup_logging("pad-logger", debug=options.debug)

    config_files = pad.config.get_config_files(options.configpath,
                                           options.siteconfigpath)

    try:
        ruleset = pad.rules.parser.parse_pad_rules(config_files,
                                                   options.paranoid)
    except pad.errors.MaxRecursionDepthExceeded as e:
        print(e.recursion_list, file=sys.stderr)
        sys.exit(1)
    except pad.errors.ParsingError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    count = 0
    for message_list in options.messages:
        for msgf in message_list:
            raw_msg = msgf.read()
            msgf.close()
            msg = pad.message.Message(ruleset.ctxt, raw_msg)

            if options.revoke:
                ruleset.ctxt.hook_revoke(msg)
            elif options.report:
                ruleset.ctxt.hook_report(msg)
            else:
                ruleset.match(msg)

                for name, result in msg.rules_checked.items():
                    if result:
                        print(ruleset.get_rule(name))
        count += 1

    print("%s message(s) examined" % count)



if __name__ == "__main__":
    main()

