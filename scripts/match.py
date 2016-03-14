#! /usr/bin/env python

"""Testing tool that parses PAD rule set files and runs a match against message.

Prints out any matching rules.
"""

from __future__ import print_function

import os
import sys
import argparse

import pad
import pad.config
import pad.errors
import pad.message
import pad.rules.parser


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
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-n", "--nice", type=int, help="set 'nice' level",
                        default=0)
    parser.add_argument("-P", "--paranoid", action="store_true", default=False,
                        help="Die upon user errors")
    parser.add_argument("--show-unknown", action="store_true", default=False,
                        help="Show warnings about unknown parsing errors")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--report", action="store_true",
                       help="Report the message as spam", default=False)
    group.add_argument("-k", "--revoke", action="store_true",
                       help="Revoke the message as spam ", default=False)
    parser.add_argument("-D", "--debug", action="store_true",
                        help="Enable debugging output", default=False)
    parser.add_argument("-v", "--version", action="version",
                        version=pad.__version__)
    parser.add_argument("-C", "--configpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=False))
    parser.add_argument("--sitepath", "--siteconfigpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=True))
    parser.add_argument("-p", "--prefspath", "--prefs-file",
                        default="~/.spamassassin/user_prefs",
                        help="Path to user preferences.")
    parser.add_argument("-t", "--test-mode", action="store_true", default=False,
                        help="Pipe message through and add extra report to the "
                             "bottom")
    parser.add_argument("-R", "--report-only", action="store_true",
                        default=False, help="Only print the report instead of "
                                            "the adjusted message.")
    parser.add_argument("messages", type=MessageList(), nargs="*",
                        metavar="path", help="Paths to messages or "
                                             "directories containing messages",
                        default=[[sys.stdin]])

    return parser.parse_args(args)


def main():
    options = parse_arguments(sys.argv[1:])
    logger = pad.config.setup_logging("pad-logger", debug=options.debug)
    config_files = pad.config.get_config_files(options.configpath,
                                               options.sitepath,
                                               options.prefspath)

    if not config_files:
        print("Config: no rules were found!", file=sys.stderr)
        sys.exit(1)

    try:
        ruleset = pad.rules.parser.parse_pad_rules(
            config_files, options.paranoid, not options.show_unknown
        ).get_ruleset()
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
            elif options.report_only:
                ruleset.match(msg)
                print(ruleset.get_report(msg))
            else:
                ruleset.match(msg)
                print(ruleset.get_adjusted_message(msg))
                if options.test_mode:
                    print(ruleset.get_report(msg))
        count += 1
    if options.revoke or options.report:
        print("%s message(s) examined" % count)


if __name__ == "__main__":
    main()
