#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import pickle
import logging
import argparse

import pad
import pad.config
import pad.errors
import pad.message
import pad.rules.parser

SERIALIZED = False


class MessageList(argparse.FileType):
    def __call__(self, string):
        if os.path.isdir(string):
            for x in os.listdir(string):
                path = os.path.join(string, x)
                msgf = super(MessageList, self).__call__(path)
                yield msgf
        else:
            yield super(MessageList, self).__call__(string)


def _is_binary_reader(stream, default=False):
    try:
        return isinstance(stream.read(0), bytes)
    except Exception:
        return default


def get_binary_stdin():
    # sys.stdin might or might not be binary in some extra cases.  By
    # default it's obviously non binary which is the core of the
    # problem but the docs recommend changing it to binary for such
    # cases so we need to deal with it.
    is_binary = _is_binary_reader(sys.stdin, False)
    if is_binary:
        return sys.stdin
    buf = getattr(sys.stdin, 'buffer', None)
    if buf is not None and _is_binary_reader(buf, True):
        return buf


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
    parser.add_argument("-D", "--debug", action="store_true",
                        help="Enable debugging output", default=False)
    parser.add_argument("-v", "--version", action="version",
                        version=pad.__version__)
    parser.add_argument("-C", "--configpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=False))
    parser.add_argument("-S", "--sitepath", "--siteconfigpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=True))
    parser.add_argument("-p", "--prefspath", "--prefs-file",
                        default="~/.spamassassin/user_prefs",
                        help="Path to user preferences.")
    parser.add_argument("-dl", "--deactivate-lazy", dest="lazy_mode",
                        action="store_true", default=False,
                        help="Deactivate lazy loading of rules/regex")
    parser.add_argument("-sp", "--serializepath", action="store",
                        help="Path to the file with serialized ruleset",
                        default="~/.spamassassin/serialized_ruleset")
    parser.add_argument("-t", "--test-mode", action="store_true",
                        default=False,
                        help="Pipe message through and add extra report to "
                             "the "
                             "bottom")
    parser.add_argument("-R", "--report-only", action="store_true",
                        default=False, help="Only print the report instead of "
                                            "the adjusted message.")
    parser.add_argument("messages", type=MessageList(), nargs="*",
                        metavar="path", help="Paths to messages or "
                                             "directories containing messages",
                        default=[[get_binary_stdin()]])

    return parser.parse_args(args)


def serialize(ruleset, path):
    logger = logging.getLogger("pad-logger")
    logger.info("Compiling ruleset to %s", path)
    try:
        with open(os.path.expanduser(path), "wb") as f:
            pickle.dump(ruleset, f, pickle.HIGHEST_PROTOCOL)
    except FileNotFoundError as e:
        logger.critical("Cannot open the file: %s", e)
        sys.exit(1)


def main():
    options = parse_arguments(sys.argv[1:])
    pad.config.LAZY_MODE = not options.lazy_mode
    logger = pad.config.setup_logging("pad-logger",
                                      debug=options.debug)
    config_files = pad.config.get_config_files(options.configpath,
                                               options.sitepath,
                                               options.prefspath)

    if not config_files:
        logger.critical("Config: no rules were found.")
        sys.exit(1)
    ruleset = pad.rules.parser.parse_pad_rules(
        config_files, options.paranoid, not options.show_unknown
    ).get_ruleset()

    serialize(ruleset, options.serializepath)


if __name__ == "__main__":
    main()
