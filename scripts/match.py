#! /usr/bin/env python

"""Testing tool that parses SA rule set files and runs a match against message.

Prints out any matching rules.
"""

from __future__ import print_function

import os
import sys
import glob
import optparse

import sa
import sa.errors
import sa.message
import sa.rules.parser


def main():
    usage = "usage: %prog [options] sa_rules_glob message_file"
    opt = optparse.OptionParser(description=__doc__, version=sa.__version__,
                                usage=usage)
    opt.add_option("-n", "--nice", dest="nice", type="int",
                   help="'nice' level", default=0)
    opt.add_option("--paranoid", action="store_true", default=False,
                   dest="paranoid", help="if errors are found in the ruleset "
                   "stop processing")
    opt.add_option("-d", "--debug", action="store_true", default=False,
                   dest="debug", help="enable debugging output")
    options, (rule_glob, msg_file) = opt.parse_args()
    os.nice(options.nice)

    try:
        ruleset = sa.rules.parser.parse_sa_rules(glob.glob(rule_glob),
                                                 options.paranoid)
    except sa.errors.MaxRecursionDepthExceeded as e:
        print(e.recursion_list, file=sys.stderr)
        sys.exit(1)
    except sa.errors.ParsingError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    with open(msg_file) as msgf:
        raw_msg = msgf.read()

    msg = sa.message.Message(raw_msg)

    ruleset.match(msg)

    for name, result in msg.rules_checked.items():
        if result:
            print(ruleset.get_rule(name))

if __name__ == "__main__":
    main()

