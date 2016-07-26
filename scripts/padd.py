#! /usr/bin/env python

"""Starts the SpamPAD daemon."""

from __future__ import print_function
from __future__ import absolute_import

import os
import argparse

import spoon.daemon

import pad
import pad.config
import pad.server


def run_daemon(args):
    """Start the daemon."""
    if args.daemonize:
        spoon.daemon.detach(pidfile=args.pidfile)
    address = (args.listen, args.port)
    if args.prefork is not None:
        server = pad.server.PreForkServer(
            address, args.sitepath, args.configpath, paranoid=args.paranoid,
            ignore_unknown=not args.show_unknown
        )
        server.prefork = args.prefork
    else:
        server = pad.server.Server(
            address, args.sitepath, args.configpath,paranoid=args.paranoid,
            ignore_unknown=not args.show_unknown
        )
    try:
        server.serve_forever()
    finally:
        try:
            os.remove(args.pidfile)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("action", nargs="?", choices=["reload", "stop"],
                        help="Send a signal a running daemon.")
    parser.add_argument("-D", "--debug", action="store_true", default=False,
                        help="Enable debugging output")
    parser.add_argument("-P", "--paranoid", action="store_true", default=False,
                        help="Die upon user errors")
    parser.add_argument("--show-unknown", action="store_true", default=False,
                        help="Show warnings about unknown parsing errors")
    parser.add_argument("-l", "--allow-tell", action="store_true", default=False,
                        help="Allow learning/reporting")
    parser.add_argument("-d", "--daemonize", action="store_true", default=False,
                        help="Detach the process")
    parser.add_argument("--prefork", type=int, default=None,
                        help="Pre fork the server with a number of workers")
    parser.add_argument("-i", "--listen", type=str, default="0.0.0.0",
                        help="Listen on IP addr and port")
    parser.add_argument("-p", "--port", type=int, default=783,
                        help="Listen on specified port, "
                             "may be overridden by -i")
    parser.add_argument("-C", "--configpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=False))
    parser.add_argument("-S", "--sitepath", "--siteconfigpath", action="store",
                        help="Path to standard configuration directory",
                        **pad.config.get_default_configs(site=True))
    parser.add_argument("-r", "--pidfile", default="/var/run/padd.pid")
    parser.add_argument("--log-file", dest="log_file",
                        default="/var/log/padd.log")
    # parser.add_argument("-4", "--ipv4-only", "--ipv4", default=False,
    #                     action="store_true", help="Use IPv4 where applicable, "
    #                                               "disables IPv6")
    # parser.add_argument("-6", default=False,
    #                     action="store_true", help="Use IPv6 where applicable, "
    #                                               "disables IPv4")
    parser.add_argument("-v", "--version", action="version",
                        version=pad.__version__)
    args = parser.parse_args()
    logger = pad.config.setup_logging("pad-logger", debug=args.debug,
                                      filepath=args.log_file)
    if args.action:
        spoon.daemon.send_action(args.action, args.pidfile)
    else:
        run_daemon(args)


if __name__ == "__main__":
    main()
