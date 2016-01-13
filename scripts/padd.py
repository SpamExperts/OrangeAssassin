#! /usr/bin/env python

"""Starts the SpamPAD daemon."""

from __future__ import absolute_import

import os
import sys
import argparse

import pad
import pad.config
import pad.server


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-D", "--debug", action="store_true", default=False,
                        help="Enable debugging output")
    parser.add_argument("-P", "--paranoid", action="store_true", default=False,
                        help="Die upon user errors")
    parser.add_argument("-d", "--daemonize", action="store_true", default=False,
                        help="Detach the process")
    parser.add_argument("--prefork", type=int, default=None,
                        help="Pre fork the server with a number of workers")
    parser.add_argument("-i", "--listen", type=str, default="0.0.0.0",
                        help="Listen on IP addr and port")
    parser.add_argument("-p", "--port", type=int, default=783,
                        help="Listen on specified port, "
                             "may be overridden by -i")
    parser.add_argument("-C", "--configpath", "--config-file", action="store",
                        help="Path to standard configuration directory",
                        default="/usr/share/spamassassin")
    parser.add_argument("--siteconfig", action="store",
                        help="Path to standard configuration directory",
                        default="/etc/mail/spamassassin")
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
    address = (args.listen, args.port)
    if args.prefork is not None:
        server = pad.server.PreForkServer(address, args.siteconfig,
                                          args.configpath,
                                          args.paranoid)
    else:
        server = pad.server.Server(address, args.siteconfig, args.configpath,
                                   args.paranoid)
    server.serve_forever()


if __name__ == "__main__":
    main()
