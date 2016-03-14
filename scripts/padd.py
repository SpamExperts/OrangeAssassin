#! /usr/bin/env python

"""Starts the SpamPAD daemon."""

from __future__ import print_function
from __future__ import absolute_import

import os
import sys
import argparse

import signal

import pad
import pad.config
import pad.server


def detach(stdout="/dev/null", stderr=None, stdin="/dev/null", pidfile=None):
    """This forks the current process into a daemon.

    The stdin, stdout, and stderr arguments are file names that
    will be opened and be used to replace the standard file descriptors
    in sys.stdin, sys.stdout, and sys.stderr.

    These arguments are optional and default to /dev/null.

    Note that stderr is opened unbuffered, so if it shares a file with
    stdout then interleaved output may not appear in the order that you
    expect."""
    # Do first fork.
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent.
            sys.exit(0)
    except OSError as err:
        print("Fork #1 failed: (%d) %s" % (err.errno, err.strerror),
              file=sys.stderr)
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0:
            # Exit second parent.
            sys.exit(0)
    except OSError as err:
        print("Fork #2 failed: (%d) %s" % (err.errno, err.strerror),
              file=sys.stderr)
        sys.exit(1)

    # Open file descriptors and print start message.
    if not stderr:
        stderr = stdout
    stdi = open(stdin, "r")
    stdo = open(stdout, "a+")
    stde = open(stderr, "ab+", 0)
    pid = str(os.getpid())
    if pidfile:
        with open(pidfile, "w+") as pidf:
            pidf.write("%s\n" % pid)

    # Redirect standard file descriptors.
    os.dup2(stdi.fileno(), sys.stdin.fileno())
    os.dup2(stdo.fileno(), sys.stdout.fileno())
    os.dup2(stde.fileno(), sys.stderr.fileno())


def run_daemon(args):
    """Start the daemon."""
    if args.daemonize:
        detach(pidfile=args.pidfile)
    address = (args.listen, args.port)
    if args.prefork is not None:
        server = pad.server.PreForkServer(
            address, args.sitepath, args.configpath, paranoid=args.paranoid,
            ignore_unknown=not args.show_unknown, prefork=args.prefork
        )
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


def send_action(args):
    """Send a signal to an existing running daemon."""
    if not os.path.exists(args.pidfile):
        print("No pid file available: %s", args.pidfile, file=sys.stderr)
        return
    with open(args.pidfile) as pidf:
        pid = int(pidf.read())

    if args.action == "reload":
        os.kill(pid, signal.SIGUSR1)
    elif args.action == "stop":
        os.kill(pid, signal.SIGTERM)


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
        send_action(args)
    else:
        run_daemon(args)


if __name__ == "__main__":
    main()
