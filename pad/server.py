"""The PAD server listens for connections, parses the messages and
returns the result.
"""
from __future__ import absolute_import

import os
import copy
import errno
import socket
import signal
import logging
import threading
import socketserver

import pad
import pad.config
import pad.protocol
import pad.rules.parser

import pad.protocol.noop
import pad.protocol.tell
import pad.protocol.check
import pad.protocol.process

COMMANDS = {
    "TELL": pad.protocol.tell.TellCommand,
    "PING": pad.protocol.noop.PingCommand,
    "SKIP": pad.protocol.noop.SkipCommand,
    "CHECK": pad.protocol.check.CheckCommand,
    "SYMBOLS": pad.protocol.check.SymbolsCommand,
    "REPORT": pad.protocol.check.ReportCommand,
    "REPORT_IFSPAM": pad.protocol.check.ReportIfSpamCommand,
    "PROCESS": pad.protocol.process.ProcessCommand,
    "HEADERS": pad.protocol.process.HeadersCommand,
}


def _eintr_retry(func, *args):
    """restart a system call interrupted by EINTR"""
    while True:
        try:
            return func(*args)
        except OSError as e:
            if e.args[0] != errno.EINTR:
                raise


class RequestHandler(socketserver.StreamRequestHandler):
    """Handle a single request."""

    def handle(self):
        """Get the command from the client and pass it to the
        correct handler.
        """
        line = self.rfile.readline().decode("utf8").strip()
        command, proto_version = line.split()
        try:
            # Run the command handler
            COMMANDS[command.upper()](self.rfile, self.wfile, self.server)
        except KeyError:
            error_line = ("SPAMD/%s 76 Bad header line: %s\r\n" %
                          (pad.__version__, line))
            self.wfile.write(error_line.encode("utf8"))


class Server(socketserver.TCPServer):
    """The PAD server. Handles incoming connections in a single
    thread and single process.
    """

    def __init__(self, address, sitepath, configpath, paranoid=False,
                 ignore_unknown=True):
        self.log = logging.getLogger("pad-logger")
        self.paranoid = paranoid
        self.ignore_unknown = ignore_unknown
        self._ruleset = None
        self._user_rulesets = {}
        self._parser_results = None
        self.sitepath = sitepath
        self.configpath = configpath

        if ":" in address[0]:
            Server.address_family = socket.AF_INET6
        else:
            Server.address_family = socket.AF_INET

        self.log.debug("Listening on %s", address)
        socketserver.TCPServer.__init__(self, address, RequestHandler,
                                        bind_and_activate=False)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, socket.error) as e:
            self.log.debug("Unable to set IPV6_V6ONLY to false %s", e)
        self.load_config()
        self.server_bind()
        self.server_activate()

        # Finally, set signals
        signal.signal(signal.SIGUSR1, self.reload_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def load_config(self):
        """Reads the configuration files and reloads the ruleset."""
        self._user_rulesets.clear()
        parser = pad.rules.parser.parse_pad_rules(
            pad.config.get_config_files(self.configpath, self.sitepath),
            paranoid=self.paranoid, ignore_unknown=self.ignore_unknown
        )
        self._ruleset = parser.get_ruleset()
        # Store a copy of the parser results to generate user
        # settings later
        self._parser_results = parser.results

    def get_user_ruleset(self, user=None):
        """Get the corresponding ruleset for this user. If the
        `allow_user_rules` is not set to True then it will get
        the main ruleset loaded from the site files/

        :param user: The username for which the config should
          be returned.
        :return: a `pad.rules.ruleset.RuleSet` object
        """
        if user is not None and self._ruleset.conf["allow_user_rules"]:
            if user in self._user_rulesets:
                return self._user_rulesets[user]

            path = pad.config.get_userprefs_path(user)
            if not os.path.exists(path):
                self.log.warn("No user preference file: %s", path)
                return self._ruleset
            parser = pad.rules.parser.PADParser(
                self._ruleset.ctxt.paranoid,
                self._ruleset.ctxt.ignore_unknown
            )
            # Use the already parsed results and pass the user
            # ones.
            parser.results = copy.deepcopy(self._parser_results)
            parser.parse_file(path)
            ruleset = parser.get_ruleset()
            # Cache the result
            self._user_rulesets[user] = ruleset
            return ruleset
        return self._ruleset

    def shutdown_handler(self, *args, **kwargs):
        """Handler for the SIGTERM signal. This should be used to kill the
        daemon and ensure proper clean-up.
        """
        self.log.info("SIGTERM received. Shutting down.")
        t = threading.Thread(target=self.shutdown)
        t.start()

    def reload_handler(self, *args, **kwargs):
        """Handler for the SIGUSR1 signal. This should be used to reload
        the configuration files.
        """
        self.log.info("SIGUSR1 received. Reloading configuration.")
        t = threading.Thread(target=self.load_config)
        t.start()

    def handle_error(self, request, client_address):
        self.log.error("Error while processing request from: %s",
                       client_address, exc_info=True)


class PreForkServer(Server):
    """The same as Server, but prefork itself when starting the self, by
    forking a number of child-processes.

    The parent process will then wait for all his child process to complete.
    """

    def __init__(self, address, sitepath, configpath, paranoid=False,
                 ignore_unknown=True, prefork=6):
        """The same as Server.__init__ but requires a list of databases
        instead of a single database connection.
        """
        self.pids = None
        self._prefork = prefork
        Server.__init__(self, address, sitepath, configpath, paranoid=paranoid,
                        ignore_unknown=ignore_unknown)

    def serve_forever(self, poll_interval=0.5):
        """Fork the current process and wait for all children to finish."""
        pids = []
        for dummy in range(self._prefork):
            pid = os.fork()
            if not pid:
                Server.serve_forever(self, poll_interval=poll_interval)
                os._exit(0)
            else:
                self.log.info("Forked worker %s", pid)
                pids.append(pid)
        self.pids = pids
        for pid in self.pids:
            _eintr_retry(os.waitpid, pid, 0)

    def shutdown(self):
        """If this is the parent process send the TERM signal to all children,
        else call the super method.
        """
        for pid in self.pids or ():
            os.kill(pid, signal.SIGTERM)
        if self.pids is None:
            Server.shutdown(self)

    def load_config(self):
        """If this is the parent process send the USR1 signal to all children,
        else call the super method.
        """
        for pid in self.pids or ():
            os.kill(pid, signal.SIGUSR1)
        if self.pids is None:
            Server.load_config(self)
