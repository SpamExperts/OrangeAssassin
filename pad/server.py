"""The PAD server listens for connections, parses the messages and
returns the result.
"""
from __future__ import absolute_import

import os
import copy

import spoon.server

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


class RequestHandler(spoon.server.Gulp):
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


class Server(spoon.server.TCPSpoon):
    """The PAD server. Handles incoming connections in a single
    thread and single process.
    """
    server_logger = "spoon-server"
    handler_klass = RequestHandler

    def __init__(self, address, sitepath, configpath, paranoid=False,
                 ignore_unknown=True):
        self.paranoid = paranoid
        self.ignore_unknown = ignore_unknown
        self._ruleset = None
        self._user_rulesets = {}
        self._parser_results = None
        self.sitepath = sitepath
        self.configpath = configpath

        super(Server, self).__init__(address)

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
            ruleset.ctxt.username = user
            # Cache the result
            self._user_rulesets[user] = ruleset
            return ruleset
        return self._ruleset


class PreForkServer(Server, spoon.server.TCPSpork):
    """The same as Server, but prefork itself when starting the self, by
    forking a number of child-processes.

    The parent process will then wait for all his child process to complete.
    """
