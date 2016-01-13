"""The PAD server listens for connections, parses the messages and
returns the result.
"""

import os
import errno
import socket
import signal
import logging
import threading
import socketserver


import pad.config


def _eintr_retry(func, *args):
    """restart a system call interrupted by EINTR"""
    while True:
        try:
            return func(*args)
        except OSError as e:
            if e.args[0] != errno.EINTR:
                raise


class Server(socketserver.TCPServer):
    """The PAD server. Handles incoming connections in a single
    thread and single process.
    """

    def __init__(self, address, sitepath, configpath, paranoid=False):
        self.log = logging.getLogger("pad-logger")
        self.paranoid = paranoid
        self.ruleset = None
        self.sitepath = sitepath
        self.configpath = configpath

        if ":" in address[0]:
            Server.address_family = socket.AF_INET6
        else:
            Server.address_family = socket.AF_INET

        self.log.debug("Listening on %s", address)
        socketserver.TCPServer.__init__(self, address, RequestHandler,
                                        bind_and_activate=False)
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
        self.ruleset = pad.config.load_ruleset(self.sitepath, self.configpath,
                                               self.paranoid)

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
                 prefork=4):
        """The same as Server.__init__ but requires a list of databases
        instead of a single database connection.
        """
        self.pids = None
        self._prefork = prefork
        Server.__init__(self, address, sitepath, configpath, paranoid=paranoid)

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


class RequestHandler(socketserver.StreamRequestHandler):
    """Handle a single pyzord request."""

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        self.server.log.info("Received: %s", self.data)
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())
