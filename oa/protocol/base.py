"""Base class for all protocol commands"""

import zlib

import oa
import oa.errors
import oa.message


class BaseProtocol(object):
    """Base object for any protocol command implementation."""
    # If this is set to True then try to load options
    has_options = False
    # If this is set to True then the command expects
    # a message
    has_message = False
    chunk_size = 8192
    ok_code = "EX_OK"

    def __init__(self, rfile, wfile, server):
        self.rfile = rfile
        self.wfile = wfile
        self.server = server
        # This is initialized with the default ruleset and it
        # will get changed later if a user is specified and
        # that option is allowed.
        self.ruleset = server.get_user_ruleset(user=None)
        # For brevity
        self.log = server.log
        self.get_and_handle()

    def get_options(self):
        """Get any options added to the command."""
        options = dict()
        while True:
            line = self.rfile.readline().decode("utf8").strip()
            if not line:
                break
            self.log.debug("Got line: %s", line)
            if ":" not in line:
                self.log.debug("Invalid option: %s", line)
                error_msg = "header not in 'Name: value' format"
                raise oa.errors.InvalidOption(error_msg)
            name, value = line.split(":", 1)
            options[name.lower()] = value.strip()
        return options

    def get_message(self, options):
        """Retrieve the message from the client.

        The data is read in chunks and returned as a joined string.
        """
        message_chunks = list()
        # If the Content-Length is available it's much easier to
        # retrieve the data.
        content_length = options.get('content-length')
        if content_length is not None:
            error_msg = "Content-Length contains non-numeric bytes"
            try:
                content_length = int(content_length)
            except ValueError:
                raise oa.errors.InvalidOption(error_msg)
            if content_length < 0:
                raise oa.errors.InvalidOption(error_msg)
        while content_length is None or content_length > 0:
            chunk = self.rfile.read(min(content_length or self.chunk_size,
                                        self.chunk_size))
            if not chunk:
                break
            message_chunks.append(chunk.decode("utf8"))
            if content_length is not None:
                content_length -= len(chunk)
        if options.get('compress') == "zlib":
            return zlib.decompress("".join(message_chunks))
        return "".join(message_chunks)

    def get_and_handle(self):
        """Get data from the client and call the handle method."""
        message = None
        options = dict()
        try:
            if self.has_options:
                options = self.get_options()
            user = options.get("user")
            self.ruleset = self.server.get_user_ruleset(user)
            if self.has_message:
                message = self.get_message(options)
                message = oa.message.Message(self.ruleset.ctxt, message)
        except oa.errors.InvalidOption as e:
            error_line = ("SPAMD/%s 76 Bad header line: (%s)\r\n" %
                          (oa.__version__, e))
            self.wfile.write(error_line.encode("utf8"))
            return

        ok_line = "SPAMD/%s 0 %s\r\n" % (oa.__version__, self.ok_code)
        self.wfile.write(ok_line.encode("utf8"))
        for response in self.handle(message, options):
            self.log.debug("Writing response: %s", response)
            self.wfile.write(response.encode("utf8"))

    def handle(self, msg, options):
        """Perform the actual command and return a response for
        the client.
        """
        raise NotImplementedError()
