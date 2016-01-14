"""Base class for all protocol commands"""

import zlib

import pad
import pad.message


class BaseProtocol(object):
    """Base object for any protocol command implementation."""
    # If this is set to True then try to load options
    has_options = False
    # If this is set to True then the command expects
    # a message
    has_message = False
    chunk_size = 8192
    ok_code = "EX_OK"

    def __init__(self, rfile, wfile, ruleset):
        self.rfile = rfile
        self.wfile = wfile
        self.ruleset = ruleset
        # For brevity
        self.log = ruleset.ctxt.log
        self.get_and_handle()

    def get_options(self):
        """Get any options added to the command."""
        options = dict()
        while True:
            line = self.rfile.readline().strip()
            if not line:
                break
            name, value = line.split(":")
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
            content_length = int(content_length)
        while content_length is None or content_length > 0:
            chunk = self.rfile.read(min(content_length, self.chunk_size))
            if not chunk:
                break
            message_chunks.append(chunk)
            if content_length is not None:
                content_length -= len(chunk)
        if options.get('compress') == "zlib":
            return zlib.decompress("".join(message_chunks))
        return "".join(message_chunks)

    def get_and_handle(self):
        """Get data from the client and call the handle method."""
        message = None
        options = dict()
        if self.has_options:
            options = self.get_options()
        if self.has_message:
            message = self.get_message(options)
            message = pad.message.Message(self.ruleset.ctxt, message)
        self.wfile.write("SPAMD/%s 0 %s\r\n" % (pad.__version__, self.ok_code))
        for response in self.handle(message, options):
            self.wfile.write(response)

    def handle(self, msg, options):
        """Perform the actual command and return a response for
        the client.
        """
        raise NotImplementedError()

