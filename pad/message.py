"""Internal representation of email messages."""

from builtins import set
from builtins import list
from builtins import dict
from builtins import object

from future import standard_library
standard_library.install_hooks()

import re
import email
import socket
import email.utils
import html.parser
import collections
import email.header
import email.mime.base
import email.mime.text
import email.mime.multipart

import pad
import pad.context

URL_RE = re.compile(r"""
(
    \b                      # the preceding character must not be alphanumeric
    (?:
        (?:
            (?:https? | ftp)  # capture the protocol
            ://               # skip the boilerplate
        )|
        (?= ftp\.[^\.\s<>"'\x7f-\xff] )|  # allow the protocol to be missing, but only if
        (?= www\.[^\.\s<>"'\x7f-\xff] )   # the rest of the url starts "www.x" or "ftp.x"
    )
    (?:[^\s<>"'\x7f-\xff]+)  # capture the guts
)
""", re.VERBOSE)

STRICT_CHARSETS = frozenset(("quopri-codec", "quopri", "quoted-printable",
                             "quotedprintable"))


class _ParseHTML(html.parser.HTMLParser):
    """Extract data from HTML parts."""
    def __init__(self, collector):
        try:
            html.parser.HTMLParser.__init__(self, convert_charrefs=False)
        except TypeError:
            # Python 2 does not have the convert_charrefs argument.
            html.parser.HTMLParser.__init__(self)
        self.reset()
        self.collector = collector

    def handle_data(self, data):
        """Keep track of the data."""
        data = data.strip()
        if data:
            self.collector.append(data)


class _Headers(collections.defaultdict):
    """Like a defaultdict that returns an empty list by default, but the
    keys are all case insensitive.
    """
    def __init__(self):
        collections.defaultdict.__init__(self, list)

    def __setitem__(self, key, value):
        super(_Headers, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(_Headers, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(_Headers, self).__contains__(key.lower())


class _memoize(object):
    """Memoize the result of the function in a cache. Used to prevent
    superfluous parsing of headers.
    """
    def __init__(self, cache_name):
        self._cache_name = cache_name

    def __call__(self, func):
        """Check if the information is available in a cache, if not call the
        function and cache the result.
        """
        def wrapped_func(fself, name):
            cache = getattr(fself, self._cache_name)
            result = cache.get(name)
            if result is None:
                result = func(fself, name)
                cache[name] = result
            return result
        return wrapped_func


class Message(pad.context.MessageContext):
    """Internal representation of an email message. Used for rule matching."""
    def __init__(self, global_context, raw_msg):
        """Parse the message, extracts and decode all headers and all
        text parts.
        """
        super(Message, self).__init__(global_context)
        self.raw_msg = self.translate_line_breaks(raw_msg)
        self.msg = email.message_from_string(self.raw_msg)

        self.headers = _Headers()
        self.raw_headers = _Headers()
        self.addr_headers = _Headers()
        self.name_headers = _Headers()
        self.mime_headers = _Headers()
        self.raw_mime_headers = _Headers()
        self.text = ""
        self.raw_text = ""
        self.uri_list = set()
        self.score = 0
        self.rules_checked = dict()
        self._parse_message()
        self._hook_parsed_metadata()
        self.interpolate_data = dict()

    def clear_matches(self):
        """Clear any already checked rules."""
        self.rules_checked = dict()
        self.score = 0

    @staticmethod
    def translate_line_breaks(text):
        """Convert any EOL style to Linux EOL."""
        text = text.replace("\r\n", "\n")
        return text.replace("\r", "\n")

    @staticmethod
    def normalize_html_part(payload):
        """Strip all HTML tags."""
        data = list()
        stripper = _ParseHTML(data)
        try:
            stripper.feed(payload)
        except (UnicodeDecodeError, html.parser.HTMLParseError):
            # We can't parse the HTML, so just strip it.  This is still
            # better than including generic HTML/CSS text.
            pass
        return data

    @staticmethod
    def _decode_header(header):
        """Decodes an email header and returns it as a string. Any  parts of
        the header that cannot be decoded are simply ignored.
        """
        parts = list()
        try:
            decoded_header = email.header.decode_header(header)
        except (ValueError, email.header.HeaderParseError):
            return
        for value, encoding in decoded_header:
            if encoding:
                try:
                    parts.append(value.decode(encoding, "ignore"))
                except (LookupError, UnicodeDecodeError):
                    continue
            else:
                parts.append(value)
        return "".join(parts)

    def get_raw_header(self, header_name):
        """Get a list of raw headers with this name."""
        # This is just for consistencies, the raw headers should have been
        # parsed together with the message.
        return self.raw_headers.get(header_name, list())

    @_memoize("headers")
    def get_decoded_header(self, header_name):
        """Get a list of decoded headers with this name."""
        values = list()
        for value in self.get_raw_header(header_name):
            values.append(self._decode_header(value))
        return values

    @_memoize("addr_headers")
    def get_addr_header(self, header_name):
        """Get a list of the first addresses from this header."""
        values = list()
        for value in self.get_decoded_header(header_name):
            for dummy, addr in email.utils.getaddresses([value]):
                if addr:
                    values.append(addr)
                    break
        return values

    @_memoize("name_headers")
    def get_name_header(self, header_name):
        """Get a list of the first names from this header."""
        values = list()
        for value in self.get_decoded_header(header_name):
            for name, dummy in email.utils.getaddresses([value]):
                if name:
                    values.append(name)
                    break
        return values

    def get_raw_mime_header(self, header_name):
        """Get a list of raw MIME headers with this name."""
        # This is just for consistencies, the raw headers should have been
        # parsed together with the message.
        return self.raw_mime_headers.get(header_name, list())

    @_memoize("mime_headers")
    def get_decoded_mime_header(self, header_name):
        """Get a list of raw MIME headers with this name."""
        values = list()
        for value in self.get_raw_mime_header(header_name):
            values.append(self._decode_header(value))
        return values

    def iter_raw_headers(self):
        """Iterate through all the raw headers.

        Yields strings like "<header_name>: <header_value>"
        """
        for header_name, values in self.raw_headers.items():
            for value in values:
                yield "%s: %s" % (header_name, value)

    def iter_decoded_headers(self):
        """Iterate through all the decoded headers.

        Yields strings like "<header_name>: <header_value>"
        """
        for header_name in self.raw_headers:
            for value in self.get_decoded_header(header_name):
                yield "%s: %s" % (header_name, value)

    def iter_addr_headers(self):
        """Iterate through all the addr decoded headers.

        Yields strings like "<header_name>: <addr>"
        """
        for header_name in self.raw_headers:
            for value in self.get_addr_header(header_name):
                yield "%s: %s" % (header_name, value)

    def iter_name_headers(self):
        """Iterate through all the name decoded headers.

        Yields strings like "<header_name>: <name>"
        """
        for header_name in self.raw_headers:
            for value in self.get_name_header(header_name):
                yield "%s: %s" % (header_name, value)

    def iter_raw_mime_headers(self):
        """Iterate through all the raw mime headers.

        Yields strings like "<header_name>: <header_value>"
        """
        for header_name, values in self.raw_mime_headers.items():
            for value in values:
                yield "%s: %s" % (header_name, value)

    def iter_mime_headers(self):
        """Iterate through all the mime decoded headers.

        Yields strings like "<header_name>: <header_value>"
        """
        for header_name in self.raw_mime_headers:
            for value in self.get_decoded_mime_header(header_name):
                yield "%s: %s" % (header_name, value)

    def _parse_message(self):
        """Parse the message."""
        self._hook_check_start()
        # Dump the message raw headers
        for name, raw_value in self.msg._headers:
            self.raw_headers[name].append(raw_value)

        # XXX This is strange, but it's what SA does.
        # The body starts with the Subject header(s)
        body = list(self.get_decoded_header("Subject"))
        raw_body = list()
        for payload, part in self._iter_parts(self.msg):
            self._hook_extract_metadata(payload, part)
            # Extract any MIME headers
            for name, raw_value in part._headers:
                self.raw_mime_headers[name].append(raw_value)
            if payload is not None:
                # this must be a text part
                self.uri_list.update(set(URL_RE.findall(payload)))
                if part.get_content_subtype() == "html":
                    body.extend(self.normalize_html_part(payload.replace("\n",
                                                                         " ")))
                    raw_body.append(payload)
                else:
                    body.append(payload.replace("\n", " "))
                    raw_body.append(payload)
        self.text = " ".join(body)
        self.raw_text = "\n".join(raw_body)

    @staticmethod
    def _iter_parts(msg):
        """Extract and decode the text parts from the parsed email message.
        For non-text parts the payload will be None.

        Yields (payload, part)
        """
        for part in msg.walk():
            if part.get_content_maintype() == "text":
                payload = part.get_payload(decode=True)

                charset = part.get_content_charset()
                errors = "ignore"
                if not charset:
                    charset = "ascii"
                elif charset.lower().replace("_", "-") in STRICT_CHARSETS:
                    errors = "strict"
                try:
                    payload = payload.decode(charset, errors)
                except (LookupError, UnicodeError, AssertionError):
                    try:
                        payload = payload.decode("ascii", "ignore")
                    except UnicodeError:
                        continue
                yield payload, part
            else:
                yield None, part
