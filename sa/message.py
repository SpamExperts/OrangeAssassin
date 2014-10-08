"""Internal representation of email messages."""

from builtins import object

from future import standard_library
standard_library.install_hooks()

import re
import email
import html.parser
import collections
import email.header

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


class Message(object):
    """Internal representation of an email message. Used for rule matching."""
    def __init__(self, raw_msg):
        """Parse the message, extracts and decode all headers and all
        text parts.
        """
        self.raw_msg = self.translate_line_breaks(raw_msg)
        self.msg = email.message_from_string(self.raw_msg)

        self.headers = []
        self.text = ""
        self.raw_text = ""
        self.uri_list = []
        self.rules_checked = {}
        self._parse_message()

    def clear_matches(self):
        """Clear any already checked rules."""
        self.rules_checked = {}

    @staticmethod
    def translate_line_breaks(text):
        """Convert any EOL style to Linux EOL."""
        text = text.replace("\r\n", "\n")
        return text.replace("\r", "\n")

    @staticmethod
    def normalize_html_part(payload):
        """Strip all HTML tags."""
        data = []
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
        parts = []
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

    @classmethod
    def _dump_headers(cls, msg):
        """Decode all headers."""
        # XXX Not all headers will actually be checked we could only parse
        # XXX the ones we know we will check or have it done lazily.
        headers = _Headers()
        for name, value in msg._headers:
            value = cls._decode_header(value)
            if value:
                headers[name].append(value)
        return headers

    def _parse_message(self):
        """Parse the message."""
        self.headers = self._dump_headers(self.msg)
        # The body starts with the Subject header(s)
        body = self.headers["Subject"][:]
        raw_body = []
        for subtype, payload in self._iter_text_parts():
            self.uri_list.extend(URL_RE.findall(payload))
            if subtype == "html":
                body.extend(self.normalize_html_part(payload.replace("\n", "")))
                raw_body.append(payload)
            else:
                body.append(payload.replace("\n", ""))
                raw_body.append(payload)
        self.text = " ".join(body)
        self.raw_text = "\n".join(raw_body)

    def _iter_text_parts(self):
        """Extract and decode the text parts from the parsed email message.

        Yields (subtype, payload)
        """
        for part in self.msg.walk():
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
                yield part.get_content_subtype(), payload
            else:
                continue


