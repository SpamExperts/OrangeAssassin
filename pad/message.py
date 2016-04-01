"""Internal representation of email messages."""

from builtins import str
from builtins import set
from builtins import list
from builtins import dict
from builtins import object

import re
import email
import functools
import ipaddress
import email.utils
import html.parser
import collections
import email.header
import email.mime.base
import email.mime.text
import email.mime.multipart

from future.utils import PY3

import pad
import pad.context
from pad.received_parser import ReceivedParser

URL_RE = re.compile(r"""
(
    \b                      # the preceding character must not be alphanumeric
    (?:
        (?:
            (?:https? | ftp)  # capture the protocol
            ://               # skip the boilerplate
        )|
        (?= ftp\.[^\.\s<>"'\x7f-\xff] )|  # allow the protocol to be missing,
        (?= www\.[^\.\s<>"'\x7f-\xff] )   # but only if the rest of the url
                                          # starts with "www.x" or "ftp.x"
    )
    (?:[^\s<>"'\x7f-\xff]+)  # capture the guts
)
""", re.VERBOSE)

IPFRE = re.compile(r"[\[ \(]{1}[a-fA-F\d\.\:]{7,}?[\] \n;\)]{1}")

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

    def get(self, k, d=None):
        return super(_Headers, self).get(k.lower(), d)

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
        @functools.wraps(func)
        def wrapped_func(fself, name):
            cache = getattr(fself, self._cache_name)
            result = cache.get(name)
            if result is None:
                result = func(fself, name)
                cache[name] = result
            return result

        return wrapped_func


DEFAULT_SENDERH = (
    "X-Sender", "X-Envelope-From", "Envelope-Sender", "Return-Path", "From"
)


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
        self.received_headers = list()
        self.raw_mime_headers = _Headers()
        self.header_ips = _Headers()
        self.text = ""
        self.raw_text = ""
        self.uri_list = set()
        self.score = 0
        self.rules_checked = dict()
        self.interpolate_data = dict()
        self.plugin_tags = dict()
        # Data
        self.sender_address = ""
        self.hostname_with_ip = list()
        self.internal_relays = []
        self.external_relays = []
        self.last_internal_relay_index = 0
        self.last_trusted_relay_index = 0
        self.trusted_relays = []
        self.untrusted_relays = []
        self._parse_message()
        self._hook_parsed_metadata()

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
                except (LookupError, UnicodeError, AssertionError):
                    continue
            else:
                if PY3:
                    parts.append(value)
                else:
                    parts.append(value.decode("utf-8", "ignore"))
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

    def get_untrusted_ips(self):
        """Returns the untrusted IPs based on the users trusted
        network settings.

        :return: A list of `ipaddress.ip_address`.
        """
        ips = [ip for ip in self.get_header_ips()
               if ip not in self.ctxt.networks.trusted]
        return ips

    def get_header_ips(self):
        values = list()
        for header in self.received_headers:
            values.append(ipaddress.ip_address(header["ip"]))
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

    def iter_decoded_headers(self):
        """Iterate through all the decoded headers.

        Yields strings like "<header_name>: <header_value>"
        """
        for header_name in self.raw_headers:
            for value in self.get_decoded_header(header_name):
                yield "%s: %s" % (header_name, value)

    def _create_plugin_tags(self, header):
        for key, value in header.items():
            self.plugin_tags[key.upper()] = value

    def _parse_sender(self):
        """Extract the envelope sender from the message."""

        always_trust_envelope_from = self.ctxt.conf[
            'always_trust_envelope_sender']
        headers = self.ctxt.conf["envelope_sender_header"] or DEFAULT_SENDERH

        if self.external_relays:
            sender = self.external_relays[0].get("envfrom").strip()
            if sender:
                self.sender_address = sender
                return
        else:
            if self.trusted_relays and not always_trust_envelope_from:
                return

            for sender_header in headers:
                try:
                    sender = self.get_addr_header(sender_header)[0]
                except IndexError:
                    continue
                if sender:
                    self.sender_address = sender.strip()
                    self.ctxt.log.debug("Using %s as sender: %s",
                                        sender_header, sender)
                    return
        return

    def _parse_relays(self, relays):
        """Walks though a relays list to extract
        [un]trusted/internal/external relays"""
        is_trusted = True
        is_internal = True
        found_msa = False

        for position, relay in enumerate(relays):
            relay['msa'] = 0
            if relay['ip']:
                ip = ipaddress.ip_address(str(relay['ip']))
                in_internal = ip in self.ctxt.networks.internal
                in_trusted = ip in self.ctxt.networks.trusted
                in_msa = ip in self.ctxt.networks.msa
                has_auth = relay.get("auth", None)
                if is_trusted and not found_msa:
                    if self.ctxt.networks.configured:
                        if not in_trusted and not has_auth:
                            is_trusted = False
                            is_internal = False

                        else:
                            if is_internal and not has_auth and not in_internal:
                                is_internal = False

                            if in_msa:
                                relay['msa'] = 1
                                found_msa = True

                    elif not ip.is_private and not has_auth:
                        pass

                relay['intl'] = int(is_internal)
                if is_internal:
                    self.internal_relays.append(relay)
                    self.last_internal_relay_index = position
                else:
                    self.external_relays.append(relay)

                if is_trusted:
                    self.trusted_relays.append(relay)
                    self.last_trusted_relay_index = position
                else:
                    self.untrusted_relays.append(relay)
        tag_template = ("[ ip={ip} rdns={rdns} helo={helo} by={by} "
                        "ident={ident} envfrom={envfrom} intl={intl} id={id} auth={auth} "
                        "msa={msa} ]")

        relays_tags = {
            "RELAYSTRUSTED": " ".join([tag_template.format(**x)
                                       for x in self.trusted_relays]),
            "RELAYSUNTRUSTED": " ".join([tag_template.format(**x)
                                         for x in self.untrusted_relays]),
            "RELAYSINTERNAL": " ".join([tag_template.format(**x)
                                        for x in self.internal_relays]),
            "RELAYSEXTERNAL": " ".join([tag_template.format(**x)
                                        for x in self.external_relays]),
        }
        if self.external_relays:
            relays_tags.update({
                "LASTEXTERNALIP": self.external_relays[-1]['ip'],
                "LASTEXTERNALRDNS": self.external_relays[-1]['rdns'],
                "LASTEXTERNALHELO": self.external_relays[-1]['helo']
            })

        self._create_plugin_tags(relays_tags)

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
            # Extract any MIME headers
            for name, raw_value in part._headers:
                self.raw_mime_headers[name].append(raw_value)
            text = None
            if payload is not None:
                # this must be a text part
                self.uri_list.update(set(URL_RE.findall(payload)))
                if part.get_content_subtype() == "html":
                    text = self.normalize_html_part(payload.replace("\n", " "))
                    text = " ".join(text)
                    body.append(text)
                    raw_body.append(payload)
                else:
                    text = payload.replace("\n", " ")
                    body.append(text)
                    raw_body.append(payload)
            self._hook_extract_metadata(payload, text, part)
        self.text = " ".join(body)
        self.raw_text = "\n".join(raw_body)
        self._parse_sender()
        received_headers = self.get_decoded_header("Received")
        for header in self.ctxt.conf["originating_ip_headers"]:
            received_headers.extend(self.get_decoded_header(header))
        received_obj = ReceivedParser(received_headers,
                                      self.ctxt.conf["originating_ip_headers"])
        self.received_headers = received_obj.received
        self._parse_relays(self.received_headers)

        try:
            self._create_plugin_tags(self.received_headers[0])
        except IndexError:
            pass

        for header in self.received_headers:
            self.hostname_with_ip.append((header["rdns"], header["ip"]))

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
