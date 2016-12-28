""" MIME Eval Plugin replacement """

import re
import email.errors

import pad.message
import pad.locales
import pad.plugins.base

MAX_HEADER_KEY = 256
MAX_HEADER_VALUE = 8192

class MIMEEval(pad.plugins.base.BasePlugin):
    """Reimplementation of the awl spamassassin plugin"""

    eval_rules = (
        "check_for_mime",
        "check_for_mime_html",
        "check_for_mime_html_only",
        "check_mime_multipart_ratio",
        "check_msg_parse_flags",
        "check_for_ascii_text_illegal",
        "check_abundant_unicode_ratio",
        "check_for_faraway_charset",
        "check_for_uppercase",
        "check_ma_non_text",
        "check_base64_length",
        "check_qp_ratio",
    )

    options = {
        "ok_locales": ("string", "all"),
    }

    parse_flags = {
        "missing_mime_head_body_separator",
        "mime_epilogue_exists",
        "missing_mime_headers",
        "truncated_headers",
    }

    mime_checks = {
        # "mime_base64_blanks": 0,
        "mime_base64_count": 0,
        "mime_base64_encoded_text": False,
        "mime_body_html_count": 0,
        "mime_body_text_count": 0,
        "mime_faraway_charset": False,
        "mime_missing_boundary": False,
        "mime_multipart_alternative": False,
        "mime_multipart_ratio": 1,
        "mime_qp_count": 0,
        "mime_qp_long_line": False,
        "mime_qp_ratio": 0,
        "mime_ascii_text_illegal": False,
        "mime_text_unicode_ratio": 0,
        "mime_bad_iso_charset": False,
    }

    def _update_base64_information(self, msg, text):

        base64_length = self.get_local(msg, "base64_length")
        self.ctxt.log.debug("BASE 64 text %s", text)
        if text:
            self.set_local(
                msg, "base64_length",
                base64_length + max(len(line) for line in text.splitlines()))

        base64_count = self.get_local(msg, "mime_base64_count")
        self.set_local(msg, "mime_base64_count", base64_count + 1)

    def _update_quopri_stats(self, msg, part):
        max_line_len = 79
        qp_count = self.get_local(msg, "mime_qp_count")
        qp_bytes = self.get_local(msg, "qp_bytes")
        qp_chars = self.get_local(msg, "qp_chars")
        quoted_printables = re.search(
            r"=(?:09|3[0-9ABCEF]|[2456][0-9A-F]|7[0-9A-E])",
            part.get_payload()
        )
        qp_bytes += len(part.get_payload())
        self.set_local(msg, "qp_bytes", qp_bytes)
        if quoted_printables:
            qp_chars += len(quoted_printables.groups())
            self.set_local(msg, "qp_chars", qp_chars)
        self.set_local(msg, "mime_qp_count", qp_count + 1)
        raw = msg.translate_line_breaks(part.as_string())
        has_long_line = self.get_local(msg, "mime_qp_long_line")
        if not has_long_line:
            has_long_line = any(
                len(line) > max_line_len and not line.startswith("SPAM")
                for line in raw.splitlines())
            self.set_local(msg, "mime_qp_long_line", has_long_line)

    def _update_base64_text_stats(self, msg, content_type,
                                  content_transfer_encoding,
                                  content_disposition, charset):

        text_charset_re = re.compile(r"(us-ascii|ansi_x3\.4-1968|iso-ir-6|"
                                     r"ansi_x3\.4-1986|iso_646\.irv:1991|"
                                     r"ascii|iso646-us|us|ibm367|cp367|"
                                     r"csascii)")

        charset_check = not charset or text_charset_re.search(charset)
        cdisposition_check = not(
            content_disposition and
            content_disposition.strip() in ("inline", "attachment"))

        if ("base64" in content_transfer_encoding and
                charset_check and
                cdisposition_check):
            self.set_local(msg, "mime_base64_encoded_text", True)

    def _update_mime_bad_iso_charset(self, msg, charset):
        is_iso_re = re.compile(r"iso-.*-.*\b")
        good_iso_re = re.compile(r"iso-(?:8859-\d{1,2}|2022-(?:jp|kr))\b")
        if is_iso_re.search(charset) and not good_iso_re.search(charset):
            self.set_local(msg, "mime_bad_iso_charset", True)

    def _update_faraway_charset(self, msg, charset):
        locales = self.get_global("ok_locales")
        if charset and re.match("[a-z]", charset, re.IGNORECASE):
            faraway_charset = self.get_local(msg, "mime_faraway_charset")
            if not faraway_charset:
                if "all" not in locales:
                    result = pad.locales.charset_ok_for_locales(charset,
                                                                locales)
                    self.set_local(msg, "mime_faraway_charset", result)

    def _update_mime_text_info(self, msg, payload, part, text):
        charset = part.get_charset()
        text_count = self.get_local(msg, "mime_body_text_count")
        self.set_local(msg, "mime_body_text_count", text_count + 1)
        if part.get_content_subtype() == "plain":
            plain_characters_count = self.get_local(msg, "plain_characters_count")
            self.set_local(msg, "plain_characters_count",
                           plain_characters_count + len(text))
            ascii_count = self.get_local(msg, "ascii_count")
            ascii_count += len(text)
            self.set_local(msg, "ascii_count", ascii_count)
            unicode_chars = re.search(r"(&\#x[0-9A-F]{4};)", text, re.X)
            unicode_count = 0
            if unicode_chars:
                unicode_count = self.get_local(msg, "unicode_count")
                unicode_count += len(unicode_chars.groups())
                self.set_local(msg, "unicode_count", unicode_count)
            # XXX This does not work properly anymore
            if not charset or charset == r"us-ascii":
                try:
                    payload.encode("ascii")
                except (UnicodeEncodeError, UnicodeDecodeError):
                    self.set_local(msg, "mime_ascii_text_illegal", True)

    def _update_mime_ma_non_text(self, msg, part):
        if not self.get_local(msg, "mime_ma_non_text"):
            for ma_part in part.get_payload():
                if(ma_part.get_content_maintype() != "text" and
                   ma_part.get_content_type not in (
                       "multipart/related", "application/rtf")):
                    self.set_local(msg, "mime_ma_non_text", True)

    def check_start(self, msg):
        for key, value in self.mime_checks.items():
            self.set_local(msg, key, value)
        self.set_local(msg, "mime_ma_non_text", False)
        self.set_local(msg, "base64_length", 0)
        self.set_local(msg, "ascii_count", 0)
        self.set_local(msg, "plain_characters_count", 0)
        self.set_local(msg, "html_characters_count", 0)
        self.set_local(msg, "unicode_count", 0)
        self.set_local(msg, "qp_chars", 0)
        self.set_local(msg, "qp_bytes", 0)


    def extract_metadata(self, msg, payload, text, part):

        content_type = part.get_content_type()
        charset = part.get_content_charset()

        content_transfer_encoding = part.get("Content-Transfer-Encoding",
                                             "")
        content_disposition = part.get("Content-Disposition", "")

        if part.get_content_type() == "multipart/alternative":
            self.set_local(msg, "mime_multipart_alternative", True)
            self._update_mime_ma_non_text(msg, part)

        if part.get_content_subtype() == "html":
            html_count = self.get_local(msg, "mime_body_html_count")
            self.set_local(msg, "mime_body_html_count", html_count + 1)
            html_characters_count = self.get_local(msg, "html_characters_count")
            self.set_local(msg, "html_characters_count",
                           html_characters_count + len(payload))

        if part.get_content_type() == "text/plain":
            self._update_mime_text_info(msg, part.get_payload(), part, text)

        self._update_base64_text_stats(msg, content_type,
                                       content_transfer_encoding,
                                       content_disposition,
                                       charset)

        if "base64" in content_transfer_encoding.lower():
            self._update_base64_information(msg, part.get_payload())

        if "quoted-printable" in content_transfer_encoding.lower():
            self._update_quopri_stats(msg, part)

        self._update_faraway_charset(msg, charset)

    def parsed_metadata(self, msg):
        html_count = self.get_local(msg, "html_characters_count")
        text_count = self.get_local(msg, "plain_characters_count")
        if html_count and text_count:
            self.set_local(msg, "mime_multipart_ratio",
                           text_count / float(html_count))

        unicode_count = self.get_local(msg, "unicode_count")
        self.ctxt.log.debug("Unicode characters count %s", unicode_count)
        ascii_count = self.get_local(msg, "ascii_count")
        self.ctxt.log.debug("Ascii characters count %s", ascii_count)
        if ascii_count:
            self.set_local(msg, "mime_text_unicode_ratio",
                           unicode_count / float(ascii_count))
        chars = float(self.get_local(msg, "qp_chars"))
        bytes = float(self.get_local(msg, "qp_bytes"))
        if chars and bytes:
            ratio = chars/bytes
            self.set_local(msg, "mime_qp_ratio", ratio)



    def check_for_mime(self, msg, test, target=None):
        """Checks for one of the the following metadata:
          mime_base64_count: Number of base64 parts in the email
          mime_base64_encoded_text: Number of base64 encoded text parts
          mime_body_html_count: Number of html parts
          mime_body_text_count: Number of text parts
          mime_faraway_charset: Is the charset different than ok_locales
          mime_missing_boundary: Missing Boundary
          mime_multipart_alternative: message type is "multipart/alternative"
          mime_multipart_ratio: text / html
          mime_qp_count: Quoted printable count
          mime_qp_long_line: Quoted printable line over 79
          mime_qp_ratio: quoted printable count / bytes
          mime_ascii_text_illegal: us-ascii mail contains unicode characters
          mime_text_unicode_ratio": number of unicode encoded chars / total chars
        """

        if test not in self.mime_checks.keys():
            self.ctxt.log.warn("Invalid check for 'check_for_mime' %s", test)
            return False
        return self.get_local(msg, test)

    def check_for_mime_html(self, msg, target=None):
        """True if at least one part of the message is text/html"""
        return bool(self.get_local(msg, "mime_body_html_count"))

    def check_for_mime_html_only(self, msg, target=None):
        """True if message has html parts and no text parts"""
        has_html = bool(self.get_local(msg, "mime_body_html_count"))
        has_text = bool(self.get_local(msg, "mime_body_text_count"))
        return has_html and not has_text

    def check_msg_parse_flags(self, msg, flag, target=None):
        """Checks the value of flags added when parsing the msssage.
        The following flags are allowed
         - missing_mime_head_body_separator: There is no newline after the header
         - missing_mime_headers: if the line after the opening boundary isn't a
          header, flag it
         - truncated_headers: if any header name is over 256 or any header
         value is over 8192
         - mime_epilogue_exists: The message has an epilogue
        """

        if flag == "missing_mime_head_body_separator":
            return msg.missing_header_body_separator

        if flag == "missing_mime_headers":
            return msg.missing_boundary_header

        if flag == "truncated_headers":
            for key, value in msg.raw_headers.items():
                if len(key) > MAX_HEADER_KEY or len(value)> MAX_HEADER_VALUE:
                    return True

        if flag == 'mime_epilogue_exists':
            try:
                return bool(msg.msg.epilogue)
            except AttributeError:
                pass

        return False

    def check_for_faraway_charset(self, msg, target=None):
        """ Checks if the message is in another locale than the users own and a
        list of preapproved locales.
        """
        return bool(self.get_local(msg, "mime_faraway_charset"))

    def check_for_uppercase(self, msg, min_percent, max_percent, target=None):
        """Checks the percent of uppercase letters is between desired limits"""

        total_lower = 0
        total_upper = 0
        length = 0
        for line in re.split("\n\n", msg.raw_text):
            if " " not in line.strip("\n").replace("\n", " "):
                continue
            text = line.replace("\n", " ")
            length += len(text)
            text = re.sub(r"[\W_]", "", text)
            count_lower = sum(
                1 for a, b in zip(text, text.upper()) if a != b or a.isdigit()
            )
            total_upper += len(text) - count_lower
            total_lower += count_lower
        self.ctxt.log.debug("LENGTH %s", length)
        if length < 200:
            return False

        try:
            return float(min_percent) < (total_upper / float(total_lower + total_upper)) * 100 <= float(max_percent)
        except ZeroDivisionError:
            return False

    def check_mime_multipart_ratio(self, msg, min_ratio, max_ratio,
                                   target=None):
        """Checks the ratio of text/plain characters to text/html characters
        :param min_ratio:
        :param max_ratio:
        """
        min_ratio = float(min_ratio)
        max_ratio = float(max_ratio)
        ratio = self.get_local(msg, "mime_multipart_ratio")
        self.ctxt.log.debug("%s %s %s", min_ratio, max_ratio, ratio)
        return float(min_ratio) <= ratio < float(max_ratio)

    def check_base64_length(self, msg, min_length, max_length='inf',
                            target=None):
        """
        Checks if there is any base64 encoded lines that above or below the
        given parameters
        :param min_length: Below this number they will return true
        :param max_length: (Optional) above this number it will reutrn true
        :return: bool
        """
        base64_length = self.get_local(msg, "base64_length")
        return float(min_length) <= base64_length <= float(max_length)

    def check_ma_non_text(self, msg, target=None):
        """
        Checks to see if an email with multipart alternative is missing a
        text like alternative like application/rtf or text/*
        """
        return self.get_local(msg, "mime_ma_non_text")

    def check_for_ascii_text_illegal(self, msg, target=None):
        """
        If a MIME part claims to be text/plain or text/plain;charset=us-ascii
        and the Content-Transfer-Encoding is 7bit (either explicitly or
        by default), then we should enforce the actual text being only TAB, NL,
        SPACE through TILDE, i.e. all 7bit characters excluding
        NO-WS-CTL (per RFC-2822).
        """
        return self.get_local(msg, "mime_ascii_text_illegal")

    def check_abundant_unicode_ratio(self, msg, min_ratio, max_ratio="inf",
                                     target=None):
        """A MIME part claiming to be text/plain and containing Unicode
        characters must be encoded as quoted-printable or base64, or use UTF
        data coding (typically with 8bit encoding).  Any message in 7bit or
        8bit encoding containing (HTML) Unicode entities will not render them
        as Unicode, but literally.

        Thus a few such sequences might occur on a mailing list of
        developers discussing such characters, but a message with a high
        density of such characters is likely spam.

        :param min_ratio:
        :param max_ratio:
        """


        ratio = self.get_local(msg, "mime_text_unicode_ratio")
        return float(min_ratio) <= ratio <= float(max_ratio)

    def check_qp_ratio(self, msg, min_ratio, max_ratio="inf", target=None):
        """
        Takes a min ratio to use in eval to see if there is an spamminess to
        the ratio of quoted printable to total bytes in an email.
        :param min_ratio:
        :param max_ratio:
        """
        ratio = self.get_local(msg, "mime_qp_ratio")
        return float(min_ratio) <= ratio <= float(max_ratio)
