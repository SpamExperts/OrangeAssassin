""" MIME Eval Plugin replacement """

import re
import pad.locales
import pad.plugins.base


class MIMEEval(pad.plugins.base.BasePlugin):
    """Reimplementation of the awl spamassassin plugin"""

    eval_rules = (
        "check_for_mime",
        "check_for_mime_html",
        "check_for_mime_html_only",
        "check_mime_multipart_ratio",
        # "check_msg_parse_flags",
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
        "mime_txt_unicode_ratio": 0,
        "mime_bad_iso_charset": False,
    }

    def _update_base64_information(self, msg, text):

        base64_length = self.get_local(msg, "base64_length")
        self.set_local(msg, "base64_length", base64_length + len(text))

        base64_count = self.get_local(msg, "mime_base64_count")
        self.set_local(msg, "mime_base64_count", base64_count + 1)

    def _update_quopri_stats(self, msg, part):
        max_line_len = 79
        qp_count = self.get_local(msg, "mime_qp_count")
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

    def _update_mime_text_info(self, msg, part, text):
        charset = part.get_charset()
        text_count = self.get_local(msg, "mime_body_text_count")
        self.set_local(msg, "mime_body_text_count", text_count + 1)
        if part.get_content_subtype() == "plain":
            ascii_count = self.get_local(msg, "ascii_count")
            ascii_count += sum(1 for c in text if ord(c) < 128)
            unicode_count = self.get_local(msg, "unicode_count")
            unicode_count += len(text) - ascii_count
            if charset or charset == r"us-ascii":
                has_illegal = bool(unicode_count)
                self.set_local(msg, "mime_ascii_text_illegal", has_illegal)

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
        self.set_local(msg, "unicode_count", 0)

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

        if part.get_content_type() == "text/plain":
            self._update_mime_text_info(msg, part, text)

        self._update_base64_text_stats(msg, content_type,
                                       content_transfer_encoding,
                                       content_disposition,
                                       charset)

        if "base64" in content_transfer_encoding.lower():
            self._update_base64_information(msg, payload)

        if "quoted-printable" in content_transfer_encoding.lower():
            self._update_quopri_stats(msg, part)

        self._update_faraway_charset(msg, charset)

    def parsed_metadata(self, msg):
        html_count = self.get_local(msg, "mime_body_html_count")
        text_count = self.get_local(msg, "mime_body_text_count")
        if html_count and text_count:
            self.set_local(msg, "mime_multipart_ratio",
                           text_count / html_count)

        unicode_count = self.get_local(msg, "unicode_count")
        ascii_count = self.get_local(msg, "ascii_count")
        if ascii_count:
            self.set_local(msg, "mime_text_unicode_ratio",
                           unicode_count / ascii_count)

    def check_for_mime(self, msg, test, target=None):
        """Checks for a mime var from the following:
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
          mime_ascii_text_illegal:
          mime_txt_unicode_ratio":
        """

        if test not in self.mime_checks.keys():
            self.ctxt.log.warn("Invalid check for 'check_for_mime' %s", test)
            return False
        return self.get_local(msg, test)

    def check_for_mime_html(self, msg, target=None):
        """True if at least part of the message is html"""
        return bool(self.get_local(msg, "mime_body_html_count"))

    def check_for_mime_html_only(self, msg, target=None):
        """True if message has html and not text"""
        has_html = bool(self.get_local(msg, "mime_body_html_count"))
        has_text = bool(self.get_local(msg, "mime_body_text_count"))
        return has_html and not has_text

    def check_msg_parse_flags(self, msg, target=None):
        """Checks the value of flags added when parsing the msssage.
        eg. """
        pass

    def check_for_faraway_charset(self, msg, target=None):
        return bool(self.get_local(msg, "mime_faraway_charset"))

    def check_for_uppercase(self, msg, min_percent, max_percent, target=None):
        text = re.sub(r"[\W_]", "", msg.text)
        if len(text) < 200:
            return False

        count_lower = sum(1 for a, b in zip(msg.msg.as_string(), msg.msg.as_string().upper())
                          if a != b or a.isdigit())
        count_upper = len(text) - count_lower
        return min_percent <= (count_upper / len(text)) * 100 <= max_percent

    def check_mime_multipart_ratio(self, msg, min_ratio, max_ratio,
                                   target=None):
        min_ratio = float(min_ratio)
        max_ratio = float(max_ratio)
        ratio = self.get_local(msg, "mime_multipart_ratio")
        return min_ratio <= ratio < max_ratio

    def check_base64_length(self, msg, min_length, max_length=None,
                            target=None):
        base64_length = self.get_local(msg, "base64_length")

        if max_length:
            return min_length <= base64_length <= max_length
        return min_length <= base64_length

    def check_ma_non_text(self, msg, target=None):
        return self.get_local(msg, "mime_ma_non_text")

    def check_for_ascii_text_illegal(self, msg, target=None):
        return self.get_local(msg, "mime_ascii_text_illegal")

    def check_abundant_unicode_ratio(self, msg, min_ratio, max_ratio=None,
                                     target=None):
        ratio = self.get_local(msg, "abundant_unicode_ratio")
        if max_ratio:
            return min_ratio <= ratio <= max_ratio
        return min_ratio <= ratio

    def check_qp_ratio(self, msg, min_ratio, max_ratio=None, target=None):

        ratio = self.get_local(msg, "qp_ratio")
        if max_ratio:
            return min_ratio <= ratio <= max_ratio
        return min_ratio <= ratio
