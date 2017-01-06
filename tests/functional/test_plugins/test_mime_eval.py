# coding: utf-8
"""Functional tests for MIMEEval Plugin"""

from __future__ import absolute_import

import sys
import unittest
import platform

import tests.util

IS_PYPY3 = ("pypy" in platform.python_implementation().lower() and
            sys.version_info.major == 3)

PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::MIMEEval

report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """
body CHECK_MIME_BASE64_COUNT                     eval:check_for_mime("mime_base64_count")   
body CHECK_MIME_BASE64_ENCODED_TEXT              eval:check_for_mime("mime_base64_encoded_text")
body CHECK_MIME_BODY_HTML_COUNT                  eval:check_for_mime("mime_body_html_count")
body CHECK_MIME_BODY_TEXT_COUNT                  eval:check_for_mime("mime_body_text_count")
body CHECK_MIME_FARAWAY_CHARSET                  eval:check_for_mime("mime_faraway_charset")
body CHECK_MIME_MISSING_BOUNDARY                 eval:check_for_mime("mime_missing_boundary")
body CHECK_MIME_MULTIPART_ALTERNATIVE            eval:check_for_mime("mime_multipart_alternative")
body CHECK_MIME_MULTIPART_RATIO                  eval:check_for_mime("mime_multipart_ratio")
body CHECK_MIME_QP_COUNT                         eval:check_for_mime("mime_qp_count")
body CHECK_MIME_QP_LONG_LINE                     eval:check_for_mime("mime_qp_long_line")
body CHECK_MIME_QP_RATIO                         eval:check_for_mime("mime_qp_ratio")
body CHECK_MIME_ASCII_TEXT_ILLEGAL               eval:check_for_mime("mime_ascii_text_illegal")                    --done
body CHECK_MIME_TEXT_UNICODE_RATIO               eval:check_for_mime("mime_text_unicode_ratio")

body CHECK_MIME_HTML                             eval:check_for_mime_html()                                        --done
body CHECK_MIME_HTML_ONLY                        eval:check_for_mime_html_only()                                   --done

body CHECK_MISSING_MIME_HEAD_BODY_SEPARATOR      eval:check_msg_parse_flags("missing_mime_head_body_separator")    --done
body CHECK_MISSING_MIME_HEADERS                  eval:check_msg_parse_flags("missing_mime_headers")                
body CHECK_TRUNCATED_HEADERS                     eval:check_msg_parse_flags("truncated_headers")                   
body CHECK_MIME_EPILOGUE_EXISTS                  eval:check_msg_parse_flags("mime_epilogue_exists")                

body CHECK_FARAWAY_CHARSET                       eval:check_for_faraway_charset()
body CHECK_UPPERCASE                             eval:check_for_uppercase('min_length', 'max_length')              --done
body CHECK_MULTIPART_RATIO                       eval:check_mime_multipart_ratio('min_ration', 'max_ratio')
body CHECK_BASE64_LENGTH                         eval:check_base64_length('min_length', 'max_length')
body CHECK_MA_NON_TEXT                           eval:check_ma_non_text()                                          --done
body CHECK_ASCII_TEXT_ILLEGAL                    eval:check_for_ascii_text_illegal()                               --done
body CHECK_ABUNDANT_UNICODE_RATIO                eval:check_abundant_unicode_ratio('min_ration', 'max_ratio')
body CHECK_QP_RATION                             eval:check_qp_ratio('min_ration', 'max_ratio')
"""

MSG_HTML_ONLY = """Subject: test
Content-Type: text/html
<div dir="ltr">Test Body</div>
"""


MSG_ILLEGAL_ASCII = u"""Subject: test

Τεστ
"""

MSG_HTML_MOSTLY = """Subject: test
Content-Type: multipart/alternative; boundary=001a1148e51c20e31305439a7bc2

--001a1148e51c20e31305439a7bc2
Content-Type: text/plain; charset=UTF-8

Test Body

--001a1148e51c20e31305439a7bc2
Content-Type: text/html; charset=UTF-8

<div dir="ltr">Test Body</div>

--001a1148e51c20e31305439a7bc2--
"""


MSG_BASE64_5_PER_LINE = """Content-Transfer-Encoding: base64

VGhp
cyBp
cyBu
b3Qg
anVz
dCBh
IHNp
bXBs
ZSB0
ZXN0
IG1l
c3Nh
Z2Uu
"""

MSG_BASE64_50_PER_LINE = """Content-Transfer-Encoding: base64

VGhpcyBpcyBub3QganVzdCBhIHNpbXBsZSB0ZXN0IG1lc3Nh
Z2UuIFdlIHRlc3QgdGhlIEJBU0U2NCBNSU1FRXZhbCBydWxl
Lg==
"""

MSG_WITH_UPPERCASE = """Content-Type: text/plain

%s
%s%s
"""

MSG_WITH_MULTIPLE_LINES = """Content-Type: text/plain

%s
%s%s
%s
%s
"""

MSG_ABUNDANT_UNICODE = """Content-Type: text/plain
abc&#x3030;
"""


MSG_PARSE_FLAGS = """Content-Type: multipart/mixed; boundary="sb"
%s: %s
MIME-Version: 1.0
Test

--sb

Test
--sb
Content-type: text/plain; charset=us-ascii

Test

--sb--
This is the epilogue.  It is also to be ignored.""" % ("a" * 257, "b" * 8193)


MSG_CHECK_MIME = """Content-Type: multipart/alternative; boundary=boundary-limit


--boundary-limit
Content-Type: text/plain; charset=us-ascii

Just some testing text.

--boundary-limit
Content-Type: text/richtext

Richtext version of same message goes here ...
--boundary-limit
Content-Type: text/x-whatever

Fanciest formatted version of same  message  goes  here

--boundary-limit--
"""

MSG_QP_MIME = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=001a11466a4487c42005453246b0

--001a11466a4487c42005453246b0
Content-Type: multipart/alternative; boundary=001a11466a4487c41a05453246ae

--001a11466a4487c41a05453246ae
Content-Type: text/plain; charset=UTF-8

---------- Forwarded message ---------
From: sender <sender@example.net>
Date: Tue, Jan 3, 2017 at 5:17 PM
Subject: test
To: test@example.com <test@example.com>


test

--001a11466a4487c41a05453246ae
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

test

--001a11466a4487c41a05453246ae--
--001a11466a4487c42005453246b0
Content-Type: text/plain; charset=US-ASCII; name="nonasciiattachment.txt"
Content-Disposition: attachment; filename="nonasciiattachment.txt"
Content-Transfer-Encoding: base64
Content-ID: <15964eef089b79488c91>
X-Attachment-Id: 15964eef089b79488c91

dGhpcyBoYXMgc29tZSDQlNC+0LHRgNGL0Lkg0LTQtdC90YwgdGV4dCAK
--001a11466a4487c42005453246b0--
"""


MSG_CHECK_FARAWAY = """Content-Type: text/plain; charset=ja_EUC-JP
Content-Transfer-Encoding: base64

z4TOtc+Dz4Q=
"""


class TestFunctionalMIMEEval(tests.util.TestBase):
    """Tests for the MIMEEval plugin."""

    debug = False

    def test_check_html_only(self):
        """Test check_for_mime_html_only eval rule.

        Check message has only html parts and no text parts.
        True if message has html parts and no text parts.
        """
        self.setup_conf(
            config="""
            body MIME_HTML_ONLY     eval:check_for_mime_html_only()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_ONLY)
        self.check_report(result, 1.0, ["MIME_HTML_ONLY"])

    def test_check_html_only_false(self):
        """Test check_for_mime_html_only eval rule.

        False, because message has both html parts and text parts.
        True if message has html parts and no text parts.
        """
        self.setup_conf(
            config="""
            body MIME_HTML_ONLY     eval:check_for_mime_html_only()l
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 0, [])

    def test_check_html(self):
        """Test check_for_mime_html eval rule.

        Check message has html parts.
        True if at least one part of the message is text/html
        """
        self.setup_conf(
            config="""
            body MIME_HTML      eval:check_for_mime_html()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 1.0, ["MIME_HTML"])

    def test_check_html_negative(self):
        """Test check_for_mime_html eval rule.

        False, because message has no html parts.
        True if at least one part of the message is text/html.
        """
        self.setup_conf(
            config="""
            body MIME_HTML      eval:check_for_mime_html()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS)
        self.check_report(result, 0, [])

    def test_check_html_on_html_only_mess(self):
        """Test check_for_mime_html eval rule.

        Check eval match on message with only html parts.
        True if at least one part of the message is text/html.
        """
        self.setup_conf(
            config="""
            body MIME_HTML      eval:check_for_mime_html()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_ONLY)
        self.check_report(result, 1.0, ["MIME_HTML"])

    def test_check_qp_ratio(self):
        """Test check_qp_ratio eval rule.

        Takes a min ratio to use in eval to see if there is an spamminess to
        the ratio of quoted printable to total bytes in an email.
        """
        self.setup_conf(
            config="""
            body MIME_QP_RATION eval:check_qp_ratio(0)
            """,
            pre_config=PRE_CONFIG)

        result = self.check_pad(MSG_QP_MIME)
        self.check_report(result, 1, ["MIME_QP_RATION"])

    def test_check_mime_multipart_ratio(self):
        """Test check_mime_multipart_ratio eval rule.

        Checks the ratio of text/plain characters to text/html characters.
        Check eval match on message with min_ratio: 0.30 & max_ratio: 0.50
        """
        self.setup_conf(
            config="""
            body MIME_HTML_MOSTLY eval:check_mime_multipart_ratio('0.30','0.50')
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 1.0, ["MIME_HTML_MOSTLY"])

    def test_check_mime_multipart_ratio_no_match(self):
        """Test check_mime_multipart_ratio eval rule.

        Checks the ratio of text/plain characters to text/html characters.
        Check eval doens't match on message with min_ratio: 0.10 & max_ratio: 0.15
        """
        self.setup_conf(
            config="""
            body MIME_HTML_MOSTLY eval:check_mime_multipart_ratio('0.10','0.15')
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 0, [])

    def test_check_mime_multipart_max_ratio(self):
        """Test check_mime_multipart_ratio eval rule.

        Checks the ratio of text/plain characters to text/html characters.
        Check eval match on message max_ratio: 0.70
        """
        self.setup_conf(
            config="""
            body MIME_HTML_MOSTLY eval:check_mime_multipart_ratio('0.10','0.70')
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 1.0, ["MIME_HTML_MOSTLY"])

    def test_check_mime_multipart_min_ratio(self):
        """Test check_mime_multipart_ratio eval rule.

        Checks the ratio of text/plain characters to text/html characters.
        Check eval match on message min_ratio: 0.50
        """
        self.setup_conf(
            config="""
            body MIME_HTML_MOSTLY eval:check_mime_multipart_ratio('0.50','0.50')
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 0, [])

    def test_abundant_unicode_ratio(self):
        """Test check_abundant_unicode_ratio eval rule.

        Check eval match unicode characters on message min_ratio: 0.02
        A message with a high density of such characters is likely spam
        """
        self.setup_conf(
            config="""
            body ABUNDANT_UNICODE eval:check_abundant_unicode_ratio(0.02)
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_ABUNDANT_UNICODE)
        self.check_report(result, 1.0, ["ABUNDANT_UNICODE"])

    def test_base64_length_min_length(self):
        """Test check_base64_length eval rule.

        min_length: Below this number they will return true
        max_length: (Optional) above this number it will reutrn true

        characters per line: 5
        Check eval match for a message min_length: 5

        """
        self.setup_conf(
            config="""
            body BASE64_LENGTH eval:check_base64_length(4)
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_BASE64_5_PER_LINE)
        self.check_report(result, 1.0, ["BASE64_LENGTH"])

    def test_base64_length_max_length(self):
        """Test check_base64_length eval rule.

        min_length: Below this number they will return true
        max_length: (Optional) above this number it will reutrn true

        characters per line: 5
        Check eval match for a message max_length: 50
        """
        self.setup_conf(
            config="""
            body BASE64_LENGTH eval:check_base64_length(6, 49)
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_BASE64_50_PER_LINE)
        self.check_report(result, 1.0, ["BASE64_LENGTH"])

    def test_base64_length_no_match(self):
        """Test check_base64_length eval rule.

        min_length: Below this number they will return true
        max_length: (Optional) above this number it will reutrn true

        characters per line: 5
        Check eval doens't match for a message
        """
        self.setup_conf(
            config="""
            body BASE64_LENGTH eval:check_base64_length(2, 3)
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_BASE64_5_PER_LINE)
        self.check_report(result, 0, [])

    @unittest.skipIf(IS_PYPY3, 'Fails on some configurations of pypy3')
    def test_mime_ascii_text_illegal(self):
        """Test check_for_mime: mime_ascii_text_illegal is True.

        mime_ascii_text_illegal: us-ascii mail contains unicode characters.
        """
        self.setup_conf(
            config="""
            body MIME_ILLEGAL_ASCII eval:check_for_mime("mime_ascii_text_illegal")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_ILLEGAL_ASCII)
        self.check_report(result, 1.0, ["MIME_ILLEGAL_ASCII"])

    def test_mime_base64_count(self):
        """Test check_for_mime: mime_base64_count is True.

        mime_base64_count: Number of base64 parts in the email
        """
        self.setup_conf(
            config="""
            body      MIME_BASE_64  eval:check_for_mime("mime_base64_count")
            describe  MIME_BASE_64  Includes a base64 attachment
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_BASE64_50_PER_LINE)
        self.check_report(result, 1.0, ["MIME_BASE_64"])

    def test_mime_base64_count_false(self):
        """Test check_for_mime: mime_base64_count is False.

        mime_base64_count: Number of base64 parts in the email
        """
        self.setup_conf(
            config="""
            body      MIME_BASE_64  eval:check_for_mime("mime_base64_count")
            describe  MIME_BASE_64  Includes a base64 attachment
            """,
            pre_config=PRE_CONFIG)
        msg = MSG_WITH_UPPERCASE % ('this' * 1, 'is' * 1, 'testing' * 1)
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_base64_encoded_text(self):
        """Test check_for_mime: mime_base64_encoded_text is True.

        mime_base64_encoded_text: Number of base64 encoded text parts.
        Check message contains base64 encoded text parts.
        """
        self.setup_conf(
            config="""
            body      MIME_BASE_64  eval:check_for_mime("mime_base64_encoded_text")
            describe  MIME_BASE_64  Message text disguised using base64 encoding
            """,
            pre_config=PRE_CONFIG)

        msg = """Content-Type: multipart/mixed; boundary="------------ss"

--------------ss
Content-Type: application/pdf; name="testfile.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="testfile.pdf"

--------------ss--
        """
        result = self.check_pad(msg)
        self.check_report(result, 1.0, ["MIME_BASE_64"])

    def test_mime_base64_encoded_text_false(self):
        """Test check_for_mime: mime_base64_encoded_text is True.

        mime_base64_encoded_text: Number of base64 encoded text parts.
        Check message doens't contains base64 encoded text parts.
        """
        self.setup_conf(
            config="""
            body      MIME_BASE_64  eval:check_for_mime("mime_base64_encoded_text")
            describe  MIME_BASE_64  Message text disguised using base64 encoding
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('this' * 1, 'is' * 1, 'testing' * 1)
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_missing_boundary(self):
        """Test check_for_mime: mime_missing_boundary is True.

        mime_missing_boundary: Missing Boundary
        Check message miss boundary
        """
        self.setup_conf(
            config="""
            body     MIME_MISSING_BOUNDARY  eval:check_for_mime("mime_missing_boundary")
            describe MIME_MISSING_BOUNDARY  MIME section missing boundary
            """,
            pre_config=PRE_CONFIG)

        msg = """Content-Type: multipart/alternative; boundary=boundary-limit


--boundary-limit
Content-Type: text/plain; charset=us-ascii

Some plain text version of message goes here....

--boundary-limit
Content-Type: text/richtext

.... richtext version of same [truncated here]
        """
        result = self.check_pad(msg)
        self.check_report(result, 1.0, ["MIME_MISSING_BOUNDARY"])

    def test_mime_missing_boundary_false(self):
        """Test check_for_mime: mime_missing_boundary is True.

        mime_missing_boundary: Missing Boundary
        Check for a message that miss boundary
        """
        self.setup_conf(
            config="""
            body     MIME_MISSING_BOUNDARY  eval:check_for_mime("mime_missing_boundary")
            describe MIME_MISSING_BOUNDARY  MIME section missing boundary
            """,
            pre_config=PRE_CONFIG)

        result = self.check_pad(MSG_CHECK_MIME)
        self.check_report(result, 0, [])

    def test_mime_multipart_alternative(self):
        """Test check_for_mime: mime_multipart_alternative is True.

        mime_multipart_alternative: message type is "multipart/alternative"
        """
        self.setup_conf(
            config="""
            body  MIME_MULTIPLE_ALTERNATIVE  eval:check_for_mime("mime_multipart_alternative")
            """,
            pre_config=PRE_CONFIG)

        result = self.check_pad(MSG_CHECK_MIME)
        self.check_report(result, 1.0, ["MIME_MULTIPLE_ALTERNATIVE"])

    def test_mime_multipart_alternative_false(self):
        """Test check_for_mime: mime_multipart_alternative is False.

        Check for a  message that is not type "multipart/alternative"
        """
        self.setup_conf(
            config="""
            body  MIME_MULTIPLE_ALTERNATIVE  eval:check_for_mime("mime_multipart_alternative")
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_MULTIPLE_LINES % ('t', 'e', 's', 't', '.')
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_qp_count(self):
        """Test check_for_mime: mime_qp_count is True.

        mime_qp_count: Quoted printable count
        """
        self.setup_conf(
            config="""
            body     MIME_QP  eval:check_for_mime("mime_qp_count")
            describe MIME_QP  Includes a quoted-printable attachment
            """,
            pre_config=PRE_CONFIG)

        MIME_QP_HEADERS = """MIME-Version: 1.0
Content-Language: en-GB
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
This is a test message.
"""
        result = self.check_pad(MIME_QP_HEADERS)
        self.check_report(result, 1.0, ["MIME_QP"])

    def test_mime_qp_count_false(self):
        """Test check_for_mime: mime_qp_count is False.

        mime_qp_count: Quoted printable count
        """
        self.setup_conf(
            config="""
            body     MIME_QP  eval:check_for_mime("mime_qp_count")
            describe MIME_QP  Includes a quoted-printable attachment
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_MULTIPLE_LINES % ('t', 'e', 's', 't', '.')
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_qp_long_line_different_header(self):
        """Test check_for_mime: mime_qp_long_line is False.

        Test that only the Quoted printable line is checked for lenght.
        """
        self.setup_conf(
            config="""
            body     MIME_QP_LONG  eval:check_for_mime("mime_qp_long_line")
            describe MIME_QP_LONG  Quoted printable line over 79 characters
            """,
            pre_config=PRE_CONFIG)

        MIME_QP_LONG = """MIME-Version: 1.0
Content-Language: en-GB
X-MS-Has-Attach:
X-MS-TNEF-Correlator:
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable
X-Custom-Long-Header: %s
MIME-Version: 1.0
This is a test message.
"""
        # XXX This seems to take in consideration the lenght for the header
        # XXX name, too. Not sure how it should count. Total 79.
        msg = MIME_QP_LONG % ("x" * 59)
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_text_unicode_ratio(self):
        """Test check_for_mime: mime_text_unicode_ratio is True.

        mime_text_unicode_ratio": number of unicode encoded chars / total chars
        """
        self.setup_conf(
            config="""
            body     ABUNDANT_UNICODE  eval:check_for_mime("mime_text_unicode_ratio")
            """,
            pre_config=PRE_CONFIG)

        result = self.check_pad(MSG_ABUNDANT_UNICODE)
        self.check_report(result, 1.0, ["ABUNDANT_UNICODE"])

    def test_mime_text_unicode_ratio_false(self):
        """Test check_for_mime: mime_text_unicode_ratio is False.

        mime_text_unicode_ratio": number of unicode encoded chars / total chars
        """
        self.setup_conf(
            config="""
            body     ABUNDANT_UNICODE  eval:check_for_mime("mime_text_unicode_ratio")
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_MULTIPLE_LINES % ('t', 'e', 's', 't', '.')
        result = self.check_pad(msg)
        self.check_report(result, 0, [])

    def test_mime_ascii_text_illegal_negative(self):
        """Test check_for_mime: mime_ascii_text_illegal is False.

        mime_ascii_text_illegal: us-ascii mail contains unicode characters
        Check for a message that doesn't contains unicode characters
        """
        self.setup_conf(
            config="""
            body MIME_ILLEGAL_ASCII eval:check_for_mime("mime_ascii_text_illegal")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS)
        self.check_report(result, 0, [])

    @unittest.skipIf(IS_PYPY3, 'Fails on some configurations of pypy3')
    def test_ascii_text_illegal(self):
        """Test check_for_ascii_text_illegal eval rule is True."""
        self.setup_conf(
            config="""
            body ILLEGAL_ASCII eval:check_for_ascii_text_illegal()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_ILLEGAL_ASCII)
        self.check_report(result, 1.0, ["ILLEGAL_ASCII"])

    def test_ascii_text_illegal_negative(self):
        """Test check_for_ascii_text_illegal eval rule is False."""
        self.setup_conf(
            config="""
            body ILLEGAL_ASCII eval:check_for_ascii_text_illegal()
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_ABUNDANT_UNICODE)
        self.check_report(result, 0, [])

    def test_mime_body_html_count(self):
        """Test check_for_mime: mime_body_html_count is True.

        mime_body_html_count: Number of html parts
        True if message has html parts
        """
        self.setup_conf(
            config="""
            body HTML_COUNT eval:check_for_mime("mime_body_html_count")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 1.0, ["HTML_COUNT"])

    def test_mime_body_text_count(self):
        """Test check_for_mime: mime_body_text_count is True.

        mime_body_text_count: Number of text parts
        True if message has text parts
        """
        self.setup_conf(
            config="""
            body TEXT_COUNT eval:check_for_mime("mime_body_text_count")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_HTML_MOSTLY)
        self.check_report(result, 1.0, ["TEXT_COUNT"])

    def test_check_parse_flags_missing_headers_body_separator(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is True.

        Check there is a newline after the header.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS)
        self.check_report(result, 1.0, ["MISSING_HB"])

    def test_missing_mime_head_body_separator(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is False.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)

        msg = """Content-Type: multipart/mixed; boundary="------------9F2120F9CF768F72EEFB81A1"

--------------9F2120F9CF768F72EEFB81A1
Content-Type: multipart/alternative; boundary="------------D8333379825190F7D7D34624"

--------------D8333379825190F7D7D34624
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit

This is just a test message. No harm is intended! Regards.
--

--------------9F2120F9CF768F72EEFB81A1
Content-Type: application/pdf; name="Holiday Season Locations -Winter Holidays.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Holiday Season Locations -Winter Holidays.pdf"

--------------9F2120F9CF768F72EEFB81A1--

        """
        result = self.check_pad(msg)
        self.check_report(result, 0.0, [])

    def test_check_parse_flags_missing_headers_body_separator_negative(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is False.

        Check there is no newline after the header.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)

        MSG_PARSE = """Content-Type: multipart/mixed; boundary="sb"
From: test.com

Test

--sb

Test

--sb

Content-type: text/plain; charset=us-ascii
Test

--sb--

This is the epilogue.  It is also to be ignored."""
        result = self.check_pad(MSG_PARSE)
        self.check_report(result, 0, [])

    def test_check_parse_flags_missing_headers_body_separator_after_header(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is True.

        Check there is a newline after the header.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)

        MSG_PARSE = """Content-Type: multipart/mixed; boundary="sb"
From: test.com
Test

--sb

Content-type: text/plain; charset=us-ascii

Test

--sb--

This is the epilogue.  It is also to be ignored."""
        result = self.check_pad(MSG_PARSE)
        self.check_report(result, 1, ["MISSING_HB"])

    @unittest.skip("python3 and spamassassin don't check for this either")
    def test_check_parse_flags_missing_headers_body_separator_after_separator(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is True.

        Check there is a newline after the header.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)

        MSG_PARSE = """Content-Type: multipart/mixed; boundary="sb"
From: test.com

Test

--sb
Content-type: text/plain; charset=us-ascii
Test

--sb--
This is the epilogue.  It is also to be ignored."""
        result = self.check_pad(MSG_PARSE, debug=True)
        self.check_report(result, 1, ['MISSING_HB'])

    @unittest.skip("python3 and spamassassin don't check for this either")
    def test_check_parse_flags_missing_headers_body_separator_before_content_type(self):
        """
        Test check_msg_parse_flags: missing_mime_head_body_separator is True.

        Check there is a newline after the header.
        """
        self.setup_conf(
            config="""
            body        MISSING_HB    eval:check_msg_parse_flags("missing_mime_head_body_separator")
            describe    MISSING_HB    Missing blank line between MIME header and body
            """,
            pre_config=PRE_CONFIG)

        MSG_PARSE = """Content-Type: multipart/mixed; boundary="sb"
From: test.com
MIME-Version: 1.0

Test

--sb

Test

--sb
Content-type: text/plain; charset=us-ascii
Test

--sb--
This is the epilogue.  It is also to be ignored."""
        result = self.check_pad(MSG_PARSE)
        self.check_report(result, 1, ["MISSING_HB"])

    def test_check_parse_flags_missing_headers(self):
        """
        Test check_msg_parse_flags: missing_mime_headers is True.

        Test we flag if the line after the opening boundary isn't a header.
        """
        self.setup_conf(
            config="""
            body        MISSING_H eval:check_msg_parse_flags("missing_mime_headers")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS, debug=True)
        self.check_report(result, 1.0, ["MISSING_H"])

    def test_check_parse_flags_truncated_headers(self):
        """
        Test check_msg_parse_flags: truncated_headers is True.

        Test if any header name is over 256 or any header value is over 8192.
        """
        self.setup_conf(
            config="""
            body     TRUNCATED_H eval:check_msg_parse_flags("truncated_headers")
            describe TRUNCATED_H Message headers are very long
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS, debug=True)
        self.check_report(result, 1.0, ["TRUNCATED_H"])

    def test_check_parse_flags_mime_epilogue_exists(self):
        """
        Test check_msg_parse_flags: mime_epilogue_exists is True.

        Test if message has an epilogue.
        """
        self.setup_conf(
            config="""
            body MIME_EPILOGUE_EXISTS eval:check_msg_parse_flags("mime_epilogue_exists")
            """,
            pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARSE_FLAGS, debug=True)
        self.check_report(result, 1.0, ["MIME_EPILOGUE_EXISTS"])

    def test_check_for_uppercase_min_limit(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters is between desired limits
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('F' * 1, 'a' * 99, 'B' * 98)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 0, [])

    def test_check_for_uppercase_min_limit_exceeded(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters exceeded min limit
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(49.9, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('F' * 1, 'a' * 99, 'B' * 98)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_UPPERCASE'])

    def test_check_for_uppercase_max_limit_exceeded(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters exceeded max limit
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 69.6)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('B' * 1, 'a' * 60, 'F' * 137)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 0, [])

    def test_check_for_uppercase_max_limit(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters is between desired limits
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 69.7)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('B' * 1, 'a' * 60, 'F' * 137)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_UPPERCASE'])

    def test_check_for_uppercase_insufficient_characters(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters with insuficient chars.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('a' * 1, 'A' * 100, 'C' * 96)
        result = self.check_pad(msg, debug=True)
        self.check_report(result, 0, [])

    def test_check_for_uppercase_just_enough_characters(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters with just enough chars.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('F' * 1, 'A' * 100, 'B' * 97)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_UPPERCASE'])

    def test_check_for_uppercase_with_digit_char(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters with multiples digit chars.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(40, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('F' * 2, 'A' * 96, '1' * 100)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_UPPERCASE'])

    def test_check_for_uppercase_that_digit_are_low(self):
        """
        Test check_for_uppercase eval rule.

        Checks the percent of uppercase letters with low digit chars.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_UPPERCASE % ('F' * 2, 'A' * 96, '1' * 100)
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 0, [])

    def test_check_for_uppercase_below_empty_line(self):
        """
        Test check_for_uppercase eval rule.

        Max limit is not reached after empty line.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_MULTIPLE_LINES % ('F' * 1, 'a' * 99, 'B' * 98, '', 'B')
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 0, [])

    def test_check_for_uppercase_200c_below_empty_line(self):
        """
        Test check_for_uppercase eval rule.

        Max limit is reached after empty line.
        """
        self.setup_conf(
            config="""
            body CHECK_UPPERCASE  eval:check_for_uppercase(50, 100)
            """,
            pre_config=PRE_CONFIG)

        msg = MSG_WITH_MULTIPLE_LINES % (
            'F' * 1, 'a' * 99, 'B' * 98, '\na', 200 * 'B') 
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_UPPERCASE'])

    def test_check_for_ma_non_tex_negative(self):
        """
        Test check_ma_non_text eval rule return False.

        Checks to see if an email with multipart alternative is missing a
        text like alternative like application/rtf or text/*
        """
        self.setup_conf(
            config="""
            body CHECK_MA_NON_TEXT  eval:check_ma_non_text()
            """,
            pre_config=PRE_CONFIG)

        result = self.check_pad(MSG_HTML_MOSTLY, debug=True)

        self.check_report(result, 0, [])

    def test_check_for_ma_non_tex_random_content_type(self):
        """
        Test check_ma_non_text eval rule return True.

        Checks to see if an email with multipart alternative is missing a
        text like alternative like application/rtf or text/*
        """
        self.setup_conf(
            config="""
            body CHECK_MA_NON_TEXT  eval:check_ma_non_text()
            """,
            pre_config=PRE_CONFIG)

        msg = """Subject: test
Content-Type: multipart/alternative; boundary=001a1148e51c20e31305439a7bc2

--001a1148e51c20e31305439a7bc2
Content-Type: multipart/related

Test Body

--001a1148e51c20e31305439a7bc2
Content-Type: test

<div dir="ltr">Test Body</div>

--001a1148e51c20e31305439a7bc2--
"""
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_MA_NON_TEXT'])

    def test_check_for_ma_non_tex_random_content_type_first(self):
        """
        Test check_ma_non_text eval rule return True.

        Checks to see if an email with multipart alternative is missing a
        text like alternative like application/rtf or text/*
        """
        self.setup_conf(
            config="""
            body CHECK_MA_NON_TEXT  eval:check_ma_non_text()
            """,
            pre_config=PRE_CONFIG)

        msg = """Subject: test
Content-Type: multipart/alternative; boundary=001a1148e51c20e31305439a7bc2

--001a1148e51c20e31305439a7bc2
Content-Type: ceva

Test Body

--001a1148e51c20e31305439a7bc2
Content-Type: application/rtf

<div dir="ltr">Test Body</div>

--001a1148e51c20e31305439a7bc2--
"""
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 1, ['CHECK_MA_NON_TEXT'])

    def test_check_for_ma_non_tex_no_multipart_alternative(self):
        """
        Test check_ma_non_text eval rule return False.

        Checks to see if an email with multipart alternative is missing a
        text like alternative like application/rtf or text/*
        """
        self.setup_conf(
            config="""
            body CHECK_MA_NON_TEXT  eval:check_ma_non_text()
            """,
            pre_config=PRE_CONFIG)

        msg = """Subject: test
Content-Type: multipart; boundary=001a1148e51c20e31305439a7bc2

--001a1148e51c20e31305439a7bc2
Content-Type: ceva

Test Body

--001a1148e51c20e31305439a7bc2
"""
        result = self.check_pad(msg, debug=True)

        self.check_report(result, 0, [])

    # @unittest.skip("Not finished - need info")
    def test_check_for_faraway_charset(self):
        """
        Test check_for_faraway_charset eval rule.

        Checks if the message is in another locale than the users own.
        """
        self.setup_conf(
            config="""
            ok_locales en
            body CHARSET_FARAWAY        eval:check_for_faraway_charset()
            describe CHARSET_FARAWAY    Character set indicates a foreign language
            """,
            pre_config=PRE_CONFIG)

#         msg = """
# 6L+Z5Y+q5piv5LiA5Liq566A5Y2V55qE5paH5pys5raI5oGv44CCDQrov5nph4zmt7vliqDnmoTku7vkvZXlhoXlrrnpg73nlKjkuo7mtYvor5XjgIIg5LiN5bqU6K+l5Lyk5a6z77yM
#         """

        result = self.check_pad(MSG_CHECK_FARAWAY, debug=True)
        self.check_report(result, 1, ['CHARSET_FARAWAY'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalMIMEEval, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
