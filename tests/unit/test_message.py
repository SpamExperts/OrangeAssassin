# -*- coding: UTF-8 -*-

"""Tests for oa.message"""

import unittest
import collections
import email.header
import hashlib

try:
    from unittest.mock import patch, Mock, call, MagicMock
except ImportError:
    from mock import patch, Mock, call, MagicMock

import oa.message
import oa.config

HTML_TEXT = """<html><head><title>Email spam</title></head><body>
<p><b>Email spam</b>, also known as <b>junk email</b>
or <b>unsolicited bulk email</b> (<i>UBE</i>), is a subset of
<a href="/wiki/Spam_(electronic)" title="Spam (electronic)">electronic spam</a>
involving nearly identical messages sent to numerous recipients by <a href="/wiki/Email" title="Email">
email</a>. Clicking on <a href="/wiki/Html_email#Security_vulnerabilities" title="Html email" class="mw-redirect">
links in spam email</a> may send users to <a href="/wiki/Phishing" title="Phishing">phishing</a>
web sites or sites that are hosting <a href="/wiki/Malware" title="Malware">malware</a>.</body></html>"""

HTML_TEXT_STRIPED = 'Email spam Email spam , also known as junk email or unsolicited bulk email ( UBE ),' \
                    ' is a subset of electronic spam involving nearly identical messages sent to numerous recipients by email' \
                    ' . Clicking on links in spam email may send users to phishing web sites or sites that are hosting malware .'


class TestHTMLStrip(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.data = []

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_HTMLStripper(self):
        stripper = oa.message._ParseHTML(self.data)
        stripper.feed(HTML_TEXT)
        res = " ".join(self.data)
        self.assertEqual(res, HTML_TEXT_STRIPED)


class TestHeaders(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_case_insensitive(self):
        value = "test123"
        headers = oa.message._Headers()
        headers["TeSt"] = value
        self.assertEqual(headers["tEsT"], value)

    def test_case_insensitive_contains(self):
        value = "test123"
        headers = oa.message._Headers()
        headers["TeSt"] = value
        self.assertTrue("tEsT" in headers)

    def test_default_value(self):
        headers = oa.message._Headers()
        self.assertIsInstance(headers["tEsT"], list)


class TestParseMessage(unittest.TestCase):
    """Unit test for Message._parse_message."""
    def setUp(self):
        unittest.TestCase.setUp(self)
        oa.config.LAZY_MODE = False
        self.parts = []
        self.headers = []
        self.mime_headers = []
        patch("oa.message.email.message_from_string",
              **{"return_value._headers": self.headers}).start()
        patch("oa.message.Message._iter_parts",
              return_value=self.parts).start()
        self.plain_part = Mock(**{"get_content_subtype.return_value": "plain",
                                  "_headers": self.mime_headers
                                  })
        self.html_part = Mock(**{"get_content_subtype.return_value": "html",
                                 "_headers": self.mime_headers
                                 })
        self.conf = {
            "originating_ip_headers": [],
            "envelope_sender_header": [],
            "always_trust_envelope_sender": "0"
        }
        self.mock_ctxt = Mock(plugins={}, conf=self.conf)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_text_raw_payload(self):
        payload = "text payload 1\ntext payload 2"
        self.parts.append((payload, self.plain_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_text, payload)

    def test_text_payload(self):
        payload = "text payload 1\ntext payload 2"
        self.parts.append((payload, self.plain_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "text payload 1 text payload 2")

    def test_html_raw_payload(self):
        payload = "<html>text payload 1\ntext payload 2</html>"
        self.parts.append((payload, self.html_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_text, payload)

    def test_html_payload(self):
        payload = "<html>text payload 1\ntext payload 2</html>"
        self.parts.append((payload, self.html_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "text payload 1 text payload 2")

    def test_non_text_part(self):
        self.parts.append((None, self.plain_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "")
        self.assertEqual(msg.raw_text, "")

    def test_dump_headers(self):
        self.headers.extend([("From", "from@example.com"),
                             ("To", "to@example.com")])
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_headers["From"], ["from@example.com"])
        self.assertEqual(msg.raw_headers["To"], ["to@example.com"])

    def test_dump_headers_multiple(self):
        self.headers.extend([("From", "from@example.com"),
                             ("To", "to@example.com"),
                             ("From", "from2@example.com")])
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_headers["From"], ["from@example.com",
                                                   "from2@example.com"])
        self.assertEqual(msg.raw_headers["To"], ["to@example.com"])

    def test_dump_mime_headers(self):
        self.mime_headers.extend([("Content-Type", "text/plain;"),
                                  ("Content-Transfer-Encoding", "base64")])
        self.parts.append((None, self.plain_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_mime_headers["Content-Type"], ["text/plain;"])
        self.assertEqual(msg.raw_mime_headers["Content-Transfer-Encoding"],
                         ["base64"])

    def test_dump_uris_plain(self):
        self.parts.append(("http://example.com", self.plain_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.uri_list, {"http://example.com"})

    def test_dump_uris_html(self):
        self.parts.append(("<a href='http://example.com'>http://example.com</a>",
                           self.html_part))
        msg = oa.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.uri_list, {"http://example.com"})


class TestMessageMisc(unittest.TestCase):
    """
    Some tests that doesn't require extensive mocking
    """
    def test_msgid(self):
        msg_id = "test-id"
        msg = oa.message.Message(MagicMock(), "Message-ID: <%s>\n\nTest" % msg_id)
        self.assertEqual(msg_id, msg.msgid)

    def test_get_msgid_generated(self):
        """Test the get_msgid method when there is no Message-ID header."""
        text = "Hello world!"
        found_id = oa.message.Message(MagicMock(), "Subject: test\n\n%s" % text).msgid
        combined = "None\x00%s" % text
        msg_id = "%s@sa_generated" % hashlib.sha1(combined.encode('utf-8')).hexdigest()
        self.assertEqual(msg_id, found_id)

    def test_receive_date(self):
        """Test the receive_date method."""
        msg = ("""Received: from server6.seinternal.com ([178.63.74.9])\r
        by mx99.antispamcloud.com with esmtps (TLSv1.2:DHE-RSA-AES128-SHA:128)\r
        (Exim 4.85) id 1azjrM-000RwX-P5\r
        for spam@mx99.antispamcloud.com; Mon, 09 May 2016 14:00:25 +0200\r\n\r\nHello world!""")
        expected = 1462802425
        result = oa.message.Message(MagicMock(), msg).receive_date
        self.assertEqual(expected, result)


class TestIterPartsMessage(unittest.TestCase):
    """Test the Message._iter_parts method."""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.parts = []
        self.msg = Mock(**{"walk.return_value": self.parts})

    def create_part(self, maintype, charset, decode):
        payload = Mock(decode=decode)
        part = Mock(**{"get_content_maintype.return_value": maintype,
                       "get_content_charset.return_value": charset,
                       "get_payload.return_value": payload})
        return part

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_normal(self):
        decode = Mock(return_value="test123")
        part = self.create_part("text", "utf-8", decode)
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("utf-8", "ignore")])

    def test_no_charset(self):
        decode = Mock(return_value="test123")
        part = self.create_part("text", "", decode)
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("ascii", "ignore")])

    def test_strict_charset(self):
        decode = Mock(return_value="test123")
        part = self.create_part("text", "quopri", decode)
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("quopri", "strict")])

    def test_error(self):
        def _decode(c, e):
            if c == "invalid":
                raise LookupError()
            return "test123"
        decode = Mock(side_effect=_decode)
        part = self.create_part("text", "invalid", decode)
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("invalid", "ignore"),
                                 call("ascii", "ignore")])

    def test_error_all(self):
        decode = Mock(side_effect=UnicodeError)
        part = self.create_part("text", "invalid", decode)
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [])
        decode.assert_has_calls([call("invalid", "ignore"),
                                 call("ascii", "ignore")])

    def test_non_test(self):
        part = self.create_part("multipart", "invalid", "")
        self.parts.append(part)
        result = oa.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(None, part)])


class TestMessageVarious(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.conf = {
            "envelope_sender_header": [],
            "originating_ip_headers": [],
            "always_trust_envelope_sender": "0"
        }
        self.mock_ctxt = Mock(plugins={}, conf=self.conf)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_clear_matches(self):
        msg = oa.message.Message(self.mock_ctxt, "Subject: test\n\n")
        msg.rules_checked["TEST_HEADER"] = True
        msg.clear_matches()
        self.assertEqual(msg.rules_checked, {})

    def test_translate_line_breaks(self):
        text = "Test1\nTest2\r\nTest3\r"
        expected = "Test1\nTest2\nTest3\n"
        result = oa.message.Message.translate_line_breaks(text)
        self.assertEqual(result, expected)

    def test_translate_line_breaks_nonascii(self):
        text = u"X-Envelope-Sender: 'ant㮩o.parreira'@credimedia.pt"
        expected = u"X-Envelope-Sender: 'ant㮩o.parreira'@credimedia.pt"
        result = oa.message.Message.translate_line_breaks(text)
        self.assertEqual(result, expected)

    def test_norm_html_data(self):
        payload = "<html> test </html>"
        mock_feed = patch("oa.message._ParseHTML.feed").start()
        oa.message.Message.normalize_html_part(payload)
        mock_feed.assert_has_calls([call(payload)])

    def test_decode_header(self):
        header = u"Это тестовое сообщение"
        enc_header = email.header.make_header([(header, "utf-8"), ])
        result = oa.message.Message._decode_header(enc_header)
        self.assertEqual(result, header)

    def test_decode_header_bad_encoding(self):
        header = "Subject: =?BASE64?B?Y2FtZXJh?="
        enc_header = email.header.make_header([(header, "utf-8"), ])
        result = oa.message.Message._decode_header(enc_header)
        self.assertEqual(result, header)

    def test_decode_header_no_encoding(self):
        header = "<alexey@spamexperts.com>"
        enc_header = email.header.make_header([(header, "utf-8"), ])
        patch("email.header.decode_header",
              return_value=[('<alexey@spamexperts.com>', None), ]).start()
        result = oa.message.Message._decode_header(enc_header)
        self.assertEqual(result, header)


class TestGetHeaders(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.conf = {
            "originating_ip_headers": [],
            "always_trust_envelope_sender": "0",
            "envelope_sender_header": []
        }
        self.mock_ctxt = Mock(plugins={}, conf=self.conf)
        self.msg = oa.message.Message(self.mock_ctxt, "Subject: test\n\n")

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_get_raw_headers(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.raw_headers = {name: expected}
        self.assertEqual(self.msg.get_raw_header(name), expected)

    def test_get_decoded_headers(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.raw_headers = {name: expected}
        self.assertEqual(self.msg.get_decoded_header(name), expected)
        self.assertEqual(self.msg.headers[name], expected)

    def test_get_cached_decoded_headers(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.headers = {name: expected}
        self.assertEqual(self.msg.get_decoded_header(name), expected)

    def test_get_addr_header(self):
        name = "test1"
        values = ["My Name <my@example.com>, <no@example.com>",
                  "Your Name <>, Non Name <you@example.com>"]
        expected = ["my@example.com", "you@example.com"]
        self.msg.raw_headers = {name: values}
        self.assertEqual(self.msg.get_addr_header(name), expected)
        self.assertEqual(self.msg.addr_headers[name], expected)

    def test_get_cached_addr_header(self):
        name = "test1"
        expected = ["my@example.com", "you@example.com"]
        self.msg.addr_headers = {name: expected}
        self.assertEqual(self.msg.get_addr_header(name), expected)

    def test_get_name_header(self):
        name = "test1"
        values = ["My Name <my@example.com>, No Name <no@example.com>",
                  "<my@example.com>, Your Name <you@example.com>"]
        expected = ["My Name", "Your Name"]
        self.msg.raw_headers = {name: values}
        self.assertEqual(self.msg.get_name_header(name), expected)
        self.assertEqual(self.msg.name_headers[name], expected)

    def test_get_cached_name_header(self):
        name = "test1"
        expected = ["My Name", "Your Name"]
        self.msg.name_headers = {name: expected}
        self.assertEqual(self.msg.get_name_header(name), expected)

    def test_get_raw_mimeheaders(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.raw_mime_headers = {name: expected}
        self.assertEqual(self.msg.get_raw_mime_header(name), expected)

    def test_get_decoded_mimeheaders(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.raw_mime_headers = {name: expected}
        self.assertEqual(self.msg.get_decoded_mime_header(name), expected)
        self.assertEqual(self.msg.mime_headers[name], expected)

    def test_get_cached_decoded_mimeheaders(self):
        name = "test1"
        expected = ["test a", "test b"]
        self.msg.mime_headers = {name: expected}
        self.assertEqual(self.msg.get_decoded_mime_header(name), expected)

    def test_iter_decoded_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1", "1value2"]
        headers["test2"] = ["2value1", "2value2"]
        headers["test3"] = ["3value1", "3value2"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_headers = headers
        results = list(self.msg.iter_decoded_headers())
        self.assertEqual(results, expected)


class TestParseRelays(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.conf = {
            "originating_ip_headers": [],
            "always_trust_envelope_sender": "0",
            "envelope_sender_header": []
        }
        self.mock_ctxt = Mock(plugins={}, conf=self.conf)
        self.msg = oa.message.Message(self.mock_ctxt, "Subject: test\n\n")

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_parse_relays_blank_ip(self):
        """parse_relays when 'ip' equals ''"""
        relays = [{'ident': '', 'envfrom': '', 'id': u'md50000059687.msg',
                   'ip': '', 'helo': '', 'by': u'proxy.example.local',
                   'auth': '', 'rdns': u'mail.example.com'}, ]
        self.msg._parse_relays(relays)
        self.assertEqual(self.msg.external_relays, [])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestHTMLStrip, "test"))
    test_suite.addTest(unittest.makeSuite(TestHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseMessage, "test"))
    test_suite.addTest(unittest.makeSuite(TestIterPartsMessage, "test"))
    test_suite.addTest(unittest.makeSuite(TestMessageVarious, "test"))
    test_suite.addTest(unittest.makeSuite(TestGetHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseRelays, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
