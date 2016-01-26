# -*- coding: UTF-8 -*-

"""Tests for pad.message"""

import re
import unittest
import collections
import email.header

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad.message

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
        stripper = pad.message._ParseHTML(self.data)
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
        headers = pad.message._Headers()
        headers["TeSt"] = value
        self.assertEqual(headers["tEsT"], value)

    def test_case_insensitive_contains(self):
        value = "test123"
        headers = pad.message._Headers()
        headers["TeSt"] = value
        self.assertTrue("tEsT" in headers)

    def test_default_value(self):
        headers = pad.message._Headers()
        self.assertIsInstance(headers["tEsT"], list)


class TestParseMessage(unittest.TestCase):
    """Unit test for Message._parse_message."""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.parts = []
        self.headers = []
        self.mime_headers = []
        patch("pad.message.email.message_from_string",
              **{"return_value._headers": self.headers}).start()
        patch("pad.message.Message._iter_parts",
              return_value=self.parts).start()
        self.plain_part = Mock(**{"get_content_subtype.return_value": "plain",
                                  "_headers": self.mime_headers
                                  })
        self.html_part = Mock(**{"get_content_subtype.return_value": "html",
                                 "_headers": self.mime_headers
                                 })
        self.mock_ctxt = Mock(plugins={})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_text_raw_payload(self):
        payload = "text payload 1\ntext payload 2"
        self.parts.append((payload, self.plain_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_text, payload)

    def test_text_payload(self):
        payload = "text payload 1\ntext payload 2"
        self.parts.append((payload, self.plain_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "text payload 1 text payload 2")

    def test_html_raw_payload(self):
        payload = "<html>text payload 1\ntext payload 2</html>"
        self.parts.append((payload, self.html_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_text, payload)

    def test_html_payload(self):
        payload = "<html>text payload 1\ntext payload 2</html>"
        self.parts.append((payload, self.html_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "text payload 1 text payload 2")

    def test_non_text_part(self):
        self.parts.append((None, self.plain_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.text, "")
        self.assertEqual(msg.raw_text, "")

    def test_dump_headers(self):
        self.headers.extend([("From", "from@example.com"),
                             ("To", "to@example.com")])
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_headers["From"], ["from@example.com"])
        self.assertEqual(msg.raw_headers["To"], ["to@example.com"])

    def test_dump_headers_multiple(self):
        self.headers.extend([("From", "from@example.com"),
                             ("To", "to@example.com"),
                             ("From", "from2@example.com")])
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_headers["From"], ["from@example.com",
                                                   "from2@example.com"])
        self.assertEqual(msg.raw_headers["To"], ["to@example.com"])

    def test_dump_mime_headers(self):
        self.mime_headers.extend([("Content-Type", "text/plain;"),
                                  ("Content-Transfer-Encoding", "base64")])
        self.parts.append((None, self.plain_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.raw_mime_headers["Content-Type"], ["text/plain;"])
        self.assertEqual(msg.raw_mime_headers["Content-Transfer-Encoding"],
                         ["base64"])

    def test_dump_uris_plain(self):
        self.parts.append(("http://example.com", self.plain_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.uri_list, {"http://example.com"})

    def test_dump_uris_html(self):
        self.parts.append(("<a href='http://example.com'>http://example.com</a>",
                           self.html_part))
        msg = pad.message.Message(self.mock_ctxt, "")
        self.assertEqual(msg.uri_list, {"http://example.com"})


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
        result = pad.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("utf-8", "ignore")])

    def test_no_charset(self):
        decode = Mock(return_value="test123")
        part = self.create_part("text", "", decode)
        self.parts.append(part)
        result = pad.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("ascii", "ignore")])

    def test_strict_charset(self):
        decode = Mock(return_value="test123")
        part = self.create_part("text", "quopri", decode)
        self.parts.append(part)
        result = pad.message.Message._iter_parts(self.msg)
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
        result = pad.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(u"test123", part)])
        decode.assert_has_calls([call("invalid", "ignore"),
                                 call("ascii", "ignore")])

    def test_error_all(self):
        decode = Mock(side_effect=UnicodeError)
        part = self.create_part("text", "invalid", decode)
        self.parts.append(part)
        result = pad.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [])
        decode.assert_has_calls([call("invalid", "ignore"),
                                 call("ascii", "ignore")])

    def test_non_test(self):
        part = self.create_part("multipart", "invalid", "")
        self.parts.append(part)
        result = pad.message.Message._iter_parts(self.msg)
        self.assertEqual(list(result), [(None, part)])


class TestMessageVarious(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_ctxt = Mock(plugins={})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_clear_matches(self):
        msg = pad.message.Message(self.mock_ctxt, "Subject: test\n\n")
        msg.rules_checked["TEST_HEADER"] = True
        msg.clear_matches()
        self.assertEqual(msg.rules_checked, {})

    def test_translate_line_breaks(self):
        text = "Test1\nTest2\r\nTest3\r"
        expected = "Test1\nTest2\nTest3\n"

        result = pad.message.Message.translate_line_breaks(text)
        self.assertEqual(result, expected)

    def test_norm_html_data(self):
        payload = "<html> test </html>"
        mock_feed = patch("pad.message._ParseHTML.feed").start()
        pad.message.Message.normalize_html_part(payload)
        mock_feed.assert_has_calls([call(payload)])

    def test_decode_header(self):
        header = u"Это тестовое сообщение"
        enc_header = email.header.make_header([(header, "utf-8"), ])
        result = pad.message.Message._decode_header(enc_header)
        self.assertEqual(result, header)

    @unittest.SkipTest
    def test_decode_header_bad_encoding(self):
        header = u"Subject: =?BASE64?B?Y2FtZXJh?="
        enc_header = email.header.make_header([(header, "utf-8"), ])
        result = pad.message.Message._decode_header(enc_header)
        self.assertEqual(result, header)


class TestGetHeaders(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_ctxt = Mock(plugins={})
        self.msg = pad.message.Message(self.mock_ctxt, "Subject: test\n\n")

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

    def test_iter_raw_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1", "1value2"]
        headers["test2"] = ["2value1", "2value2"]
        headers["test3"] = ["3value1", "3value2"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_headers = headers
        results = list(self.msg.iter_raw_headers())
        self.assertEqual(results, expected)

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

    def test_iter_addr_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1", "1value2"]
        headers["test2"] = ["2value1", "2value2"]
        headers["test3"] = ["3value1", "3value2"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_headers = headers
        results = list(self.msg.iter_addr_headers())
        self.assertEqual(results, expected)

    def test_iter_name_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1 <>", "1value2 <>"]
        headers["test2"] = ["2value1 <>", "2value2 <>"]
        headers["test3"] = ["3value1 <>", "3value2 <>"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_headers = headers
        results = list(self.msg.iter_name_headers())
        self.assertEqual(results, expected)

    def test_iter_raw_mime_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1", "1value2"]
        headers["test2"] = ["2value1", "2value2"]
        headers["test3"] = ["3value1", "3value2"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_mime_headers = headers
        results = list(self.msg.iter_raw_mime_headers())
        self.assertEqual(results, expected)

    def test_iter_decoded_mime_headers(self):
        headers = collections.OrderedDict()
        headers["test1"] = ["1value1", "1value2"]
        headers["test2"] = ["2value1", "2value2"]
        headers["test3"] = ["3value1", "3value2"]
        expected = ['test1: 1value1', 'test1: 1value2',
                    'test2: 2value1', 'test2: 2value2',
                    'test3: 3value1', 'test3: 3value2', ]
        self.msg.raw_mime_headers = headers
        results = list(self.msg.iter_mime_headers())
        self.assertEqual(results, expected)



def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestHTMLStrip, "test"))
    test_suite.addTest(unittest.makeSuite(TestHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestParseMessage, "test"))
    test_suite.addTest(unittest.makeSuite(TestIterPartsMessage, "test"))
    test_suite.addTest(unittest.makeSuite(TestMessageVarious, "test"))
    test_suite.addTest(unittest.makeSuite(TestGetHeaders, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
