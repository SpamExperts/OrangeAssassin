"""Tests for pad.plugins.uri_detail plugin"""
import unittest

try:
    from unittest.mock import patch, MagicMock, Mock, call
except ImportError:
    from mock import patch, MagicMock, Mock, call

from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

import pad.context
import pad.message
import pad.plugins.uri_detail


class TestURIDetail(unittest.TestCase):
    """Tests for the URIDetail plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {"geodb":"/innexistent/location/"}
        self.cmds = {"uri_detail": pad.plugins.uri_detail.URIDetailRule}
        patch("pad.plugins.uri_detail.URIDetailPlugin.options",
              self.options).start()
        patch("pad.plugins.uri_detail.URIDetailPlugin.cmds",
              self.cmds).start()
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
                                  )
        self.plugin = pad.plugins.uri_detail.URIDetailPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def _get_basic_message(self, text = ""):
        msg = MIMEMultipart()
        msg["from"] = "sender@example.com"
        msg["to"] = "recipient@example.com"
        msg["subject"] = "test"
        if text:
            msg.attach(MIMEText(text))
        return msg
            

    def _check_parsed_links(self, keys, result, expected):
        """Check the results agains the expected result"""
        for key in keys:
            self.assertEqual(result[key]["raw"], expected[key]["raw"], result[key])
            self.assertEqual(result[key]["scheme"], expected[key]["scheme"], result[key])
            self.assertEqual(result[key]["cleaned"], expected[key]["cleaned"], result[key])
            self.assertEqual(result[key]["type"], expected[key]["type"], result[key])
            self.assertEqual(result[key]["domain"], expected[key]["domain"], result[key])
            
    def test_parsed_metadata_one_link(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = ("<html><body><a href='http://example.com'>example.com</a>"
                   "</body></html>")
        msg = self._get_basic_message(htmltext)
        msg = pad.message.Message(self.mock_ctxt, msg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {u"http://example.com": {"raw": u"http://example.com",
                     "scheme": u"http",
                     "cleaned": u"http://example.com",
                     "type": u"a",
                     "domain": u"example.com",
                   }}
        keys = [u"http://example.com",]
        self._check_parsed_links(keys, msg.uri_detail_links, expected)

    def test_parsed_metadata_one_link_no_html(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = """http://example.com"""
        msg = self._get_basic_message(htmltext)
        msg = pad.message.Message(self.mock_ctxt, msg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {u"http://example.com": {"raw": u"http://example.com",
                     "scheme": u"http",
                     "cleaned": u"http://example.com",
                     "type": u"parsed",
                     "domain": u"example.com",
                   }}
        keys = [u"http://example.com",]
        self._check_parsed_links(keys, msg.uri_detail_links, expected)

    def test_parsed_metadata_multiple_links(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = ("<html><body>"
                "<a href='http://example.com'>link to example.com</a>"
                "https://example.com"
                "<link src='http://test%2Ecom'>exampletest.com</a>"
                "</body></html>")
        msg = self._get_basic_message(htmltext)
        msg = pad.message.Message(self.mock_ctxt, msg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {u"http://example.com": {"raw": u"http://example.com",
                     "scheme": u"http",
                     "cleaned": u"http://example.com",
                     "type": u"a",
                     "domain": u"example.com",
                     "text": u"link to example.com"
                     },
                    u"https://example.com": {"raw": u"https://example.com",
                     "scheme": u"https",
                     "cleaned": u"https://example.com",
                     "type": u"parsed",
                     "domain": u"example.com",
                     "text": ""
                     },
                    u"http://test.com": {"raw": u"http://test%2Ecom",
                     "scheme": u"http",
                     "cleaned": u"http://test.com",
                     "type": u"link",
                     "domain": u"test.com",
                     "text": u"exampletest.com"
                     },
                    }
        keys = [u"http://example.com",]
        self._check_parsed_links(keys, msg.uri_detail_links, expected)

class TestUriDetailRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.uri_detail_links = {u"http://example.com": {"raw": u"http://example.com",
                     "scheme": u"http",
                     "cleaned": u"http://example.com",
                     "type": u"a",
                     "domain": u"example.com",
                     "text": u"link to example.com"
                     },
                    u"https://example.com": {"raw": u"https://example.com",
                     "scheme": u"https",
                     "cleaned": u"https://example.com",
                     "type": u"parsed",
                     "domain": u"example.com",
                     "text": ""
                     },
                    u"http://test.com": {"raw": u"http://test%2Ecom",
                     "scheme": u"http",
                     "cleaned": u"http://test.com",
                     "type": u"link",
                     "domain": u"test.com",
                     "text": u"exampletest.com"
                     },
                    }

        self.mock_msg = Mock(uri_detail_links = self.uri_detail_links)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = (("domain", Mock(**{"match.return_value": True})),)
        rule = pad.plugins.uri_detail.URIDetailRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        for key, pattern in mock_pattern:
            pattern.match.assert_called_with(self.uri_detail_links["http://example.com"][key])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = (("domain", Mock(**{"match.return_value": False})),)
        rule = pad.plugins.uri_detail.URIDetailRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        calls = []
        for key in self.uri_detail_links:
            value = self.uri_detail_links[key]
            calls.append(call(value["domain"]))
        for key, pattern in mock_pattern:
            pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        mock_perl2re = patch("pad.rules.uri.pad.regex.perl2re").start()
        data = {"value": r'domain =~ /\bexample.com\b/'}
        expected = {"pattern": [("domain",mock_perl2re("/example.com/")),]}
        kwargs = pad.plugins.uri_detail.URIDetailRule.get_rule_kwargs(data)
        mock_perl2re.assert_called_with(r'/\bexample.com\b/',"=~")
        self.assertEqual(kwargs, expected)

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestURIDetail, "test"))
    test_suite.addTest(unittest.makeSuite(TestUriDetailRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
