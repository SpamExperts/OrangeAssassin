"""Tests for pad.plugins.uri_detail plugin"""
import collections
import unittest

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from unittest.mock import patch, MagicMock, Mock, call
except ImportError:
    from mock import patch, MagicMock, Mock, call


import oa.context
import oa.message
import oa.plugins.uri_detail

def _get_basic_message(text=""):
    msg = MIMEMultipart()
    msg["from"] = "sender@example.com"
    msg["to"] = "recipient@example.com"
    msg["subject"] = "test"
    if text:
        msg.attach(MIMEText(text))
    return msg


class TestURIDetail(unittest.TestCase):
    """Tests for the URIDetail plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {"geodb":"/innexistent/location/"}
        self.cmds = {"uri_detail": oa.plugins.uri_detail.URIDetailRule}
        patch("oa.plugins.uri_detail.URIDetailPlugin.options",
              self.options).start()
        patch("oa.plugins.uri_detail.URIDetailPlugin.cmds",
              self.cmds).start()
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
                                  )
        self.plugin = oa.plugins.uri_detail.URIDetailPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()



    def _check_parsed_links(self, keys, type, result, expected):
        """Check the results agains the expected result"""
        for key in keys:
            self.assertEqual(result[key][type]["raw"], expected[key][type]["raw"])
            self.assertEqual(result[key][type]["scheme"], expected[key][type]["scheme"])
            self.assertEqual(result[key][type]["cleaned"], expected[key][type]["cleaned"])
            self.assertEqual(result[key][type]["domain"], expected[key][type]["domain"])

    def test_parsed_metadata_one_link(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = ("<html><body><a href='http://example.com'>example.com</a>"
                    "</body></html>")
        emsg = _get_basic_message(htmltext)
        msg = oa.message.Message(self.mock_ctxt, emsg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {u"http://example.com":
                        {"a":
                             {"raw": u"http://example.com",
                              "scheme": u"http",
                              "cleaned": u"http://example.com",
                              "domain": u"example.com",
                              }}
                         }
        keys = [u"http://example.com",]
        self._check_parsed_links(keys, "a", msg.uri_detail_links, expected)# pylint: disable=no-member

    def test_parsed_metadata_no_html(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = """http://example.com"""
        emsg = _get_basic_message(htmltext)
        msg = oa.message.Message(self.mock_ctxt, emsg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {u"http://example.com":
                        {"parsed":
                             {"raw": u"http://example.com",
                              "scheme": u"http",
                              "cleaned": u"http://example.com",
                              "domain": u"example.com",
                              }}
                         }
        keys = [u"http://example.com",]
        self._check_parsed_links(keys, "parsed", msg.uri_detail_links, expected)# pylint: disable=no-member

    def test_pm_multiple_links(self):
        """Test the plugin by asking it process one line of the configuration file"""
        htmltext = ("<html><body>"
                    "<a href='http://example.com'>link to example.com</a>"
                    "https://example.com"
                    "<link src='http://test%2Ecom'>exampletest.com</a>"
                    "</body></html>")
        emsg = _get_basic_message(htmltext)
        msg = oa.message.Message(self.mock_ctxt, emsg.as_string())
        self.plugin.parsed_metadata(msg)
        expected = {'http://example.com':
                        {'a':
                             {'cleaned': 'http://example.com',
                              'domain': 'example.com',
                              'raw': 'http://example.com',
                              'scheme': 'http',
                              'text': ['link to example.com']}},
                    'http://test%2Ecom':
                        {'link':
                             {'cleaned': 'http://test.com',
                              'domain': 'test%2Ecom',
                              'raw': 'http://test%2Ecom',
                              'scheme': 'http',
                              'text': ['exampletest.com']}},
                    'https://example.com':
                        {'parsed':
                             {'cleaned': 'https://example.com',
                              'domain': 'example.com',
                              'raw': 'https://example.com',
                              'scheme': 'https'}}}

        keys = [u"http://example.com",]
        self._check_parsed_links(keys, "a", msg.uri_detail_links, expected)# pylint: disable=no-member
        keys = [u"https://example.com", ]
        self._check_parsed_links(keys, "parsed", msg.uri_detail_links, expected)
        keys = [u"http://test%2Ecom", ]
        self._check_parsed_links(keys, "link", msg.uri_detail_links, expected)

class TestUriDetailRule(unittest.TestCase):
    """Test case for the URIDetailRule class"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        items = {u"http://example.com":
                     {"a":
                          {
                              "raw": u"http://example.com",
                              "scheme": u"http",
                              "cleaned": u"http://example.com",
                              "domain": u"example.com",
                              "text": u"link to example.com"}},
                 u"https://example.com":
                     {"parsed":
                         {
                             "raw": u"https://example.com",
                             "scheme": u"https",
                             "cleaned": u"https://example.com",
                             "domain": u"example.com",
                             "text": ""}},
                 u"http://test.com":
                     {"link":
                         {
                             "raw": u"http://test%2Ecom",
                             "scheme": u"http",
                             "cleaned": u"http://test.com",
                             "domain": u"test.com",
                             "text": u"exampletest.com"}},
                }
        self.uri_detail_links = collections.OrderedDict(sorted(items.items(),
                                                               key=lambda t: t[0]))
        self.mock_msg = Mock(uri_detail_links=self.uri_detail_links)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        """Test the match method in the Rule, the result of the match is True"""
        mock_pattern = (("domain", Mock(**{"match.return_value": True})),)
        rule = oa.plugins.uri_detail.URIDetailRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        for key, pattern in mock_pattern:
            pattern.match.assert_called_once_with(
                self.uri_detail_links[u"http://example.com"]["a"][key])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        """Test the match method in the Rule, the result of the match is False"""
        mock_pattern = (("domain", Mock(**{"match.return_value": False})),)
        rule = oa.plugins.uri_detail.URIDetailRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)
        calls = []
        for key in self.uri_detail_links:
            for type in  self.uri_detail_links[key]:
                value = self.uri_detail_links[key][type]
                calls.append(call(value["domain"]))
        for key, pattern in mock_pattern:
            pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)

    def test_get_rule_kwargs(self):
        """Test getting the kwargs for the rule, the rule have keys (what to match in the
        link) and the value to be used in against the regex"""
        mock_perl2re = patch("oa.rules.uri.oa.regex.perl2re").start()
        data = {"value": r'domain =~ /\bexample.com\b/'}
        expected = {"pattern": [("domain", mock_perl2re("/example.com/")),]}
        kwargs = oa.plugins.uri_detail.URIDetailRule.get_rule_kwargs(data)
        mock_perl2re.assert_called_with(r'/\bexample.com\b/', "=~")
        self.assertEqual(kwargs, expected)

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestURIDetail, "test"))
    test_suite.addTest(unittest.makeSuite(TestUriDetailRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
