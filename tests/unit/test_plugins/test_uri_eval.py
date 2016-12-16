"""Tests for pad.plugins.uri_eval plugin"""
import unittest

try:
    from unittest.mock import patch, MagicMock, Mock, call
except ImportError:
    from mock import patch, MagicMock, Mock, call


import pad.context
import pad.message
import pad.plugins.uri_eval


class TestURIDetail(unittest.TestCase):
    """Tests for the URIDetail plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        # self.global_data = {"geodb":"/innexistent/location/"}
        # self.cmds = {"uri_detail": pad.plugins.uri_detail.URIDetailRule}
        # patch("pad.plugins.uri_detail.URIDetailPlugin.options",
        #       self.options).start()
        # patch("pad.plugins.uri_detail.URIDetailPlugin.cmds",
        #       self.cmds).start()

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)})
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(k,
                                                                              v),
        })
        self.plugin = pad.plugins.uri_eval.URIEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_for_http_redirector(self):
        self.mock_msg.uri_list = {
                       'https://user:pass@redirect.comp.com:50/in/'
                       'elena-mocanu-96715140/https://externalsite.com/page'}
        result = self.plugin.check_for_http_redirector(self.mock_msg)
        self.assertEqual(result, 1)

    def test_check_for_http_redirector_no_match(self):
        self.mock_msg.uri_list = {
                       'https://www.PAYPAL.com/login/account-unlock'}
        result = self.plugin.check_for_http_redirector(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_https_ip_mismatch(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.paypal.com/login/account-unlock"]
        self.mock_msg.uri_detail_links = \
            {'http://45.42.12.12/login/account-unlock':
                 {'cleaned': 'http://45.42.12.12/login/account-unlock',
                  'domain': '45.42.12.12',
                  'raw': 'http://45.42.12.12/login/account-unlock',
                  'scheme': 'http',
                  'text': 'https://www.paypal.com/login/account-unlock',
                  'type': 'a'}}
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 1)

    def test_check_https_ip_mismatch_http(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account-unlock"]
        self.mock_msg.uri_detail_links = \
            {'http://45.42.12.12/login/account-unlock':
                 {'cleaned': 'http://45.42.12.12/login/account-unlock',
                  'domain': '45.42.12.12',
                  'raw': 'http://45.42.12.12/login/account-unlock',
                  'scheme': 'http',
                  'text': 'https://www.paypal.com/login/account-unlock',
                  'type': 'a'}}
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_https_ip_mismatch_without_ip(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account-unlock"]
        self.mock_msg.uri_detail_links = \
            {'http://example.com/login/account-unlock':
                 {'cleaned': 'http://example.com/login/account-unlock',
                  'domain': 'example.com',
                  'raw': 'http://example.com/login/account-unlock',
                  'scheme': 'http',
                  'text': 'https://www.paypal.com/login/account-unlock',
                  'type': 'a'}}
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_https_ip_mismatch_KeyError(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account-unlock"]
        self.mock_msg.side_effect= KeyError
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_extract_url_from_text(self):
        text = "Anchor text with https://example.com"
        result = self.plugin.extract_url_from_text(text)
        self.assertEqual(result, ["https://example.com"])

    def test_match_uri_truncated(self):
        key = 'https://www.PAYPAL.com/login/account-unlock'
        uri_list = ['https://www.PAYPAL.com/...']
        self.mock_urlparse = patch("pad.plugins.uri_eval.urlparse").start()
        self.mock_urlparse.return_value.netloc =  'www.PAYPAL.com'

        uri_details = \
                 {'cleaned': 'https://www.PAYPAL.com/...',
                  'domain': 'www.PAYPAL.com',
                  'raw': 'https://www.PAYPAL.com/...',
                  'scheme': 'https',
                  'type': 'parsed'}
        result = self.plugin.match_uri_truncated(key, uri_list, uri_details)
        self.assertEqual(result, True)

    def test_match_uri_truncated_False(self):
        key = 'https://www.PAYPAL.com/login/account-unlock'
        uri_list = ['https://www.PAYPAL.com/login/account-unlock']
        self.mock_urlparse = patch("pad.plugins.uri_eval.urlparse").start()
        self.mock_urlparse.return_value.netloc = 'www.PAYPAL.com'
        uri_details = \
                 {'cleaned': 'https://www.PAYPAL.com/login/account-unlock',
                  'domain': 'www.PAYPAL.com'}
        result = self.plugin.match_uri_truncated(key, uri_list, uri_details)
        self.assertEqual(result, False)

    def test_check_uri_truncated(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.PAYPAL.com/..."]
        self.mock_match_uri_truncated = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "match_uri_truncated").start().return_value = True
        self.mock_msg.uri_detail_links = \
            {'https://www.PAYPAL.com/login/account-unlock':
                 {'cleaned': 'https://www.PAYPAL.com/login/account-unlock',
                  'domain': 'www.PAYPAL.com',
                  'raw': 'https://www.PAYPAL.com/login/account-unlock',
                  'scheme': 'https',
                  'text': 'It is a truncated uri https://www.PAYPAL.com/...',
                  'type': 'a'}}
        result = self.plugin.check_uri_truncated(self.mock_msg)
        self.assertEqual(result, 1)

    def test_check_uri_truncated_does_not_match(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.PAYPAL.com/..."]
        self.mock_match_uri_truncated = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "match_uri_truncated").start().return_value = False
        # self.mock_msg.side_effect = KeyError
        self.mock_msg.uri_detail_links = \
            {'https://www.PAYPAL.com/login/account-unlock':
                 {'cleaned': 'https://www.PAYPAL.com/login/account-unlock',
                  'domain': 'www.PAYPAL.com',
                  'raw': 'https://www.PAYPAL.com/login/account-unlock',
                  'scheme': 'https',
                  'text': 'It is a truncated uri https://www.PAYPAL.com/...',
                  'type': 'a'}}
        result = self.plugin.check_uri_truncated(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_uri_truncated_KeyError(self):
        self.mock_extract_url_from_text = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.PAYPAL.com/..."]
        self.mock_match_uri_truncated = \
            patch("pad.plugins.uri_eval.URIEvalPlugin."
                  "match_uri_truncated").start().return_value = False
        self.mock_msg.side_effect = KeyError
        result = self.plugin.check_uri_truncated(self.mock_msg)
        self.assertEqual(result, 0)