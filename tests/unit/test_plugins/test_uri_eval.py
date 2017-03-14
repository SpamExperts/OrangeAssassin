"""Tests for pad.plugins.uri_eval plugin"""
import random
import unittest

try:
    from unittest.mock import patch, MagicMock, Mock, call
except ImportError:
    from mock import patch, MagicMock, Mock, call


import oa.context
import oa.message
import oa.plugins.uri_eval

ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ascii_letters = ascii_lowercase + ascii_uppercase

class TestURIDetail(unittest.TestCase):
    """Tests for the URIDetail plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
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
        self.plugin = oa.plugins.uri_eval.URIEvalPlugin(self.mock_ctxt)

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
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.paypal.com/login/account-unlock"]
        self.mock_msg.uri_detail_links = \
            {'http://45.42.12.12/login/account-unlock':
                 {"a":
                      {'cleaned': 'http://45.42.12.12/login/account-unlock',
                       'domain': '45.42.12.12',
                       'raw': 'http://45.42.12.12/login/account-unlock',
                       'scheme': 'http',
                       'text': 'https://www.paypal.com/login/account-unlock',}}
                 }
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 1)

    def test_check_https_ip_mismatch_http(self):
        self.mock_extract_url_from_text = \
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account"]
        self.mock_msg.uri_detail_links = \
            {'http://45.42.12.12/login/account':
                 {"a":
                      {'cleaned': 'http://45.42.12.12/login/account',
                       'domain': '45.42.12.12',
                       'raw': 'http://45.42.12.12/login/account',
                       'scheme': 'http',
                       'text': 'https://www.paypal.com/login/account', }}}
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_https_ip_mismatch_without_ip(self):
        self.mock_extract_url_from_text = \
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account"]
        self.mock_msg.uri_detail_links = \
            {'http://example.com/login/account':
                 {"a":
                      {'cleaned': 'http://example.com/login/account',
                       'domain': 'example.com',
                       'raw': 'http://example.com/login/account',
                       'scheme': 'http',
                       'text': 'https://www.paypal.com/login/account',}}}
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_https_ip_mismatch_KeyError(self):
        self.mock_extract_url_from_text = \
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["http://www.paypal.com/login/account-unlock"]
        self.mock_msg.side_effect= KeyError
        result = self.plugin.check_https_ip_mismatch(self.mock_msg)
        self.assertEqual(result, 0)

    def test_extract_url_from_text(self):
        text = ["Anchor text with https://example.com"]
        result = self.plugin.extract_url_from_text(text)
        self.assertEqual(result, ["https://example.com"])


    def test_check_uri_truncated_does_not_match(self):
        self.mock_extract_url_from_text = \
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.PAYPAL.com/..."]
        self.mock_msg.uri_detail_links = \
            {'https://www.PAYPAL.com/login/account-unlock':
                 {'cleaned': 'https://www.PAYPAL.com/login/account-unlock',
                  'domain': 'www.PAYPAL.com',
                  'raw': 'https://www.PAYPAL.com/login/account-unlock',
                  'scheme': 'https',
                  'text': 'It is a truncated uri https://www.PAYPAL.com/...',}}
        result = self.plugin.check_uri_truncated(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_uri_truncated(self):
        mytext = [random.choice(ascii_letters) for _ in range(8192)]
        long_text = "".join(mytext)
        self.mock_extract_url_from_text = \
            patch("oa.plugins.uri_eval.URIEvalPlugin."
                  "extract_url_from_text").start()
        self.mock_extract_url_from_text.return_value = \
            ["https://www.PAYPAL.com/..."]
        self.mock_msg.uri_detail_links = \
            {long_text:
                 {"a":
                      {'cleaned': 'https://www.PAYPAL.com/login/account',
                       'domain': 'www.PAYPAL.com',
                       'text': 'It is a truncated uri'}}}
        result = self.plugin.check_uri_truncated(self.mock_msg)
        self.assertEqual(result, 0)
