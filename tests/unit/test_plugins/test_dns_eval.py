"""Test DNSEval"""
import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.context
import pad.plugins.dns_eval


class TestDNSEval(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.ips = ["127.0.0.1"]
        self.local_data = {}
        self.global_data = {}
        self.mock_ctxt = MagicMock()
        self.mock_ctxt.reverse_ip = pad.context.GlobalContext.reverse_ip
        self.mock_msg = MagicMock()
        self.mock_msg.get_untrusted_ips.return_value = self.ips
        self.plugin = pad.plugins.dns_eval.DNSEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k, v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def test_finish_parsing_end(self):
        pass

    def test_check_rbl(self):
        self.plugin._check_rbl(self.mock_msg, "example.com")
        self.mock_ctxt.query_dns.assert_called_with(
            "1.0.0.127.example.com", )
