"""Test DNSEval"""
import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import ipaddress

import pad.context
import pad.plugins.dns_eval


class TestDNSEval(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.ips = [ipaddress.ip_address(u"127.0.0.1")]
        self.local_data = {}
        self.global_data = {}
        self.mock_ctxt = MagicMock()
        self.mock_ctxt.reverse_ip = pad.context.GlobalContext().reverse_ip
        self.mock_msg = MagicMock()
        self.mock_msg.sender_address = "sender@example.com"
        self.mock_msg.get_untrusted_ips.return_value = self.ips
        self.plugin = pad.plugins.dns_eval.DNSEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k, v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock(checked={}, not_checked={})

    def test_finish_parsing_end(self):
        eval_rule = MagicMock()
        eval_rule.eval_rule_name = "check_rbl"
        eval_rule.eval_args = ("set id", "rbl.example.com.")
        self.mock_ruleset.checked["MY_RULE"] = eval_rule
        patch("pad.plugins.dns_eval.isinstance", return_value=True,
              create=True).start()

        self.plugin.finish_parsing_end(self.mock_ruleset)
        self.assertEqual(
            self.plugin["zones"], {"set id": "rbl.example.com."}
        )

    def test_check_rbl(self):
        """Test the check_rbl method."""
        self.plugin.check_rbl(
            self.mock_msg, "example_ser", "example.com"
        )
        self.mock_ctxt.query_dns.assert_called_with(
            "1.0.0.127.example.com", 'A')

    def test_check_rbl_from_domain(self):
        """Test the check_rbl_from_domain eval rule"""
        from_headers = ["test@example.org"]
        self.mock_msg.get_addr_header.return_value = from_headers
        self.plugin.check_rbl_from_domain(
            self.mock_msg, "example_set", "example.com"
        )
        self.mock_ctxt.query_dns.assert_called_with(
            "example.org.example.com", 'A')
