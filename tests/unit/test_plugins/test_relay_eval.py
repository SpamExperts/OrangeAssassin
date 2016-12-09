"""Test for pad.plugins.relay_eval Plugin"""


import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.relay_eval
import pad.message


class TestRelayEvalBase(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.global_data = {}
        self.local_data = {}
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock(msg={}, trusted_relays=[],
                                  untrusted_relays=[])
        self.plugin = pad.plugins.relay_eval.RelayEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()


class TestEvalRules(TestRelayEvalBase):
    def test_check_for_numeric_helo(self):
        self.mock_msg.untrusted_relays = [{"helo": "127.0.0.1"}]
        result = self.plugin.check_for_numeric_helo(self.mock_msg)
        self.assertFalse(result)

        self.mock_msg.untrusted_relays = [{"helo": "83.45.21.22"}]
        result = self.plugin.check_for_numeric_helo(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_illegal_ip(self):
        result = self.plugin.check_for_illegal_ip(self.mock_msg)
        self.assertFalse(result)

    def test_check_all_trusted(self):
        self.mock_msg.trusted_relays = [{"ip": "127.0.0.1"}]
        self.mock_msg.untrusted_relays = []
        result = self.plugin.check_all_trusted(self.mock_msg)
        self.assertTrue(result)

        self.mock_msg.trusted_relays = [{"ip": "127.0.0.1"}]
        self.mock_msg.untrusted_relays = [{"ip": "128.0.0.2"}]
        result = self.plugin.check_all_trusted(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_sender_no_reverse(self):
        self.mock_msg.trusted_relays = [{"ip": "127.0.0.1"}]
        self.mock_msg.untrusted_relays = []
        result = self.plugin.check_for_sender_no_reverse(self.mock_msg)
        self.assertFalse(result)

        self.mock_msg.untrusted_relays = [{"rdns": "badrdns"}]
        result = self.plugin.check_for_sender_no_reverse(self.mock_msg)
        self.assertFalse(result)

        self.mock_msg.untrusted_relays = [{"rdns": "test.example.com",
                                           "ip": "127.0.0.1"}]
        result = self.plugin.check_for_sender_no_reverse(self.mock_msg)
        self.assertFalse(result)

        self.mock_msg.untrusted_relays = [{"rdns": "test.example.com",
                                           "ip": "83.45.21.22"}]
        result = self.plugin.check_for_sender_no_reverse(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_from_domain_in_received_headers(self):
        mock_get_addr_header = Mock(return_value=["test@example.com"])
        self.mock_msg.attach_mock(mock_get_addr_header, 'get_addr_header')
        result = self.plugin.check_for_from_domain_in_received_headers(
            self.mock_msg, 'example.org', 'true')
        self.assertFalse(result)

        self.mock_msg.trusted_relays = [{"rdns": "example.com",
                                         "by": "example.com"}]
        result = self.plugin.check_for_from_domain_in_received_headers(
            self.mock_msg, 'example.com', 'true')
        self.assertTrue(result)

    def test_helo_ip_mismatch(self):
        self.mock_msg.untrusted_relays = [{"helo": "83.45.21.22",
                                           "ip": "84.55.21.45"}]
        result = self.plugin.helo_ip_mismatch(self.mock_msg)
        self.assertTrue(result)

        self.mock_msg.untrusted_relays = [{"helo": "83.45.21.22",
                                           "ip": "83.45.21.45"}]

        result = self.plugin.helo_ip_mismatch(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_no_rdns_dotcom_helo(self):
        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22", "rdns": "",
                                           "helo": "subdomain.lycos.com"}]
        result = self.plugin.check_for_no_rdns_dotcom_helo(self.mock_msg)
        self.assertTrue(result)

        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22", "rdns": "some",
                                           "helo": "subdomain.lycos.com"}]
        result = self.plugin.check_for_no_rdns_dotcom_helo(self.mock_msg)
        self.assertFalse(result)

    def test_hostname_to_domain(self):
        hostname = "subdomain.example.com"
        result = self.plugin.hostname_to_domain(hostname)
        self.assertEqual(result, "example.com")
        hostname = "83.45.21.22"
        result = self.plugin.hostname_to_domain(hostname)
        self.assertEqual(result, hostname)

    def test_check_for_forged_received(self):
        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22",
                                           "rdns": "test.example.com",
                                           "by": "example.com",
                                           "helo": "22.33.44.55"}]
        self.plugin._check_for_forged_received(self.mock_msg)
        mismatch_ip_helo = self.plugin.get_global("mismatch_ip_helo")
        self.assertEqual(mismatch_ip_helo, 1)

    def test_check_for_forged_received_mismatch_from(self):
        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22",
                                           "rdns": "test.example.com",
                                           "by": "example.com",
                                           "helo": "22.33.44.55"},
                                          {"ip": "83.45.21.22",
                                           "rdns": "test.example.com",
                                           "by": "example.com",
                                           "helo": "22.33.44.55"}]
        self.plugin._check_for_forged_received(self.mock_msg)
        mismatch_ip_helo = self.plugin.get_global("mismatch_ip_helo")
        mismatch_from = self.plugin.get_global("mismatch_from")
        self.assertEqual(mismatch_ip_helo, 2)
        self.assertEqual(mismatch_from, 1)

    def test_check_for_forged_received_trail(self):
        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22",
                                           "rdns": "test.example.com",
                                           "by": "example.com",
                                           "helo": "22.33.44.55"}
                                          for _ in range(3)]
        result = self.plugin.check_for_forged_received_trail(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_received_ip_helo(self):
        self.mock_msg.untrusted_relays = [{"ip": "83.45.21.22",
                                           "rdns": "test.example.com",
                                           "by": "example.com",
                                           "helo": "22.33.44.55"}]
        result = self.plugin.check_for_forged_received_ip_helo(self.mock_msg)
        self.assertTrue(result)

