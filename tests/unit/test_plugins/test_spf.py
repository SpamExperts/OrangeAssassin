"""Tests for pad.plugins.spf."""

import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.spf


class TestParsed(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })
        self.mock_rcvd_headers = patch("pad.plugins.spf."
                                       "SpfPlugin.received_headers").start()
        self.mock_check_spf = patch("pad.plugins.spf."
                                       "SpfPlugin.check_spf_header").start()

        self.plug = pad.plugins.spf.SpfPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parsed_metadata_ignore_received(self):
        self.global_data["ignore_received_spf_header"] = True
        self.mock_msg.get_decoded_header.return_value = ["lala"]
        self.mock_msg.sender_address = "user@example.com"
        self.plug.parsed_metadata(self.mock_msg)
        calls = [
            call(self.mock_msg, ''),
            call(self.mock_msg, "user@example.com")
        ]
        self.mock_rcvd_headers.assert_has_calls(calls)

    def test_parsed_metadata_ignore_received_no_sender_address(self):
        self.global_data["ignore_received_spf_header"] = True
        self.mock_msg.get_decoded_header.return_value = ["lala"]
        self.mock_msg.sender_address = ""
        self.plug.parsed_metadata(self.mock_msg)
        self.mock_rcvd_headers.assert_called_with(self.mock_msg, '')

    def test_parsed_metadata_spf_header(self):
        self.global_data["ignore_received_spf_header"] = False
        self.plug.parsed_metadata(self.mock_msg)
        self.mock_check_spf.assert_called_with(self.mock_msg)

    def test_parse_list(self):
        list_name = "whitelist_form_spf"
        self.global_data["whitelist_form_spf"] = ["*spamexperts.com", "*@g?ogle.com"]
        result = self.plug.parse_list(list_name)
        self.assertEqual(result, ['.*@.*spamexperts\\.com', '.*\\@g.?ogle\\.com'])


class TestCheckSPF(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.mock_check_whitelist = patch("pad.plugins.spf.SpfPlugin."
                                          "check_spf_whitelist").start()
        #
        self.mock_check_spf_received_header = patch(
            "pad.plugins.spf.SpfPlugin.check_spf_received_header").start()
        self.mock_check_authres_header = patch(
            "pad.plugins.spf.SpfPlugin.check_authres_header").start()
        self.mock_received_header = patch(
            "pad.plugins.spf.SpfPlugin.received_headers").start()

        self.plug = pad.plugins.spf.SpfPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_for_spf_pass(self):
        self.plug.check_result["check_spf_pass"] = 1
        result = self.plug.check_for_spf_pass(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_pass(self):
        self.plug.check_result["check_spf_helo_pass"] = 1
        result = self.plug.check_for_spf_helo_pass(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_neutral(self):
        self.plug.check_result["check_spf_neutral"] = 1
        result = self.plug.check_for_spf_neutral(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_neutral(self):
        self.plug.check_result["check_spf_helo_neutral"] = 1
        result = self.plug.check_for_spf_helo_neutral(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_none(self):
        self.plug.check_result["check_spf_none"] = 1
        result = self.plug.check_for_spf_none(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_none(self):
        self.plug.check_result["check_spf_helo_none"] = 1
        result = self.plug.check_for_spf_helo_none(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_fail(self):
        self.plug.check_result["check_spf_fail"] = 1
        result = self.plug.check_for_spf_fail(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_fail(self):
        self.plug.check_result["check_spf_helo_fail"] = 1
        result = self.plug.check_for_spf_helo_fail(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_softfail(self):
        self.plug.check_result["check_spf_softfail"] = 1
        result = self.plug.check_for_spf_softfail(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_softfail(self):
        self.plug.check_result["check_spf_helo_softfail"] = 1
        result = self.plug.check_for_spf_helo_softfail(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_permerror(self):
        self.plug.check_result["check_spf_permerror"] = 1
        result = self.plug.check_for_spf_permerror(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_permerror(self):
        self.plug.check_result["check_spf_helo_permerror"] = 1
        result = self.plug.check_for_spf_helo_permerror(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_temperror(self):
        self.plug.check_result["check_spf_temperror"] = 1
        result = self.plug.check_for_spf_temperror(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_helo_temperror(self):
        self.plug.check_result["check_spf_helo_temperror"] = 1
        result = self.plug.check_for_spf_helo_temperror(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_spf_whitelist(self):
        self.mock_check_whitelist.return_value = True
        result = self.plug.check_for_spf_whitelist_from(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_def_spf_whitelist(self):
        self.mock_check_whitelist.return_value = True
        result = self.plug.check_for_def_spf_whitelist_from(self.mock_msg)
        self.assertTrue(result)

    def test_check_spf_header_received_sender(self):
        self.mock_msg["authentication-results"] = []
        self.mock_msg["received"] = ["heade1"]
        self.global_data["use_newest_received_spf_header"] = 0
        self.plug.check_spf_header(self.mock_msg)
        self.mock_check_spf_received_header.assert_called_with(
            self.mock_msg.get_decoded_header())
        self.mock_received_header.assert_called_with(self.mock_msg, '')

    def test_check_spf_header_received_sender_helo_true(self):
        self.plug.spf_check_helo = True
        self.mock_msg["authentication-results"] = []
        self.mock_msg["received"] = ["heade1"]
        self.global_data["use_newest_received_spf_header"] = 0
        self.plug.check_spf_header(self.mock_msg)
        self.mock_check_spf_received_header.assert_called_with(
            self.mock_msg.get_decoded_header())
        self.mock_received_header.assert_called_with(self.mock_msg,
                                                     self.mock_msg.sender_address)

    def test_check_spf_header_no_spfheaders(self):
        self.mock_msg["authentication-results"] = []
        self.mock_msg["received"] = ["header"]
        self.mock_msg.get_decoded_header.return_value = []
        self.plug.check_spf_header(self.mock_msg)
        self.mock_received_header.assert_called_with(self.mock_msg, '')


    def test_query_spf(self):
        result = self.plug._query_spf(timeout=3, ip='2a00:1450:4017:804::200e',
                                      mx='example.com',
                                      sender_address='test@google.com')
        self.assertEqual(result, "pass")


class TestCheckWhitelist(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.mock_parse_list = patch("pad.plugins.spf.SpfPlugin."
                                          "parse_list").start()
        self.mock_check_for_spf_pass = patch("pad.plugins.spf.SpfPlugin."
                                     "check_for_spf_pass").start()

        self.plug = pad.plugins.spf.SpfPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_spf_whitelist_no_spf_pass(self):
        self.global_data["whitelist_from_spf"] = ["*spamexperts.com"]
        self.mock_parse_list.return_value = ['.*@.*spamexperts\\.com']
        self.mock_msg.sender_address = "user@spamexperts.com"
        self.mock_check_for_spf_pass.return_value = False
        result = self.plug.check_spf_whitelist(self.mock_msg,
                                             "whitelist_from_spf")
        self.assertFalse(result)

    def test_check_spf_whitelist_False(self):
        self.global_data["whitelist_from_spf"] = ["*spamexperts.com"]
        self.mock_parse_list.return_value = ['.*@.*spamexperts\\.com']
        self.mock_msg.sender_address = "user@example.com"
        self.mock_check_for_spf_pass.return_value = True
        result = self.plug.check_spf_whitelist(self.mock_msg,
                                               "whitelist_from_spf")
        self.assertFalse(result)

    def test_check_spf_whitelist(self):
        self.global_data["whitelist_from_spf"] = ["*spamexperts.com"]
        self.mock_parse_list.return_value = ['.*@.*spamexperts\\.com']
        self.mock_msg.sender_address = "user@spamexperts.com"
        self.mock_check_for_spf_pass.return_value = True
        result = self.plug.check_spf_whitelist(self.mock_msg,
                                               "whitelist_from_spf")
        self.assertTrue(result)


class TestReceivedHeaders(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.mock_query_spf = patch("pad.plugins.spf.SpfPlugin."
                                     "_query_spf").start()

        self.plug = pad.plugins.spf.SpfPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_received_headers_check_helo_True(self):
        self.spf_timeout = 4
        self.plug.spf_check_helo = True
        self.mock_msg.external_relays = [{'auth': '', 'ident': '',
                                          'envfrom': 'envfrom@google.com',
                                          'helo': 'spamexperts.com',
                                          'ip': '5.79.73.204', 'msa': 0,
                                          'intl': 0, 'id': '',
                                          'by': 'example.com',
                                          'rdns': 'spamexperts.com'}]
        self.mock_query_spf.return_value = "error"
        self.plug.received_headers(self.mock_msg, "user@example.com")

    def test_received_headers_match(self):
        self.spf_timeout = 4
        self.mock_msg.external_relays = [{'auth': '', 'ident': '',
                                          'envfrom': 'envfrom@google.com',
                                          'helo': 'spamexperts.com',
                                          'ip': '5.79.73.204', 'msa': 0,
                                          'intl': 0, 'id': '',
                                          'by': 'example.com',
                                          'rdns': 'spamexperts.com'}]
        self.mock_query_spf.return_value = "error"
        self.plug.received_headers(self.mock_msg, "user@example.com")

    def test_received_headers_not_match(self):
        self.spf_timeout = 4
        self.mock_msg.external_relays = [{'auth': '', 'ident': '',
                                          'envfrom': 'envfrom@google.com',
                                          'helo': 'spamexperts.com',
                                          'ip': '5.79.73.204', 'msa': 0,
                                          'intl': 0, 'id': '',
                                          'by': 'example.com',
                                          'rdns': 'spamexperts'}]
        self.mock_query_spf.return_value = "error"
        self.plug.received_headers(self.mock_msg, "user@example.com")

    def test_received_headers_return(self):
        self.spf_timeout = 4
        self.mock_msg.external_relays = []
        self.plug.received_headers(self.mock_msg, "user@example.com")

    def test_check_authres_header_mailform(self):
        authres = """example.com;
                    spf=pass (example.com: domain of test@example.com designates
                    192.0.2.1 as permitted sender) smtp.mailfrom=test@example.com;
                    dkim=pass header.i=@example.com;
                    dmarc=pass (p=NONE dis=NONE) header.from=example.com"""
        self.plug.check_authres_header(authres)

    def test_check_authres_header_helo(self):
        authres = """example.com;
                    spf=pass (example.com: domain of test@example.com designates
                    192.0.2.1 as permitted sender) smtp.helo=test@example.com;
                    dkim=pass header.i=@example.com;
                    dmarc=pass (p=NONE dis=NONE) header.from=example.com"""
        self.plug.check_authres_header(authres)


class TestCheckHeaders(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.mock_query_spf = patch("pad.plugins.spf.SpfPlugin."
                                    "_query_spf").start()

        self.plug = pad.plugins.spf.SpfPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_spf_received_header_no_valid_header(self):
        self.plug.check_spf_received_header(received_spf_headers=["header"])

    def test_check_spf_received_header(self):
        self.plug.spf_check = True
        received_spf_headers = ['softfail (example.com: domain of test@example.com)']
        self.plug.check_spf_received_header(received_spf_headers)

    def test_check_spf_received_header_identity_check_True(self):
        self.plug.spf_check_helo = True
        self.plug.spf_check = True
        received_spf_headers = [
            'softfail (example.com: domain of test@example.com) identity=helo']
        self.plug.check_spf_received_header(received_spf_headers)

    def test_check_spf_received_header_identity_check_False(self):
        self.plug.spf_check_helo = False
        received_spf_headers = [
            'softfail (example.com: domain of test@example.com) identity=helo']
        self.plug.check_spf_received_header(received_spf_headers)

    def test_check_spf_received_header_identity_mfrom_spf_check_true(self):
        self.plug.spf_check = True
        received_spf_headers = [
            'softfail (example.com: domain of test@example.com) identity=mfrom']
        self.plug.check_spf_received_header(received_spf_headers)

    def test_check_spf_received_header_identity_mfrom_spf_check_false(self):
        self.plug.spf_check = False
        received_spf_headers = [
            'softfail (example.com: domain of test@example.com) identity=mfrom']
        self.plug.check_spf_received_header(received_spf_headers)
