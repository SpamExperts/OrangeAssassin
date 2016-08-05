import unittest
from collections import defaultdict


try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.wlbl_eval


class TestWhitelist(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(k,
                                                                              v),
        })
        self.mock_rcvd = patch("pad.plugins.wlbl_eval."
                               "WLBLEvalPlugin.check_whitelist_rcvd").start()

        self.mock_addr_in_list = patch("pad.plugins.wlbl_eval."
                                       "WLBLEvalPlugin.check_address_in_list").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_def_whitelist_one_address(self):
        self.mock_rcvd.return_value = 1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        result = self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                                      list_name)
        self.assertTrue(result)
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_def_whitelist_two_address_stop_first(self):
        self.mock_rcvd.return_value = 1
        list_name = "whitelist_from"
        addresses = ["test1@example.com", "test2@example.com"]
        result = self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                                      list_name)
        self.assertTrue(result)
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_def_whitelist_two_address(self):
        self.mock_rcvd.return_value = 0
        list_name = "whitelist_from"
        addresses = ["test1@example.com", "test2@example.com"]
        result = self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                                      list_name)
        self.assertFalse(result)
        calls = [
            call(self.mock_msg, list_name, addresses[0]),
            call(self.mock_msg, list_name, addresses[1]),
        ]
        self.mock_rcvd.assert_has_calls(calls)

    def test_check_def_whitelist_set_cached_true(self):
        self.mock_rcvd.return_value = 1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertEqual(self.msg_data["from_in_default_whitelist"], 1)

    def test_check_def_whitelist_set_cached_undefined(self):
        self.mock_rcvd.return_value = 0
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertNotIn("from_in_default_whitelist", self.msg_data)

    def test_check_def_whitelist_set_cached_false(self):
        self.mock_rcvd.return_value = -1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertEqual(self.msg_data["from_in_default_whitelist"], -1)

    # check_in_list method
    def test_check_in_list_match_regex(self):
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex.com", "*@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertTrue(result)
        self.mock_addr_in_list.assert_called_with(addresses[0],
                                                  ["*@ex.com", "*@example.com"])

    def test_check_in_list_founded(self):
        self.mock_addr_in_list.return_value = True
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex.com", "*@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertTrue(result)
        self.mock_addr_in_list.assert_called_with(addresses[0],
                                                  ["*@ex.com", "*@example.com"])

    def test_check_in_list_not_founded(self):
        self.mock_rcvd.return_value = -1
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex1.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertFalse(result)
        self.mock_addr_in_list.assert_called_with(addresses[0],
                                                  ["*@ex1.com"])

    def test_check_in_list_founded_rcvd(self):
        self.mock_rcvd.return_value = 1
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex1.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertTrue(result)
        self.mock_addr_in_list.assert_called_with(addresses[0],
                                                  ["*@ex1.com"])
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_in_list_set_cached_true(self):
        self.mock_addr_in_list.return_value = True
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 1)

    def test_check_in_list_regex_set_cached_true(self):
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 1)
        self.mock_rcvd.assert_not_called()

    def test_check_in_list_rcvd_set_cached_true(self):
        self.mock_rcvd.return_value = 1
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 1)

    def test_check_in_list_set_cached_false(self):
        self.mock_rcvd.return_value = -1
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], -1)

    def test_check_in_list_set_cached_undefined(self):
        self.mock_rcvd.return_value = 0
        self.mock_addr_in_list.return_value = False
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = ["*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertNotIn("from_in_whitelist", self.msg_data)


class TestUrilist(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.parsed_delist = {
            "ALL": ["example.com", "ceva.example.net", "example1.com",
                    "!ceva.example.net"],
            "WHITE": ["example.com", "ceva.example.net", "example1.com",
                      "ceva1.example.net"],
            "BLACK": ["example.com", "ceva.example.net"]
        }

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(k,
                                                                              v),
        })

        self.mock_add_in_list = patch("pad.plugins.wlbl_eval."
                               "WLBLEvalPlugin.add_in_list").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parse_delist_uri_true(self):
        self.global_data["delist_uri_host"] = [
            "example.com ceva.example.net",
            "(WHITE) example.com ceva.example.net",
            "(WHITE) example1.com ceva1.example.net",
            "example1.com !ceva.example.net",
            "(BLACK) example.com ceva.example.net",
        ]

        result = self.plug.parse_delist_uri()
        self.assertDictEqual(result, self.parsed_delist)

    def test_parse_delist_uri_flase(self):
        self.global_data["delist_uri_host"] = [
            "example.com ceva.example.net",
            "(WHITE) example.com ceva.example.net",
            "example1.com !ceva.example.net"
        ]

        result = self.plug.parse_delist_uri()
        self.assertNotEqual(result, self.parsed_delist)

#...........................
    def test_add_in_dict_two_calls(self):

        self.global_data['parsed_delist_uri_host'] = defaultdict(list)
        self.global_data['parsed_delist_uri_host']["LIST"] = ["bvc"]
        parsed_list = {
        "WHITE": {
            "in_list": ["example.com"],
            "not_in_list": ["ceva.example.com"]
            },
        "BLACK": {
            "in_list": ["example.com"],
            "not_in_list": ["ceva.example.com"]
            },
        "MYLIST": {
            "in_list": ["example.com"],
            "not_in_list": ["ceva.example.com"]
            }
        }

        list_name = ["!cv.ex.com", "cv.ex.com"]
        result = self.plug.add_in_dict(list_name, "MYLIST", parsed_list)
        calls = [
            call("MYLIST",list_name[0], parsed_list),
            call("MYLIST", list_name[1], parsed_list),
        ]
        self.mock_add_in_list.assert_has_calls(calls)

    def test_add_in_dict_correct_call(self):
        self.global_data['parsed_delist_uri_host'] = defaultdict(list)
        self.global_data['parsed_delist_uri_host']["LIST"] = ["delist.com"]
        parsed_list = {
            "WHITE": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            },
            "BLACK": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            },
            "MYLIST": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            }
        }

        list_name = ["!cv.ex.com"]
        result = self.plug.add_in_dict(list_name, "MYLIST", parsed_list)
        self.mock_add_in_list.assert_called_with("MYLIST",
                                                 list_name[0], parsed_list)

#................................

    def test_parse_wlbl_uri_true(self):
        list_name = [
            "example.com !ceva.example.net",
            "example1.com !ceva1.example.net"
        ]
        parsed_set = {"example.com", "!ceva.example.net",
                       "example1.com", "!ceva1.example.net"
                      }
        result = self.plug.parse_wlbl_uri(list_name)
        self.assertEqual(result, parsed_set)

    def test_parse_wlbl_uri_duplicate_values(self):
        list_name = [
            "example.com !ceva.example.net",
            "example1.com !ceva.example.net"
        ]
        parsed_list = {"example.com", "!ceva.example.net",
                       "example1.com"
                       }
        result = self.plug.parse_wlbl_uri(list_name)
        self.assertEqual(result, parsed_list)

#................................

class TestGetAddresses(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.parsed_delist = {
            "ALL": ["example.com", "ceva.example.net", "example1.com",
                    "!ceva.example.net"],
            "WHITE": ["example.com", "ceva.example.net", "example1.com",
                      "ceva1.example.net"],
            "BLACK": ["example.com", "ceva.example.net"]
        }

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(
                k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def get_resent_header(self, header):
        if header == "Resent-To":
            return ["addr1", "addr2"]
        elif header == "Resent-Cc":
            return ["addr1_Cc", "addr2_Cc"]
        elif header ==  "To":
            return ["address1", "address2", "address3"]
        return list()

    def get_header(self, header):
        if header == "To":
            return ["address1", "address2", "address3"]
        return list()

    def test_get_to_addresses_resent_header(self):
        self.mock_msg.get_addr_header.side_effect = self.get_resent_header
        result = self.plug.get_to_addresses(self.mock_msg)
        self.assertEqual(list(result), ["addr1", "addr2", "addr1_Cc",
                                        "addr2_Cc"])

    def test_get_to_addresses_to_headers(self):
        self.mock_msg.get_addr_header.side_effect = self.get_header
        self.mock_to_headers = patch("pad.plugins.wlbl_eval.TO_HEADERS",
                                     ["To"]).start()
        result = self.plug.get_to_addresses(self.mock_msg)
        self.assertEqual(list(result),
                         ["address1", "address2", "address3"])


class TestToFromWlBl(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.parsed_delist = {
            "ALL": ["example.com", "ceva.example.net", "example1.com",
                    "!ceva.example.net"],
            "WHITE": ["example.com", "ceva.example.net", "example1.com",
                      "ceva1.example.net"],
            "BLACK": ["example.com", "ceva.example.net"]
        }

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(
                k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)
        self.mock__check_whitelist = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin._check_whitelist").start()
        self.mock_check_address_in_list = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin.check_address_in_list").start()
        self.mock_get_to_addresses = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin.get_to_addresses").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_from_in_whitelist_call(self):
        result = self.plug.check_from_in_whitelist(self.mock_msg)
        self.mock__check_whitelist.assert_called_with(self.mock_msg,
                                                      "from_in_whitelist")

    def test_check_to_in_whitelist_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_to_in_whitelist(self.mock_msg)
        self.mock_check_address_in_list.assert_called_with(["addr1", "addr2"],
                                                      "parsed_whitelist_to")

    def test_check_to_in_blacklist_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_to_in_blacklist(self.mock_msg)
        self.mock_check_address_in_list.assert_called_with(["addr1", "addr2"],
                                                    "parsed_blacklist_to")

    def test_check_to_in_list_call(self):
        list_name = "whitelist_to"
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_to_in_list(self.mock_msg, list_name)
        self.mock_check_address_in_list.assert_called_with(["addr1", "addr2"],
                                                           list_name)

    def test_check_to_in_more_spam_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_to_in_more_spam(self.mock_msg)
        self.mock_check_address_in_list.assert_called_with(["addr1", "addr2"],
                                                           "parsed_more_spam_to")

class TestMatchRcvd(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.parsed_delist = {
            "ALL": ["example.com", "ceva.example.net", "example1.com",
                    "!ceva.example.net"],
            "WHITE": ["example.com", "ceva.example.net", "example1.com",
                      "ceva1.example.net"],
            "BLACK": ["example.com", "ceva.example.net"]
        }

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(
                k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)
        self.mock_base_domain = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin.base_domain").start()
    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_mailfrom_matches_rcvd_no_addr(self):
        self.mock_msg.sender_address = None
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertFalse(result)

    def test_check_mailfrom_matches_rcvd_no_relays(self):
        self.mock_base_domain.return_value = ".co.uk"
        self.mock_msg.untrusted_relays = []
        self.mock_msg.trusted_relays = []
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertFalse(result)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    # test_suite.addTest(unittest.makeSuite(TestWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
