import unittest
from collections import defaultdict

from dns import reversename

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.wlbl_eval


class TestGetHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })

        self.mock_addr_header = patch(
            "pad.message.Message.get_all_addr_header").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

        FROM_HEADERS = ('From', "Envelope-Sender", 'Resent-From',
                        'X-Envelope-From','EnvelopeFrom')

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def get_resent_from_header(self, header):
        if header == "Resent-From":
            return ["addr1", "addr2"]
        elif header == "From":
            return ["address1", "address2", "address3"]
        return list()

    def get_from_header(self, header):
        if header == "From":
            return ["address1", "address2", "address3"]

        return list()


    @unittest.skip("implementation moved in message.py should be tested there")
    def test_get_from_addresses_resent_header(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_resent_from_header

        result = get_from_addresses(self.mock_msg)
        self.assertEqual(list(result), ["addr1", "addr2"])

    @unittest.skip("implementation moved in message.py should be tested there")
    def test_get_from_addresses_from_headers(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_from_header

        self.mock_from_headers = patch("pad.plugins.wlbl_eval.FROM_HEADERS",
                                     ["From"]).start()
        result = get_from_addresses(self.mock_msg)
        self.assertEqual(list(result),
                         ["address1", "address2", "address3"])


class TestBaseDomain(unittest.TestCase):
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
        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)
        self.mock_check_in_TL_TLDS = patch(
            "pad.plugins.wlbl_eval.WLBLEvalPlugin.check_in_TL_TLDS").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_base_domain_no_address(self):
        address = ""
        result = self.plug.base_domain(address)
        self.assertEqual(result, "")

    def test_base_domain_no_TLD(self):
        address = "1.2.3.4"
        result = self.plug.base_domain(address)
        self.assertEqual(result, "4.3.2.1")

    def test_base_domain_first(self):
        """Test if len(parts) < 3"""
        address = "surbl.org"
        result = self.plug.base_domain(address)
        self.assertEqual(result, "surbl.org")

    def test_base_domain_third(self):
        """Test if ".".join(parts[-3:]) in TL_TLDS """
        address = "40.30.20.10.multi.surbl.org"
        self.mock_check_in_TL_TLDS.side_effect = [True, False]
        result = self.plug.base_domain(address)
        self.assertEqual(result, "10.multi.surbl.org")

    def test_base_domain_fourth(self):
        """Test if ".".join(parts[-2:]) in TL_TLDS"""
        address = "40.30.20.10.multi.co.uk"
        self.mock_check_in_TL_TLDS.side_effect = [False, True]
        result = self.plug.base_domain(address)
        self.assertEqual(result, "multi.co.uk")

    def test_base_domain_return(self):
        address = "40.30.20.10.multi.surbl"
        self.mock_check_in_TL_TLDS.side_effect = [False, False]
        result = self.plug.base_domain(address)
        self.assertEqual(result, "multi.surbl")


class TestWhitelist(unittest.TestCase):
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
                                  setdefault(k,v),
        })
        self.mock_rcvd = patch("pad.plugins.wlbl_eval."
                               "WLBLEvalPlugin.check_whitelist_rcvd").start()

        self.mock_addr_in_list = patch("pad.plugins.wlbl_eval.WLBLEvalPlugin."
                  "check_address_in_list").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)


    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_def_whitelist_one_address(self):
        self.mock_rcvd.return_value = 1
        list_name = "def_whitelist_from_rcvd"
        addresses = ["test@example.com"]
        result = self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                                      list_name)
        self.assertTrue(result)
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_def_whitelist_two_address_stop_first(self):
        self.mock_rcvd.return_value = 1
        list_name = "def_whitelist_from_rcvd"
        addresses = ["test1@example.com", "test2@example.com"]
        result = self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                                      list_name)
        self.assertTrue(result)
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_def_whitelist_two_address(self):
        self.mock_rcvd.return_value = 0
        list_name = "def_whitelist_from_rcvd"
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
        list_name = "def_whitelist_from_rcvd"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertEqual(self.msg_data["from_in_default_whitelist"], 1)

    def test_check_def_whitelist_set_cached_undefined(self):
        self.mock_rcvd.return_value = 0
        list_name = "def_whitelist_from_rcvd"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertEqual(self.msg_data["from_in_default_whitelist"], 0)

    def test_check_def_whitelist_set_cached_false(self):
        self.mock_rcvd.return_value = -1
        list_name = "def_whitelist_from_rcvd"
        addresses = ["test@example.com"]
        self.plug.check_in_default_whitelist(self.mock_msg, addresses,
                                             list_name)
        self.assertEqual(self.msg_data["from_in_default_whitelist"], -1)

    def test_check_in_list_match_regex(self):
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex.com", ".*@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertTrue(result)

    def test_check_in_list_not_founded(self):
        self.mock_rcvd.return_value = -1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex1.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertFalse(result)

    def test_check_in_list_founded_rcvd(self):
        self.mock_rcvd.return_value = 1
        list_name = "parsed_whitelist_from_rcvd"
        addresses = ["test@example.com"]
        self.global_data["parsed_whitelist_from_rcvd"] = [".*@ex1.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertTrue(result)
        self.mock_rcvd.assert_called_with(self.mock_msg, list_name,
                                          addresses[0])

    def test_check_in_list_set_cached_true(self):
        self.mock_addr_in_list.return_value = True
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex.com", ".*@example.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 1)

    def test_check_in_list_rcvd_set_cached_true(self):
        self.mock_rcvd.return_value = 1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 1)

    def test_check_in_list_set_cached_false(self):
        self.mock_rcvd.return_value = -1
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], -1)

    def test_check_in_list_set_cached_undefined(self):
        self.mock_rcvd.return_value = 0
        self.msg_data["from_in_whitelist"] = 0
        list_name = "whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["whitelist_from"] = [".*@ex.com"]
        result = self.plug.check_in_list(self.mock_msg, addresses,
                                         list_name)
        self.assertEqual(self.msg_data["from_in_whitelist"], 0)

    def test_check_in_tld(self):
        self.global_data["util_rb_tld"] = ["com"]
        self.global_data["util_rb_2tld"] = []
        self.global_data["util_rb_3tld"] = []
        result = self.plug.check_in_TL_TLDS("com")
        self.assertTrue(result)

    def test_check_in_2tld(self):
        self.global_data["util_rb_tld"] = ["com"]
        self.global_data["util_rb_2tld"] = ["co.uk"]
        self.global_data["util_rb_3tld"] = []
        result = self.plug.check_in_TL_TLDS("co.uk")
        self.assertTrue(result)

    def test_check_in_3tld(self):
        self.global_data["util_rb_tld"] = ["com"]
        self.global_data["util_rb_2tld"] = ["co.uk"]
        self.global_data["util_rb_3tld"] = ["sa.edu.au"]
        result = self.plug.check_in_TL_TLDS("sa.edu.au")
        self.assertTrue(result)

    def test_check_in_tld_not_found(self):
        self.global_data["util_rb_tld"] = ["com"]
        self.global_data["util_rb_2tld"] = ["co.uk"]
        self.global_data["util_rb_3tld"] = ["sa.edu.au"]
        result = self.plug.check_in_TL_TLDS("cm")
        self.assertFalse(result)


class TestUrilist(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        self.parsed_delist = {
            "ALL": ["example.com", "ceva.example.net", "example1.com",
                    "ceva.example.net"],
            "WHITE": ["example.com", "ceva.example.net", "example1.com",
                      "ceva1.example.net"],
            "BLACK": ["example.com", "ceva.example.net"]
        }

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k,v),
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

    def test_parse_delist_uri_false(self):
        self.global_data["delist_uri_host"] = [
            "example.com ceva.example.net",
            "(WHITE) example.com ceva.example.net",
            "example1.com !ceva.example.net"
        ]

        result = self.plug.parse_delist_uri()
        self.assertNotEqual(result, self.parsed_delist)

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
            call("MYLIST", list_name[0], parsed_list),
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

    def test_add_in_dict_delist(self):
        self.global_data['parsed_delist_uri_host'] = defaultdict(list)
        self.global_data['parsed_delist_uri_host']["MYLIST"] = ["example.com"]
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

        list_name = ["example.com"]
        self.plug.add_in_dict(list_name, "MYLIST", parsed_list)
        self.mock_add_in_list.assert_not_called()

    def test_my_list(self):
        result = self.plug.my_list()
        self.assertEqual(result, {"in_list": [], "not_in_list": []})

    def test_parse_wlbl_uri_true(self):
        self.global_data["whitelist_uri_host"] = [
            "example.com !ceva.example.net",
            "example1.com !ceva1.example.net"
        ]
        parsed_set = {"example.com", "!ceva.example.net",
                      "example1.com", "!ceva1.example.net"
                      }
        result = self.plug.parse_wlbl_uri("whitelist_uri_host")
        self.assertEqual(result, parsed_set)

    def test_parse_wlbl_uri_duplicate_values(self):
        self.global_data["whitelist_uri_host"] = [
            "example.com !ceva.example.net",
            "example1.com !ceva.example.net"
        ]
        parsed_list = {"example.com", "!ceva.example.net",
                       "example1.com"
                       }
        result = self.plug.parse_wlbl_uri("whitelist_uri_host")
        self.assertEqual(result, parsed_list)


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
                                                  v: self.global_data.
                                   setdefault(k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
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
        elif header == "To":
            return ["address1", "address2", "address3"]
        return list()

    def get_header(self, header):
        if header == "To":
            return ["address1", "address2", "address3"]
        return list()

    @unittest.skip("implementation moved in message.py should be tested there")
    def test_get_to_addresses_resent_header(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_resent_header
        result = get_to_addresses(self.mock_msg)
        self.assertEqual(list(result), ["addr1", "addr2", "addr1_Cc",
                                        "addr2_Cc"])

    @unittest.skip("implementation moved in message.py should be tested there")
    def test_get_to_addresses_to_headers(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_header
        self.mock_to_headers = patch("pad.plugins.wlbl_eval.TO_HEADERS",
                                     ["To"]).start()
        result = get_to_addresses(self.mock_msg)
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
                                                  v: self.global_data.
                                   setdefault(k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)
        self.mock__check_whitelist = \
            patch("pad.plugins.wlbl_eval.WLBLEvalPlugin."
                  "_check_whitelist").start()
        self.mock_check_address_in_list = \
            patch("pad.plugins.wlbl_eval.WLBLEvalPlugin."
                  "check_address_in_list").start()
        self.mock_get_to_addresses = self.mock_msg.get_to_addresses

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_from_in_whitelist_call(self):
        self.plug.check_from_in_whitelist(self.mock_msg)
        self.mock__check_whitelist.assert_called_with(self.mock_msg,
                                                      "from_in_whitelist")

    def test_check_to_in_whitelist_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        self.plug.check_to_in_whitelist(self.mock_msg)
        self.mock_check_address_in_list.\
            assert_called_with(["addr1", "addr2"], "parsed_whitelist_to")

    def test_check_to_in_blacklist_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        self.plug.check_to_in_blacklist(self.mock_msg)
        self.mock_check_address_in_list.\
            assert_called_with(["addr1", "addr2"], "parsed_blacklist_to")

    def test_check_to_in_list_call(self):
        list_name = "whitelist_to"
        parsed_list_name = "parsed_%s" % list_name
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        self.plug.check_to_in_list(self.mock_msg, list_name)
        self.mock_check_address_in_list.\
            assert_called_with(["addr1", "addr2"], parsed_list_name)

    def test_check_to_in_more_spam_call(self):
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        self.plug.check_to_in_more_spam(self.mock_msg)
        self.mock_check_address_in_list.\
            assert_called_with(["addr1", "addr2"], "parsed_more_spam_to")

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
                                                  v: self.global_data.
                                   setdefault(k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })
        self.mock_base_domain = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin.base_domain").start()
        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

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

    def test_check_mailfrom_matches_rcvd_no_untrusted_relays(self):
        self.mock_base_domain.return_value = ".co.uk"
        self.mock_msg.untrusted_relays = []
        self.mock_msg.trusted_relays = [{"ip": "127.0.0.1", "rdns": ".co.uk"}]
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertTrue(result)

    def test_check_mailfrom_matches_rcvd_no_trusted_relays(self):
        self.mock_base_domain.return_value = ".co.uk"
        self.mock_msg.untrusted_relays = [{"ip": "127.0.0.1", "rdns": ".co.uk"}]
        self.mock_msg.trusted_relays = []
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertTrue(result)

    def test_check_mailfrom_matches_rcvd_domain(self):
        self.mock_base_domain.return_value = "in-addr.arpa"
        self.mock_msg.untrusted_relays = [{"ip": "127.0.0.1", "rdns": "in-addr.arpa"}]
        self.mock_msg.trusted_relays = []
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertTrue(result)

    def test_check_mailfrom_matches_rcvd_except(self):
        self.mock_base_domain.return_value = "in-addr.arpa"
        self.mock_msg.untrusted_relays = [{"ip": "127.0.0.1", "rdns": "co.uk"}]
        self.mock_msg.trusted_relays = []
        result = self.plug.check_mailfrom_matches_rcvd(self.mock_msg)
        self.assertFalse(result)

    def test_check_rcvd_match_rdns(self):
        relays = [{"ip": "127.0.0.1", "rdns": "1.0.0.127.in-addr.arpa."}]
        result = self.plug.check_rcvd("[in-addr.arpa.]", relays)
        self.assertEqual(result, 1)

    def test_check_rcvd_match_ip(self):
        relays = [{"ip": "127.0.0.1", "rdns": "1.0.0.127.in-addr.arpa."}]
        result = self.plug.check_rcvd("[127.0.0.1]", relays)
        self.assertEqual(result, 1)

    def test_check_rcvd_unmatch(self):
        relays = [{"ip": "127.0.0.1", "rdns": "1.0.0.127.in-addr.arpa."}]
        result = self.plug.check_rcvd("[addr.arpa]", relays)
        self.assertEqual(result, -1)


class TestUriHost(unittest.TestCase):
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
                                                  v: self.global_data.
                                   setdefault(k, v)
        })

        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_uri_host_listed(self):
        self.mock_msg.uri_list = ["ceva.example.com"]
        self.global_data["parsed_enlist_uri_host"] = {
            "WHITE": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            },
            "MYLIST": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            }
        }
        result = self.plug.check_uri_host_listed(self.mock_msg, "WHITE")
        self.assertFalse(result)

    def test_check_uri_host_listed_match(self):
        self.mock_msg.uri_list = ["ceva.example.com"]
        self.global_data["parsed_enlist_uri_host"] = {
            "WHITE": {
                "in_list": ["example.com"],
                "not_in_list": ["ce.example.com"]
            },
            "MYLIST": {
                "in_list": ["example.com"],
                "not_in_list": ["ceva.example.com"]
            }
        }
        result = self.plug.check_uri_host_listed(self.mock_msg, "WHITE")
        self.assertTrue(result)


class TestCheckForged(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.global_data.setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.msg_data.setdefault(k, v),
        })

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_found_forged_zero(self):
        found_forged = 0
        address = "example@example.com"
        result = self.plug.check_found_forged(address, found_forged)
        self.assertEqual(result, 0)

    def test_check_found_forged_one(self):
        found_forged = 1
        self.global_data['parsed_whitelist_allow_relays'] = {
            ".*@example.com": "user@example.com"}
        address = "example1@example.com"
        result = self.plug.check_found_forged(address, found_forged)
        self.assertEqual(result, 0)

    def test_check_found_forged_no_if(self):
        found_forged = 1
        self.global_data['parsed_whitelist_allow_relays'] = {
            ".*@example.com": ["user@example.com"]}
        address = "example1@exle.com"
        result = self.plug.check_found_forged(address, found_forged)
        self.assertEqual(result, 1)

    def test_check_forged_in_whitelist(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", -1)
        self.plug.set_local(self.mock_msg, "from_in_default_whitelist", 0)

        result = self.plug.check_forged_in_whitelist(self.mock_msg)
        self.assertTrue(result)

    def test_check_forged_in_whitelist_false(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", 1)
        self.plug.set_local(self.mock_msg, "from_in_default_whitelist", 0)

        result = self.plug.check_forged_in_whitelist(self.mock_msg)
        self.assertFalse(result)

    def test_check_forged_in_default_whitelist(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", 0)
        self.plug.set_local(self.mock_msg, "from_in_default_whitelist",-1)

        result = self.plug.check_forged_in_default_whitelist(self.mock_msg)
        self.assertTrue(result)

    def test_check_forged_in_default_whitelist_false(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", -1)
        self.plug.set_local(self.mock_msg, "from_in_default_whitelist", 0)

        result = self.plug.check_forged_in_default_whitelist(self.mock_msg)
        self.assertFalse(result)


class TestAddInList(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.global_data.setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.msg_data.setdefault(k, v)})

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_add_in_list_not(self):
        key = 'BLACK'
        item = "!example2.com"
        parsed_list = {
            "BLACK": {
                "in_list": ["example.com"],
                "not_in_list": ["ex.example.com"]
            }
        }
        result = self.plug.add_in_list(key, item, parsed_list)
        result_expected = {
            "BLACK": {
                "in_list": ["example.com"],
                "not_in_list": ["ex.example.com", "example2.com"]
            }
        }
        self.assertEqual(parsed_list, result_expected)

    def test_add_in_list_in(self):
        key = 'BLACK'
        item = "example2.com"
        parsed_list = {
            "BLACK": {
                "in_list": ["example.com"],
                "not_in_list": ["ex.example.com"]
            }
        }
        self.plug.add_in_list(key, item, parsed_list)
        result_expected = {
            "BLACK": {
                "in_list": ["example.com", "example2.com"],
                "not_in_list": ["ex.example.com"]
            }
        }
        self.assertEqual(parsed_list, result_expected)


class TestCheckToFrom(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect":
                lambda p, k,v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect":
                lambda p, k,v: self.msg_data.setdefault(k, v),
        })
        self.mock_rcvd = patch("pad.plugins.wlbl_eval."
                               "WLBLEvalPlugin.check_whitelist_rcvd").start()
        self.mock_check_address = patch("pad.plugins.wlbl_eval."
                               "WLBLEvalPlugin.check_address_in_list").start()
        self.mock_check_whitelist = patch("pad.plugins.wlbl_eval."
                                "WLBLEvalPlugin._check_whitelist").start()
        self.mock_get_from_addresses = self.mock_msg.get_from_addresses
        self.mock_get_to_addresses = self.mock_msg.get_to_addresses
        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_from_in_blacklist(self):
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        self.plug.check_from_in_blacklist(self.mock_msg)
        self.mock_check_address.assert_called_with(
            ["addr1", "addr2"], "parsed_blacklist_from")

    def test_check_from_in_list(self):
        list_name = "*@example.com    smt@example.com"
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        self.mock_check_address.return_value = True
        result = self.plug.check_from_in_list(self.mock_msg, list_name)
        self.assertTrue(result)

    def test_check_from_in_list_null(self):
        list_name = ""
        self.mock_check_address.return_value = True
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_from_in_list(self.mock_msg, list_name)
        self.assertFalse(result)

    def test_check_to_in_all_spam(self):
        self.mock_check_address.return_value = True
        self.mock_get_to_addresses.return_value = ["addr1", "addr2"]
        result = self.plug.check_to_in_all_spam(self.mock_msg)
        self.assertTrue(result)
        self.mock_check_address.assert_called_with(["addr1", "addr2"],
                                                   "parsed_all_spam_to")

    def test_check_from_in_default_whitelist(self):
        self.mock_check_whitelist.return_value = True
        result = self.plug.check_from_in_default_whitelist(self.mock_msg)
        self.assertTrue(result)


class TestAddressInList(unittest.TestCase):
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


        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_address_in_list_one_address(self):
        list_name = "parsed_whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["parsed_whitelist_from"] = [".*@example.com"]
        result = self.plug.check_address_in_list(addresses, list_name)
        self.assertTrue(result)

    def test_check_address_in_list_two_addresses(self):
        self.global_data["parsed_whitelist_from"] = [".*@example.com"]
        list_name = "parsed_whitelist_from"
        addresses = ["test1@example.com", "test2@example.com"]
        result = self.plug.check_address_in_list(addresses, list_name)
        self.assertTrue(result)

    def test_check_address_in_list_no_match(self):
        list_name = "parsed_whitelist_from"
        addresses = ["test@example.com"]
        self.global_data["parsed_whitelist_from"] = [".*@ex.com"]
        result = self.plug.check_address_in_list(addresses, list_name)
        self.assertFalse(result)


class TestCheckWhitelist(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.global_data.setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect":
                lambda p, k, v: self.msg_data.setdefault(k, v),
        })

        self.mock_get_from_addresses = self.mock_msg.get_from_addresses
        self.mock_check_in_list = patch("pad.plugins.wlbl_eval."
                                        "WLBLEvalPlugin.check_in_list").start()
        self.mock_check_in_default_whitelist = patch(
            "pad.plugins.wlbl_eval.WLBLEvalPlugin."
            "check_in_default_whitelist").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_whitelist(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", 0)
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        self.plug._check_whitelist(self.mock_msg, "from_in_whitelist")
        self.mock_check_in_list.assert_called_with(self.mock_msg,
                                                   ["addr1", "addr2"],
                                                   'parsed_whitelist_from')

    def test_check_whitelist_default(self):
        self.plug.set_local(self.mock_msg, "from_in_default_whitelist", 0)
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        self.plug._check_whitelist(self.mock_msg, "from_in_default_whitelist")
        self.mock_check_in_default_whitelist.assert_called_with(self.mock_msg,
                                                   ["addr1", "addr2"],
                                                   'parsed_def_whitelist_from_rcvd')

    def test_check_whitelist_return(self):
        self.plug.set_local(self.mock_msg, "from_in_whitelist", 1)
        self.mock_get_from_addresses.return_value = ["addr1", "addr2"]
        result = self.plug._check_whitelist(self.mock_msg, "from_in_whitelist")
        self.assertTrue(result)


class TestParseList(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect":
                lambda p, k,v: self.global_data.setdefault(k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect":
                lambda p, k,v: self.msg_data.setdefault(k,v),
        })
        self.mock_add_in_dict = patch("pad.plugins.wlbl_eval."
                                      "WLBLEvalPlugin.add_in_dict").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parse_input(self):
        list_name = "whitelist_from_rcvd"
        self.global_data["whitelist_from_rcvd"] = [
            "*@example.com user1@example.com",
            "*@example.com user2@example.com",
            "*@exam.com user@exam.com"]
        result = self.plug.parse_input(list_name)
        result_expected = {".*\\@example\\.com": ["user1@example.com",
                                             "user2@example.com"],
                           ".*\\@exam\\.com": ["user@exam.com"]}
        self.assertEqual(result, result_expected)

    def test_parse_list(self):
        list_name = "whitelist_from"
        self.global_data["whitelist_from"] =\
            ["ex1.com", "*@ex2.com", "@?ex3.com", "user@ex.com"]
        result = self.plug.parse_list(list_name)
        result_expected = \
            [".*@ex1\\.com", ".*\\@ex2\\.com", "\\@.?ex3\\.com", "user\\@ex\\.com"]
        self.assertEqual(result, result_expected)

    def test_parse_list_uri(self):
        self.global_data["enlist_uri_host"] = [
            "(BLACK) example.com !ceva.example.net",
            "(WHITE) example.com !ceva.example.net",
            "(MYLIST) example.org !ceva.example.net example.org",
        ]

        list_name = "enlist_uri_host"

        self.global_data["parsed_whitelist_uri_host"] = [
            "example.com", "user.example.com"
        ]

        self.global_data["parsed_blacklist_uri_host"] = [
            "example.com", "user.example.com"
        ]

        result = self.plug.parse_list_uri(list_name)
        self.assertEqual(result, {})

        self.plug.parse_list_uri(list_name)
        calls = [
            call(["example.com", "!ceva.example.net"], "BLACK", {}),
            call(["example.com", "!ceva.example.net"], 'WHITE', {}),
            call(["example.org", "!ceva.example.net", "example.org"], 'MYLIST',
                 {}),
            call(["example.com", "user.example.com"], 'WHITE', {}),
            call(["example.com", "user.example.com"], 'BLACK', {})
        ]
        self.mock_add_in_dict.assert_has_calls(calls)


class TestCheckUriWB(unittest.TestCase):
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
        self.mock_check_uri = patch(
            "pad.plugins.wlbl_eval.WLBLEvalPlugin.check_uri_host_listed").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_uri_host_whitelist(self):
        self.plug.check_uri_host_in_whitelist(self.mock_msg)
        self.mock_check_uri.assert_called_with(self.mock_msg, 'WHITE', None)

    def test_check_uri_host_blacklist(self):
        self.plug.check_uri_host_in_blacklist(self.mock_msg)
        self.mock_check_uri.assert_called_with(self.mock_msg, 'BLACK', None)


class TestCheckWhitelistRcvd(unittest.TestCase):
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
                                                  v: self.msg_data.
                                  setdefault(k, v),
        })
        self.mock_check_rcvd = patch("pad.plugins.wlbl_eval.WLBLEvalPlugin."
                                     "check_rcvd").start()
        self.mock_check_found_forged = patch(
            "pad.plugins.wlbl_eval.WLBLEvalPlugin.check_found_forged").start()

        self.plug = pad.plugins.wlbl_eval.WLBLEvalPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_whitelist_rcvd_match(self):
        address = "user@example.com"
        list_name = "parsed_whitelist_from_rcvd"
        self.global_data["parsed_whitelist_from_rcvd"] = {
            "*@example.com": ["user1@example.com", "user2@example.com"],
            "*@exmp.com": ["user@exmp.com"]
        }
        address = "user@exmp.com"

        self.mock_msg.untrusted_relays = [{"ip": "127.0.0.1"}]
        self.mock_msg.trusted_relays = [{"ip": "123.0.0.2"}]

        self.mock_check_rcvd.return_value = 1
        self.mock_check_found_forged.return_value = 0
        result = self.plug.check_whitelist_rcvd(self.mock_msg, list_name,
                                                address)
        self.assertEqual(result, 1)

    def test_check_whitelist_rcvd_not_match(self):
        list_name = "parsed_whitelist_from_rcvd"
        self.global_data["parsed_whitelist_from_rcvd"] = {
            "*@example.com": ["user1@example.com", "user2@example.com"],
            "*@exmp.com": ["user@exmp.com"]
        }
        address = "user@ele.com"

        self.mock_msg.untrusted_relays = [{"ip": "127.0.0.1"}]
        self.mock_msg.trusted_relays = [{"ip": "123.0.0.2"}]

        self.mock_check_rcvd.return_value = 1
        self.mock_check_found_forged.return_value = -1
        result = self.plug.check_whitelist_rcvd(self.mock_msg, list_name,
                                                address)
        self.assertEqual(result, -1)

    def test_check_whitelist_rcvd_no_relays(self):
        list_name = "parsed_whitelist_from_rcvd"
        self.global_data["parsed_whitelist_from_rcvd"] = {
            "*@example.com": ["user1@example.com", "user2@example.com"],
            "*@exmp.com": ["user@exmp.com"]
        }
        address = "user@ele.com"
        self.mock_check_found_forged.return_value = 0
        self.mock_msg.untrusted_relays = []
        self.mock_msg.trusted_relays = []
        result = self.plug.check_whitelist_rcvd(self.mock_msg, list_name,
                                                address)
        self.assertEqual(result, 0)

    def test_check_whitelist_rcvd_trusted_relays_not_match(self):
        list_name = "parsed_whitelist_from_rcvd"
        self.global_data["parsed_whitelist_from_rcvd"] = {
            "*@example.com": ["user1@example.com", "user2@example.com"],
            "*@exmp.com": ["user@exmp.com"]
        }
        address = "user@ele.com"

        self.mock_msg.untrusted_relays = []
        self.mock_msg.trusted_relays = [{"ip": "127.0.0.1"}]

        self.mock_check_rcvd.return_value = -1
        self.mock_check_found_forged.return_value = -1
        result = self.plug.check_whitelist_rcvd(self.mock_msg, list_name,
                                                address)
        self.assertEqual(result, -1)




def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
