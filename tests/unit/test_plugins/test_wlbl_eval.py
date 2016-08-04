import unittest

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
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
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


#check_in_list method
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

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    #test_suite.addTest(unittest.makeSuite(TestWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
