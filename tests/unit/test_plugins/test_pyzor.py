"""Tests for pad.plugins.base."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock

import oa.plugins.pyzor


class TestPyzorCheck(unittest.TestCase):
    digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_pyzor = patch(
            "oa.plugins.pyzor.pyzor.client.BatchClient").start()
        self.mock_digester = patch("oa.plugins.pyzor.pyzor.digest.DataDigester",
                                   **{"return_value.value":
                                      self.digest}).start()
        self.msg_data = {}
        self.global_data = {}
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
            })
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_client = MagicMock()
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_finish_parsing(self):
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)
        plugin.finish_parsing_end(self.mock_ruleset)
        expected = ("PyzorPlugin", "client", self.mock_pyzor(timeout=3.5))

        self.mock_ctxt.set_plugin_data.assert_called_with(*expected)

    def test_check_pyzor_set_digest(self):
        self.global_data["client"] = self.mock_client

        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)
        plugin.check_pyzor(self.mock_msg)

        expected = ("PyzorPlugin", "digest", self.digest)
        self.mock_msg.set_plugin_data.assert_called_with(*expected)

    def test_check_pyzor_no_use(self):
        self.global_data["client"] = self.mock_client
        self.global_data["use_pyzor"] = False
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        result = plugin.check_pyzor(self.mock_msg)

        self.assertFalse(self.mock_msg.set_plugin_data.called)
        self.assertFalse(result)

    def test_check_pyzor_check_server(self):
        self.global_data["client"] = self.mock_client
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        plugin.check_pyzor(self.mock_msg)

        self.mock_client.check.assert_called_with(self.digest,
                                                  ["oa.pyzor.org", '24441'])

    def test_check_pyzor_check_matched(self):
        self.global_data["client"] = self.mock_client
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        self.mock_client.check.return_value = {"Count": 6, "WL-Count": 0}

        result = plugin.check_pyzor(self.mock_msg)
        self.assertEqual(result, True)

    def test_check_pyzor_check_matched_too_few(self):
        self.global_data["client"] = self.mock_client
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        self.mock_client.check.return_value = {"Count": 4, "WL-Count": 0}

        result = plugin.check_pyzor(self.mock_msg)
        self.assertEqual(result, False)

    def test_check_pyzor_check_matched_whitelisted(self):
        self.global_data["client"] = self.mock_client
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        self.mock_client.check.return_value = {"Count": 6, "WL-Count": 1}

        result = plugin.check_pyzor(self.mock_msg)
        self.assertEqual(result, False)


class TestPyzorReport(unittest.TestCase):
    digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_pyzor = patch(
            "oa.plugins.pyzor.pyzor.client.BatchClient").start()
        self.mock_digester = patch("oa.plugins.pyzor.pyzor.digest.DataDigester",
                                   **{"return_value.value":
                                      self.digest}).start()
        self.msg_data = {}
        self.global_data = {}
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
            })
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_client = MagicMock()
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_report_pyzor_spam(self):
        self.global_data["client"] = self.mock_client
        self.msg_data["digest"] = self.digest
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        plugin.plugin_report(self.mock_msg)

        self.mock_client.report.assert_called_with(self.digest,
                                                   ["oa.pyzor.org", '24441'])

    def test_report_pyzor_ham(self):
        self.global_data["client"] = self.mock_client
        self.msg_data["digest"] = self.digest
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        plugin.plugin_revoke(self.mock_msg)

        self.mock_client.whitelist.assert_called_with(self.digest,
                                                      ["oa.pyzor.org", '24441'])

    def test_report_no_digest(self):
        self.global_data["client"] = self.mock_client
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        plugin.plugin_report(self.mock_msg)
        expected = ("PyzorPlugin", "digest", self.digest)
        self.mock_msg.set_plugin_data.assert_called_with(*expected)

    def test_report_pyzor_no_use(self):
        self.global_data["client"] = self.mock_client
        self.global_data["use_pyzor"] = False
        self.msg_data["digest"] = self.digest
        plugin = oa.plugins.pyzor.PyzorPlugin(self.mock_ctxt)

        plugin.plugin_report(self.mock_msg)

        self.assertFalse(self.mock_client.report.called)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestPyzorCheck, "test"))
    test_suite.addTest(unittest.makeSuite(TestPyzorReport, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
