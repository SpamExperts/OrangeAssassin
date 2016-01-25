"""Tests for pad.plugins.base."""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock


import pad.plugins.textcat


class TestTextCat(unittest.TestCase):
    digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_detect_langs = patch(
            "pad.plugins.textcat.langdetect.detect_langs").start()
        self.mock_msg = MagicMock()
        self.msg_data = {}
        self.global_data = {
            "ok_languages": ["all"],
            "textcat_max_languages": 5,
            "textcat_acceptable_prob": 0.70,
        }
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
            })
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_all_ok(self):
        self.mock_detect_langs.return_value = [Mock(lang="en", prob=0.99)]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, False)

    def test_one_ok(self):
        self.mock_detect_langs.return_value = [Mock(lang="en", prob=0.99)]
        self.global_data["ok_languages"] = ["en"]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, False)

    def test_one_not_ok(self):
        self.mock_detect_langs.return_value = [Mock(lang="fr", prob=0.99)]
        self.global_data["ok_languages"] = ["en"]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, True)

    def test_multiple_langs_ok(self):
        self.mock_detect_langs.return_value = [Mock(lang="fr", prob=0.99),
                                               Mock(lang="en", prob=0.71)]
        self.global_data["ok_languages"] = ["en", "fr"]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, False)

    def test_multiple_langs_not_ok(self):
        self.mock_detect_langs.return_value = [Mock(lang="es", prob=0.99),
                                               Mock(lang="en", prob=0.71)]
        self.global_data["ok_languages"] = ["en", "fr"]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, True)

    def test_too_many_langs(self):
        self.mock_detect_langs.return_value = [Mock(lang="es", prob=0.99),
                                               Mock(lang="en", prob=0.71),
                                               Mock(lang="fr", prob=0.71)]
        self.global_data["ok_languages"] = ["en", "fr"]
        self.global_data["textcat_max_languages"] = 2

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, False)

    def test_multiple_langs_low_prob(self):
        self.mock_detect_langs.return_value = [Mock(lang="es", prob=0.60),
                                               Mock(lang="en", prob=0.71)]
        self.global_data["ok_languages"] = ["en", "fr"]

        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        result = plugin.check_language(self.mock_msg)
        self.assertEqual(result, False)

    def test_set_list_option(self):
        plugin = pad.plugins.textcat.TextCatPlugin(self.mock_ctxt)
        plugin.set_list_option("my_key", "test1 test2 test3")

        self.mock_ctxt.set_plugin_data.assert_called_with(
            "TextCatPlugin", "my_key", ["test1", "test2", "test3"]
        )


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestTextCat, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
