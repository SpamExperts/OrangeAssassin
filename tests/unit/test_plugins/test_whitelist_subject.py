"""Tests for sa.plugins.whitelist_subject."""
import email

import unittest
import sa.plugins

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock

from sa.plugins import whitelist_subject


MESSAGE = """MIME-Version: 1.0
Sender: testuser@spamexperts.com
Received: by 10.229.20.15 with HTTP; Thu, 10 Aug 2015 19:22:50 -0800 (PST)
Date: %s
Delivered-To: testuser@spamexperts.com
X-Google-Sender-Auth: qa9Es1PL-4oDsS5MHPzgYOYIGCU
Message-ID: <AANLkTinNEu2iZfuMjWPLN+kHfu-T1OTRLRR8bEhsppU-@mail.gmail.com>
Subject: {0}
From: Test User <testuser@spamexperts.com>
To: Alexey <alexey@spamexperts.com>
Content-Type: text/plain; charset=ISO-8859-1

This is a test message.

"""

class TestWhitelistSubject(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        patch("sa.plugins.whitelist_subject.WhiteListSubjectPlugin.options", self.options).start()
        patch("sa.plugins.whitelist_subject.WhiteListSubjectPlugin.inhibit_further_callbacks").start()

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_subject_one_regex(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.msg = email.message_from_string(MESSAGE.format("Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertTrue(plugin._check_subject(self.mock_msg, self.options["whitelist_subject"][1]))

    def test_check_subject_one_regex_false(self):
        self.options["whitelist_subject"] = ("list", [r"[a-z]+"])
        self.msg = email.message_from_string(MESSAGE.format("Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertFalse(plugin._check_subject(self.mock_msg, self.options["whitelist_subject"][1]))

    def test_check_subject_one_regex_blank(self):
        self.options["whitelist_subject"] = ("list", [])
        self.msg = email.message_from_string(MESSAGE.format("Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertFalse(plugin._check_subject(self.mock_msg, self.options["whitelist_subject"][1]))

    def test_check_subject_list_regex(self):
        self.options["whitelist_subject"] = ("list", [r"[a-z]+", r".*\d$", r"^\d.*"])
        self.msg = email.message_from_string(MESSAGE.format("1Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertTrue(plugin._check_subject(self.mock_msg, self.options["whitelist_subject"][1]))

    def test_check_subject_one_regex_black(self):
        self.options["blacklist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.options["whitelist_subject"] = ("list", [])
        self.msg = email.message_from_string(MESSAGE.format("Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertFalse(plugin.check_subject_in_whitelist(self.mock_msg))
        self.assertTrue(plugin.check_subject_in_blacklist(self.mock_msg))

    def test_check_subject_one_regex_white(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.options["blacklist_subject"] = ("list", [])
        self.msg = email.message_from_string(MESSAGE.format("Test subject"))
        self.mock_msg.msg = self.msg
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        self.assertFalse(plugin.check_subject_in_blacklist(self.mock_msg))
        self.assertTrue(plugin.check_subject_in_whitelist(self.mock_msg))

    def test_set_append_option(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        new_option = r"^\d.*"
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        plugin.set_append_option("whitelist_subject", new_option)
        self.assertEqual(self.options["whitelist_subject"], ('list', ['[a-zA-Z]+', new_option]))

    def test_parse_config(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.options["blacklist_subject"] = ("list", [])
        new_option = r"^\d.*"
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        plugin.parse_config("whitelist_subject", new_option)
        self.assertEqual(self.options["whitelist_subject"], ('list', ['[a-zA-Z]+', new_option]))

    def test_parse_config_bad_regex(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.options["blacklist_subject"] = ("list", [])
        new_option = "he(lo"
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        plugin.parse_config("whitelist_subject", new_option)
        self.assertEqual(self.options["whitelist_subject"], ('list', ['[a-zA-Z]+']))

    def test_parse_config_wrong_key(self):
        self.options["whitelist_subject"] = ("list", [r"[a-zA-Z]+"])
        self.options["blacklist_subject"] = ("list", [])
        new_option = r"^\d.*"
        plugin = sa.plugins.whitelist_subject.WhiteListSubjectPlugin(self.mock_ctxt)
        plugin.parse_config("whitelist", new_option)
        self.assertEqual(self.options["whitelist_subject"], ('list', ['[a-zA-Z]+']))


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestWhitelistSubject, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
