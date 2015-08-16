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
        self.assertTrue(plugin.check_subject_in_whitelist(self.mock_msg))


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestWhitelistSubject, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
