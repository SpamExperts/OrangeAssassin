"""Tests the TextCat Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

LANG_CONFIG = """
body UNWANTED_LANGUAGE_BODY	eval:check_language()
describe UNWANTED_LANGUAGE_BODY	Message written in an undesired language
score UNWANTED_LANGUAGE_BODY 2.800
"""
PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::TextCat
ok_languages   %s
textcat_acceptable_prob %s

report _SCORE_
report _TESTS_
"""


class TestFunctionalTextCat(tests.util.TestBase):
    def test_notok_one_language(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("ro", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?")
        self.check_report(result, 2.8, ["UNWANTED_LANGUAGE_BODY"])

    def test_notok_two_languages(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("ro, fr", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?")
        self.check_report(result, 2.8, ["UNWANTED_LANGUAGE_BODY"])

    def test_notok_five_languages(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("ro, fr, it, sp, de", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?")
        self.check_report(result, 2.8, ["UNWANTED_LANGUAGE_BODY"])

    def test_notok_probability_low(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("fr", "0.90"))
        result = self.check_pad("Body: Why?\n\nThis is some random test for my plugin.")
        self.check_report(result, 2.8, ["UNWANTED_LANGUAGE_BODY"])

    def test_ok_probability_high(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("fr", "1.0"))
        result = self.check_pad("Body: Why?\n\nThis is some random test for my plugin.")
        self.check_report(result, 0.0, [])

    def test_ok_one_language(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("en", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?")
        self.check_report(result, 0.0, [])

    def test_ok_two_languages(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("en, fr", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?\n\nQue est-ce que tu fait mon ami?")
        self.check_report(result, 0.0, [])

    def test_all_languages(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % ("all", "0.70"))
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?\n\nQue est-ce que tu fait mon ami?")
        self.check_report(result, 0.0, [])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalTextCat, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
