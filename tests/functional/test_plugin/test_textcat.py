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

report _SCORE_
report _TESTS_
"""


class TestFunctionalTextCat(tests.util.TestBase):

    def test_ok_languages(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG % "ro")
        result = self.check_pad("Subject: test\n\nTest abcd test.")
        self.check_report(result, 2.8, ["UNWANTED_LANGUAGE_BODY"])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalTextCat, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
