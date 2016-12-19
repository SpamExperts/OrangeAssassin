"""Tests the HeaderEval Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin Mail::SpamAssassin::Plugin::HeaderEval
report _SCORE_
report _TESTS_
"""

class TestFunctionalHeaderEval(tests.util.TestBase):

    def test_check_for_faraway_charset_in_headers_match(self):

        config = ("header TEST_RULE eval:check_for_faraway_charset_in_headers() "
            "ok_locales ru")

        email = "Subject: This is a test subject";

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalHeaderEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
