"""Tests the URIDetail Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

URI_DETAIL = """
body URI_DETAIL	uri_detail TEST1 raw =~ /%2Ebar/ domain =~ /^viaggra\.com$/ type =~ /^a$/
describe URI_DETAIL	Suspicious URL received
score URI_DETAIL 1.000
"""
PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::URIDetail

report _SCORE_
report _TESTS_
"""


class TestFunctionalUriDetail(tests.util.TestBase):

    @unittest.skip("Skipped until issue #23 is fixed")
    def test_basic_uri_rule(self):
            self.setup_conf(config=URI_DETAIL,
                            pre_config=PRE_CONFIG)
            result = self.check_pad("Body: Test\n\nhttp://www.viaggra.com/pills\n\nBad URI")
            self.check_report(result, 1.0, ["URI_DETAIL"])


def suite():
        """Gather all the tests from this package in a test suite."""
        test_suite = unittest.TestSuite()
        test_suite.addTest(unittest.makeSuite(TestFunctionalUriDetail, "test"))
        return test_suite

if __name__ == '__main__':
        unittest.main(defaultTest='suite')
