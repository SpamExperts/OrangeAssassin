"""Tests the URIDetail Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

LANG_CONFIG = """
body URI_DETAIL	eval:uri_detail()
describe URI_DETAIL	Suspicious URL received
score URI_DETAIL 2.800
"""
PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::URIDetail

report _SCORE_
report _TESTS_
"""


class TestFunctionalUriDetail(tests.util.TestBase):

    def test_basic_uri_rule(self):
        self.setup_conf(config=LANG_CONFIG,
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Why?\n\nWhy? Are you doing this?\n\nDar vreau sa vb in romana sa vad daca pica!")
        self.check_report(result, 2.8, ["URI_DETAIL"])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalUriDetail, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')