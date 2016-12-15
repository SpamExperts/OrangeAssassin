"""Functional tests for URIEval Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin pad.plugins.uri_eval.URIEvalPlugin

report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """
body CHECK_FOR_HTTP_REDIRECTOR    eval:check_for_http_redirector()
body CHECK_HTTPS_IP_MISMATCH      eval:check_https_ip_mismatch()
body CHECK_URI_TRUNCATED          eval:check_uri_truncated()
"""

class TestFunctionalURIEval(tests.util.TestBase):
    """Class containing functional tests for the URI Plugin"""

    def test_check_for_http_redirector(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_http_redirector_links_combined(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&urlhttps://log0.wordpress.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_http_redirector_no_http(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=://log0.wordpress.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_http_redirector_with_ftp(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=ftp://log0.wordpress.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_http_redirector_only_http(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=https://""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_http_redirector_incomplete_link(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=https://ceva""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_http_redirector_different_links(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url= https://ceva.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_http_redirector_middle_of_body(self):

        email = """From: sender@example.com
\nFYI, this week is Learning Week @LinkedIn, so if you are interested in taking some free courses, hurry up
asfglajds;galsg a;slfa;sl laddg http://utility.baidu.com/traf/click.php?id=215&url=https://ceva.com asdgksal;fjlaskfdghs""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalURIEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')