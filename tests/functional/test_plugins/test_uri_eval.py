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

    def test_check_for_https_ip_mismatch(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited http://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com:
<a href="http://45.42.12.12/login/account-unlock">https://www.paypal.com/login/account-unlock</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_domains(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://google.com/">https://www.google.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ip_right(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://google.com/">http://300.58.209.206/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_both_ips(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://5.79.73.204/">http://300.58.209.206/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_incomplete_domain(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://5.79.73.204/">https://ceva/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_ipv6_left(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://300.58.209.206/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ipv6_left_domain_right(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ipv6_left_domain_right(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_incorrect_ipv4_domain_right(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ipv6_right(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://2001:1af8:4700:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_ipv6_right_negative(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">http://2001:1af8:4700:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_incorrect_link_label(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link href="http://1.2.3.4/">https://google.com/</link>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_multiple_labels_incorrect_link_label(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<link href="http://1.2.3.4/">https://google.com/</link>
<a href="http://1.2.3.4/">https://6.6.6.6/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_multiple_labels_incorrect_link_label_last(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://2.2.2.2/</a>
<link href="http://1.2.3.4/">https://test.com/</link>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_multiple_labels_match_on_a(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://google.com/</a>
<link href="http://1.2.3.4/">https://test.com/</link>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_multiple_labels(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<a href="http://1.2.3.4/">https://google.com/</a>
<a href="http://1.2.3.4/">https://6.6.6.6/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_multiple_labels_match_last(self):

        email = """From: sender@example.com
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<a href="http://1.2.3.4/">https://google.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_multiple_labels_match_first(self):

        email = """From: sender@example.com
\n<html>
<a href="http://1.2.3.4/">https://google.com/</a>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<a href="http://1.2.3.4/">https://1.2.3.4./</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalURIEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')