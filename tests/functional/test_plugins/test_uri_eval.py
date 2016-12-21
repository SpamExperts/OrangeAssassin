"""Functional tests for URIEval Plugin"""

from __future__ import absolute_import

import unittest
import random
import tests.util

from string import ascii_letters
from string import digits

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
    mytext = [random.choice(ascii_letters + digits) for _ in range(8182)]
    long_text = "".join(mytext)

    def test_check_for_http_redirector(self):

        email = """From: sender@example.com
\nhttp://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_http_redirector_in_a_label_closed_commas(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com"></a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_http_redirector_in_a_label_no_commas(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href=http://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com></a>
</html>""" 

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
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited http://utility.baidu.com/traf/click.php?id=215&url=https://log0.wordpress.com:
<a href="http://45.42.12.12/login/account-unlock">https://www.paypal.com/login/account-unlock</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_a_label(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://google.com=https://log0.wordpress.com/">https://ceva.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_a_label_with_invalid_expression(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://@1.2.3.4=https://log0.wordpress.com/">https://ceva.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_a_label_ip_left(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/https://log0.wordpress.com/">https://ceva.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_link_label_same_address(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link rel=parent href="http://log0.wordpress.com/https://log0.wordpress.com/">
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_and_redirector_in_link_label(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link rel=parent href="http://google.com=https://log0.wordpress.com/">https://ceva.com/
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_link_label_with_invalid_expression(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link rel=parent href="http://@1.2.3.4=https://log0.wordpress.com/">https://ceva.com/
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_and_redirector_in_link_label_ip_left(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link rel=parent href="http://1.2.3.4=https://log0.wordpress.com/">https://ceva.com/
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_domains(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://google.com/">https://www.google.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_domains_incomplete_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://google.com/"> cevatest https://ceva/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ip_right(self):

        email = """From: sender@example.com
Content-Type: text/html
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
Content-Type: text/html
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
Content-Type: text/html
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
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://1.2.3.4/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ipv6_left_domain_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_ipv6_left_multiple_labels(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://1.2.3.4/</a>
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
<a href="http://2001:1af8:4700:a02d:2::1/">https://6.6.6.6/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_ipv6_with_redirector(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/https://test">https://1.2.3.4/</a>
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_ipv6_with_redirector_and_link_label(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/https://test">https://1.2.3.4/</a>
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
<link href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_ipv6_with_false_redirector(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/https://2001:1af8:4700:a02d:2::1">https://1.2.3.4/</a>
<a href="http://2001:1af8:4700:a02d:2::1/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_incorrect_ipv4_domain_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d/https://2001:1af8:4700:a02d/">https://yahoo.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_no_domain(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_incorrect_ip(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3/">https://</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_unfinished_ip(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3./">https://</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_inverted_commas_16_ip(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.'2'.3.4/">https://test.com</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_inverted_commas_ip_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://'1'.2.3.4</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_inverted_commas_on_all_ip(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://'1.2.3.4'/">https://test.com</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_invalid_expression_ip(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://@1.2.3.4/">https://test.com</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_ipv6_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://2001:1af8:4700:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_same_ipv6_right_and_left(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/">https://2001:1af8:4700:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_same_ipv6_right_and_left_with_redirector(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/https://2901:1af8:4711:a02d:2::1">https://2901:1af8:4711:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_same_ipv6_right_and_left_with_redirector_negative(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://2001:1af8:4700:a02d:2::1/https://2001:1af8:4700:a02d:2::1/">https://2901:1af8:4711:a02d:2::1/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_text_between_links_domain_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/"> cevatest https://google.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_text_between_links_ip_right(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/"> cevatest https://1.2.3.4/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_with_multiple_uri(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/"> cevatest https://1.2.3.4/ https://test.com/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_redirector_with_multiple_redirector(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/https://1.2.3.4/https://test.com/https://1.2.3.4/"> cevatest https://1.2.3.4/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_redirector_with_multiple_redirector_negative(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/https://1.2.3.4/https://1.2.3.4/"> cevatest https://1.2.3.4/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_label_not_closed(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://google
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_incorrect_link_label(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<link href="http://1.2.3.4/">https://google.com/</link>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_https_ip_mismatch_multiple_labels_redirector_in_link_label(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<link href="http://1.2.3.4/https://google.com/">
<a href="http://1.2.3.4/">https://6.6.6.6/</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_multiple_labels_match_on_a(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://google.com/</a>
<link href="http://1.2.3.4/">https://test.com/
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_multiple_labels_match_on_both(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://google.com/</a>
<link href="http://1.2.3.4/https://test.com/">
<a href="http://6.6.6.6/"></a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_HTTPS_IP_MISMATCH', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_https_ip_mismatch_multiple_labels(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/">https://5.5.5.5/</a>
<a href="http://1.2.3.4/">https://google.com/</a>
<a href="http://1.2.3.4/">https://6.6.6.6/></a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_HTTPS_IP_MISMATCH'])

    def test_check_for_https_ip_mismatch_multiple_labels_match_last(self):

        email = """From: sender@example.com
Content-Type: text/html
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
Content-Type: text/html
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

    def test_check_for_uri_truncated_negative(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="https://www.PAYPAL.com/login/account-unlock">https://www.PAYPAL.com/...</a>
</html>""" 

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_uri_truncated_superior_limit(self):

        mytext1 = [random.choice(ascii_letters + digits) for _ in range(8181)]
        long_text1 = "".join(mytext1)

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://%s.com">https://test.com</a>
</html>"""
        email = email % (long_text1)

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_uri_truncated(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://%s.com">https://test.com</a>
</html>"""
        email = email % (self.long_text)

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_URI_TRUNCATED'])

    def test_check_for_uri_truncated_and_redirector_after(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://%s.com/https://ceva.com">https://test.com</a>
</html>"""
        email = email % (self.long_text)

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_URI_TRUNCATED', 'CHECK_FOR_HTTP_REDIRECTOR'])

    def test_check_for_uri_truncated_redirector_before_and_ip_mismatch(self):

        email = """From: sender@example.com
Content-Type: text/html
\n<html>
Dear user,
Your account has been limited please follow the instructions on the next link:
<a href="http://1.2.3.4/https://%s.com/">https://test.com</a>
</html>"""
        email = email % (self.long_text)

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_TRUNCATED', 'CHECK_FOR_HTTP_REDIRECTOR','CHECK_HTTPS_IP_MISMATCH'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalURIEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')



