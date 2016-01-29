"""Tests the URIDetail Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

URI_DETAIL = """
uri_detail TEST %s
describe TEST	Suspicious URL received
score TEST 1.000
"""
PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::URIDetail

report _SCORE_
report _TESTS_
"""

MSG_MULTIPART = """
Subject: test
Content-Type: multipart/alternative; boundary=001a11c39d507b0142052155ffb1

--001a11c39d507b0142052155ffb1
Content-Type: text/plain; charset=UTF-8

Hello,

dwdwdwd

--001a11c39d507b0142052155ffb1
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<html>https://www.example.com</html>

--001a11c39d507b0142052155ffb1--
"""


class TestFunctionalUriDetail(tests.util.TestBase):

    def test_check_for_www_rule(self):
        self.setup_conf(config=URI_DETAIL % "raw =~ /www(w|ww|www|www\.)?/",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://www.example.com\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_domain_rule(self):
        self.setup_conf(config=URI_DETAIL % "domain =~ ([a-z0-9\-]+\.){1,2}[a-z]{2,4}",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://www.example.com\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_tld_rule(self):
        self.setup_conf(config=URI_DETAIL % "text =~ [^\sw\.@/]([0-9a-zA-Z\-\.]*[0-9a-zA-Z\-]+\.)(de|com|org|net|edu|DE|COM|ORG|NET|EDU)",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://www.example.org\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_subdomain_rule(self):
        self.setup_conf(config=URI_DETAIL % "domain =~ ^(?!www|clients)([a-zA-Z0-9\-\_]*).example.com$",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://test.example.com\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_domain_and_subdomain_rule(self):
        self.setup_conf(config=URI_DETAIL % "text =~ \b[a-z-A-Z0-9]{1,99}\.((com|org|net|eu|pt|uk|es|br|co|cz|fn)|\.(uk|vu|cz|en|br|es)){1,2}",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://www.example.fn\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_full_url_rule(self):
        self.setup_conf(config=URI_DETAIL % "type =~ ([a-z0-9_\-]{1,5}:\/\/)?(([a-z0-9_\-]{1,}):([a-z0-9_\-]{1,})\@)?((www\.)|([a-z0-9_\-]{1,}\.)+)?([a-z0-9_\-]{3,})(\.[a-z]{2,4})(\/([a-z0-9_\-]{1,}\/)+)?([a-z0-9_\-]{1,})?(\.[a-z]{2,})?(\?)?(((\&)?[a-z0-9_\-]{1,}(\=[a-z0-9_\-]{1,})?)+)?",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttp://www.example.co.uk\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

    def test_check_url_detail_in_email_address_rule(self):
        self.setup_conf(config=URI_DETAIL % "raw =~ ([\d\w]+[\.\w\d]*)\+?([\.\w\d]*)?@([\w\d]+[\.\w\d]*)",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhacker@example.co.uk\n\nBad URI")
        self.check_report(result, 0.0)

    def test_check_url_encoded_rule(self):
        self.setup_conf(config=URI_DETAIL % "raw =~ %3[A-Z,a-z,0-9]i|%2[A-Z,a-z,0-9]i|%3[A-Z,a-z,0-9]|%2[A-Z,a-z,0-9]|\+",
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_MULTIPART)
        self.check_report(result, 1.0, ["TEST"])

    def test_check_fake_https(self):
        self.setup_conf(config=URI_DETAIL % "text =~ ^(http(s)?)\:\/\/((www)|([a-z0-9]+))?\.[a-z0-9]+\.[a-z]{2,4}$",
                        pre_config=PRE_CONFIG)
        result = self.check_pad("Body: Test\n\nhttps://www.example.com\n\nBad URI")
        self.check_report(result, 1.0, ["TEST"])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalUriDetail, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')