"""Functional tests the DKIM Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

PRE_CONFIG = """
loadplugin pad.plugins.dkim.DKIMPlugin
report _SCORE_
report _TESTS_
"""

# Define rules for plugin
DEFAULT_CONFIG = """
full DKIM_SIGNED              eval:check_dkim_signed()
full DKIM_VALID               eval:check_dkim_valid()
full DKIM_VALID_AUTHOR_SIG    eval:check_dkim_valid_author_sig()

header DKIM_ADSP                eval:check_dkim_adsp("D")
header DKIM_DEPENDABLE          eval:check_dkim_dependable()
header DKIM_WHITELIST_FROM      eval:check_for_dkim_whitelist_from()
header DKIM_DEF_WHITELIST_FROM  eval:check_for_def_dkim_whitelist_from()
"""

MSG = """DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple;
 d=dkim.simplyspamfree.com; i=@dkim.simplyspamfree.com; q=dns/txt;
 s=sel; t=1481798029; h=Subject : From : To;
 bh=FCPAsiuQWCFlrJ7iR/yrZ6aafRyUVew0I6JKFrP5atE=; b=gw/FqdTVCfo7SLK9ZvbU0dHf8h0M1MRXQ0b/gjA713MUJhwWsfuZCf3YWXiFuzJxwMHN/jO5tjjLif3igXxmXiijlOx+9dnsF1gYzKog4f1olUSGaw0Xxmx3OD1hzBMRpCP3zlYG4Hz9hziMgZnb8+jJXgAjHhWPmTpkhCW8lOA=
Subject: Test message
From: test@dkim.simplyspamfree.com
To: test@example.com

Hello World.
"""


class TestFunctionalDKIM(tests.util.TestBase):
    """Class containing functional tests for the DKIM Plugin"""
    dkim_domain = 'dkim.simplyspamfree.com'
    test_domain = 'example.com'

    def test_dkim_signed(self):
        config = ("full DKIM_SIGNED    "
                 "eval:check_dkim_signed()")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_SIGNED'])

    def test_dkim_valid(self):
        config = ("full DKIM_VALID    "
                 "eval:check_dkim_valid()")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID'])

    def test_dkim_valid_author_sig(self):
        config = ("full DKIM_VALID_AUTHOR_SIG    "
                  "eval:check_dkim_valid_author_sig()")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID_AUTHOR_SIG'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_signed_list(self):
        config = ("full DKIM_SIGNED    eval:"
                  "check_dkim_signed(\"{}\", \"{}\")".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_SIGNED'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_valid_list(self):
        config = ("full DKIM_VALID    eval:"
                  "check_dkim_valid(\"{}\", \"{}\")".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_valid_author_sig_list(self):
        config = ("full DKIM_VALID_AUTHOR_SIG    eval:"
                  "check_dkim_valid_author_sig(\"{}\", \"{}\")".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID_AUTHOR_SIG'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_d(self):
        config = ("header DKIM_ADSP_DISCARD    eval:"
                  "check_dkim_adsp('D')")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_DISCARD'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_a(self):
        config = ("header DKIM_ADSP_ALL    eval:"
                  "check_dkim_adsp('A')")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_ALL'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_n(self):
        config = ("header DKIM_ADSP_NXDOMAIN    eval:"
                  "check_dkim_adsp('N')")
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_NXDOMAIN'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_low(self):
        config = ("header DKIM_ADSP_CUSTOM_LOW    eval:"
                  "check_dkim_adsp('1')")
        pconfig = PRE_CONFIG + "\nadsp_override {} custom_low".format(
            self.dkim_domain)
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_LOW'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_med(self):
        config = ("header DKIM_ADSP_CUSTOM_MED    eval:"
                  "check_dkim_adsp('2')")
        pconfig = PRE_CONFIG + "\nadsp_override {} custom_med".format(
            self.dkim_domain)
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_MED'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_high(self):
        config = ("header DKIM_ADSP_CUSTOM_HIGH    eval:"
                  "check_dkim_adsp('3')")
        pconfig = PRE_CONFIG + "\nadsp_override {} custom_high".format(
            self.dkim_domain)
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_HIGH'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_override_all(self):
        config = ("header DKIM_ADSP_ALL    eval:"
                  "check_dkim_adsp('A')\n"
                  "header DKIM_ADSP_CUSTOM_LOW    eval:"
                  "check_dkim_adsp('1')\n")
        pconfig = PRE_CONFIG + "\nadsp_override {} custom_low".format(
            self.dkim_domain)
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_LOW'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_high_wildcard_domain(self):
        config = ("header DKIM_ADSP_CUSTOM_HIGH    eval:"
                  "check_dkim_adsp('3')")
        pconfig = PRE_CONFIG + "\nadsp_override *{} custom_high".format(
            self.dkim_domain[-3:])
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_HIGH'])

    @unittest.skip("Skipping until fixed")
    def test_dkim_adsp_high_wildcard(self):
        config = ("header DKIM_ADSP_CUSTOM_HIGH    eval:"
                  "check_dkim_adsp('3')")
        pconfig = PRE_CONFIG + "\nadsp_override *@{} custom_high".format(
            self.dkim_domain)
        self.setup_conf(config, pconfig)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_ADSP_CUSTOM_HIGH'])

    def test_whitelist_from_address(self):
        pass

    def test_whitelist_from_wildcard(self):
        pass

    def test_def_whitelist_from_address(self):
        pass

    def test_def_whitelist_from_wildcard(self):
        pass


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalDKIM, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
