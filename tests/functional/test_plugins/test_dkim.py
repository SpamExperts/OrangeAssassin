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

    @unittest.skip
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

    @unittest.skip
    def test_dkim_signed_list(self):
        config = ("full DKIM_SIGNED    eval:"
                  "check_dkim_signed('{}', '{}')".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_SIGNED'])

    @unittest.skip
    def test_dkim_valid_list(self):
        config = ("full DKIM_VALID    eval:"
                  "check_dkim_valid('{}', '{}')".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID'])

    @unittest.skip
    def test_dkim_valid_author_sig_list(self):
        config = ("full DKIM_VALID_AUTHOR_SIG    eval:"
                  "check_dkim_valid_author_sig('{}', '{}')".format(
            self.dkim_domain, self.test_domain))
        self.setup_conf(config, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1, ['DKIM_VALID_AUTHOR_SIG'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalDKIM, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
