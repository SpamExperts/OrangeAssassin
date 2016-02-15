"""Tests the ReplaceTags Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::ReplaceTags

report _SCORE_
report _TESTS_
"""

TAG_SIMPLE_CONFIG = r"""
# Rule definitions here

  replace_start <
  replace_end   >

  replace_tag   %s       [%s]

  body          TEST_RULE     %s
  replace_rules TEST_RULE
"""

TAG_CUSTOM_CONFIG = r"""
# You should specify the tags, the header or body and the option:
# replace options: inter|rules|end|post|start|pre|tag
#
# replaceoption A        expresion
# header|body
  replace_%s   %s       %s
  %s          TEST_RULE     %s

  replace_rules TEST_RULE
"""

TAG_CONFIG_OPTIONS = r"""
  replace_%s   %s       %s
  replace_%s   %s       %s

  replace_%s   %s       %s

  body          TEST_RULE     %s
  replace_rules TEST_RULE
"""

TAG_EXP_CONFIG = r"""
  replace_start <
  replace_end   >

  replace_tag   %s       %s
  replace_tag   %s       %s
  replace_tag   %s       %s
  replace_tag   %s       %s
  replace_tag   %s       %s

  body          TEST_RULE     %s
  replace_rules TEST_RULE
"""

MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: /Test message - pharmacy./

This is a test message for the ReplaceTags Plugin.
This rule should mathch: %s
"""


class TestFunctionalReplaceTags(tests.util.TestBase):
    """Functional Tests for the RelayCountryPlugin"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_check_replace_simple_tag(self):
        """Test the replace_tag using a single tag which match"""
        test_rule = '/a*<A>*z/'

        self.setup_conf(config=TAG_SIMPLE_CONFIG % ('A', 'SPAM', test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(MSG % 'tag /a SPAM z/ match')
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_simple_tag_no_match(self):
        """Test the replace_tag using a single tag which doens't match"""
        test_rule = '/a+<A>+z/'

        self.setup_conf(config=TAG_SIMPLE_CONFIG % ('A', 'TEST', test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(MSG % "tag /aTESeTz/ doesn't match")
        self.check_report(result, 0.0, [])

    def test_check_replace_expression(self):
        """Test the replace_tag using an expresion tag which match"""
        test_rule = '/<A> a <B> at <C>. Please <D> <E>/'

        tag_a = 'won'
        tag_b = 'million'
        tag_c = 'lottery'
        tag_d = 'claim'
        tag_e = 'today'

        self.setup_conf(config=TAG_EXP_CONFIG % ('A', tag_a, 'B', tag_b,
                        'C', tag_c, 'D', tag_d, 'E', tag_e, test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'You won a million at lottery. Please claim today.')
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_tag_header(self):
        """Test the replace_tag for the Subject header which match"""
        test_rule = 'Subject =~ /Test message - <A>./'

        self.setup_conf(config=TAG_CUSTOM_CONFIG % ('tag', 'A', 'pharmacy',
                        'header', test_rule), pre_config=PRE_CONFIG)

        result = self.check_pad(MSG % "This should match the tag in header")
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_tag_header_no_match(self):
        """Test the replace_tag for the Subject header which doesn't match"""
        test_rule = 'Subject =~ /Test message - <A>./'

        self.setup_conf(config=TAG_CUSTOM_CONFIG % ('tag', 'A',
                        'pharmaceutics', 'header', test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(MSG % "This should not match tag in header")
        self.check_report(result, 0.0, [])

    def test_check_replace_inter(self):
        """Test the replace_inter which match"""
        test_rule = '/<inter W1><A><B>/'

        self.setup_conf(config=TAG_CONFIG_OPTIONS %
                        ('tag', 'A', '[medication]', 'tag', 'B', '[cheap]',
                         'inter', 'W1', '<inter>', test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'Buy medication<inter>cheap!')
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_pre(self):
        """Test the replace_pre which match"""
        test_rule = '/<pre SP><A><B>/'

        self.setup_conf(config=TAG_CONFIG_OPTIONS %
                        ('tag', 'A', 'rolex', 'tag', 'B', 'now', 'pre', 'SP',
                         '<pre>', test_rule), pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'Buy a brand new <pre>rolex<pre>now!')
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_post(self):
        """Test the replace_post which match"""
        test_rule = '/<post RT><A><B>/'

        self.setup_conf(config=TAG_CONFIG_OPTIONS %
                        ('tag', 'A', 'unlimited', 'tag', 'B', 'mortgage',
                         'post', 'RT', '<post>', test_rule),
                        pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'Unlock unlimited<post>mortgage<post>!')
        self.check_report(result, 1.0, ["TEST_RULE"])

    def test_check_replace_start_and_replace_end(self):
        """Test the replace_start and replace_end which match"""
        test_rule = '(A)'

        self.setup_conf(config=TAG_CONFIG_OPTIONS %
                        ('start', '(', '', 'end', ')', '', 'tag', 'A',
                         '/thousands/', test_rule), pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'thousands dollars')
        self.check_report(result, 1.0, ["TEST_RULE"])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalReplaceTags, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')