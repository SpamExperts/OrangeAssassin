"""Tests the Short Circuit Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

PRE_CONFIG = """
loadplugin     Mail::SpamAssassin::Plugin::Shortcircuit

report _SCORE_
report _TESTS_
"""

CONFIG = r"""
# Rule definitions here
body UNLIMITED /unlimited/i
score UNLIMITED 10.45
shortcircuit UNLIMITED off

body EMAIL /email/
score EMAIL -12.15
shortcircuit EMAIL off

body SPAM_TEST /spam_test/i
score SPAM_TEST 55.12
shortcircuit SPAM_TEST spam

body SPAM_ON /spam_on/i
score SPAM_ON 25.73
shortcircuit SPAM_ON on

body HAM_TEST /ham_test/
score HAM_TEST -75.3
shortcircuit HAM_TEST ham

body HAM_ON /ham_on/i
score HAM_ON -35.01
shortcircuit HAM_ON on

body MONEY /money/i
score MONEY 50.11
shortcircuit MONEY spam

body ROLEX /rolex/i
score ROLEX 15.05
shortcircuit ROLEX on

header HEADER_TEST X-Header =~ /match_header/i
score HEADER_TEST 1.0
shortcircuit HEADER_TEST off
"""

CONFIG_HEADER = r"""
# Rule definitions here
header %s %s =~ /%s/i
score %s %s
shortcircuit %s %s
"""

MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.
X-Header: match_header

This is a test message for the Short Circuit Plugin.
Adjust the body for your case: %s
"""

MSG_NO_MATCH = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.

This is a test message for the Short Circuit Plugin.
Adjust the body for your case: %s
"""

class TestFunctionalShortCircuit(tests.util.TestBase):
    """Functional Tests for the Shortcircuit Plugin"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_shortcircuit_simple_score(self):
        """Test using some rules that match but don't shortcircuit"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % 'UnliMited email services!')

        # UNLIMITED: +10.45 & EMAIL: -12.15 & HEADER_TEST: 1.0 => -0.7
        self.check_report(result, -0.7, ['UNLIMITED', 'EMAIL', 'HEADER_TEST'])

    def test_shortcircuit_ham_match(self):
        """Test shortcircuit using ham rule that match"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % 'Test email ham_test no match_header!')

        # HAM_TEST: -75.3 & EMAIL: -12.15 & -100 (ham default )=> -187.48
        self.check_report(result, -187.4, ['HAM_TEST', 'EMAIL'])

    def test_shortcircuit_spam_match(self):
        """Test shortcircuit using spam rule that match"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % 'Test match spam_TEST!')

        # SPAM_TEST: 55.12 +100 (spam default)=> 155.12
        self.check_report(result, 155.1, ['SPAM_TEST'])

    def test_shortcircuit_ham_on_match(self):
        """Test shortcircuit using ham on rule that match"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(
            MSG % 'Unlimited Email match HAM_on and should shortcircuit!'
            'MONEY also match but should not be taken into consideration')

        # UNLIMITED: +10.45 & HAM_ON: -35.01 => -24.56
        self.check_report(result, -24.6, ['UNLIMITED', 'HAM_ON'])

    def test_shortcircuit_spam_on_match(self):
        """Test shortcircuit using spam on rule that match"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(
            MSG % 'Rolex email match spam_ON and should shortcircuit!'
            'ROLEX & HAM_TEST also match but should not be included')

        # EMAIL: -12.15 & SPAM_ON: +25.73 => 13.58
        self.check_report(result, 13.6, ['EMAIL', 'SPAM_ON'])

    def test_shortcircuit_no_match(self):
        """Test shortcircuit for a message that don't match any rule"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(
            MSG_NO_MATCH % 'I shoud not score anything!')

        self.check_report(result, 0, [])

    def test_shortcircuit_header_spam(self):
        """Test shortcircuit using rules that match for header"""
        test_rule = ('HEADER_SPAM', 'X-Header', 'match_header', 'HEADER_SPAM',
                     '23.01', 'HEADER_SPAM', 'spam')

        self.setup_conf(config=CONFIG_HEADER % test_rule,
                        pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'Just testing header shortcircuit spam')

        # HEADER_SPAM: 23.01 & +100 (spam default) => 123.01
        self.check_report(result, 123.0, ['HEADER_SPAM'])

    def test_shortcircuit_header_ham(self):
        """Test shortcircuit using rules that match for header"""
        test_rule = ('HEADER_HAM', 'X-Header', 'match_header', 'HEADER_HAM',
                     '-23.01', 'HEADER_HAM', 'ham')

        self.setup_conf(config=CONFIG_HEADER % test_rule,
                        pre_config=PRE_CONFIG)

        result = self.check_pad(
            MSG % 'Just testing header shortcircuit ham')

        # HEADER_HAM: -23.01 & -100 (ham default) => -123.01
        self.check_report(result, -123.0, ['HEADER_HAM'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalShortCircuit, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
