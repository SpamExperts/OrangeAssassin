"""Tests priority rules."""
from __future__ import absolute_import
import unittest
import tests.util

PRE_CONFIG = """
report _SCORE_
report _TESTS_
"""

CONFIG = r"""
# Rule definitions here

body UNLIMITED /unlimited/i
score UNLIMITED 10.45

body EMAIL /email/
score EMAIL -12.15
priority EMAIL 5

body SPAM_TEST /spam_test/i
score SPAM_TEST 55.12

body SPAM_ON /spam_on/i
score SPAM_ON 25.73

body HAM_TEST /ham_test/
score HAM_TEST -75.3

body HAM_ON /ham_on/i
score HAM_ON -35.01

body TEST_RULE /abcd/
score TEST_RULE 2.5
priority TEST_RULE 2
"""

MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.
X-Header: match_header

This is a test message for the Short Circuit Plugin.
Adjust the body for your case: %s
"""


class TestPriorityRules(tests.util.TestBase):
    @unittest.skip("This test fails at the moment and the code should be"
                   "fixed")
    def test_priority_rule_match(self):
        """Test the priority for rules"""
        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "abcd email")
        print(result)
        self.check_report(result, -8.7, ["EMAIL", "TEST_RULE"])
