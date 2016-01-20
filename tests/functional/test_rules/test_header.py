"""Tests header rules."""
from __future__ import absolute_import

import tests.util

from tests.util import GTUBE


class TestBodyRules(tests.util.TestBase):

    def test_header_rule_match(self):
        self.check_symbols("Subject: test abcd test\n\nTest email.",
                           config="header TEST_RULE Subject =~ /abcd/",
                           score=1.0, symbols=["TEST_RULE"])

    def test_header_rule_no_match(self):
        self.check_symbols("Subject: test abc test\n\nTest email.",
                           config="header TEST_RULE Subject =~ /abcd/",
                           score=0.0, symbols=[])

    def test_header_rule_score_match(self):
        config = ("header TEST_RULE Subject =~ /abcd/ \n"
                  "score TEST_RULE 4.2")
        self.check_symbols("Subject: test abcd test\n\nTest email.",
                           config=config,
                           score=4.2, symbols=["TEST_RULE"])

    def test_header_rule_score_no_match(self):
        config = ("header TEST_RULE Subject =~ /abcd/ \n"
                  "score TEST_RULE 4.2")
        self.check_symbols("Subject: test abc test\n\nTest email.",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_multiple_match(self):
        config = ("header TEST_RULE1 Subject =~ /abcd/ \n"
                  "header TEST_RULE2 Subject =~ /dcba/ \n")
        self.check_symbols("Subject: Test dcba abcd test\n\nTest email.",
                           config=config,
                           score=2, symbols=["TEST_RULE1", "TEST_RULE2"])

    def test_header_rule_multiple_no_match(self):
        config = ("header TEST_RULE1 Subject =~ /abcd/ \n"
                  "header TEST_RULE2 Subject =~ /dcba/ \n")
        self.check_symbols("Subject: Test dcb abc test\n\nTest email.",
                           config=config,
                           score=0.0, symbols=[])