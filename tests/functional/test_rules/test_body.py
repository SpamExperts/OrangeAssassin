"""Tests body rules."""
from __future__ import absolute_import
import unittest

import tests.util

from tests.util import GTUBE


class TestBodyRules(tests.util.TestBase):

    def test_gtube_rule(self):
        """Check the GTUBE matched rule."""
        self.check_symbols("Subject: test\n\n%s" % GTUBE,
                           score=1000.0, symbols=["GTUBE"])

    def test_body_rule_match(self):
        self.check_symbols("Subject: test\n\nTest abcd test.",
                           config="body TEST_RULE /abcd/",
                           score=1.0, symbols=["TEST_RULE"])

    def test_body_rule_case_insensitive_match(self):
        self.check_symbols("Subject: test\n\nTest ABCD test.",
                           config="body TEST_RULE /abcd/i",
                           score=1.0, symbols=["TEST_RULE"])

    def test_body_rule_no_match(self):
        self.check_symbols("Subject: test\n\nTest abc test.",
                           config="body TEST_RULE /abcd/",
                           score=0.0, symbols=[])

    def test_body_rule_score_match(self):
        config = ("body TEST_RULE /abcd/ \n"
                  "score TEST_RULE 4.2")
        self.check_symbols("Subject: test\n\nTest abcd test.",
                           config=config,
                           score=4.2, symbols=["TEST_RULE"])

    def test_invalid_body_rule_score_match(self):
        config = ("body TEST_RULE /#$%#$/ \n"
                  "score TEST_RULE 4.2")
        message = "Subject: test\n\nTest #$%#$ test."
        self.setup_conf(config=config)
        result = self.check_pad(message)
        expected = ""
        self.assertEqual(expected, result)

    def test_body_rule_score_no_match(self):
        config = ("body TEST_RULE /abcd/ \n"
                  "score TEST_RULE 4.2")
        self.check_symbols("Subject: test\n\nTest abc test.",
                           config=config,
                           score=0.0, symbols=[])

    def test_body_rule_multiple_match(self):
        config = ("body TEST_RULE1 /abcd/ \n"
                  "body TEST_RULE2 /dcba/ \n")
        self.check_symbols("Subject: test\n\nTest dcba abcd test.",
                           config=config,
                           score=2, symbols=["TEST_RULE1", "TEST_RULE2"])

    def test_body_rule_multiple_no_match(self):
        config = ("body TEST_RULE1 /abcd/ \n"
                  "body TEST_RULE2 /dcba/ \n")
        self.check_symbols("Subject: test\n\nTest dcb abc test.",
                           config=config,
                           score=0.0, symbols=[])