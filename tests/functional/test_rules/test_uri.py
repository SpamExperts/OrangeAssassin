"""Tests uri rules."""
from __future__ import absolute_import
import tests.util


class TestBodyRules(tests.util.TestBase):

    def test_header_uri_rule_match(self):
        config = ("uri TEST_URI_RULE /^https:\/\/example.com$/")
        self.check_symbols("Please click this link https://example.com and follow the instructions",
                           config=config,
                           score=1.0, symbols=["TEST_URI_RULE"])

    def test_header_uri_rule_no_match(self):
        config = ("uri TEST_URI_RULE /^https:\/\/example.com$/")
        self.check_symbols("Please click this link https://test.com and follow the instructions",
                           config=config,
                           score=0.0, symbols=[])