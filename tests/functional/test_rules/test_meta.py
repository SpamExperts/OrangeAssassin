"""Tests meta rules."""
from __future__ import absolute_import
import tests.util


class TestBodyRules(tests.util.TestBase):

    def test_header_meta_rule_and_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE && __TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 4.0")
        self.check_symbols("DKIM-Signature: TestDkim \n"
                           "From: test <test@example.com>",
                           config=config,
                           score=4.0, symbols=["TEST_DKIM_AND_FROM"])

    def test_header_meta_rule_and_no_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE && __TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 4.0")
        self.check_symbols("DKIM-Signature: TestDkim \n"
                           "From: test <test@test.com>",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_meta_rule_or_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE || __TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 4.0")
        self.check_symbols("DKIM-Signature: TestDkim \n"
                           "From: test <test@test.com>",
                           config=config,
                           score=4.0, symbols=["TEST_DKIM_AND_FROM"])

    def test_header_meta_rule_or_no_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE || __TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 4.0")
        self.check_symbols("To: test2 <test@example.com> \n"
                           "From: test <test@test.com>",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_meta_rule_not_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE || !__TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 4.0")
        self.check_symbols("To: test2 <test@example.com> \n"
                           "From: test <test@test.com>",
                           config=config,
                           score=4.0, symbols=["TEST_DKIM_AND_FROM"])

    def test_header_meta_rule_not_no_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE || !__TEST_SENDER_RULE \n" # One of them should be true
                  "score TEST_DKIM_AND_FROM 4.0")                                      # For this example the second is
        self.check_symbols("To: test2 <test@example.com> \n"
                           "From: test <test@example.com>",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_meta_rule_combined_match(self):
        config = ("header __TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "header __TEST_SENDER_RULE From:addr =~ /@example.com/ \n"
                  "uri __TEST_URI_RULE /^https:\/\/example.com$/ \n"
                  "meta TEST_DKIM_AND_FROM __TEST_DKIM_RULE && __TEST_SENDER_RULE \n"
                  "score TEST_DKIM_AND_FROM 2 \n"
                  "meta TEST_FROM_AND_URL __TEST_SENDER_RULE && __TEST_URI_RULE \n"
                  "score TEST_FROM_AND_URL 2 \n"
                  "meta TEST_ALL_RULE TEST_DKIM_AND_FROM && TEST_FROM_AND_URL \n"
                  "score TEST_ALL_RULE 5")  # 2 + 2 + 5 = 9
        self.check_symbols("DKIM-Signature: TestDkim \n"
                           "From: test <test@example.com>\n\n"
                           "Please click this link: https://example.com and follow the instructions",
                           config=config,
                           score=9.0, symbols=["TEST_DKIM_AND_FROM", "TEST_FROM_AND_URL", "TEST_ALL_RULE"])