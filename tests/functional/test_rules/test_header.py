"""Tests header rules."""
from __future__ import absolute_import

import base64

import re

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

    def test_header_rule_multiple_score_match(self):
        config = ("header TEST_RULE1 Subject =~ /abcd/ \n"
                  "header TEST_RULE2 Subject =~ /dcba/ \n"
                  "score TEST_RULE1 4.2 \n"
                  "score TEST_RULE2 4.2")
        self.check_symbols("Subject: Test abcd dcba test\n\nTest email.",
                           config=config,
                           score=8.4, symbols=["TEST_RULE1", "TEST_RULE2"])

    def test_header_rule_multiple_score_no_match(self):
        config = ("header TEST_RULE1 Subject =~ /abcd/ \n"
                  "header TEST_RULE2 Subject =~ /dcba/ \n"
                  "score TEST_RULE1 4.2 \n"
                  "score TEST_RULE2 4.2")
        self.check_symbols("Subject: Test abc dcb test\n\nTest email.",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_gtube(self):
        config = ("header TEST_GTUBE Subject =~ /%s/ \n"
                  "score TEST_GTUBE 1000.0" % re.escape(GTUBE))
        self.check_symbols("Subject: Test %s test \n\nTest email." % GTUBE,
                           config=config,
                           score=1000.0, symbols=["TEST_GTUBE"])

    def test_header_rule_utf8(self):
        subject = "=?utf8?B?" + base64.b64encode("This is a spam message") + "?="
        config = ("header TEST_UTF8_ENCODE Subject:raw =~ /^=\?utf8\?/ \n"
                  "score TEST_UTF8_ENCODE -0.5")
        self.check_symbols("Subject: %s\n\nTest email." % subject,
                           config=config,
                           score=-0.5, symbols=["TEST_UTF8_ENCODE"])

    def test_header_rule_utf8_match(self):
        subject = "=?utf8?B?" + base64.b64encode("This is a spam message") + "?="
        config = "header TEST_UTF8_ENCODE Subject =~ /spam/"
        self.check_symbols("Subject: %s\n\nTest email." % subject,
                           config=config,
                           score=1.0, symbols=["TEST_UTF8_ENCODE"])

    def test_header_rule_utf8_no_match(self):
        subject = "=?utf8?B?" + base64.b64encode("This is a clean message") + "?="
        config = "header TEST_UTF8_ENCODE Subject =~ /spam/ \n"
        self.check_symbols("Subject: %s\n\nTest email." % subject,
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_modifiers_match_addr(self):
        config = ("header TEST_ADDR_RULE From:addr =~ /@example.com/ \n"
                  "score TEST_ADDR_RULE 4")
        self.check_symbols("From: Sender Name <SenderName@example.com\n\nTest email",
                           config=config,
                           score=4.0, symbols=["TEST_ADDR_RULE"])

    def test_header_rule_modifiers_no_match_addr(self):
        config = ("header TEST_ADDR_RULE From:addr =~ /@example.com/ \n"
                  "score TEST_ADDR_RULE 4")
        self.check_symbols("From: Sender Name <SenderName@test.com\n\nTest email",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_modifiers_match_name(self):
        config = ("header TEST_NAME_RULE From:name =~ /Name/ \n"
                  "score TEST_NAME_RULE 4")
        self.check_symbols("From: Sender Name <SenderName@test.com\n\nTest email",
                           config=config,
                           score=4.0, symbols=["TEST_NAME_RULE"])

    def test_header_rule_modifiers_no_match_name(self):
        config = ("header TEST_NAME_RULE From:name !~ /Name/ \n"
                  "score TEST_NAME_RULE 4")
        self.check_symbols("From: Firstname Lastname <SenderName@test.com\n\nTest email",
                           config=config,
                           score=4.0, symbols=["TEST_NAME_RULE"])

    def test_header_rule_exists_match(self):
        config = ("header TEST_DKIM_RULE exists:DKIM-Signature \n"
                  "score TEST_DKIM_RULE -5.0")
        self.check_symbols("DKIM-Signature: a=rsa-sha1; q=dns; d=example.com; i=user@eng.example.com; "
                           "s=jun2005.eng; c=relaxed/simple; t=1117574938; x=1118006938; h=from:to:subject:date; "
                           "h=from:to:subject:date; "
                           "b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR; ",
                           config=config,
                           score=-5.0, symbols=["TEST_DKIM_RULE"])

    def test_header_rule_exists_match(self):
        config = "header TEST_DKIM_RULE exists:DKIM-Signature"
        self.check_symbols("Subject: This is a test subject\n\nTest email",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_header_all_match(self):
        config = "header TEST_HEADER_RULE ALL =~ /spam/"
        self.check_symbols("From: Sender Name <name@test.com>\n"
                           "Subject: This is a spam subject\n"
                           "Return-Path: <name@test.com>",
                           config=config,
                           score=1.0, symbols=["TEST_HEADER_RULE"])

    def test_header_rule_header_all_no_match(self):
        config = "header TEST_HEADER_RULE ALL =~ /spam/"
        self.check_symbols("From: Sender Name <name@test.com>\n"
                           "Subject: This is a clear subject\n"
                           "Return-Path: <name@test.com>",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_header_ToCC_match(self):
        config = ("header TEST_HEADER_RULE ToCc =~ /@example.com/ \n"
                  "score TEST_HEADER_RULE 2.5")
        self.check_symbols("To: Receiver Name <name@example.com>\n\nTest message",
                           config=config,
                           score=2.5, symbols=["TEST_HEADER_RULE"])

    def test_header_rule_header_ToCC_no_match(self):
        config = "header TEST_HEADER_RULE ToCc =~ /@example.com/ \n"
        self.check_symbols("To: Receiver Name <name@test.com>\n\nTest message",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_header_messageid_match(self):
        config = "header TEST_MESSAGEID_RULE MESSAGEID =~ /example.com/"
        self.check_symbols("Message-ID: <test@example.com>\n\nTest message",
                           config=config,
                           score=1.0, symbols=["TEST_MESSAGEID_RULE"])

    def test_header_rule_header_messageid_no_match(self):
        config = "header TEST_MESSAGEID_RULE MESSAGEID =~ /example.com/"
        self.check_symbols("Message-ID: <test@test.com>\n\nTest message",
                           config=config,
                           score=0.0, symbols=[])

    def test_header_rule_mimeheader_match(self):
        config = "mimeheader TEST_MIMEHEADER_RULE Content-Type =~ /^application\/pdf/i"
        self.check_symbols("Content-Type: application/pdf;\n\nTest message",
                           config=config,
                           score=1.0, symbols=["TEST_MIMEHEADER_RULE"])

    def test_header_rule_mimeheader_no_match(self):
        config = "mimeheader TEST_MIMEHEADER_RULE Content-Type =~ /^application\/pdf/i"
        self.check_symbols("Content-Type: application/msword;\n\nTest message",
                           config=config,
                           score=0.0, symbols=[])
