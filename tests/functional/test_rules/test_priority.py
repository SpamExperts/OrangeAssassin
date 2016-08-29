"""Tests priority rules."""
from __future__ import absolute_import

import tests.util
import unittest

PRE_CONFIG = """
report _SCORE_
report _TESTS_
"""

CONFIG_BODY = r"""
body UNLIMITED /unlimited/i
priority UNLIMITED 3

body EMAIL /email/
priority EMAIL -5

body SPAM_TEST /spam_test/i
priority SPAM_TEST -5

body SPAM_ON /spam_on/i
priority SPAM_ON -6

body HAM_TEST /ham_test/
priority HAM_TEST 2
priority HAM_TEST 1

body HAM_ON /ham_on/i
priority HAM_ON 2

body TEST_RULE /abcd/
priority TEST_RULE 2

body TEST_OUT /test_out/
priority TEST_OUT  3
priority TEST_OUT -1

body MONEY /money/
priority MONEY 0.2
"""

CONFIG_INVALID = r"""
body EMAIL /email/
priority EMAIL -5

body MONEY /money/
priority MONEY first

body TEST_RULE /abcd/
priority TEST_RULE 2
"""

CONFIG_HEADER = r"""
header      LOOK_FOR_SUBJECT   Subject =~ /subject/
priority LOOK_FOR_SUBJECT 2

header      LOOK_FOR_SUBJECT_SPAM   Subject =~ /spam/
priority LOOK_FOR_SUBJECT_SPAM 3

header      LOOK_FOR_SUBJECT_HAM   Subject =~ /ham/
"""

CONFIG_FULL = r"""
full        NULL_IN_MESSAGES       /\x00/
priority    NULL_IN_MESSAGES 2

full        NULL_IN_MESSAGES_SECOND       /\x000/
priority    NULL_IN_MESSAGES_SECOND 2
"""

CONFIG_MIMEHEADER = r"""
mimeheader  HAS_PDF_ATTACHMENT  Content-Type =~ /^application\/pdf/i
priority  HAS_PDF_ATTACHMENT 2

mimeheader  HAS_JPEG_ATTACHMENT  Content-Type =~ /^application\/jpeg/i
priority HAS_JPEG_ATTACHMENT 3
"""

CONFIG_URI = r"""
uri         HAS_EXAMPLE_HTTPS   /^https:\/\/example.com$/\
priority HAS_EXAMPLE_HTTPS 2

uri         HAS_EXAMPLE_HTTP   /^http:\/\/example.com$/\
priority HAS_EXAMPLE_HTTP 4
"""

CONFIG_META = r"""
header      __DKIM_EXISTS           exists:DKIM-Signature
header      __EXAMPLE_COM_SENDER    From:addr =~ /@example.com/
uri         __HAS_EXAMPLE_HTTPS     /^https:\/\/example.com$/\

meta        NO_EXAMPLE_DKIM         __EXAMPLE_COM_SENDER && !__DKIM_EXISTS

meta        EXAMPLE_URL_SENDER      __EXAMPLE_COM_SENDER || __HAS_EXAMPLE_HTTPS

meta        NO_DKIM_AND_URL         EXAMPLE_URL_SENDER && NO_EXAMPLE_DKIM
priority NO_DKIM_AND_URL 2
"""

CONFIG_EVAL = r"""
loadplugin     Mail::SpamAssassin::Plugin::SPF
whitelist_from_spf test@example.com

header SPF_PASS     eval:check_for_spf_pass()

header SPF_WHITELIST    eval:check_for_spf_whitelist_from()
priority SPF_WHITELIST 2
"""

MSG = """Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
    (envelope-from <test@example.com>)
Subject: Test Message is a spam subject.
From: test@example.com
X-Header: match_header
Received-SPF: pass (google.com: domain of trac@seinternal.com designates\n
  2a01:4f8:202:1145::2 as permitted sender) client-ip=2a01:4f8:202:1145::2;
This is a test message.
Adjust the body for your case: %s
"""

MSG_MIMEHEADER = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [21.13.99.1]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.
Content-Type: application/pdf; name="file.pdf"
Content-Type: application/jpeg; name="picture.jpeg"

This is a test message.
"""

MSG_URI = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message

This is a test message.
Subject https://example.com
Subject http://example.com
"""

MSG_META = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message
From: test@example.com

This is a test message.
"""

class TestPriorityRules(tests.util.TestBase):

    def test_priority_rule_for_body_both_negative_priority(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "SPAM_ON email ")
        self.check_report(result, 2.0, ["EMAIL", "SPAM_ON"])

    def test_priority_rule_for_body_negative_and_positive(self):
        """Test two rules with negative and positive priority"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "abcd email")
        self.check_report(result, 2.0, ["TEST_RULE", "EMAIL"])

    def test_priority_rule_for_body_same_priority_positive(self):
        """Test two rules with same priority positive"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "HAM_ON abcd")
        self.check_report(result, 2.0, ["HAM_ON", "TEST_RULE"])

    def test_priority_rule_for_body_same_priority_negative(self):
        """Test two rules with same priority negative"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "SPAM_TEST email")
        self.check_report(result, 2.0, ["EMAIL", "SPAM_TEST"])

    def test_priority_rule_for_body_one_rule_two_priority_positive(self):
        """Test for one rule with two different priority positives"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "ham_test email")
        self.check_report(result, 2.0, ["HAM_TEST", "EMAIL"])

    def test_priority_rule_for_body_one_rule_two_priority_negative(self):
        """Test for one rule with two different priority negatives"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "test_out email")
        self.check_report(result, 2.0, ["TEST_OUT", "EMAIL"])

    def test_priority_rule_for_body_one_rule_with_two_priority_combined(self):
        """Test for one rule with two different priority positive and"""
        """negative"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "test_out email")
        self.check_report(result, 2.0, ["TEST_OUT", "EMAIL"])

    def test_priority_rule_for_body_multiple_rules(self):
        """Test three rules, one with priorities `3`, `-5`, `-5`"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "UNLIMITED email SPAM_TEST")
        self.check_report(result, 3.0, ["UNLIMITED", "SPAM_TEST", "EMAIL"])

    def test_priority_rule_for_body_with_default(self):
        """Test three rules, one with priorities default, `2`, `-5`"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "money email abcd")
        self.check_report(result, 3.0, ["MONEY", "TEST_RULE", "EMAIL"])

    def test_priority_rule_for_header_rules(self):
        """Test priority for header rules"""
        self.setup_conf(config=CONFIG_HEADER, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "subject spam")
        self.check_report(result, 2.0, ["LOOK_FOR_SUBJECT_SPAM",
                                        "LOOK_FOR_SUBJECT"])

    def test_priority_rule_for_full_rules(self):
        """Test priority for full rules"""
        self.setup_conf(config=CONFIG_FULL, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "\x00 \x000")
        self.check_report(result, 2.0, ["NULL_IN_MESSAGES",
                                        "NULL_IN_MESSAGES_SECOND"])

    def test_priority_rule_for_mimeheader_rules(self):
        """Test priority for mimeheader rules"""
        self.setup_conf(config=CONFIG_MIMEHEADER, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_MIMEHEADER)
        self.check_report(result, 2.0, ["HAS_JPEG_ATTACHMENT",
                                        "HAS_PDF_ATTACHMENT"])

    def test_priority_rule_for_uri_rules(self):
        """Test priority uri for rules"""
        self.setup_conf(config=CONFIG_URI, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_URI)
        self.check_report(result, 2.0, ["HAS_EXAMPLE_HTTP",
                                        "HAS_EXAMPLE_HTTPS"])

    def test_priority_rule_for_meta_rules(self):
        """Test priority for meta rules"""
        self.setup_conf(config=CONFIG_META, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_META)
        self.check_report(result, 3.0, ["NO_DKIM_AND_URL",
                                        "NO_EXAMPLE_DKIM",
                                        "EXAMPLE_URL_SENDER"])

    def test_priority_rule_for_eval_rules(self):
        """Test priority for eval rules"""
        self.setup_conf(config=CONFIG_EVAL, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 2.0, ["SPF_WHITELIST", "SPF_PASS"])

    def test_priority_rule_invalid_value(self):
        """Test priority for eval rules"""
        self.setup_conf(config=CONFIG_INVALID, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "money email abcd")
        self.check_report(result, 3.0, ["TEST_RULE", "MONEY", "EMAIL"])
