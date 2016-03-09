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

uri         HAS_EXAMPLE_HTTPS_SECOND   /^https:\/\/example.com$/\z
priority HAS_EXAMPLE_HTTPS_SECOND 3
"""

CONFIG_META = r"""
meta        NO_EXAMPLE_DKIM         __EXAMPLE_COM_SENDER && !__DKIM_EXISTS
priority NO_EXAMPLE_DKIM 2

meta        EXAMPLE_URL_SENDER      __EXAMPLE_COM_SENDER || __HAS_EXAMPLE_HTTPS
priority EXAMPLE_URL_SENDER 3

meta        NO_DKIM_AND_URL         EXAMPLE_URL_SENDER && NO_EXAMPLE_DKIM
priority NO_DKIM_AND_URL 4
"""

CONFIG_EVAL = r"""
full        PYZOR_CHECK     eval:check_pyzor()
priority PYZOR_CHECK 2

full        PYZOR_CHECK_SECOND    seval:check_pyzor()
priority PYZOR_CHECK_SECOND 3
"""

MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.
X-Header: match_header

This is a test message.
Adjust the body for your case: %s
"""

MSG_MIMEHEADER = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [21.13.99.1]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test Message.
Content-Type: application/pdf; name="file.pdf"
Content-Type: application/jpeg; name="picture.jpeg"

MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_36205"

------=_MIME_BOUNDARY_000_36205
Content-Type: text/plain

This is a test mailing
------=_MIME_BOUNDARY_000_36205
Content-Type: application/octet-stream; name="fisier.pdf"
Content-Description: fisier.pdf
Content-Disposition: attachment; filename="fisier.pdf"
Content-Transfer-Encoding: BASE64

------=_MIME_BOUNDARY_000_36205--

This is a test message.
Adjust the body for your case: %s
"""

class TestPriorityRules(tests.util.TestBase):

    def test_priority_rule_both_negative_priority(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "SPAM_ON email ")
        self.check_report(result, 2.0, ["EMAIL", "SPAM_ON"])

    def test_priority_rule_negative_and_positive(self):
        """Test two rules with negative and positive priority"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "abcd email")
        self.check_report(result, 2.0, ["TEST_RULE", "EMAIL"])

    def test_priority_rule_same_priority_positive(self):
        """Test two rules with same priority positive"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "HAM_ON abcd")
        self.check_report(result, 2.0, ["HAM_ON", "TEST_RULE"])

    def test_priority_rule_same_priority_negative(self):
        """Test two rules with same priority negative"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "SPAM_TEST email")
        self.check_report(result, 2.0, ["EMAIL", "SPAM_TEST"])

    def test_priority_for_one_rule_two_priority_positive(self):
        """Test for one rule with two different priority positives"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "ham_test email")
        self.check_report(result, 2.0, ["HAM_TEST", "EMAIL"])

    def test_priority_for_one_rule_two_priority_negative(self):
        """Test for one rule with two different priority negatives"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "test_out email")
        self.check_report(result, 2.0, ["TEST_OUT", "EMAIL"])

    def test_priority_for_one_rule_with_two_priority_combined(self):
        """Test for one rule with two different priority positive and"""
        """negative"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "test_out email")
        self.check_report(result, 2.0, ["TEST_OUT", "EMAIL"])

    def test_priority_multiple_rules(self):
        """Test three rules, one with priorities `3`, `-5`, `-5`"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "UNLIMITED email SPAM_TEST")
        self.check_report(result, 3.0, ["UNLIMITED", "SPAM_TEST", "EMAIL"])

    def test_priority_rule_with_default(self):
        """Test three rules, one with priorities default, `2`, `-5`"""
        self.setup_conf(config=CONFIG_BODY, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "money email abcd")
        self.check_report(result, 3.0, ["MONEY", "TEST_RULE", "EMAIL"])

    @unittest.skip("This test fails at the moment and the code should be"
                   "fixed")
    def test_priority_rule_for_header_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_HEADER, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "subject spam", debug=True)
        print(result)
        self.check_report(result, 2.0, ["LOOK_FOR_SUBJECT_SPAM",
                                        "LOOK_FOR_SUBJECT"])

    @unittest.skip("This is not finished and the test fails")
    def test_priority_rule_for_full_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_FULL, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "\x00 \x000", debug=True)
        print(result)
        self.check_report(result, 2.0, ["NULL_IN_MESSAGES",
                                        "NULL_IN_MESSAGES_SECOND"])

    @unittest.skip("This is not finished and the test fails")
    def test_priority_rule_for_mimeheader_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_MIMEHEADER, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_MIMEHEADER % "test", debug=True)
        print(result)
        self.check_report(result, 3.0, ["HAS_JPEG_ATTACHMENT",
                                        "HAS_PDF_ATTACHMENT"])

    @unittest.skip("This is not finished and the test fails")
    def test_priority_rule_for_url_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_URI, pre_config=PRE_CONFIG)
        result = self.check_pad(
          MSG % "/^https:\/\/example.com$/\ /^https:\/\/example.com$/\second")
        print(result)
        self.check_report(result, 2.0, ["HAS_EXAMPLE_HTTPS_SECOND",
                                        "HAS_EXAMPLE_HTTPS"])

    @unittest.skip("This is not finished and the test fails")
    def test_priority_rule_for_meta_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_META, pre_config=PRE_CONFIG)
        result = self.check_pad(
          MSG % "")
        print(result)
        self.check_report(result, 2.0, ["NO_DKIM_AND_URL",
                                        "EXAMPLE_URL_SENDER",
                                        "NO_EXAMPLE_DKIM"])

    @unittest.skip("This is not finished and the test fails")
    def test_priority_rule_for_eval_rules(self):
        """Test two rules with two negative priority"""
        self.setup_conf(config=CONFIG_EVAL, pre_config=PRE_CONFIG)
        result = self.check_pad(MSG % "eval:check_pyzor() seval:check_pyzor()")
        print(result)
        self.check_report(result, 2.0, ["PYZOR_CHECK_SECOND", "PYZOR_CHECK"])
