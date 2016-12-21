"""Tests the HeaderEval Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin Mail::SpamAssassin::Plugin::HeaderEval
report _SCORE_
report _TESTS_
"""

class TestFunctionalHeaderEval(tests.util.TestBase):

    def test_check_for_fake_aol_relay_in_rcvd_match(self):

        config = "header TEST_RULE eval:check_for_fake_aol_relay_in_rcvd()"

        email = ("Received: from unknown (HELO mta05bw.bigpond.com) (80.71.176.130) "
         "by rly-xw01.mx.aol.com with QMQP; Sat, 15 Jun 2002 "
         "23:37:16 -0000")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_fake_aol_relay_in_rcvd_not_match1(self):

        config = "header TEST_RULE eval:check_for_fake_aol_relay_in_rcvd()"

        email = ("Received: from  rly-xj02.mx.aol.com (rly-xj02.mail.aol.com "
                 "[172.20.116.39]) by omr-r05.mx.aol.com (v83.35) with "
                 "ESMTP id RELAYIN7-0501132011; Wed, 01 May 2002 "
                 "13:20:11 -0400")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


    def test_check_for_fake_aol_relay_in_rcvd_not_match2(self):

        config = "header TEST_RULE eval:check_for_fake_aol_relay_in_rcvd()"

        email = ("Received: from logs-tr.proxy.aol.com (logs-tr.proxy.aol.com "
                 "[152.163.201.132]) by rly-ip01.mx.aol.com "
                 "(8.8.8/8.8.8/AOL-5.0.0) with ESMTP id NAA08955 for "
                 "<sapient-alumni@yahoogroups.com>; Thu, 4 Apr 2002 13:11:20 "
                 "-0500 (EST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_fake_aol_relay_in_rcvd_not_match_aol(self):

        config = "header TEST_RULE eval:check_for_fake_aol_relay_in_rcvd()"

        email = ("Received: by 10.28.54.13 with SMTP id d13csp1785386wma; Mon, "
                  "28 Nov 2016 07:40:07 -0800 (PST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

# ==============================================================================

    def test_check_for_faraway_charset_in_headers_match(self):

        config = ("header TEST_RULE eval:check_for_faraway_charset_in_headers()\n"
            "ok_locales ru")

        email = "Subject: This is a test subject"

        print(config)

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_faraway_charset_in_headers_not_match(self):

        config = "header TEST_RULE eval:check_for_faraway_charset_in_headers()"

        email = "Subject: This is a test subject"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

# ==============================================================================

    def test_check_for_unique_subject_id_starting_with_special_char_match(self):

        config = "header TEST_RULE eval:check_for_unique_subject_id()"

        email = "Subject: This is a test subject   :3ad41d421"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_unique_subject_id_in_parenthesis_match(self):

        config = "header TEST_RULE eval:check_for_unique_subject_id()"

        email = "Subject: This is a test subject (7217vPhZ0-478TLdy5829qicU9-0@26)"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_unique_subject_id_starting_with_number_sign(self):

        config = "header TEST_RULE eval:check_for_unique_subject_id()"

        email = "Subject: This is a test subject #30D7"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_unique_subject_id_not_match(self):

        config = "header TEST_RULE eval:check_for_unique_subject_id()"

        email = "Subject: This is a test subject 7217vPhZ0-478TLdy5829qicU9-0@26"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

# ==============================================================================

    def test_check_illegal_chars_in_header_match_ratio_and_count(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.5','2')"

        email = "MyHeader: ὲὲaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_illegal_chars_in_header_not_match_ratio_and_count(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.6','2')"

        email = "MyHeader: ὲὲaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_no_illegal_chars_in_header(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.5','1')"

        email = "MyHeader: aaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_header_match_if_ratio_and_count_zero(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0','0')"

        email = "MyHeader: aaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_illegal_chars_if_empty_header(self):
        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0','0')"

        email = "MyHeader:"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_multiple_subject_exemptions(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.5','3')"

        email = "Subject:  ®¢£aaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def text_check_illegal_chars_single_subject_exemption_registered(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = "Subject: ®aa";

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_single_subject_exemption_cent(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = "Subject: a¢a"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_single_subject_exemption_pound(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = "Subject: aa£"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_all_headers_with_from_and_subject(self):

        config = "header TEST_RULE eval:check_illegal_chars('ALL','0.5','3')"

        email = ("Subject: a∞a∞a∞\n"
                 "From: a∞a∞a∞")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_all_headers(self):
        config = "header TEST_RULE eval:check_illegal_chars('ALL','0.45','5')"

        email = ("To: a∞a∞a∞\n"
                 "Cc: a∞a∞a")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalHeaderEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
