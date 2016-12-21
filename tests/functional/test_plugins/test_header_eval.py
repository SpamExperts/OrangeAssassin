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

class TestFunctionalCheckForFakeAolRelayInRcvd(tests.util.TestBase):

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


class TestFunctionalCheckForFarawayCharset(tests.util.TestBase):

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


class TestFunctionalCheckForUniqueSubjectId(tests.util.TestBase):

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


class TestFunctionalCheckIllegalCharsInHeader(tests.util.TestBase):

    def test_check_illegal_chars_in_header_match_ratio_and_count(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.5','2')"

        email = u"MyHeader: ὲὲaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_illegal_chars_in_header_not_match_ratio_and_count(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.6','2')"

        email = u"MyHeader: ὲὲaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_no_illegal_chars_in_header(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0.5','1')"

        email = u"MyHeader: aaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_header_match_if_ratio_and_count_zero(self):

        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0','0')"

        email = u"MyHeader: aaaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_illegal_chars_if_empty_header(self):
        config = "header TEST_RULE eval:check_illegal_chars('MyHeader','0','0')"

        email = u"MyHeader:"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_multiple_subject_exemptions(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.5','3')"

        email = u"Subject:  ®¢£aaa"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def text_check_illegal_chars_single_subject_exemption_registered(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = u"Subject: ®aa";

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_single_subject_exemption_cent(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = u"Subject: a¢a"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def text_check_illegal_chars_single_subject_exemption_pound(self):

        config = "header TEST_RULE eval:check_illegal_chars('Subject','0.33','1')"

        email = u"Subject: aa£"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_all_headers_with_from_and_subject(self):

        config = "header TEST_RULE eval:check_illegal_chars('ALL','0.5','3')"

        email = (u"Subject: a∞a∞a∞\n"
                 u"From: a∞a∞a∞")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_illegal_chars_in_all_headers(self):
        config = "header TEST_RULE eval:check_illegal_chars('ALL','0.45','5')"

        email = (u"To: a∞a∞a∞\n"
                 u"Cc: a∞a∞a")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckForForgedHotmailReceivedHeaders(tests.util.TestBase):

    def test_check_for_forget_hotmail_received_headers_match(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "by example.com\n"
                 "(envelope-from <example.com.user@something>)\n"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE1'])

    def test_check_for_forget_hotmail_received_headers_false_addr(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "by example.com\n"
                 "(envelope-from <example.com.user@something>)\n"
                 "From: user@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE1'])

    def test_check_for_forget_hotmail_received_headers_false_pickup(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from mail pickup service by hotmail.com with Microsoft SMTPSVC;"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forget_hotmail_received_headers_false_gated_true(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "by example.com\n"
                 "(envelope-from <example.com.user@something>)\n"
                 "X-ORIGINATING-IP: [1.2.3.4]\n"
                 "From: user@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE1'])

    def test_check_for_forget_hotmail_received_headers_ip_regex1(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from user.hotmail.com (user.hotmail.com)\n"
                 "X-ORIGINATING-IP: [1.2.3.4]\n"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forget_hotmail_received_headers_ip_regex2(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from example.hotmail.com ([1.2.3.4])\n"
                 "X-ORIGINATING-IP: [1.2.3.4]\n"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forget_hotmail_received_headers_ip_regex3(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from example by example.hotmail.com with HTTP;\n"
                 "X-ORIGINATING-IP: [1.2.3.4]\n"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forget_hotmail_received_headers_ip_regex4(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from [66.218.example] by example.yahoo.com\n"
                 "X-ORIGINATING-IP: [1.2.3.4]\n"
                 "From: user@hotmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForFakeAolRelayInRcvd, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForFarawayCharset, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForUniqueSubjectId, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckIllegalCharsInHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForForgedHotmailReceivedHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForNoHotmailReceivedHeaders, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
