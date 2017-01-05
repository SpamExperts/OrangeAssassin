#coding:utf8
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

    def test_check_for_faraway_charset_in_headers_match_subject(self):

        config = ("header TEST_RULE eval:check_for_faraway_charset_in_headers()\n"
                  "ok_locales ru")

        email = "Subject: This is a test subject"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_faraway_charset_in_headers_match_from(self):

        config = ("header TEST_RULE eval:check_for_faraway_charset_in_headers()\n"
                  "ok_locales ru")

        email = "From: This is a test subject"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_faraway_charset_in_headers_not_match(self):

        config = "header TEST_RULE eval:check_for_faraway_charset_in_headers()"

        email = "Subject: This is a test subject"

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_faraway_charset_in_headers_with_all_locales(self):

        config = ("header TEST_RULE eval:check_for_faraway_charset_in_headers()\n"
                  "ok_locales all")

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

    def test_check_for_forget_hotmail_received_headers_no_from_address(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forget_hotmail_received_headers_with_msn_group_headers(self):

        config = ("header TEST_RULE1 eval:check_for_forged_hotmail_received_headers()\n"
                  "header TEST_RULE2 eval:check_for_no_hotmail_received_headers()\n")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <testid123-bounce@groups.msn.com>)\n"
                 "Message-Id: <testid123-aaa@groups.msn.com>\n"
                 "To: <testid123@groups.msn.com>\n"
                 "From: testid123-aaa@groups.msn.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

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


class TestFunctionalCheckForMsnGroupsHeaders(tests.util.TestBase):

    def test_check_for_msn_groups_headers_match(self):

        config = ("header TEST_RULE eval:check_for_msn_groups_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <testid123-bounce@groups.msn.com>)\n"
                 "Message-Id: <testid123-aaa@groups.msn.com>\n"
                 "To: <testid123@groups.msn.com>\n"
                 "From: testid123-aaa@groups.msn.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_msn_groups_headers_match_listname_notifications(self):

        config = ("header TEST_RULE eval:check_for_msn_groups_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Message-Id: <anything@p23.groups.msn.com>\n"
                 "To: <notifications@groups.msn.com>")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_msn_groups_headers_wrong_message_id(self):

        config = ("header TEST_RULE eval:check_for_msn_groups_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <testid123-bounce@groups.msn.com>)\n"
                 "Message-Id: <testid123@groups.msn.com>\n"
                 "To: <testid123@groups.msn.com>\n"
                 "From: testid123-aaa@groups.msn.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_msn_groups_headers_wrong_sender_address(self):

        config = ("header TEST_RULE eval:check_for_msn_groups_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Received: from hotmail.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <testid123@groups.msn.com>)\n"
                 "Message-Id: <testid123-aaa@groups.msn.com>\n"
                 "To: <notifications@groups.msn.com>\n"
                 "From: testid123-aaa@groups.msn.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_msn_groups_headers_not_match_listname_notifications(self):

        config = ("header TEST_RULE eval:check_for_msn_groups_headers()")

        email = ("Received: from mail pickup service by p23.groups.msn.com\n"
                 "Message-Id: <anything@groups.msn.com>\n"
                 "To: <notifications@groups.msn.com>")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalGatedThroughReceivedHdrRemover(tests.util.TestBase):

    def test_gated_through_received_hdr_remover(self):

        config = "header TEST_RULE eval:gated_through_received_hdr_remover()"

        email = ("Mailing-List: contact test@example.com; run by ezmlm\n"
                 "Received: (qmail 47240 invoked by uid 33); 01 Oct 2010 20:35:23 +0000\n"
                 "Delivered-To: mailing list test@example.com\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_gated_through_received_hdr_remover_no_rcvd(self):

        config = "header TEST_RULE eval:gated_through_received_hdr_remover()"

        email = ("Mailing-List: contact test@example.com; run by ezmlm\n"
                 "Delivered-To: mailing list test@example.com\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_gated_through_received_hdr_remover_with_msngroups(self):

        config = "header TEST_RULE eval:gated_through_received_hdr_remover()"

        email = ("Received: from groups.msn.com (test.msn.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckForForgedEudoramailReceivedHeaders(tests.util.TestBase):

    def test_check_for_forged_eudoramail_received_headers_not_gated_through_received_hdr_remover(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_eudoramail_received_headers_gated_through_received_hdr_remover(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("Mailing-List: contact test@example.com; run by ezmlm\n"
                 "Received: (qmail 47240 invoked by uid 33); 01 Oct 2010 20:35:23 +0000\n"
                 "Delivered-To: mailing list test@example.com\n"
                 "From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_eudoramail_received_headers_no_rcvd(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


    def test_check_for_forged_eudoramail_received_headers_rcvd_from_msngroups(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("Received: from groups.msn.com (test.msn.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_eudoramail_received_headers_rcvd_whowhere_with_valid_sender_ip(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby whowhere.com;\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Sender-Ip: 1.2.3.4\n"
                 "From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_eudoramail_received_headers_rcvd_whowhere_with_invalid_sender_ip(self):

        config = "header TEST_RULE eval:check_for_forged_eudoramail_received_headers()"

        email = ("Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby whowhere.com;\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Sender-Ip: invalid\n"
                 "From: test@eudoramail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

class TestFunctionalCheckForForgedYahooReceivedHeaders(tests.util.TestBase):

    def test_check_for_forged_yahoo_received_headers_not_yahoo_domain_in_from(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@google.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_yahoo_domain_in_from(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_via_http(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby web12ceva.mail77ceva.test123.yahoo.com via HTTPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_via_http_negative(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby web12ceva.mail77ceva.test123.yahoo.com with HTTP\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_via_http_no_http(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby web12ceva.mail77ceva.test123.yahoo.com with SMTP\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_smtp(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby smtpceva12.test123.yahoo.com with SMTPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_smtp_negative(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example1.com (example2.com [1.2.3.4])\n"
                 "\tby smttpceva12.smtptest123.yahoo.com with SMTP\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_nnfmp_groups(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from [1.2.3.4]\n"
                 "\tby test123.groups.yahoo.com with NNFMPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_nnfmp_groups_negative(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from (ceva.com [1.2.3.4])\n"
                 "\tby test123.groups.yahoo.com with NNFMPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_nnfmp_scd(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from [1.2.3.4]\n"
                 "\tby test123.scd.yahoo.com with NNFMPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_nnfmp_dcn(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from [1.2.3.4]\n"
                 "\tby test123.dcn.yahoo.com with NNFMPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_nnfmp_other(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from [1.2.3.4]\n"
                 "\tby test123.other.yahoo.com with NNFMPceva\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_gated_through_received_hdr_remover(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Mailing-List: contact test@example.com; run by ezmlm\n"
                 "Received: (qmail 47240 invoked by uid 33); 01 Oct 2010 20:35:23 +0000\n"
                 "Delivered-To: mailing list test@example.com\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_bulk_scd_negative(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from mailer123.bulk.scd.yahoo.com\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@reply.test.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_bulk_scd_diff_domain(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from mailer123.bulk.scd.yahoo.com\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@ceva.reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_bulk_scd(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from mailer123.bulk.scd.yahoo.com\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_bulk_scd_in_by(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example.com (ceva.com [1.2.3.4])\n"
                 "\tby mailer123.bulk.scd.yahoo.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_bulk_scd_in_by_diff_domain(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example.com (ceva.com [1.2.3.4])\n"
                 "\tby mailer123.bulk.scd.yahoo.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@ceva.reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_bulk_scd_in_by_with_incorrect_domain(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from example.com (ceva.com [1.2.3.4])\n"
                 "\tby mailer123.bulk.scd.yahooo.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_id(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from (ceva.com [1.2.3.4])\n"
                 "\tby ceva12.ceva123.yahoo.com (1.2.3/2.2.2) id w5si53504623wjf.107.2017.01.04.05.05.55\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_esmtp(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from (ceva.com [1.2.3.4])\n"
                 "\tby ceva12.ceva123.yahoo.com (1.2.3/2.2.2) with ESMTP id w5si53504623wjf.107.2017.01.04.05.05.55\n"
                 "\tfor <testers@spamexperts.com>; Wed, 04 Jan 2017 05:04:48 -0800 (PST)\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_id_negative(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from (ceva.com [1.2.3.4])\n"
                 "\tby ceva12.ceva123.yahoo.com (1.2.3/2.2.2) with ESMTPS id w5si53504623wjf.107.2017.01.04.05.05.55\n"
                 "\t(envelope-from <test@example.com>\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_x_received(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by smtp123.yahoo.com with SMTP id 201mr48450881ioc.67.1483535087773\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_via_http(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by web12ceva.mail77ceva.test123.yahoo.com via HTTPceva id 201mr48450881ioc.67.1483535087773\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_with_groups(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: from [1.2.3.4] by test123.groups.yahoo.com with NNFMPceva\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_with_scd(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: from [1.2.3.4] by test123.scd.yahoo.com with NNFMPceva\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_with_dcn(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: from [1.2.3.4] by test123.dcn.yahoo.com with NNFMPceva\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_no_resent_from(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by smtp123.yahoo.com with SMTP id 201mr48450881ioc.67.1483535087773\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_x_received_no_resent_to(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by smtp123.yahoo.com with SMTP id 201mr48450881ioc.67.1483535087773\n"
                 "Resent-From: example.com\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_x_received_first(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("X-Received: by 1.2.3.4 with SMTP id 201mr48450881ioc.67.1483535087773\n"
                 "Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby smtp123.yahoo.com with SMTP\n"
                 "\t(envelope-from <test@example.com>\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_forged_yahoo_received_headers_with_x_received_id_format(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by ceva123.test77.yahoo.com (8.14.4/8.13.8) id u5I50E6V009236\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_id_format_and_esmtp(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by ceva123.test77.yahoo.com (8.14.4/8.13.8) with ESMTP id u5I50E6V009236\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_yahoo_received_headers_with_x_received_bulk_scd(self):

        config = "header TEST_RULE eval:check_for_forged_yahoo_received_headers()"

        email = ("Received: from ceva.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>\n"
                 "X-Received: by mailer321.bulk.scd.yahoo.com\n"
                 "Resent-From: example.com\n"
                 "Resent-To: test@example.net\n"
                 "From: test@reply.yahoo.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

class TestFunctionalCheckForMissingToHeader(tests.util.TestBase):

    def test_check_for_missing_to_header(self):

        config = "header TEST_RULE eval:check_for_missing_to_header()"

        email = ("From: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_for_existing_to_header(self):

        config = "header TEST_RULE eval:check_for_missing_to_header()"

        email = ("To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_existing_apparently_to_header(self):

        config = "header TEST_RULE eval:check_for_missing_to_header()"

        email = ("Apparently-To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalSubjectIsAllCaps(tests.util.TestBase):


    def test_subject_is_all_caps_but_single_word(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: THISISATESTSUBJECT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_subject_is_all_caps_but_less_than_10_chars(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: SUB JECT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_subject_is_all_caps_match(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: THISISAT ESTSUBJECT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_subject_is_all_caps_strip_uppercase_notations_in_subject(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: RE:THISI SAT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_subject_is_all_caps_strip_capitalized_notations_in_subject(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: Re:THIS IS A TEST SUBJECT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_subject_is_all_caps_strip_lowercase_notations_in_subject(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: re:THIS IS A TEST SUBJECT")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_subject_is_all_caps_false(self):

        config = "header TEST_RULE eval:subject_is_all_caps()"

        email = ("Subject: this is a test subject")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalCheckForToInSubject(tests.util.TestBase):

    def test_check_for_to_in_subject_full_address_match(self):

        config = ("header TEST_RULE1 eval:check_for_to_in_subject('address')\n"
                  "header TEST_RULE2 eval:check_for_to_in_subject('user')")

        email = ("Subject: test@example.com\n"
                 "To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE1'])

    def test_check_for_to_in_subject_full_address_dont_match(self):

        config = ("header TEST_RULE1 eval:check_for_to_in_subject('address')"
                  "header TEST_RULE2 eval:check_for_to_in_subject('user')")

        email = ("Subject: test@example.net\n"
                 "To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_to_in_subject_user_match(self):

        config = ("header TEST_RULE1 eval:check_for_to_in_subject('address')\n"
                  "header TEST_RULE2 eval:check_for_to_in_subject('user')")

        email = ("Subject: test\n"
                 "To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE2'])


    def test_check_for_to_in_subject_user_dont_match(self):

        config = ("header TEST_RULE1 eval:check_for_to_in_subject('address')\n"
                  "header TEST_RULE2 eval:check_for_to_in_subject('user')")

        email = ("Subject: This is a testing case\n"
                 "To: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalCheckMessageidNotUsable(tests.util.TestBase):

    def test_check_messageid_not_usable_list_unsibscribe(self):

        config = "header TEST_RULE eval:check_messageid_not_usable()"

        email = ("List-Unsubscribe: <mailto:example-unsubscribe@-espc-tech-12345N@domain.com>\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_messageid_not_usable_gated_through_received_hdr_remover(self):

        config = "header TEST_RULE eval:check_messageid_not_usable()"

        email = ("Mailing-List: contact test@example.com; run by ezmlm\n"
                 "Received: (qmail 47240 invoked by uid 33); 01 Oct 2010 20:35:23 +0000\n"
                 "Delivered-To: mailing list test@example.com\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_messageid_not_usable_cwt_dce(self):

        config = "header TEST_RULE eval:check_messageid_not_usable()"

        email = ("Received:  by smtp.mesvr.com (8.14.4/8.13.8/CWT/DCE) with ESMTP id u5I50E6V009236")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_messageid_not_usable_dont_match(self):

        config = "header TEST_RULE eval:check_messageid_not_usable()"

        email = ("Received: by 10.107.170.150 with HTTP; Thu, 22 Dec 2016 03:54:03 -0800 (PST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_messageid_not_usable_iplanet_messaging_server(self):

        config = "header TEST_RULE eval:check_messageid_not_usable()"

        email = ("Received: by iPlanet Messaging Server (10.107.170.150) with HTTP; Thu, 22 Dec 2016 03:54:03 -0800 (PST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckOutlookMessageId(tests.util.TestBase):

    def test_check_outlook_invalid_message_id(self):

        config = "header TEST_RULE eval:check_outlook_message_id()"

        email = ("Message-ID: <CA+KsZ1C=Lm-ehUW7wQuGud7ifh6_dQDzy>")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_outlook_message_id(self):

        config = "header TEST_RULE eval:check_outlook_message_id()"

        email = ("Message-ID: <111112a45678$111b1111$1111a111@>\n"
                 "Date: Tue, 29 Nov 2016 14:38:59 +0200\n"
                 "Received: by 10.28.145.16 with SMTP id t16csp2363316wmd;\n"
                 "Tue, 29 Nov 2016 04:39:00 -0800 (PST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckHeaderCountRange(tests.util.TestBase):

    def test_check_header_count_range(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', 2, 3)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.net")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_unique_header_count_range(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', 2, 3)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_header_count_invalid_range(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', 3, 2)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.net")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_header_count_negative_range(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', -3, -2)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.net")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_header_count_combined_range(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', -1, 2)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.net")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_header_count_same_edges(self):

        config = "header TEST_RULE eval:check_header_count_range('MyHeader', 2, 2)"

        email = ("MyHeader: test@example.com\n"
                 "MyHeader: test@example.net")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckUnresolvedTemplate(tests.util.TestBase):

    def test_check_unresolved_template_true(self):

        config = "header TEST_RULE eval:check_unresolved_template()"

        email = ("Delivered-To: user@gmail.com%AA\n"
                 "Received: from smtp.mesvr.com (localhost.localdomain [127.0.0.1])\n"
                 "From: user@gmail.com\n"
                 "Date: Tue, 10 Nov 2016 14:38:59 +0200\n"
                 "Subject: This is a test\n"
                 "To: user@gmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_unresolved_template_false(self):

        config = "header TEST_RULE eval:check_unresolved_template()"

        email = ("Delivered-To: user@gmail.com\n"
                 "Received: from smtp.mesvr.com (localhost.localdomain [127.0.0.1])\n"
                 "From: user@gmail.com\n"
                 "Date: Tue, 10 Nov 2016 14:38:59 +0200\n"
                 "Subject: This is a test\n"
                 "To: user@gmail.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalCheckRatwareNameId(tests.util.TestBase):


    def test_check_ratware_name_id_match(self):

        config = "header TEST_RULE eval:check_ratware_name_id()"

        email = ('Message-Id: <AAAAAAAAAAAAAAAAAAAAAAAAAAAA.EXAMPLE>\n'
                 'From: "UNSER EXAMPLE" <EXAMPLE>')

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


    def test_check_ratware_name_id_dont_match(self):


        config = "header TEST_RULE eval:check_ratware_name_id()"

        email = ('Message-Id: <AAAAAAAAAAAAAAAAAAAAAAAAAAAA>\n'
                 'From: "UNSER EXAMPLE" <EXAMPLE>')

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalCheckRatwareEnvelopeFrom(tests.util.TestBase):

    def test_check_ratware_envelope_from(self):

        config = ("header TEST_RULE eval:check_ratware_envelope_from()\n"
                  "util_rb_tld com")

        email = ("To: user@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <example.com.user@something>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])

    def test_check_ratware_envelope_from_SRS(self):

        config = "header TEST_RULE eval:check_ratware_envelope_from()"

        email = ("To: user@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <SRS5=example.com.user@something>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_ratware_envelope_from_invalid_domain(self):

        config = "header TEST_RULE eval:check_ratware_envelope_from()"

        email = ("To: user@examplecom\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <example.com.user@something>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_ratware_envelope_from_no_to_header(self):

        config = "header TEST_RULE eval:check_ratware_envelope_from()"

        email = ("Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <example.com.user@something>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_ratware_envelope_from_no_envelope_from(self):

        config = "header TEST_RULE eval:check_ratware_envelope_from()"

        email = ("To: user@example.com")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_ratware_envelope_from_false(self):

        config = "header TEST_RULE eval:check_ratware_envelope_from()"

        email = ("To: user@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <user@example.com>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


class TestFunctionalCheckForForgedGw05ReceivedHeaders(tests.util.TestBase):

    def test_check_for_forged_gw05_received_headers_dont_match(self):

        config = "header TEST_RULE eval:check_for_forged_gw05_received_headers()"

        email = ("Received: by 10.107.5.198 with SMTP id 189csp3231581iof;\n"
                 "Wed, 21 Dec 2016 05:56:26 -0800 (PST)")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_forged_gw05_received_headers_match(self):

        config = "header TEST_RULE eval:check_for_forged_gw05_received_headers()"

        email = ("Received: from mail3.icytundra.com by gw05 with ESMTP;\n"
                 "\tThu, 21 Jun 2001 02:28:32 -0400")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


class TestFunctionalCheckForMatchingEnvAndHdrFrom(tests.util.TestBase):

    def test_check_for_matching_env_and_hdr_from_true(self):

        config = "header TEST_RULE eval:check_for_matching_env_and_hdr_from()"

        email = ("From: test@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['TEST_RULE'])


    def test_check_for_matching_env_and_hdr_from_true_multi_relays(self):

        config = "header TEST_RULE eval:check_for_matching_env_and_hdr_from()"

        email = ("From: test1@example.com, test2@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>)\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test2@example.com>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_matching_env_and_hdr_from_false(self):

        config = "header TEST_RULE eval:check_for_matching_env_and_hdr_from()"

        email = ("From: test@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.net>)\n")

        self.setup_conf(config=config, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_check_for_matching_env_and_hdr_from_false_multi_relays(self):

        config = "header TEST_RULE eval:check_for_matching_env_and_hdr_from()"

        email = ("From: test1@example.com, test2@example.com\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>)\n"
                 "Received: from example.com (example.com [1.2.3.4])\n"
                 "\tby example.com\n"
                 "\t(envelope-from <test@example.com>)\n")

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
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForMsnGroupsHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalGatedThroughReceivedHdrRemover, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForForgedEudoramailReceivedHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForForgedYahooReceivedHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForMissingToHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalSubjectIsAllCaps, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForToInSubject, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckMessageidNotUsable, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckOutlookMessageId, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckHeaderCountRange, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckUnresolvedTemplate, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckRatwareNameId, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckRatwareEnvelopeFrom, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForForgedGw05ReceivedHeaders, "test"))
    test_suite.addTest(unittest.makeSuite(TestFunctionalCheckForMatchingEnvAndHdrFrom, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
