#!/usr/local/bin/python
# coding: utf-8

import datetime
import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.header_eval


class TestHeaderEvalBase(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {}
        self.global_data = {}
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.
                                   setdefault(k, v)
        })
        self.mock_msg = MagicMock()
        self.plugin = pad.plugins.header_eval.HeaderEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()
        self.mock_locale = patch("pad.plugins.header_eval."
                                 "pad.locales.charset_ok_for_locales").start()
        self.mock_is_domain_valid = patch("pad.plugins.header_eval."
                                          "HeaderEval.is_domain_valid").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()


class TestHeaderEval(TestHeaderEvalBase):

    def test_check_for_fake_aol_relay_in_rcvd_spam(self):
        header = ("from unknown (HELO mta05bw.bigpond.com) (80.71.176.130) "
                  "by rly-xw01.mx.aol.com with QMQP; Sat, 15 Jun 2002 "
                  "23:37:16 -0000")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.check_for_fake_aol_relay_in_rcvd(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_fake_aol_relay_in_rcvd_not_spam1(self):
        header = ("from  rly-xj02.mx.aol.com (rly-xj02.mail.aol.com "
                  "[172.20.116.39]) by omr-r05.mx.aol.com (v83.35) with "
                  "ESMTP id RELAYIN7-0501132011; Wed, 01 May 2002 "
                  "13:20:11 -0400")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.check_for_fake_aol_relay_in_rcvd(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_fake_aol_relay_in_rcvd_not_spam2(self):
        header = ("from logs-tr.proxy.aol.com (logs-tr.proxy.aol.com "
                  "[152.163.201.132]) by rly-ip01.mx.aol.com "
                  "(8.8.8/8.8.8/AOL-5.0.0) with ESMTP id NAA08955 for "
                  "<sapient-alumni@yahoogroups.com>; Thu, 4 Apr 2002 13:11:20 "
                  "-0500 (EST)")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.check_for_fake_aol_relay_in_rcvd(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_fake_aol_relay_in_rcvd_not_spam3_not_aol(self):
        header = ("by 10.28.54.13 with SMTP id d13csp1785386wma; Mon, "
                  "28 Nov 2016 07:40:07 -0800 (PST)")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.check_for_fake_aol_relay_in_rcvd(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_no_locale(self):
        self.mock_locale.return_value = False
        self.mock_ctxt.conf.get_global.return_value = ""
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_all_locale(self):
        self.mock_locale.return_value = False
        self.mock_ctxt.conf.get_global.return_value = "all"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_spam(self):
        self.mock_locale.return_value = False
        self.mock_ctxt.conf.get_global.return_value = "ru"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_faraway_charset_in_headers_ham(self):
        self.mock_locale.return_value = True
        self.mock_ctxt.conf.get_global.return_value = "ru"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_invalid_header(self):
        self.mock_locale.return_value = False
        self.mock_ctxt.conf.get_global.return_value = "ru"
        patch("pad.plugins.header_eval.email.header.decode_header",
              side_effect=ValueError).start()
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_correct_call(self):
        self.mock_locale.return_value = False
        self.mock_ctxt.conf.get_global.return_value = "ru ko"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.mock_locale.assert_called_with("utf8", ["ru", "ko"])

    def test_check_header_count_range_match(self):
        self.mock_msg.get_raw_header.return_value = ["a", "b"]
        result = self.plugin.check_header_count_range(self.mock_msg, "Test",
                                                      "2", "3")
        self.mock_msg.get_raw_header.assert_called_with("Test")
        self.assertTrue(result)

    def test_check_header_count_range_no_match(self):
        self.mock_msg.get_raw_header.return_value = ["a", "b"]
        result = self.plugin.check_header_count_range(self.mock_msg, "Test",
                                                      "3", "4")
        self.mock_msg.get_raw_header.assert_called_with("Test")
        self.assertFalse(result)

    def test_check_for_missing_to_header_has_to(self):
        self.mock_msg.get_raw_header.side_effect = [["test@example.com"]]
        result = self.plugin.check_for_missing_to_header(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_missing_to_header_has_apparently_to(self):
        self.mock_msg.get_raw_header.side_effect = [[], ["test@example.com"]]
        result = self.plugin.check_for_missing_to_header(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_missing_to_header_match(self):
        self.mock_msg.get_raw_header.side_effect = [[], []]
        result = self.plugin.check_for_missing_to_header(self.mock_msg)
        self.assertTrue(result)

    def test_subject_is_all_caps(self):
        header = ("Re: THIS IS A CAPS HEADER")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.subject_is_all_caps(self.mock_msg)
        self.assertTrue(result)

    def test_subject_is_all_caps_false(self):
        header = ("Fwd: Re: this is not a caps header")
        self.mock_msg.get_decoded_header.return_value = [header]
        result = self.plugin.subject_is_all_caps(self.mock_msg)
        self.assertFalse(result)

    def test_illegal_chars(self):
        self.mock_msg.get_raw_header.return_value = ["ùTest"]
        result = self.plugin.check_illegal_chars(self.mock_msg, "Subject",
                                                 '0.1', '0')
        self.assertTrue(result)

    def test_illegal_chars_all(self):
        self.mock_msg.raw_headers = {"From": ["ùTùùesùùùùtù"],
                                     "Subject": ["ùTùùesùùùùtù"],
                                     "Another": ["Normal Text"]}
        result = self.plugin.check_illegal_chars(self.mock_msg, "ALL", '0.1',
                                                 '0')
        self.assertFalse(result)

    def test_illegal_chars_all_true(self):
        self.mock_msg.raw_headers = {"From": ["ùTùùesùùùùtù"],
                                     "Subject": ["ùTùùesùùùùtù"],
                                     "Another": ["ùùesùùù"]}
        result = self.plugin.check_illegal_chars(self.mock_msg, "ALL", '0.1',
                                                 '0')
        self.assertTrue(result)

    def test_illegal_chars_exempt(self):
        self.mock_msg.get_raw_header.return_value = ["Test\\xa2"]
        result = self.plugin.check_illegal_chars(self.mock_msg, "Subject",
                                                 '0.1', '0')
        self.assertFalse(result)

    def test_check_for_msn_groups_headers(self):
        received = "from mail pickup service by p23.groups.msn.com"
        message_id = "<testid123@p23.groups.msn.com>"
        self.mock_msg.get_decoded_header.side_effect = [["<notifications@groups.msn.com>"],
                                                        [received],
                                                        [message_id]]
        result = self.plugin.check_for_msn_groups_headers(self.mock_msg)
        self.assertTrue(result)

    def test_gated_through_received_hdr_remover(self):
        mailing_list = "contact test@example.com; run by ezmlm"
        received = "(qmail 47240 invoked by uid 33); 01 Oct 2010 20:35:23 +0000"
        delivered_to = "mailing list test@example.com"
        self.mock_msg.get_decoded_header.side_effect = [[mailing_list],
                                                        [received],
                                                        [delivered_to]]
        result = self.plugin.gated_through_received_hdr_remover(self.mock_msg)
        self.assertTrue(result)

    def test_gated_thorugh_received_hdr_remover_no_received(self):
        mailing_list = "test@example.com"
        received = ''
        self.mock_msg.get_decoded_header.side_effect = [[mailing_list],
                                                        [received],
                                                        ]
        result = self.plugin.gated_through_received_hdr_remover(self.mock_msg)
        self.assertTrue(result)

    def test_gated_thorugh_received_hdr_remover_msn_group(self):
        mailing_list = "test@example.com"
        received = ("from groups.msn.com (tk2dcpuba02.msn.com [65.54.195.210]) by"
                    "dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id g72K35v10457 for"
                    "<zzzzzzzzzzzz@jmason.org>; Fri, 2 Aug 2002 21:03:05 +0100")
        self.mock_msg.get_decoded_header.side_effect = [[mailing_list],
                                                        [received],
                                                        ]
        result = self.plugin.gated_through_received_hdr_remover(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_eudoramail_received_headers(self):
        from_addr = "test@eudoramail.com"
        received = ("from Unknown/Local ([?.?.?.?]) by "
                    "shared1-mail.example.com; Thu Nov 29 13:44:25 2001")
        ip = ""
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[received], [ip]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_eudoramail_received_headers(
            self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_eudoramail_received_headers_false(self):
        from_addr = "test@eudoramail.com"
        received = ("from Unknown/Local ([?.?.?.?]) by "
                    "shared1-mail.whowhere.com; Thu Nov 29 13:44:25 2001")
        ip = "192.168.34.41"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[received], [ip]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_eudoramail_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_juno_received_headers_no_juno(self):
        from_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_juno_received_headers_gated_through(self):
        from_addr = "test@juno.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=True).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_juno_received_headers(self):
        from_addr = "test@juno.com"
        xorig = "8.8.8.8"
        received = "from test.com[5.6.7.8] by cookie.juno.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[xorig], [""],
                                                        [received]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_juno_received_headers_juno_xmailer(self):
        from_addr = "test@juno.com"
        xorig = "8.8.8.8"
        xmailer = "Juno Mailer v.8.2.3"
        received = "from untd.com[5.6.7.8] by cookie.juno.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[xorig], [xmailer],
                                                        [received]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_juno_received_headers_no_xorig(self):
        from_addr = "test@juno.com"
        xorig = ""
        xmailer = "Juno Mailer v.8.2.3"
        received = "from mail.com [45.46.37.48] by example.juno.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[xorig], [xmailer],
                                                        [received]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_juno_received_headers_no_xorig_webmail(self):
        from_addr = "test@juno.com"
        xorig = ""
        xmailer = "Juno Mailer v.8.2.3"
        received = "from webmail.test.untd.com (webmail.test.untd.com [1.2.3.4]) by "
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[xorig], [xmailer],
                                                        [received]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_juno_received_headers_no_xorig_no_ip(self):
        from_addr = "test@juno.com"
        xorig = ""
        xmailer = "Juno Mailer v.8.2.3"
        received = "from mail.com[5.6.7.8] by example.juno.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[xorig], [xmailer],
                                                        [received]]
        patch("pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover",
              return_value=False).start()
        result = self.plugin.check_for_forged_juno_received_headers(
            self.mock_msg)
        self.assertTrue(result)

    def test_check_for_to_in_subject_address_true(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["test@example.com"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "address")
        self.assertTrue(result)

    def test_check_for_to_in_subject_address_false(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["This is a"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "address")
        self.assertFalse(result)

    def test_check_for_to_in_subject_no_to_address(self):
        self.mock_msg.get_all_addr_header.side_effect = [[]]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "address")
        self.assertFalse(result)

    def test_check_for_to_in_subject_user_true_regex1(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["test"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "user")
        self.assertTrue(result)

    def test_check_for_to_in_subject_user_true_regex2(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["re: for test"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "user")
        self.assertTrue(result)

    def test_check_for_to_in_subject_user_true_regex3(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["test,"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "user")
        self.assertTrue(result)

    def test_check_for_to_in_subject_user_true_regex4(self):
        to_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[to_addr]]
        self.mock_msg.msg.get.side_effect = ["test , This is a test"]
        result = self.plugin.check_for_to_in_subject(self.mock_msg, "user")
        self.assertTrue(result)

    def test_check_outlook_message_id_invalid_message_id(self):
        self.mock_msg.msg.get.side_effect = [
            "<CA+KsZ1C=Lm-ehUW7wQuGud7ifh6_dQDzy>"]
        result = self.plugin.check_outlook_message_id(self.mock_msg)
        self.assertFalse(result)

    def test_check_outlook_message_id(self):
        self.mock_msg.msg.get.side_effect = [
            "<111112345678$11111111$11111111@>",
            "Tue, 29 Nov 2016 14:38:59 +0200",
            """by 10.28.145.16 with SMTP id t16csp2363316wmd;
        Tue, 29 Nov 2016 04:39:00 -0800 (PST)"""]
        result = self.plugin.check_outlook_message_id(self.mock_msg)
        self.assertTrue(result)

    def check_for_matching_env_and_hdr_from(self):
        from_addr = "test@example.com"
        envfrom = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.trusted_relays = [{"envfrom": ''}]
        self.mock_msg.untrusted_relays = [{"envfrom": envfrom}]
        result = self.plugin.check_for_matching_env_and_hdr_from(self.mock_msg)
        self.assertTrue(result)

    def check_for_matching_env_and_hdr_from_false(self):
        from_addr = "test@example.com"
        envfrom = "accept@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.trusted_relays = [{"envfrom": ''}]
        self.mock_msg.untrusted_relays = [{"envfrom": envfrom}]
        result = self.plugin.check_for_matching_env_and_hdr_from(self.mock_msg)
        self.assertFalse(result)

    def check_for_matching_env_and_hdr_from_false_no_envfrom(self):
        from_addr = "test@example.com"
        envfrom = ""
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.trusted_relays = [{"envfrom": ''}]
        self.mock_msg.untrusted_relays = [{"envfrom": envfrom}]
        result = self.plugin.check_for_matching_env_and_hdr_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_unresolved_template_false(self):
        message = """
        Delivered-To: user@gmail.com
Received: from smtp.mesvr.com (localhost.localdomain [127.0.0.1])
From: user@gmail.com
Date: Tue, 10 Nov 2016 14:38:59 +0200
Subject: This is a test
To: user@gmail.com

        """
        self.mock_msg.raw_msg = message
        result = self.plugin.check_unresolved_template(self.mock_msg)
        self.assertFalse(result)

    def test_check_unresolved_template_true(self):
        message = """
        Delivered-To: user@gmail.com%AA
Received: from smtp.mesvr.com (localhost.localdomain [127.0.0.1])
From: user@gmail.com
Date: Tue, 10 Nov 2016 14:38:59 +0200
Subject: This is a test
To: user@gmail.com

        """
        self.mock_msg.raw_msg = message
        result = self.plugin.check_unresolved_template(self.mock_msg)
        self.assertTrue(result)

    def test_check_ratware_name_id(self):
        self.mock_msg.msg.get.side_effect = [
            '<AAAAAAAAAAAAAAAAAAAAAAAAAAAA.EXAMPLE>',
            '"UNSER EXAMPLE" <EXAMPLE>']
        result = self.plugin.check_ratware_name_id(self.mock_msg)
        self.assertTrue(result)

    def test_check_ratware_name_id_no_message_id(self):
        self.mock_msg.msg.get.side_effect = ['', '']
        result = self.plugin.check_ratware_name_id(self.mock_msg)
        self.assertFalse(result)

    def test_check_ratware_name_id_false(self):
        self.mock_msg.msg.get.side_effect = [
            '<AAAAAAAAAAAAAAAAAAAAAAAAAAAA>',
            '"UNSER EXAMPLE" <EXAMPLE>']
        result = self.plugin.check_ratware_name_id(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_gw05_received_headers(self):
        received = "from mail3.icytundra.com by gw05 with ESMTP; Thu, 21 Jun 2001 02:28:32 -0400"
        self.mock_msg.get_decoded_header.side_effect = [[received]]
        result = self.plugin.check_for_forged_gw05_received_headers(self.mock_msg)
        self.assertTrue(result)

    def test_check_ratware_envelope_from(self):
        self.mock_msg.msg.get.side_effect = ["user@example.com"]
        self.mock_msg.sender_address = "example.com.user@something"
        self.mock_is_domain_valid.return_value = True
        result = self.plugin.check_ratware_envelope_from(self.mock_msg)
        self.assertTrue(result)

    def test_check_ratware_envelope_from_SRS(self):
        self.mock_msg.msg.get.side_effect = ["user@example.com"]
        self.mock_msg.sender_address = "SRS5=example.com.user@something"
        result = self.plugin.check_ratware_envelope_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_ratware_envelope_from_invalid_domain(self):
        self.mock_msg.msg.get.side_effect = ["user@examplecom"]
        self.mock_msg.sender_address = "example.com.user@something"
        self.mock_is_domain_valid.return_value = False
        result = self.plugin.check_ratware_envelope_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_ratware_envelope_from_no_to_header(self):
        self.mock_msg.msg.get.side_effect = [""]
        self.mock_msg.sender_address = "example.com.user@something"
        result = self.plugin.check_ratware_envelope_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_ratware_envelope_from_false(self):
        self.mock_msg.msg.get.side_effect = ["user@example.com"]
        self.mock_msg.sender_address = "user@example.com"
        self.mock_is_domain_valid.return_value = True
        result = self.plugin.check_ratware_envelope_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_unique_subject_id(self):
        subject = "This is an subject with -------ak2l4"
        self.mock_msg.get_decoded_header.side_effect = [[subject]]
        result = self.plugin.check_for_unique_subject_id(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_unique_subject_id_case(self):
        subject = "Invoice 45621 "
        self.mock_msg.get_decoded_header.side_effect = [[subject]]
        result = self.plugin.check_for_unique_subject_id(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_unique_subject_id_regex3(self):
        subject = "This is a test   :3ad41d421"
        self.mock_msg.get_decoded_header.side_effect = [[subject]]
        result = self.plugin.check_for_unique_subject_id(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_yahoo_received_headers_true(self):
        from_addr = "test.example@yahoo.com"
        received = ("from unknown (HELO mta05bw.bigpond.com) (80.71.176.130) "
                    "by rly-xw01.mx.aol.com with QMQP; Sat, 15 Jun 2002 "
                    "23:37:16 -0000")
        resent_from = ""
        resent_to = ""
        xreceived = ""
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[received],
                                                        [resent_from],
                                                        [resent_to],
                                                        [xreceived]]
        patch(
            "pad.plugins.header_eval.HeaderEval."
            "gated_through_received_hdr_remover", return_value=False).start()
        result = self.plugin.check_for_forged_yahoo_received_headers(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_forged_yahoo_received_headers_not_yahoo(self):
        from_addr = "test.example@example.com"
        received = ("from unknown (HELO mta05bw.bigpond.com) (80.71.176.130) "
                    "by rly-xw01.mx.aol.com with QMQP; Sat, 15 Jun 2002 "
                    "23:37:16 -0000")
        resent_from = ""
        resent_to = ""
        xreceived = ""
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[received],
                                                        [resent_from],
                                                        [resent_to],
                                                        [xreceived]]
        patch(
            "pad.plugins.header_eval.HeaderEval."
            "gated_through_received_hdr_remover", return_value=False).start()
        result = self.plugin.check_for_forged_yahoo_received_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_forged_yahoo_received_headers_yahoo_real(self):
        from_addr = "test.example@yahoo.com"
        received = ("from omp1035.mail.bf1.yahoo.com (omp1035.mail.bf1.yahoo.com "
                    "[98.139.212.226]) by mx9.webfaction.com (Postfix) with "
                    "ESMTPS id 8B4514989194 for <b@aromaesti.ro>; "
                    "Wed, 29 Oct 2014 10:11:29 +0000 (UTC)")
        resent_from = "another@yahoo.com"
        resent_to = "test@example.com"
        xreceived = ""
        self.mock_msg.get_all_addr_header.side_effect = [[from_addr]]
        self.mock_msg.get_decoded_header.side_effect = [[received],
                                                        [resent_from],
                                                        [resent_to],
                                                        [xreceived]]
        self.mock_msg.trusted_relays = [{'intl': 0, 'auth': '',
                                         'ident': '', 'ip': '98.139.212.226',
                                         'helo': 'omp1035.mail.bf1.yahoo.com',
                                         'rdns': 'omp1035.mail.bf1.yahoo.com',
                                         'envfrom': '', 'id': '8B4514989194',
                                         'by': 'mx9.webfaction.com', 'msa': 0}]
        self.mock_msg.untrusted_relays = []
        patch(
            "pad.plugins.header_eval.HeaderEval."
            "gated_through_received_hdr_remover", return_value=False).start()
        result = self.plugin.check_for_forged_yahoo_received_headers(self.mock_msg)
        self.assertFalse(result)

    def test_parse_recipients(self):
        rcpt = "test@example.com"
        expected = ("test@", "example.com", "ex")
        result = self.plugin._parse_rcpt(rcpt)
        self.assertEqual(result, expected)


class TestMessageId(TestHeaderEvalBase):
    def setUp(self):
        super(TestMessageId, self).setUp()
        self.mock_gated = patch(
            "pad.plugins.header_eval.HeaderEval."
            "gated_through_received_hdr_remover").start()
        self.mock_check_msn = patch(
            "pad.plugins.header_eval.HeaderEval."
            "check_for_msn_groups_headers").start()

    def test_check_messageid_not_usable_list_unsubscribe_true(self):
        self.mock_msg.msg.get.side_effect = [
            "<mailto:example-unsubscribe@-espc-tech-12345N@domain.com>"
        ]
        result = self.plugin.check_messageid_not_usable(self.mock_msg)
        self.assertTrue(result)

    def test_check_messageid_not_usable_gated(self):
        self.mock_msg.msg.get.side_effect = [
            "<mailto:unsubscribe@-espc-tech-12345N@domain.com>"]
        self.mock_gated.return_value = True
        result = self.plugin.check_messageid_not_usable(self.mock_msg)
        self.assertTrue(result)

    def test_check_messageid_not_usable_received(self):
        self.mock_msg.msg.get.side_effect = [
            "<mailto:unsubscribe@-espc-tech-12345N@domain.com>",
            """from smtp.mesvr.com (localhost.localdomain [127.0.0.1])
by smtp.mesvr.com (8.14.4/8.13.8/CWT/DCE) with ESMTP id u5I50E6V009236
(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-SHA bits=256 verify=NO)
for ; Sat, 18 Jun 2016 05:00:14 GMT"""]
        self.mock_gated.return_value = False
        result = self.plugin.check_messageid_not_usable(self.mock_msg)
        self.assertTrue(result)

    def test_check_messageid_not_usable_false(self):
        self.mock_msg.msg.get.side_effect = [
            "<mailto:unsubscribe@-espc-tech-12345N@domain.com>",
            """by 10.28.145.16 with SMTP id t16csp2363316wmd;
        Tue, 29 Nov 2016 04:39:00 -0800 (PST)"""]
        self.mock_gated.return_value = False
        result = self.plugin.check_messageid_not_usable(self.mock_msg)
        self.assertFalse(result)

    def test_check_messageid_not_usable_iplanet(self):
        self.mock_msg.msg.get.side_effect = [
            "<mailto:unsubscribe@-espc-tech-12345N@domain.com>",
            """by 10.28.145.16 with SMTP id t16csp2363316wmd;
        Tue, 29 Nov 2016 04:39:00 -0800 (iPlanet Messaging Server)"""]
        self.mock_gated.return_value = False
        result = self.plugin.check_messageid_not_usable(self.mock_msg)
        self.assertTrue(result)

    def test_check_forged_hotmail(self):
        self.mock_msg.msg.get.side_effect = [
            """from hotmail.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <example.com.user@something>)""",
            "",
            "user@hotmail.com"]
        self.mock_check_msn.return_value = False
        self.mock_gated.return_value = False
        self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertEqual(self.plugin.hotmail_addr_with_forged_hotmail_received, 1)

    def test_check_forged_hotmail_hotmail_addr(self):
        self.mock_msg.msg.get.side_effect = [
            """from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <example.com.user@something>)""",
            "",
            "user@hotmail.com"]
        self.mock_check_msn.return_value = False
        self.mock_gated.return_value = False
        self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertEqual(self.plugin.hotmail_addr_but_no_hotmail_received, 1)

    def test_check_forged_hotmail_hotmail_addr_false(self):
        self.mock_msg.msg.get.side_effect = [
            """from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <example.com.user@something>)""",
            "",
            "user@example.com"]
        self.mock_check_msn.return_value = False
        self.mock_gated.return_value = False
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_forged_hotmail_false_pickup(self):
        self.mock_msg.msg.get.side_effect = [
            """from mail pickup service by hotmail.com with Microsoft SMTPSVC;"""]
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_forged_hotmail_check_msn_true(self):
        self.mock_msg.msg.get.side_effect = [
            """from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <example.com.user@something>)""",
            "",
            "user@example.com"""]
        self.mock_check_msn.return_value = True
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_forged_hotmail_false_gated_true(self):
        self.mock_msg.msg.get.side_effect = [
            """from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <example.com.user@something>)""",
            "[1.2.3.4]",
            "user@example.com"""]
        self.mock_check_msn.return_value = False
        self.mock_gated.return_value = True
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)

    def test_check_forged_hotmail_originating_ip_regex1(self):
        self.mock_msg.msg.get.side_effect = [
            """from user.hotmail.com (user.hotmail.com)""",
            "[1.2.3.4]",
            "user@example.com"""]
        self.mock_check_msn.return_value = False
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)
        self.assertEqual((self.plugin.hotmail_addr_but_no_hotmail_received,
                          self.plugin.hotmail_addr_with_forged_hotmail_received),
                         (0, 0))

    def test_check_forged_hotmail_originating_ip_regex2(self):
        self.mock_msg.msg.get.side_effect = [
            """from example.hotmail.com ([1.2.3.4])""",
            "[1.2.3.4]"]
        self.mock_check_msn.return_value = False
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)
        self.assertEqual((self.plugin.hotmail_addr_but_no_hotmail_received,
                          self.plugin.hotmail_addr_with_forged_hotmail_received),
                         (0, 0))

    def test_check_forged_hotmail_originating_ip_regex3(self):
        self.mock_msg.msg.get.side_effect = [
            """from example by example.hotmail.com with HTTP;""",
            "[1.2.3.4]"]
        self.mock_check_msn.return_value = False
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)
        self.assertEqual((self.plugin.hotmail_addr_but_no_hotmail_received,
                          self.plugin.hotmail_addr_with_forged_hotmail_received),
                         (0, 0))

    def test_check_forged_hotmail_originating_ip_regex4(self):
        self.mock_msg.msg.get.side_effect = [
            """from [66.218.example] by example.yahoo.com""",
            "[1.2.3.4]"]
        self.mock_check_msn.return_value = False
        result = self.plugin._check_for_forged_hotmail_received_headers(
            self.mock_msg)
        self.assertFalse(result)
        self.assertEqual((self.plugin.hotmail_addr_but_no_hotmail_received,
                          self.plugin.hotmail_addr_with_forged_hotmail_received),
                         (0, 0))

    def test_get_received_headers_times(self):
        received = [
            ("from localhost (unknown [127.0.0.1]) by cabbage.jmason.org "
             "(Postfix) with ESMTP id A96E18BD97 for <jm@localhost>; "
             "Thu, 13 Mar 2003 15:23:15 -0500 (EST)"),
            ("cabbage.jmason.org [127.0.0.1] "
             "by localhost with IMAP (fetchmail-5.9.0) "
             "for jm@localhost (single-drop)"
             "Thu, 13 Mar 2004 19:00:15 -0500 (EST)"),
            ("from server1.test10.simplyspamfree.com ([5.79.78.146])"
             "by server1.test10.simplyspamfree.com with esmtpa (Exim 4.86)"
             "(envelope-from <sorin@spamexperts.com>)"
             "id 1cIvAL-0004E2-3M"
             "for sorin@spamexperts.com; Mon, 19 Dec 2016 21:27:34 +1100"),
        ]
        self.mock_msg.get_decoded_header.side_effect = [received]
        self.plugin._get_received_header_times(self.mock_msg)
        header_times = self.local_data.get("received_header_times", None)
        self.assertTrue(header_times)

    def test_check_date_diff_none(self):
        self.local_data = {"date_header_time": -1}
        result = self.plugin._check_date_diff(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_date_diff(self):
        date_header_time = datetime.datetime(2016, 10, 10, 15, 0, 0)
        received_header_times = [datetime.datetime(2016, 10, 10, 14, 0)]
        self.local_data = {"date_header_time": date_header_time,
                           "received_header_times": received_header_times}
        self.plugin._check_date_diff(self.mock_msg)
        self.assertIsNotNone(self.local_data.get("date_diff"))
        self.assertEqual(datetime.timedelta(0, 3600),
                         self.local_data.get("date_diff"))

    def test_check_date_diff_many_dates(self):
        date_header_time = datetime.datetime(2016, 10, 10, 15, 0, 0)
        received_header_times = [datetime.datetime(2016, 10, 10, 14, 0, 0),
                                 datetime.datetime(2016, 10, 10, 12, 0, 0),
                                 datetime.datetime(2016, 10, 10, 11, 0, 0)]
        self.local_data = {"date_header_time": date_header_time,
                           "received_header_times": received_header_times}
        self.plugin._check_date_diff(self.mock_msg)
        self.assertIsNotNone(self.local_data.get("date_diff"))
        self.assertEqual(datetime.timedelta(0, 3600),
                         self.local_data.get("date_diff"))

    def test_check_for_shifted_date(self):
        """Date is 3 to 6 hours before Received: date"""
        self.local_data = {"date_diff": datetime.timedelta(0, -14400)}
        result = self.plugin.check_for_shifted_date(self.mock_msg, min="-6",
                                                    max="-3")
        self.assertTrue(result)


class TestRecipientsRules(TestHeaderEvalBase):

    def setUp(self):
        super(TestRecipientsRules, self).setUp()
        self.headers = {}
        self.mock_msg.get_all_addr_header.side_effect  = self._get_headers

    def _get_headers(self, name):
        try:
            return self.headers[name]
        except KeyError:
            return []

    def test_sorted_rcpt(self):
        self.headers["To"] = ["alex@example.com", "bob@example.com"]
        result = self.plugin.sorted_recipients(self.mock_msg)
        self.assertTrue(result)

    def test_sorted_multi_header(self):
        self.headers["To"] = ["alex@example.com"]
        self.headers["Cc"] = ["bob@example.com"]
        self.headers["Bcc"] = ["carol@example.com"]
        self.headers["ToCc"] = ["david@example.com"]
        result = self.plugin.sorted_recipients(self.mock_msg)
        self.assertTrue(result)

    def test_sorted_rcpt_no_match(self):
        self.headers["To"] = ["bob@example.com", "alice@example.com"]
        result = self.plugin.sorted_recipients(self.mock_msg)
        self.assertFalse(result)

    def test_similar_rcpt(self):
        self.headers["To"] = [
            "alex@example.com", "bob@example.com", "alex@example.com",
            "david@example.com", "alex@example.com", "frank@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.2)
        self.assertTrue(result)

    def test_similar_rcpt_fq_match(self):
        self.headers["To"] = [
            "alex@1.example.com", "bob@1.example.net", "carol@1.example.org",
            "david@1.example.com", "eli@1.example.net", "frank@1.example.org"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.8)
        self.assertTrue(result)

    def test_similar_rcpt_no_match(self):
        self.headers["To"] = [
            "alex@example.com", "bob@example.com", "carol@example.com",
            "david@example.com", "eli@example.com", "frank@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.0)
        self.assertFalse(result)

    def test_similar_rcpt_diff_domains(self):
        self.headers["To"] = [
            "alex@example.com", "bob@example.com", "alex@example.net",
            "david@example.com", "alex@example.org", "frank@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.8)
        self.assertTrue(result)

    def test_similar_rcpt_no_match_dupes(self):
        self.headers["To"] = [
            "alex@example.com", "alex@example.com", "carol@example.com",
            "carol@example.com", "eli@example.com", "eli@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.0)
        self.assertFalse(result)

    def test_similar_rcpt_not_consecutive_dupes(self):
        self.headers["To"] = [
            "alex@example.com", "carol@example.com", "alex@example.com",
            "eli@example.com", "carol@example.com", "eli@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.2)
        self.assertTrue(result)

    def test_similar_rcpt_to_few_recipient(self):
        self.headers["To"] = [
            "alex@example.com", "carol@example.com", "alex@example.com",
            "eli@example.com"
        ]
        result = self.plugin.similar_recipients(self.mock_msg,
                                                0, 1)
        ratio = self.local_data["tocc_similar"]
        self.assertEqual(ratio, 0.0)
        self.assertFalse(result)

    def test_check_equal_from_domain(self):
        from_addr = ["test@example.com"]
        envfrom_addr = "test@example.com"
        self.mock_msg.get_all_addr_header.side_effect = [from_addr]
        self.mock_msg.sender_address = envfrom_addr
        result = self.plugin.check_equal_from_domains(self.mock_msg)
        self.assertFalse(result)

    def test_check_equal_from_domain_true(self):
        from_addr = ["test@example.com"]
        envfrom_addr = "test@another.example.com"
        self.mock_msg.get_all_addr_header.side_effect = [from_addr]
        self.mock_msg.sender_address = envfrom_addr
        result = self.plugin.check_equal_from_domains(self.mock_msg)
        self.assertTrue(result)

    def test_check_date_received(self):
        date_header_time = datetime.datetime(2016, 11, 28, 12, 49, 22)
        received_header_times = [datetime.datetime(2016, 11, 28, 2, 49, 35),
                                 datetime.datetime(2016, 11, 28, 2, 49, 35),
                                 datetime.datetime(2016, 11, 28, 2, 49, 35),
                                 datetime.datetime(2016, 11, 28, 2, 49, 35),
                                 datetime.datetime(2016, 11, 28, 11, 49, 35),
                                 datetime.datetime(2016, 11, 28, 2, 49, 23),
                                 datetime.datetime(2016, 11, 28, 2, 49, 22)]
        received_fetchmail_time = None
        date_diff = 3587.0
        self.local_data = {"date_header_time": date_header_time,
                           "received_header_times": received_header_times,
                           "received_fetchmail_time": received_fetchmail_time,
                           "date_diff": date_diff}
        self.plugin._check_date_received(self.mock_msg)
        date_received = self.local_data.get("date_received")
        self.assertEqual(datetime.datetime(2016, 11, 28, 2, 49, 35),
                         date_received)

    def test_received_within_months(self):
        current_date = datetime.datetime.utcnow()
        date_received = current_date - datetime.timedelta(days=20)
        self.local_data = {
            "date_received": date_received
        }
        result = self.plugin.received_within_months(self.mock_msg, 1, 3)
        self.assertFalse(result)

    def test_received_within_months_true(self):
        current_date = datetime.datetime.utcnow()
        date_received = current_date - datetime.timedelta(days=60)
        self.local_data = {
            "date_received": date_received
        }
        result = self.plugin.received_within_months(self.mock_msg, 1, 3)
        self.assertTrue(result)


class TestForgedHotmailRcvd(TestHeaderEvalBase):
    def setUp(self):
        super(TestForgedHotmailRcvd, self).setUp()
        self.headers = {}
        self.mock_forged_hotmail = patch("pad.plugins.header_eval.HeaderEval."
                                         "_check_for_forged_hotmail"
                                         "_received_headers").start()

    def test_check_for_forged_hotmail_received_headers(self):
        self.plugin.hotmail_addr_with_forged_hotmail_received = 1
        result = self.plugin.check_for_forged_hotmail_received_headers(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_no_hotmail_received_headers(self):
        self.plugin.hotmail_addr_but_no_hotmail_received = 1
        result = self.plugin.check_for_no_hotmail_received_headers(self.mock_msg)
        self.assertTrue(result)