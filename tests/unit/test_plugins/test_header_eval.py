import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.header_eval


class TestHeaderEval(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {}
        self.global_data = {}
        self.mock_ctxt = MagicMock()
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

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

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
        self.global_data["ok_locales"] = ""
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_all_locale(self):
        self.mock_locale.return_value = False
        self.global_data["ok_locales"] = "all"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_spam(self):
        self.mock_locale.return_value = False
        self.global_data["ok_locales"] = "ru"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertTrue(result)

    def test_check_for_faraway_charset_in_headers_ham(self):
        self.mock_locale.return_value = True
        self.global_data["ok_locales"] = "ru"
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_invalid_header(self):
        self.mock_locale.return_value = False
        self.global_data["ok_locales"] = "ru"
        patch("pad.plugins.header_eval.email.header.decode_header",
              side_effect=ValueError).start()
        self.mock_msg.get_raw_header.return_value = ["=?UTF8?B?dGVzdA==?="]
        result = self.plugin.check_for_faraway_charset_in_headers(self.mock_msg)
        self.assertFalse(result)

    def test_check_for_faraway_charset_in_headers_correct_call(self):
        self.mock_locale.return_value = False
        self.global_data["ok_locales"] = "ru ko"
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
        self.mock_msg.get_raw_header.return_value = [u"ùTest"]
        result = self.plugin.check_illegal_chars(self.mock_msg, "Subject",
                                                 '0.1', '0')
        self.assertTrue(result)

    def test_illegal_chars_all(self):
        self.mock_msg.raw_headers = {"From": [u"ùTùùesùùùùtù"],
                                     "Subject": [u"ùTùùesùùùùtù"],
                                     "Another": [u"Normal Text"]}
        result = self.plugin.check_illegal_chars(self.mock_msg, "ALL", '0.1',
                                                 '0')
        self.assertFalse(result)

    def test_illegal_chars_all_true(self):
        self.mock_msg.raw_headers = {"From": [u"ùTùùesùùùùtù"],
                                     "Subject": [u"ùTùùesùùùùtù"],
                                     "Another": [u"ùùesùùù"]}
        result = self.plugin.check_illegal_chars(self.mock_msg, "ALL", '0.1',
                                                 '0')
        self.assertTrue(result)

    def test_illegal_chars_exempt(self):
        self.mock_msg.get_raw_header.return_value = [u"Test\xa2"]
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


class TestMessageId(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {}
        self.global_data = {}
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock()
        self.plugin = pad.plugins.header_eval.HeaderEval(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()
        self.mock_gated = patch(
            "pad.plugins.header_eval.HeaderEval."
            "gated_through_received_hdr_remover").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

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
