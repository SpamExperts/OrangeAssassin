import unittest

import time
import datetime
import email.utils
try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.spam_cop


class TestSpamCop(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })

        self.mock_now_date = patch(
            "pad.plugins.spam_cop.SpamCopPlugin.get_now_date").start()
        self.mock_mail_date = patch(
            "pad.plugins.spam_cop.SpamCopPlugin.get_mail_date").start()
        self.mock_send_mail = patch(
            "pad.plugins.spam_cop.SpamCopPlugin.send_mail_method").start()

        self.plug = pad.plugins.spam_cop.SpamCopPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_plugin_report_message_older(self):
        self.global_data["spamcop_from_address"] = "user@example.com"
        self.global_data["spamcop_to_address"] = "user@example.com"
        self.mock_now_date.return_value = 1472540496.0
        self.mock_mail_date.return_value = 1471935131.0
        result = self.plug.plugin_report(self.mock_msg)
        self.assertFalse(result)

    def test_plugin_report_missing_required_value(self):
        self.global_data["spamcop_from_address"] = "user@example.com"
        self.global_data["spamcop_to_address"] = "userexample.com"
        self.mock_now_date.return_value = 1472540496.0
        self.mock_mail_date.return_value = 1472539931.0
        result = self.plug.plugin_report(self.mock_msg)
        self.assertFalse(result)

    def test_plugin_report(self):
        self.global_data["spamcop_from_address"] = "user@example.com"
        self.global_data["spamcop_to_address"] = "user@example.com"
        self.mock_now_date.return_value = 1472540496.0
        self.mock_mail_date.return_value = 1472539931.0
        result = self.plug.plugin_report(self.mock_msg)
        self.assertTrue(result)


class TestSendMail(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(k,
                                                                              v),
        })

        self.mock_plugin_report = patch(
            "pad.plugins.spam_cop.SpamCopPlugin.plugin_report").start()
        self.mock_now_date = patch(
            "pad.plugins.spam_cop.SpamCopPlugin.get_now_date").start()
        self.mock_smtp = patch(
            "pad.plugins.spam_cop.smtplib").start()
        self.mock_send_mail = patch(
            "pad.plugins.spam_cop.smtplib.sendmail").start()
        self.mock_dns = patch(
            "pad.plugins.spam_cop.dns.resolver").start()

        self.plug = pad.plugins.spam_cop.SpamCopPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_send_mail_method_true(self):
        sender = "user@example.com"
        receiver = "user@example.com"
        self.mock_dns.query.return_value[0] = '0 mail.example.com.'
        result = self.plug.send_mail_method(sender, receiver, "Message")
        self.assertTrue(result)

    def test_spamcop_report_true(self):
        self.global_data["dont_report_to_spamcop"] = 0
        self.mock_plugin_report.return_value = True
        result = self.plug._spamcop_report(self.mock_msg)
        self.assertTrue(result)

    def test_spamcop_report_false(self):
        self.global_data["dont_report_to_spamcop"] = 0
        self.mock_plugin_report.return_value = False
        result = self.plug._spamcop_report(self.mock_msg)
        self.assertFalse(result)

    def test_spamcop_report_no_report(self):
        self.global_data["dont_report_to_spamcop"] = 1
        result = self.plug._spamcop_report(self.mock_msg)
        self.assertFalse(result)


class TestGetDate(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v)}
                                   )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.msg_data.setdefault(k,
                                                                              v),
        })

        self.mock_get_decoded_header = patch(
            "pad.message.Message.get_decoded_header").start()

        self.plug = pad.plugins.spam_cop.SpamCopPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_get_now_date(self):
        time_now = datetime.datetime.now()
        now_date = time.mktime(time_now.timetuple())
        result = self.plug.get_now_date()
        self.assertEqual(result, now_date)

    def test_get_mail_date(self):
        received_header = 'by 10.25.215.16 with HTTP; Fri, 26 Aug 2016 ' \
                          '10:30:08 +0300 (PDT)'
        self.mock_msg.get_decoded_header.return_value = [received_header]
        time_mail = received_header.split(";")[1]
        result_expected = time.mktime(email.utils.parsedate(time_mail))
        result = self.plug.get_mail_date(self.mock_msg)
        self.assertEqual(result, result_expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')