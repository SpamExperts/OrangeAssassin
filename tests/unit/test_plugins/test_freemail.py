"""Test for pad.plugins.freemail Plugin"""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.free_mail


class TestFreeMailBase(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.local_data = {}
        self.global_data = {
            "freemail_domains": ["freemail.example.com", "freemail2.example.com"],
            "freemail_whitelist": ["white.example.org", "white2.example.org"],
            "util_rb_tld": ["com", "org"],
            "util_rb_2tld": ["co.uk", "go.ro"],
            "util_rb_3tld": ["net.co.uk", "org.co.uk"]
        }
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock(msg={})
        self.plugin = pad.plugins.free_mail.FreeMail(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()


class TestCheckStart(TestFreeMailBase):

    def test_check_start(self):
        """Test if global_data is filled in the start"""
        self.plugin.check_start(self.mock_msg)
        self.assertTrue("email_re" in self.global_data.keys())
        self.assertTrue("body_emails" in self.global_data.keys())
        self.assertTrue("check_if_parsed" in self.global_data.keys())

    def test_check_start_valid_freemail_domains(self):
        """Test if bad domains are removed from freemail_domains"""
        expected_length = len(self.global_data["freemail_domains"])
        self.global_data["freemail_domains"].append("inv*&&a_lidq.com")
        self.plugin.check_start(self.mock_msg)
        self.assertEqual(expected_length,
                         len(self.global_data["freemail_domains"]))

    def test_check_start_wild_domains(self):
        """Test if wildcard appears in domain"""
        self.global_data["freemail_domains"].append("*.example.org")
        self.plugin.check_start(self.mock_msg)
        self.assertTrue("freemail_domains_re" in self.global_data.keys())

    def test_check_start_regexes(self):
        """Test if regexes are compiled corectly"""
        self.global_data["freemail_domains"].append("*.example.org")
        self.plugin.check_start(self.mock_msg)
        self.assertIsNotNone(self.global_data['email_re'].search("email@test.com"))
        self.assertIsNone(self.global_data['email_re'].search("email@test.co.za"))
        self.assertIsNotNone(self.global_data['freemail_domains_re'].search("test@anything.example.org"))
        self.assertIsNone(self.global_data['freemail_domains_re'].search("test@anything.example.com"))


class TestEvalRules(TestFreeMailBase):
    """Test the eval rules
        * check_freemail_replyto
        * check_freemail_from
        * check_freemail_header
        * check_freemail_body"""

    def setUp(self):
        super(TestEvalRules, self).setUp()
        self.plugin.check_start(self.mock_msg)

    def test_freemail_replyto_invalid_option(self):
        result = self.plugin.check_freemail_replyto(self.mock_msg, option="invalid_option")
        self.assertFalse(result)

    def test_freemail_replyto_no_option(self):
        self.global_data['freemail_skip_bulk_envfrom'] = False
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_replyto_skip_bulk_envfrom(self):
        self.global_data['freemail_skip_bulk_envfrom'] = True
        self.mock_msg.msg["EnvelopeFrom"] = "postmaster@example.com"
        self.mock_msg.sender_address = "postmaster@example.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_replyto_true(self):
        self.global_data['freemail_skip_bulk_envfrom'] = False
        freemail_domain = self.global_data['freemail_domains'][0]
        self.mock_msg.msg["From"] = "test@" + freemail_domain
        self.mock_msg.msg["Reply-To"] = "different@" + freemail_domain
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertTrue(result)

    def test_freemail_replyto_no_freemail(self):
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.mock_msg.msg["Reply-To"] = "test@paidomain.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_replyto_option_reply(self):
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.mock_msg.msg["Reply-To"] = "test@paidomain.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg, "reply")
        self.assertFalse(result)

    def test_freemail_replyto_option_reply_with_freemail(self):
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.mock_msg.msg["From"] = "test2@paidomain.com"
        self.mock_msg.msg["Reply-To"] = "test@paidomain.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg, "reply")
        self.assertFalse(result)

    def test_freemail_replyto_with_parse_body_false(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=False).start()
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.mock_msg.msg["Reply-To"] = "test@freemail2.example.com"
        self.mock_msg.msg["From"] = "test@freemail2.example.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg, "reply")
        self.assertFalse(result)

    def test_freemail_replyto_with_parse_body_true(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=True).start()
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.global_data['freemail_body_emails'] = ["test@freemail.example.com"]
        self.mock_msg.msg["Reply-To"] = "test@freemail2.example.com"
        self.mock_msg.msg["From"] = "test2@paidomain.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertTrue(result)

    def test_freemail_replyto_with_parse_body_true_false(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=True).start()
        self.global_data['freemail_skip_bulk_envfrom'] = False
        self.global_data['freemail_body_emails'] = ["test@freemail.example.com"]
        self.mock_msg.msg["Reply-To"] = "test@freemail.example.com"
        self.mock_msg.msg["From"] = "test2@paidomain.com"
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_from_invalid_regex(self):
        result = self.plugin.check_freemail_from(self.mock_msg, regex="?^&$")
        self.assertFalse(result)

    def test_freemail_from_no_headers(self):
        result = self.plugin.check_freemail_from(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_from_with_email(self):
        self.mock_msg.msg["From"] = "test2@freemail.example.com"
        self.mock_msg.get_all_from_headers_addr.return_value = [
            "test2@freemail.example.com"]
        result = self.plugin.check_freemail_from(self.mock_msg)
        self.assertTrue(result)

    def test_freemail_from_with_re(self):
        self.mock_msg.msg["EnvelopeFrom"] = "envelop<test11@freemail.example.com>"
        self.mock_msg.get_all_from_headers_addr.return_value = [
            "test11@freemail.example.com"]
        result = self.plugin.check_freemail_from(self.mock_msg, regex=r"^.*\d@")
        self.assertTrue(result)

    def test_freemail_from_with_re_no_email(self):
        self.mock_msg.msg["EnvelopeFrom"] = "envelop<test11@test.example.com>"
        self.mock_msg.msg["Envelope-Sender"] = "mail@test2.example.org"
        self.mock_msg.get_all_from_headers_addr.return_value = [
            "test11@test.example.com", "mail@test2.example.org"]
        result = self.plugin.check_freemail_from(self.mock_msg, regex=r"^.*\d@")
        self.assertFalse(result)

    def test_freemail_header_no_header(self):
        result = self.plugin.check_freemail_header(self.mock_msg, header='')
        self.assertFalse(result)

    def test_freemail_header_bad_header(self):
        result = self.plugin.check_freemail_header(self.mock_msg, header='Bad')
        self.assertFalse(result)

    def test_freemail_header_good_header_no_emails(self):
        self.mock_msg.msg["Subject"] = "Hello World"
        result = self.plugin.check_freemail_header(self.mock_msg, header='Subject')
        self.assertFalse(result)

    def test_freemail_header_good_header_email(self):
        self.mock_msg.msg["Subject"] = "test@example.com"
        result = self.plugin.check_freemail_header(self.mock_msg, header='Subject')
        self.assertFalse(result)

    def test_freemail_header_good_header_freemail(self):
        self.mock_msg.msg["Subject"] = "test@freemail.example.com"
        result = self.plugin.check_freemail_header(self.mock_msg, header='Subject')
        self.assertTrue(result)

    def test_freemail_header_good_header_freemail_and_regex(self):
        self.mock_msg.msg["Subject"] = "test10@freemail.example.com"
        result = self.plugin.check_freemail_header(self.mock_msg,
                                                   header='Subject',
                                                   regex='^.*\d@')
        self.assertTrue(result)

    def test_freemail_header_good_header_freemail_and_regex_no(self):
        self.mock_msg.msg["Subject"] = "test@freemail.example.com"
        result = self.plugin.check_freemail_header(self.mock_msg,
                                                   header='Subject',
                                                   regex='^.*\d@')
        self.assertFalse(result)

    def test_freemail_header_good_header_freemail_and_bad_regex(self):
        self.mock_msg.msg["Subject"] = "test@freemail.example.com"
        result = self.plugin.check_freemail_header(self.mock_msg,
                                                   header='Subject',
                                                   regex="?^&$")
        self.assertFalse(result)

    def test_freemail_body_no_body_emails(self):
        result = self.plugin.check_freemail_body(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_body_bad_regex(self):
        result = self.plugin.check_freemail_body(self.mock_msg,
                                                 regex="?^&$")
        self.assertFalse(result)

    def test_freemail_body_not_parsed(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=False).start()
        result = self.plugin.check_freemail_body(self.mock_msg)
        self.assertFalse(result)

    def test_freemail_body_parsed(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=True).start()
        self.global_data["body_emails"] = ["body@example.com",
                                           "body@freemail.example.com",
                                           "body2@freemail2.example.com"]
        self.global_data["freemail_body_emails"] = ["body@freemail.example.com",
                                                    "body2@freemail2.example.com"]
        result = self.plugin.check_freemail_body(self.mock_msg)
        self.assertTrue(result)

    def test_freemail_body_parsed_regex(self):
        patch("pad.plugins.free_mail.FreeMail._parse_body", return_value=True).start()
        self.global_data["body_emails"] = ["body@example.com",
                                           "body@freemail.example.com",
                                           "body2@freemail2.example.com"]
        self.global_data["freemail_body_emails"] = ["body@freemail.example.com",
                                                    "body2@freemail2.example.com"]
        result = self.plugin.check_freemail_body(self.mock_msg, regex=r"^.*\d@")
        self.assertTrue(result)


class TestIsFreemail(TestFreeMailBase):
    """Test _is_freemail(email) method"""

    def test_with_no_email(self):
        self.plugin.check_start(self.mock_msg)
        result = self.plugin._is_freemail(email=None)
        self.assertFalse(result)

    def test_freemail_whitelist(self):
        self.plugin.check_start(self.mock_msg)
        whitelist_domain = self.global_data['freemail_whitelist'][0]
        email = "test@" + whitelist_domain
        result = self.plugin._is_freemail(email=email)
        self.assertFalse(result)

    def test_freemail_whitelist_with_re(self):
        self.global_data['freemail_domains'].append("*.test.example.com")
        self.plugin.check_start(self.mock_msg)
        email = "test@anything.test.example.com"
        result = self.plugin._is_freemail(email=email)
        self.assertTrue(result)

    def test_freemail_domains(self):
        self.plugin.check_start(self.mock_msg)
        freemail_domain = self.global_data['freemail_domains'][0]
        email = "test@" + freemail_domain
        result = self.plugin._is_freemail(email=email)
        self.assertTrue(result)

    def test_email_whitelist_re(self):
        self.plugin.check_start(self.mock_msg)
        email = "support@example.com"
        result = self.plugin._is_freemail(email=email)
        self.assertFalse(result)


class TestParseBody(TestFreeMailBase):
    """Test _parse_body() method"""

    def setUp(self):
        super(TestParseBody, self).setUp()
        self.plugin.check_start(self.mock_msg)

    def test_parse_body_already_parsed(self):
        self.global_data["check_if_parsed"] = True
        result = self.plugin._parse_body()
        self.assertTrue(result)

    def test_parse_body_no_body_emails_skip(self):
        self.global_data["freemail_max_body_emails"] = 5
        self.global_data["freemail_skip_when_over_max"] = True
        result = self.plugin._parse_body()
        self.assertTrue(result)

    def test_parse_body_with_emails(self):
        self.global_data["body_emails"] = ["body@example.com",
                                           "body2@example.com",
                                           "body3@example.com"]
        self.global_data["freemail_max_body_emails"] = 2
        self.global_data["freemail_skip_when_over_max"] = True
        result = self.plugin._parse_body()
        self.assertFalse(result)

    def test_parse_body_with_freemail(self):
        self.global_data["body_emails"] = ["body@freemail.example.com",
                                           "body2@freemail2.example.com"]
        self.global_data["freemail_max_body_emails"] = 5
        self.global_data["freemail_skip_when_over_max"] = True
        self.global_data["freemail_max_body_freemails"] = 3
        result = self.plugin._parse_body()
        self.assertTrue(result)
        self.assertEqual(self.global_data["body_emails"],
                         self.global_data["freemail_body_emails"])

    def test_parse_body_with_freemail_limit(self):
        self.global_data["body_emails"] = ["body@freemail.example.com",
                                           "body2@freemail2.example.com"]
        self.global_data["freemail_max_body_emails"] = 5
        self.global_data["freemail_skip_when_over_max"] = True
        self.global_data["freemail_max_body_freemails"] = 1
        result = self.plugin._parse_body()
        self.assertFalse(result)
