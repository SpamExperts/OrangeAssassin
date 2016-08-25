"""Test for pad.plugins.freemail Plugin"""

import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.free_mail


class TestCheckStart(unittest.TestCase):

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


class TestEvalRules(unittest.TestCase):
    """Test the eval rules
        * check_freemail_replyto
        * check_freemail_from
        * check_freemail_header
        * check_freemail_body"""

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
        self.plugin.check_start(self.mock_msg)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

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
        result = self.plugin.check_freemail_replyto(self.mock_msg)
        self.assertFalse(result)


