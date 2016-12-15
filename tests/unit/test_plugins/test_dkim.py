import unittest

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import dkim

import pad.plugins.dkim


class TestGetHeader(unittest.TestCase):
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

        self.mock_addr_header = patch(
            "pad.message.Message.get_all_addr_header").start()

        self.plug = pad.plugins.dkim.DKIMPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    @staticmethod
    def get_resent_from_header(header):
        if header == "Resent-From":
            return ["addr1", "addr2"]
        elif header == "From":
            return ["address1", "address2", "address3"]
        return list()

    @staticmethod
    def get_from_header(header):
        if header == "From":
            return ["address1", "address2", "address3"]

        return list()

    def test_get_from_addresses_resent_header(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_resent_from_header

        result = self.plug.get_from_addresses(self.mock_msg)
        self.assertEqual(list(result), ["addr1", "addr2"])

    def test_get_from_addresses_from_headers(self):
        self.mock_msg.get_all_addr_header.side_effect = self.get_from_header

        self.mock_from_headers = patch("pad.plugins.wlbl_eval.FROM_HEADERS",
                                     ["From"]).start()
        result = self.plug.get_from_addresses(self.mock_msg)
        self.assertEqual(list(result),
                         ["address1", "address2", "address3"])

    def test_parse_input(self):
        list_name = "def_whitelist_from_dkim"
        self.global_data["def_whitelist_from_dkim"] = [
            "*@gmail.com gmail.com"]
        result = self.plug.parse_input(list_name)
        result_expected = {b".*@gmail.com": "gmail.com"}
        self.assertEqual(result, result_expected)

    def test_parse_input_unwhitelist(self):
        list_name = "whitelist_from_dkim"
        self.global_data["whitelist_from_dkim"] = [
            "user@example.com"]
        self.global_data["unwhitelist_from_dkim"] = ["user@example.com"]
        result = self.plug.parse_input(list_name)
        result_expected = {}
        self.assertEqual(result, result_expected)

    def test_parse_input_no_domain(self):
        list_name = "def_whitelist_from_dkim"
        self.global_data["def_whitelist_from_dkim"] = [
            "*@gmail.com"]
        result = self.plug.parse_input(list_name)
        result_expected = {b".*@gmail.com": ""}
        self.assertEqual(result, result_expected)


class TestGetTxt(unittest.TestCase):
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

        self.mock_get_txt_dnspython = patch(
            "pad.plugins.dkim.DKIMPlugin.get_txt_dnspython").start()

        self.plug = pad.plugins.dkim.DKIMPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_get_txt(self):
        txt = 'k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1' \
              'Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjO' \
              'VIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3FgD2Ap3ZB5DekAo5wMm' \
              'k4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbbhzY8i+RQ9Dp' \
              'SVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5Oc' \
              'tMEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZ' \
              'K9vlfuac0598HY+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21' \
              'MycBX5jYchHjPY/wIDAQAB'
        self.mock_get_txt_dnspython.return_value = txt
        result = self.plug.get_txt(b'20120113._domainkey.gmail.com.')
        self.assertEqual(result, txt.encode('utf-8'))


class TestGetAuthors(unittest.TestCase):
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

        self.mock_get_addr_header = patch(
            "pad.message.Message.get_addr_header").start()

        self.plug = pad.plugins.dkim.DKIMPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_get_authors(self):
        self.mock_msg.get_addr_header.return_value = ['test@example.com']
        self.plug._get_authors(self.mock_msg)


class TestCheckDKIM(unittest.TestCase):
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

        self.mock_get_authors = patch(
            "pad.plugins.dkim.DKIMPlugin._get_authors").start()
        self.mock_parse_input = patch(
            "pad.plugins.dkim.DKIMPlugin.parse_input").start()
        self.mock_check_signed_by = patch(
            "pad.plugins.dkim.DKIMPlugin._check_dkim_signed_by").start()
        self.mock_check_signature = patch(
            "pad.plugins.dkim.DKIMPlugin.check_dkim_signature").start()

        self.plug = pad.plugins.dkim.DKIMPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_dkim_adsp_all(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"example.com": "all"}
        result = self.plug.check_dkim_adsp(self.mock_msg, "A")
        self.assertTrue(result)

    def test_check_dkim_adsp_discardable(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"example.com": ""}
        result = self.plug.check_dkim_adsp(self.mock_msg, "D")
        self.assertTrue(result)

    def test_check_dkim_adsp_custom_low(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"example.com": "custom_low"}
        result = self.plug.check_dkim_adsp(self.mock_msg, "1")
        self.assertTrue(result)

    def test_check_dkim_adsp_nxdomain(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"example.com": "all"}
        result = self.plug.check_dkim_adsp(self.mock_msg, "*", "example.com")
        self.assertTrue(result)

    def test_check_dkim_adsp_false(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"example.com": "all"}
        result = self.plug.check_dkim_adsp(self.mock_msg, "*", "exam.com")
        self.assertFalse(result)

    def test_check_dkim_adsp_valid_signature(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 1
        result = self.plug.check_dkim_adsp(self.mock_msg, "*", "exam.com")
        self.assertFalse(result)

    def test_check_dkim_adsp_no_signature(self):
        self.plug.dkim_checked_signature = 0
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = None
        self.mock_parse_input.return_value = {b"example.com": "all"}
        self.mock_check_signature.return_value = True
        result = self.plug.check_dkim_adsp(self.mock_msg, "*", "example.com")
        self.assertTrue(result)

    def test_check_dkim_signed_false(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_signed = 0
        result = self.plug.check_dkim_signed(self.mock_msg)
        self.assertFalse(result)

    def test_check_dkim_signed_no_acceptable_domains(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_signed = 1
        result = self.plug.check_dkim_signed(self.mock_msg)
        self.assertTrue(result)

    def test_check_dkim_signed_true(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_signed = 1
        self.mock_check_signed_by.return_value = True
        result = self.plug.check_dkim_signed(self.mock_msg, 'gmail.com')
        self.assertTrue(result)

    def test_check_dkim_valid_true(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 1
        self.mock_check_signed_by.return_value = True
        result = self.plug.check_dkim_valid(self.mock_msg, 'gmail.com')
        self.assertTrue(result)

    def test_check_dkim_valid_no_acceptable_domains(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 1
        result = self.plug.check_dkim_valid(self.mock_msg)
        self.assertTrue(result)

    def test_check_dkim_valid_false(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_valid = 0
        result = self.plug.check_dkim_valid(self.mock_msg, 'gmail.com')
        self.assertFalse(result)

    def test_check_dkim_valid_author_sig_true(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_has_valid_author_sig = 1
        self.mock_check_signed_by.return_value = True
        result = self.plug.check_dkim_valid_author_sig(self.mock_msg, 'gmail.com')
        self.assertTrue(result)

    def test_check_dkim_valid_author_sig_no_acceptable_domains(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_has_valid_author_sig = 1
        result = self.plug.check_dkim_valid_author_sig(self.mock_msg)
        self.assertTrue(result)

    def test_check_dkim_valid_author_sig_false(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_has_valid_author_sig = 0
        result = self.plug.check_dkim_valid_author_sig(self.mock_msg, 'gmail.com')
        self.assertFalse(result)

    def test_check_dkim_signature_dependable(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_signatures_dependable = 1
        result = self.plug.check_dkim_dependable(self.mock_msg)
        self.assertTrue(result)

    def test_check_whitelist_from(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_valid = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"test@example.com":
                                                  "example.com"}
        result = self.plug.check_for_dkim_whitelist_from(self.mock_msg)
        self.assertTrue(result)

    def test_check_whitelist_from_no_address(self):
        self.plug.dkim_checked_signature = 0
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = []
        self.mock_parse_input.return_value = {b"test@example.com":
                                                  "example.com"}
        result = self.plug.check_for_dkim_whitelist_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_whitelist_from_false(self):
        self.plug.dkim_checked_signature = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b"test@examp.com": "example.com"}
        result = self.plug.check_for_dkim_whitelist_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_def_whitelist_from(self):
        self.plug.dkim_checked_signature = 0
        self.plug.dkim_valid = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b".*@example.com": "example.com"}
        result = self.plug.check_for_def_dkim_whitelist_from(self.mock_msg)
        self.assertTrue(result)

    def test_check_def_whitelist_from_false(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b".*@exampl.com": "example.com"}
        result = self.plug.check_for_def_dkim_whitelist_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_def_whitelist_from_invalid_signature(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 0
        result = self.plug.check_for_def_dkim_whitelist_from(self.mock_msg)
        self.assertFalse(result)

    def test_check_def_whitelist_from_no_domain(self):
        self.plug.dkim_checked_signature = 1
        self.plug.dkim_valid = 1
        self.plug.author_domains = [b"example.com"]
        self.plug.author_addresses = ["test@example.com"]
        self.mock_parse_input.return_value = {b".*@example.com": ""}
        result = self.plug.check_for_def_dkim_whitelist_from(self.mock_msg)
        self.assertTrue(result)


class TestCheckSignature(unittest.TestCase):
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

        self.mock_get_authors = patch(
            "pad.plugins.dkim.DKIMPlugin._get_authors").start()
        self.mock_dkim_parse_tag = patch(
            "dkim.util.parse_tag_value").start()
        self.mock_dkim_verify = patch(
            "dkim.verify").start()
        self.mock_dkim_validate_signature_fields = patch(
            "dkim.validate_signature_fields").start()

        self.plug = pad.plugins.dkim.DKIMPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_signed_by_true(self):
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.plug.is_valid = 1
        self.plug.author_domains = [b'gmail.com']
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature

        result = self.plug._check_dkim_signed_by(self.mock_msg, 1, 1,
                                                 'gmail.com')
        self.assertTrue(result)

    def test_check_signed_by_no_acceptable_domains(self):
        result = self.plug._check_dkim_signed_by(self.mock_msg, 1, 1)
        self.assertTrue(result)

    def test_check_signed_by_not_valid(self):
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.plug.is_valid = 0
        self.plug.author_domains = [b'gmail.com']
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature

        result = self.plug._check_dkim_signed_by(self.mock_msg, 1, 1,
                                                 'gmail.com')
        self.assertFalse(result)

    def test_check_signed_by_no_d_field(self):
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.plug.is_valid = 1
        self.plug.author_domains = [b'gmail.com']
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature

        result = self.plug._check_dkim_signed_by(self.mock_msg, 1, 1,
                                                 'gmail.com')
        self.assertFalse(result)

    def test_check_signed_by_incorrect_signature_domain(self):
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'google.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.plug.is_valid = 1
        self.plug.author_domains = [b'gmail.com']
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature

        result = self.plug._check_dkim_signed_by(self.mock_msg, 1, 1,
                                                 'gmail.com')
        self.assertFalse(result)

    def test_check_dkim_signature(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.return_value = True
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (1, 1, 1))

    def test_check_dkim_signature_message_format_error(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.side_effect = dkim.MessageFormatError
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (0, 1, 0))

    def test_check_dkim_signature_message_validation_error(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.side_effect = dkim.ValidationError
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (0, 1, 0))

    def test_check_dkim_signature_message_key_format_error(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.side_effect = dkim.KeyFormatError
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (0, 1, 0))

    def test_check_dkim_signature_uncorrect_signature_domain(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'example.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.return_value = True
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (0, 0, 0))

    def test_check_dkim_signature_result_false(self):
        message = "Message"
        dkim_signature = "Signature"
        parsed_signature = {b'a': b'rsa-sha256',
                            b'c': b'relaxed/relaxed',
                            b's': b'20120113',
                            b'h': b'mime-version:from:date:message-id:subject:to',
                            b'v': b'1',
                            b'bh': b'Dv0CkJSC1ekvQd/JcC/hXp/1AjTsoZ+GIbd7HbXO/4M=',
                            b'd': b'gmail.com',
                            b'b': b'fgMfuR+WI3pI+yUJnZgwdOs1BU5DEepzyF4Z0QNvTvnGj79OVjCcHY70JrDglExU+c\n         '
                                  b'mCQsc3yocY/k5jMeU47imXjWFxeJGdHSlNe6mQf5GsXMizEl97BbcDkkGso66RjrJ4dE\n         '
                                  b'2Na4bQ/rJGU4gTuhD3bMEvkfXXWNHbDyCPjZnOAz97qryWHZZauKzqJ9pRgpj9cj9Rge\n         '
                                  b'TMoOYbv/exIF/VIiC9IXiCFmFY0NVCbqi1ksbjt/0cp+S1NeEl95d2FkAkOUPsCu9kto\n         '
                                  b'eriiEP6KqssKrmmX4XC2ovcTg9fxJZeS2VsgBOT0WHXDMEtp1KldthDIOZYVMZFbXRlc\n         '
                                  b'RsvA=='}
        self.global_data["dkim_minimum_key_bits"] = -2
        self.mock_msg.raw_msg = message
        self.mock_msg.get.return_value = dkim_signature
        self.mock_dkim_parse_tag.return_value = parsed_signature
        self.mock_dkim_verify.return_value = False
        self.plug.author_domains = [b"gmail.com"]
        self.plug.check_dkim_signature(self.mock_msg)

        self.assertEqual((self.plug.dkim_valid, self.plug.dkim_signed,
                          self.plug.dkim_has_valid_author_sig), (0, 1, 1))


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')