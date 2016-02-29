"""Tests for pad.plugins.spf."""

import unittest
import collections

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.spf


class TestSpf(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.hostname_with_ip = []
        self.local_data = {}
        self.global_data = {
            "spf_timeout": 10
        }
        self.mock_ctxt = MagicMock()
        self.mock_msg = MagicMock(hostname_with_ip=self.hostname_with_ip,
                                  msg={})
        self.plugin = pad.plugins.spf.SpfPlugin(self.mock_ctxt)
        self.plugin.set_local = lambda m, k, v: self.local_data.__setitem__(k,
                                                                            v)
        self.plugin.get_local = lambda m, k: self.local_data.__getitem__(k)
        self.plugin.set_global = self.global_data.__setitem__
        self.plugin.get_global = self.global_data.__getitem__
        self.mock_ruleset = MagicMock()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parsed_metadata_with_headers(self):
        self.plugin._query_spf = Mock()
        self.hostname_with_ip.append(("example.com", "127.0.0.1"))
        self.global_data["ignore_received_spf_header"] = True
        self.plugin.parsed_metadata(self.mock_msg)
        self.plugin._query_spf.assert_called_with(
            10, "127.0.0.1", "example.com", self.mock_msg.sender_address
        )

    def test_parsed_metadata_with_query(self):
        self.plugin._check_spf_header = Mock()
        self.global_data["ignore_received_spf_header"] = False
        self.global_data["use_newest_received_spf_header"] = False
        self.plugin.parsed_metadata(self.mock_msg)
        self.plugin._check_spf_header.assert_called_with(
            self.mock_msg, self.global_data["use_newest_received_spf_header"]
        )

    def test_check_for_spf_pass_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "pass")
        self.assertTrue(self.plugin.check_for_spf_pass(self.mock_msg))

    def test_check_for_spf_pass_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_pass(self.mock_msg))

    def test_check_for_spf_neutral_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "neutral")
        self.assertTrue(self.plugin.check_for_spf_neutral(self.mock_msg))

    def test_check_for_spf_neutral_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_neutral(self.mock_msg))

    def test_check_for_spf_none_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "none")
        self.assertTrue(self.plugin.check_for_spf_none(self.mock_msg))

    def test_check_for_spf_none_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_none(self.mock_msg))

    def test_check_for_spf_fail_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "fail")
        self.assertTrue(self.plugin.check_for_spf_fail(self.mock_msg))

    def test_check_for_spf_fail_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_fail(self.mock_msg))

    def test_check_for_spf_softfail_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "softfail")
        self.assertTrue(self.plugin.check_for_spf_softfail(self.mock_msg))

    def test_check_for_spf_softfail_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_softfail(self.mock_msg))

    def test_check_for_spf_permerror_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "permerror")
        self.assertTrue(self.plugin.check_for_spf_permerror(self.mock_msg))

    def test_check_for_spf_permerror_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_permerror(self.mock_msg))

    def test_check_for_spf_temperror_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "temperror")
        self.assertTrue(self.plugin.check_for_spf_temperror(self.mock_msg))

    def test_check_for_spf_temperror_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_temperror(self.mock_msg))

    def test_check_for_spf_helo_pass_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_pass")
        self.assertTrue(self.plugin.check_for_spf_helo_pass(self.mock_msg))

    def test_check_for_spf_helo_pass_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_helo_pass(self.mock_msg))

    def test_check_for_spf_helo_neutral_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_neutral")
        self.assertTrue(self.plugin.check_for_spf_helo_neutral(self.mock_msg))

    def test_check_for_spf_helo_neutral_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_helo_neutral(self.mock_msg))

    def test_check_for_spf_helo_none_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_none")
        self.assertTrue(self.plugin.check_for_spf_helo_none(self.mock_msg))

    def test_check_for_spf_helo_none_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_helo_none(self.mock_msg))

    def test_check_for_spf_helo_fail_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_fail")
        self.assertTrue(self.plugin.check_for_spf_helo_fail(self.mock_msg))

    def test_check_for_spf_helo_fail_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_helo_fail(self.mock_msg))

    def test_check_for_spf_helo_softfail_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_softfail")
        self.assertTrue(self.plugin.check_for_spf_helo_softfail(self.mock_msg))

    def test_check_for_spf_helo_softfail_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(self.plugin.check_for_spf_helo_softfail(self.mock_msg))

    def test_check_for_spf_helo_permerror_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_permerror")
        self.assertTrue(self.plugin.check_for_spf_helo_permerror(self.mock_msg))

    def test_check_for_spf_helo_permerror_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(
            self.plugin.check_for_spf_helo_permerror(self.mock_msg))

    def test_check_for_spf_helo_temperror_true(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "helo_temperror")
        self.assertTrue(self.plugin.check_for_spf_helo_temperror(self.mock_msg))

    def test_check_for_spf_helo_temperror_false(self):
        self.plugin.set_local(self.mock_msg, "spf_result", "")
        self.assertFalse(
            self.plugin.check_for_spf_helo_temperror(self.mock_msg))

    def test_query_spf(self):
        mockspf_check = patch("pad.plugins.spf.spf.check2", return_value=(
        'pass', 'sender SPF authorized')).start()
        self.plugin._query_spf(10, "127.0.0.1", "example.com",
                               self.mock_msg.sender_address)
        mockspf_check.assert_called_with(i="127.0.0.1",
                                         s=self.mock_msg.sender_address,
                                         h="example.com", timeout=10)

    def test_check_spf_header_no_headers(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = ""
        authres = ""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, '')

    def test_check_spf_header_only_receivedspf(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""
        authres = ""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'pass')

    def test_check_spf_header_only_authres(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = ""
        authres = """example.com;
           spf=pass (example.com: domain of test@example.com designates
           192.0.2.1 as permitted sender) smtp.mailfrom=test@example.com;
           dkim=pass header.i=@example.com;
           dmarc=pass (p=NONE dis=NONE) header.from=example.com"""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'pass')

    def test_check_spf_header_authres_and_received(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""
        authres = """example.com;
           spf=pass (example.com: domain of test@example.com designates
           192.0.2.1 as permitted sender) smtp.mailfrom=test@example.com;
           dkim=pass header.i=@example.com;
           dmarc=pass (p=NONE dis=NONE) header.from=example.com"""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'pass')

    def test_check_spf_header_received_helo_pass(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=helo; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""

        authres = ""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'helo_pass')

    def test_check_spf_header_authres_helo_pass(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = ""
        authres = """example.com;
           spf=pass (example.com: domain of test@example.com designates
           192.0.2.1 as permitted sender) smtp.helo=test@example.com;
           dkim=pass header.i=@example.com;
           dmarc=pass (p=NONE dis=NONE) header.from=example.com"""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'helo_pass')

    def test_check_spf_header_received_mailfrom_pass(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=mailfrom; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""
        authres = ""

        self.mock_msg.get_decoded_header.return_value = [received_spf]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'pass')

    def test_check_spf_header_many_received(self):
        self.global_data["use_newest_received_spf_header"] = False
        received_spf1 = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=mailfrom; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""

        received_spf2 = """fail (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=mailfrom; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""

        authres = """example.com;
           spf=pass (example.com: domain of test@example.com designates
           192.0.2.1 as permitted sender) smtp.helo=test@example.com;
           dkim=pass header.i=@example.com;
           dmarc=pass (p=NONE dis=NONE) header.from=example.com"""

        self.mock_msg.get_decoded_header.return_value = [received_spf1,
                                                         received_spf2]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'fail')

    def test_check_spf_header_many_received_newest(self):
        self.global_data["use_newest_received_spf_header"] = True
        received_spf1 = """pass (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=mailfrom; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""

        received_spf2 = """fail (mybox.example.org: domain of
        myname@example.com designates 192.0.2.1 as permitted sender)
        identity=mailfrom; receiver=mybox.example.org; client-ip=192.0.2.1;
        envelope-from=<myname@example.com>; helo=foo.example.com;"""

        authres = """example.com;
           spf=pass (example.com: domain of test@example.com designates
           192.0.2.1 as permitted sender) smtp.helo=test@example.com;
           dkim=pass header.i=@example.com;
           dmarc=pass (p=NONE dis=NONE) header.from=example.com"""

        self.mock_msg.get_decoded_header.return_value = [received_spf1,
                                                         received_spf2]
        self.mock_msg.msg["authentication-results"] = authres

        result = self.plugin._check_spf_header(self.mock_msg, self.global_data[
            "use_newest_received_spf_header"])
        self.assertEqual(result, 'pass')
