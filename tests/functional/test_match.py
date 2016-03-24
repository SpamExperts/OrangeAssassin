# -*- coding: UTF-8 -*-

"""Test the match script."""

from __future__ import absolute_import, print_function
import os
import unittest

import tests.util

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

MULTIPART_MSG = r"""From: Marco Antonio Islas Cruz <marco@seinternal.com>
Content-Type: multipart/alternative;
    boundary="Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C"
X-Smtp-Server: smtp.gmail.com:marco@seinternal.com
Subject: Non text email
X-Universally-Unique-Identifier: 6c318f30-bec6-49cf-a37c-e651b9ce970e
Message-Id: <FC768970-9D08-4702-B0BF-9ED7A21F9D97@islascruz.org>
To: Marco antonio Islas Cruz <marco@seinternal.com>
Mime-Version: 1.0 (Apple Message framework v1257)


--Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C
Content-Type: multipart/related;
    type="text/html";
    boundary="Apple-Mail=_7F2342CA-8904-478A-B198-D63EE91D8288"


--Apple-Mail=_7F2342CA-8904-478A-B198-D63EE91D8288
Content-Transfer-Encoding: 7bit
Content-Type: text/html;
    charset=us-ascii

<html><head></head><body style="word-wrap: break-word; -webkit-nbsp-mode: space; -webkit-line-break: after-white-space; "><div>This is a test?</div><div><br></div><img id="7c666adc-282a-46d4-9f3c-adce8a02b0be" height="339" width="530" apple-width="yes" apple-height="yes" src="cid:40808429-84C6-4DB6-982E-451F05730FE0@ubuntu"><br><br>
Testing rule one-two-three
<br></body></html>
--Apple-Mail=_9311E301-2E56-423D-B730-30A522F3844C--
"""

BAD_ENCODING = u"""Received: from example.com ([2a01:4f8:d12:1380::1337])
 by server1.com with esmtp (Exim 4.76)
 (envelope-from <test@example.com>) id 1SlXJV-0006Vp-GB
 for testuser@example.com; Mon, 02 Jul 2012 05:28:37 +0200
From: test@example.com
To: testuser@example.com
Subject: Test message тест

Test
"""


class TestMatchScript(tests.util.TestBase):

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_pass(self):
        """No rule matched here, no report"""
        self.setup_conf()
        result = self.check_pad("Subject: test\n\nThis is a test")
        self.assertEqual(result, "")

    def test_match(self):
        """Rule should be matched and score reported"""
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.")
        self.assertEqual(result, "1.0")

    def test_no_match(self):
        """Rule shouldn't be matched but score reported"""
        self.setup_conf(config="body TEST_RULE /abddd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.")
        self.assertEqual(result, "0.0")

    def test_gtube(self):
        """Gtube should be matched"""
        self.setup_conf(pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\n" + GTUBE)
        self.assertEqual(result, "1000.0")

    def test_match_revoke(self):
        """Rule should be matched and revoked"""
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=False, extra_args=["--revoke", ])
        self.assertEqual(result, "1 message(s) examined")

    def test_match_report(self):
        """Rule should be matched and reported"""
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=False, extra_args=["--report", ])
        self.assertEqual(result, "1 message(s) examined")

    def test_match_show_unknown(self):
        """Rule should be matched with show-unknown option"""
        # This will fail on SA
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=True, extra_args=["--show-unknown", ])
        self.assertEqual(result, "1.0")

    def test_match_show_paranoid(self):
        """Rule should be matched with paranoid option"""
        # This will fail on SA
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=True, extra_args=["--paranoid", ])
        self.assertEqual(result, "1.0")

    def test_match_multipart(self):
        """Rule should be matched with multipart message"""
        self.setup_conf(config="body TEST_RULE /one-two-three/",
                        pre_config="report _SCORE_")
        result = self.check_pad(MULTIPART_MSG)
        self.assertEqual(result, "1.0")

    def test_no_match_multipart(self):
        """Rule shouldn't be matched with multipart message"""
        self.setup_conf(config="body TEST_RULE /one-two-four/",
                        pre_config="report _SCORE_")
        result = self.check_pad(MULTIPART_MSG)
        self.assertEqual(result, "0.0")

    def test_match_several_rules(self):
        """Rule should be matched and score reported"""
        self.setup_conf(
            config="body TEST_RULE /abcd/\n"
                   "body GTUBE /XJS\*C4JDBQADN1\.NSBN3\*2IDN"
                   "EN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/",
            pre_config="report _SCORE_")
        result = self.check_pad(
            "Subject: test\n\nTest abcd test. {0}".format(GTUBE))
        self.assertEqual(result, "2.0")

    def test_no_match_several_rules(self):
        """Rule shouldn't be matched but score reported"""
        self.setup_conf(
            config="body TEST_RULE /abcd/\n"
                   "body GTUBE /XJS\*C4JDBQADN1\.NSBN3\*2IDN"
                   "EN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/",
            pre_config="report _SCORE_")
        result = self.check_pad(MULTIPART_MSG)
        self.assertEqual(result, "0.0")

    def test_no_match_bad_encoding(self):
        """Rule shouldn't be matched but score reported.
        No errors should occur."""
        self.setup_conf(
            config="body TEST_RULE /abcd/\n"
                   "body GTUBE /XJS\*C4JDBQADN1\.NSBN3\*2IDN"
                   "EN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/",
            pre_config="report _SCORE_")
        result = self.check_pad(BAD_ENCODING)
        self.assertEqual(result, "0.0")

    def test_report_plugin(self):
        # This will fail on SA
        expected = u"Reporting message.\n1 message(s) examined"
        cwd = os.path.join(os.getcwd(), "tests", "util", "sample_plugin.py")
        plugin_name = "TestPluginReportRevoke"
        self.setup_conf(
            config="",
            pre_config="loadplugin %s %s" % (plugin_name, cwd)
        )
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=False, extra_args=["--report", ])
        self.assertEqual(result, expected)

    def test_revoke_plugin(self):
        # This will fail on SA
        expected = u"Revoking message.\n1 message(s) examined"
        cwd = os.path.join(os.getcwd(), "tests", "util", "sample_plugin.py")
        plugin_name = "TestPluginReportRevoke"
        self.setup_conf(
            config="",
            pre_config="loadplugin %s %s" % (plugin_name, cwd)
        )
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=False, extra_args=["--revoke", ])
        self.assertEqual(result, expected)

    def test_report_revoke_error(self):
        # This will fail on SA
        expected = ""
        cwd = os.path.join(os.getcwd(), "tests", "util", "sample_plugin.py")
        plugin_name = "TestPluginReportRevoke"
        self.setup_conf(
            config="",
            pre_config="loadplugin %s %s" % (plugin_name, cwd)
        )
        result = self.check_pad("Subject: test\n\nTest abcd test.",
                                report_only=False, extra_args=["--report",
                                                               "--revoke"])
        self.assertEqual(result, expected)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestMatchScript, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
