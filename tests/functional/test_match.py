"""Test the match script."""

from __future__ import absolute_import

import tests.util

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


class TestBodyRules(tests.util.TestBase):

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
        """Rule should be matched and reported"""
        self.setup_conf(config="body TEST_RULE /abcd/", pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\nTest abcd test.")
        self.assertEqual(result, "1.0")

    def test_gtube(self):
        """Gtube should be matched and reported"""
        self.setup_conf(pre_config="report _SCORE_")
        result = self.check_pad("Subject: test\n\n" + GTUBE)
        self.assertEqual(result, "1000.0")



