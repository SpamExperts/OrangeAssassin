"""Test the match script."""

from __future__ import absolute_import

import tests.util


class TestBodyRules(tests.util.TestBase):

    def test_pass(self):
        """No rule matched here, no report"""
        self.setup_conf()
        result = self.check_pad("Subject: test\n\nThis is a test")
        self.assertEqual(result, "")
