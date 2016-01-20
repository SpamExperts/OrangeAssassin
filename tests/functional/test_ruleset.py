"""Functional tests for the Ruleset features such as:

 - Configuring a report
 - Interpolating tags correctly
 - Adjust the message (headers/body)

etc.
"""
from __future__ import absolute_import

import tests.util

from tests.util import GTUBE


class TestReport(tests.util.TestBase):

    def test_custom_report_yesno_spam(self):
        """Test the custom report and YESNO tag"""
        self.setup_conf(pre_config="report Test report template: _YESNO_")
        result = self.check_pad("Subject: test\n\n%s" % GTUBE)
        self.assertEqual(result, "Test report template: Yes")

    def test_custom_report_yesno_ham(self):
        """Test the custom report and YESNO tag"""
        self.setup_conf(pre_config="report Test report template: _YESNO_")
        result = self.check_pad("Subject: test\n\nTest message.")
        self.assertEqual(result, "Test report template: No")

