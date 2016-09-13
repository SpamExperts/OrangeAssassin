"""Functional tests for the Ruleset features such as:

 - Configuring a report
 - Interpolating tags correctly
 - Adjust the message (headers/body)

etc.
"""
from __future__ import absolute_import

import os
import tests.util

from tests.util import GTUBE


PRE_CONFIG = """
report _REPORT_
"""

# Define rules for plugin
CONFIG = """
full   CHECK_TEST_EXIST  /test/
describe CHECK_TEST_EXIST This description is in US english
lang en_GB describe CHECK_TEST_EXIST This description is in GB english
"""

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

class TestLocaleReport(tests.util.TestBase):
    """Class containing tests for rules locale description and report locale
    description"""

    def test_default_locale_rule_description(self):
        """If locale is set to en_US the default rule description should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.UTF-8"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST This description is in US english")

    def test_custom_locale_rule_description(self):
        """If locale is set to en_GB the corresponding rule description should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.UTF-8"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST This description is in GB english")

    def test_override_custom_locale_rule_description(self):
        """If locale is set to en-GB and two descriptions are used for this language,
        the las corresponding description should be displayed."""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.UTF-8"

        second_description = "\nlang en_GB describe CHECK_TEST_EXIST Last description"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + second_description)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST Last description")

    def test_default_locale_report_description(self):
        """If locale is set to en_US only the default report description
        should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.UTF-8"

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in US english")

    def test_custom_locale_report_description(self):
        """If locale is set to en_GB the default report description + the en_GB
        report description should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.UTF-8"

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in US english\nThis text is in GB english")

    def test_override_custom_locale_report_description(self):
        """If locale is set to en_GB the default report description + all the en_GB
        report descriptions should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.UTF-8"

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english
        \nlang en_GB report This second text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result,
            "This text is in US english\nThis text is in GB english\nThis second text is in GB english")
