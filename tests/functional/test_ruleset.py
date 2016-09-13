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
describe CHECK_TEST_EXIST This text is in english
lang fr describe CHECK_TEST_EXIST This text is in french
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
        """If locale is set to en_US the default rule description should be used"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.UTF-8"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST This text is in english")

    def test_fr_locale_rule_description(self):
        """If locale is set to fr_FR the frech rule description should be used"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "fr_FR.utf8"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST This text is in french")

    def test_override_fr_locale_rule_description(self):
        """If locale is set to fr_FR and two french descriptions are used,
        the last frech rule description should be used. This also tests if
        lang_Country (fr_FR) works"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "fr_FR.utf8"

        second_description = "\nlang fr_FR describe CHECK_TEST_EXIST Last description"

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + second_description)
        result = self.check_pad(message="Subject: test\n\nTest message.", env=my_env)
        self.assertEqual(result, "* 1.0 CHECK_TEST_EXIST Last description")

    def test_default_locale_report_description(self):
        """If locale is set to en_US only the default report description
        should be used"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.UTF-8"

        report_description = """\nreport This text is in english
        \nlang fr report This text is in french"""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in english")

    def test_fr_locale_report_description(self):
        """If locale is set to fr_FR the default report description + the fr
        report description should be used"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "fr_FR.UTF-8"

        report_description = """\nreport This text is in english
        \nlang fr report This text is in french"""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in english\nThis text is in french")

