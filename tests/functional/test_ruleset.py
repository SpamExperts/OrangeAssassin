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
score CHECK_TEST_EXIST 5
describe CHECK_TEST_EXIST This description is in US english
lang en_GB describe CHECK_TEST_EXIST This description is in GB english
"""

UNSAFE_PRE_CONFIG = """
report Normal report
report Normal report appended
unsafe_report Unsafe report
unsafe_report Unsafe report appended
"""

SPAM_EMAIL = """Content-Type: multipart/mixed; boundary=001a1140b054739bd2054029cd16

Subject: Test Spam

test

--001a1140b054739bd2054029cd16
Content-Type: application/octet-stream; name=keep
Content-Disposition: attachment; filename=keep
Content-Transfer-Encoding: base64
X-Attachment-Id: f_iuy5ajvs0

--001a1140b054739bd2054029cd16--
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
        """If locale is set to en_US the default rule description
        should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.utf8"
        my_env["LC_ALL"] = ""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.",
                                env=my_env)
        self.assertEqual(result, "* 5.0 CHECK_TEST_EXIST "
                                 "This description is in US english")

    def test_custom_locale_rule_description(self):
        """If locale is set to en_GB the corresponding rule description
        should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.utf8"
        my_env["LC_ALL"] = ""

        self.setup_conf(pre_config=PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Subject: test\n\nTest message.",
                                env=my_env)
        self.assertEqual(result, "* 5.0 CHECK_TEST_EXIST "
                                 "This description is in GB english")

    def test_override_custom_locale_rule_description(self):
        """If locale is set to en-GB and two descriptions are used for this
        language, the las corresponding description should be displayed."""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.utf8"
        my_env["LC_ALL"] = ""

        second_description = ("\nlang en_GB describe CHECK_TEST_EXIST "
                              "Last description")

        self.setup_conf(pre_config=PRE_CONFIG,
                        config=CONFIG + second_description)
        result = self.check_pad(message="Subject: test\n\nTest message.",
                                env=my_env)
        self.assertEqual(result, "* 5.0 CHECK_TEST_EXIST "
                                 "Last description")

    def test_default_locale_report_description(self):
        """If locale is set to en_US only the default report description
        should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_US.utf8"
        my_env["LC_ALL"] = ""

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG,
                        config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in US english")

    def test_custom_locale_report_description(self):
        """If locale is set to en_GB the default report description + the en_GB
        report description should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.utf8"
        my_env["LC_ALL"] = ""

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG,
                        config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result, "This text is in US english\n"
                                 "This text is in GB english")

    def test_override_custom_locale_report_description(self):
        """If locale is set to en_GB the default report description + all
        the en_GB report descriptions should be displayed"""
        my_env = os.environ.copy()
        my_env["LC_MESSAGES"] = "en_GB.utf8"
        my_env["LC_ALL"] = ""

        report_description = """\nreport This text is in US english
        \nlang en_GB report This text is in GB english
        \nlang en_GB report This second text is in GB english"""

        self.setup_conf(pre_config=PRE_CONFIG,
                        config=CONFIG + report_description)
        result = self.check_pad(message="Empty message", env=my_env)
        self.assertEqual(result,
                         "This text is in US english\n"
                         "This text is in GB english\n"
                         "This second text is in GB english")


class TestReportTemplate(tests.util.TestBase):

    def test_report_template_enabled(self):
        self.setup_conf(pre_config=UNSAFE_PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message=SPAM_EMAIL,
                                report_only=False, message_only=True)

        self.assertTrue("Normal report" in result)
        self.assertTrue("Normal report appended" in result)
        self.assertTrue("Unsafe report" in result)
        self.assertTrue("Unsafe report appended" in result)

    def test_report_template_disabled(self):
        self.setup_conf(pre_config=UNSAFE_PRE_CONFIG, config=CONFIG)
        result = self.check_pad(message="Test email",
                                report_only=False, message_only=True)

        self.assertTrue("Normal report" not in result)
        self.assertTrue("Normal report appended" not in result)
        self.assertTrue("Unsafe report" not in result)
        self.assertTrue("Unsafe report appended" not in result)

    def test_clear_report_template(self):
        self.setup_conf(pre_config=UNSAFE_PRE_CONFIG +
                        "\n clear_unsafe_report_template" +
                        "\n clear_report_template", config=CONFIG)
        result = self.check_pad(message=SPAM_EMAIL, report_only=False,
                                message_only=True)

        self.assertTrue("Normal report" not in result)
        self.assertTrue("Normal report appended" not in result)
        self.assertTrue("Unsafe report" not in result)
        self.assertTrue("Unsafe report appended" not in result)
