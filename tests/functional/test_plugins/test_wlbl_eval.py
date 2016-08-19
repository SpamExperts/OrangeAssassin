"""Tests the WLBLEval Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin pad.plugins.wlbl_eval.WLBLEvalPlugin
report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """
body   CHECK_FROM_IN_WHITELIST             eval:check_from_in_whitelist()
body   CHECK_FROM_IN_BLACKLIST             eval:check_from_in_blacklist()
body   CHECK_TO_IN_WHITELIST               eval:check_to_in_whitelist()
body   CHECK_TO_IN_BLACKLIST               eval:check_to_in_blacklist()
body   CHECK_TO_IN_MORE_SPAM               eval:check_to_in_more_spam()
body   CHECK_TO_IN_ALL_SPAM                eval:check_to_in_all_spam()
body   CHECK_FORGED_IN_WHITELIST           eval:check_forged_in_whitelist()
body   CHECK_FROM_IN_DEFAULT_LIST          eval:check_from_in_default_list()
body   CHECK_FORGED_IN_DEFAULT_WHITELIST   eval:check_forged_in_default_whitelist()
body   CHECK_MALFORM_MATCHES_RCVD          eval:check_malform_matches_rcvd()
body   CHECK_URI_HOST_IN_BLACKLIST         eval:check_uri_host_in_blacklist()
body   CHECK_URI_HOST_IN_WHITELIST         eval:check_uri_host_in_whitelist()
"""

#body   CHECK_FROM_IN_LIST                  eval:check_from_in_list()
#body   CHECK_TO_IN_LIST                    eval:check_to_in_list()
#body   CHECK_URI_HOST_LISTED               eval:check_uri_host_listed()


class TestFunctionalWLBLEval(tests.util.TestBase):
    """Functional Tests for the WLBLEval Plugin"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_wlbl_from_full_address_on_from_header(self):
        lists = """
            whitelist_from fulladdress@example.com
            blacklist_from fulladdress@example.com
        """

        email = "From: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_local_part_on_from_header(self):
        lists = """
            whitelist_from *@e?ample.com
            blacklist_from *@e?ample.com
        """

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_domain_on_from_header(self):
        lists = """
            whitelist_from *exampl?.com
            blacklist_from *exampl?.com
        """

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_full_domain_on_from_header(self):
        lists = """
            whitelist_from example.com
            blacklist_from example.com
        """

        email = "From: <test@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_invalid_globing_on_from_header(self):
        lists = """
            whitelist_from .*example.com
            blacklist_from .*example.com
        """

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_from_header_containing_full_name(self):
        lists = """
            whitelist_from example.com
            blacklist_from example.com
        """

        email = "From: example.com <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_from_header(self):
        lists = """
            whitelist_from .*example.com example.net test@example.org
            blacklist_from .*example.com example.net test@example.org
        """

        email = "From: <test@example.com> <test@example.net> <test@example.org>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_split_list_on_from_header(self):
        lists = """
            whitelist_from .*example.com
            whitelist_from example.net
            whitelist_from test@example.org
            blacklist_from .*example.com
            blacklist_from example.net
            blacklist_from test@example.org
        """

        email = "From: <test@example.com> <test@example.net> <test@example.org>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_from_header_containing_combined_stuff_negative(self):
        lists = """
            whitelist_from test@example.com test2@example.com
            blacklist_from test@example.com test2@example.com
        """

        email = "From: email1@example.com, test@example.com <email2@example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_from_header_containing_combined_stuff_positive(self):
        lists = """
            whitelist_from test@example.com test2@example.com
            blacklist_from test@example.com test2@example.com
        """

        email = "From: email1@example.com, Full Name <test2@example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_from_header_no_list(self):
        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')

