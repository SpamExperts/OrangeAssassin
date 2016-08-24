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
body   CHECK_FROM_IN_DEFAULT_WHITELIST     eval:check_from_in_default_whitelist()

body   CHECK_TO_IN_WHITELIST               eval:check_to_in_whitelist()
body   CHECK_TO_IN_BLACKLIST               eval:check_to_in_blacklist()
body   CHECK_TO_IN_MORE_SPAM               eval:check_to_in_more_spam()
body   CHECK_TO_IN_ALL_SPAM                eval:check_to_in_all_spam()

body   CHECK_URI_HOST_LISTED_MYLIST        eval:check_uri_host_listed('MYLIST')
body   CHECK_URI_HOST_IN_WHITELIST         eval:check_uri_host_in_whitelist()
body   CHECK_URI_HOST_IN_BLACKLIST         eval:check_uri_host_in_blacklist()
"""


class TestFunctionalWLBLEval(tests.util.TestBase):
    """Functional Tests for the WLBLEval Plugin"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    # From header tests

    def test_wlbl_from_on_to_header(self):
        lists = """
            whitelist_from test@example.com
            blacklist_from test@example.com
        """

        email = """To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_in_wlbl_with_full_address(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_in_wlbl_with_full_address_negative(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                """

        email = """From: email@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_in_wlbl_with_wild_local_part(self):
        lists = """
                    whitelist_from *@e?ample.com
                    blacklist_from *@e?ample.com
                """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_with_full_domain(self):
        lists = """
                    whitelist_from example.com
                    blacklist_from example.com
                """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_with_wild_domain(self):
        lists = """
                    whitelist_from *exam?le.com
                    blacklist_from *exam?le.com
                """

        email = """From: test@test.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_with_regex(self):
        lists = """
                    whitelist_from .*.com
                    blacklist_from .*.com
                """

        email = """From: test@test.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_with_full_name_on_from_header(self):
        lists = """
            whitelist_from test@example.com
            blacklist_from test@example.com
        """

        email = "From: Full Name <test@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_no_lists(self):
        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_empty_lists(self):
        lists = """
            whitelist_from
            blacklist_from
        """

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_invalid_lists(self):
        lists = """
            whitelist_from example
            blacklist_from example
        """

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_combined_lists(self):
        lists = """
            whitelist_from .*example.com example.net test@example.org
            blacklist_from .*example.com example.net test@example.org
        """

        email = """From: test@example.com, test@example.net, test@example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_split_lists(self):
        lists = """
            whitelist_from .*example.com
            blacklist_from .*example.com
            whitelist_from example.net
            blacklist_from example.net
            whitelist_from test@example.org
            blacklist_from test@example.org
        """

        email = """From: test@example.com, test@example.net, test@example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_from_wlbl_ignore_headers_if_resent_from_exist(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                """

        email = """Resent-From: email@example.com\n
        From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_resent_from(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                """

        email = """Resent-From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    # To header tests

    def test_wlbl_to_on_from_header(self):
        lists = """
            whitelist_to test@example.com
            blacklist_to test@example.com
            more_spam_to test@example.com
            all_spam_to test@example.com
        """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_in_wlbl_with_full_address(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_in_wlbl_with_full_address_negative(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                    more_spam_to   test@example.com
                    all_spam_to    test@example.com
                """

        email = """To: email@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_in_wlbl_with_wild_local_part(self):
        lists = """
                     whitelist_to *@e?ample.com
                     blacklist_to *@e?ample.com
                     more_spam_to *@e?ample.com
                     all_spam_to  *@e?ample.com
                """

        email = """To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_with_full_domain(self):
        lists = """
                    whitelist_to example.com
                    blacklist_to example.com
                    more_spam_to example.com
                    all_spam_to  example.com
                """

        email = """To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_with_wild_domain(self):
        lists = """
                    whitelist_to *exam?le.com
                    blacklist_to *exam?le.com
                    more_spam_to *exam?le.com
                    all_spam_to  *exam?le.com
                """

        email = """To: test@test.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_with_regex(self):
        lists = """
                    whitelist_to .*.com
                    blacklist_to .*.com
                    more_spam_to .*.com
                    all_spam_to  .*.com
                """

        email = """To: test@test.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_with_full_name_on_from_header(self):
        lists = """
            whitelist_to test@example.com
            blacklist_to test@example.com
            more_spam_to test@example.com
            all_spam_to  test@example.com
        """

        email = "To: Full Name <test@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_no_lists(self):
        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_empty_lists(self):
        lists = """
            whitelist_to
            blacklist_to
            more_spam_to
            all_spam_to
        """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_invalid_lists(self):
        lists = """
            whitelist_to example
            blacklist_to example
        """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_combined_lists(self):
        lists = """
            whitelist_to .*example.com example.net test@example.org
            blacklist_to .*example.com example.net test@example.org
            more_spam_to .*example.com example.net test@example.org
            all_spam_to  .*example.com example.net test@example.org
        """

        email = """To: test@example.com, test@example.net, test@example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_split_lists(self):
        lists = """
            whitelist_to .*example.com
            blacklist_to .*example.com
            more_spam_to .*example.com
            all_spam_to  .*example.com
            whitelist_to example.net
            blacklist_to example.net
            more_spam_to example.net
            all_spam_to example.net
            whitelist_to test@example.org
            blacklist_to test@example.org
            more_spam_to test@example.org
            more_spam_to test@example.org
        """

        email = """To: test@example.com, test@example.net, test@example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_ignore_headers_if_resent_to_exist(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """Resent-To: email@example.com\n
        To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_ignore_headers_if_resent_cc_exist(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """Resent-Cc: email@example.com\n
        To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_resent_to(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """Resent-To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    def test_to_wlbl_resent_cc(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """Resent-Cc: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 4, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM'])

    # From header, default whitelist tests

    def test_from_in_def_wl_ignore_headers_if_resent_from_exist(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
                    whitelist_from_rcvd     test@spamexperts.com [5.79.73.204]
                """

        email = """Resent-From: test@example.com
From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_in_def_wl_with_full_address_with_ip(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
                    whitelist_from_rcvd     test@spamexperts.com [5.79.73.204]
                """

        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_in_def_wl_with_full_address_with_domain(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com spamexperts.com
                    whitelist_from_rcvd     test@spamexperts.com spamexperts.com
                """

        email = """From: test@spamexperts.com
Received: from example.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_in_def_wl_with_full_address_negative(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
                    whitelist_from_rcvd     test@spamexperts.com [5.79.73.204]
                """

        email = """From: email@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_in_def_wl_with_wild_local_part(self):
        lists = """
                    def_whitelist_from_rcvd *@s?amexperts.com [5.79.73.204]
                    whitelist_from_rcvd     *@s?amexperts.com [5.79.73.204]
                """

        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_with_full_domain(self):
        lists = """
                    def_whitelist_from_rcvd spamexperts.com [5.79.73.204]
                    whitelist_from_rcvd     spamexperts.com [5.79.73.204]
                """

        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_with_wild_domain(self):
        lists = """
                    def_whitelist_from_rcvd *spame?perts.com [5.79.73.204]
                    whitelist_from_rcvd     *spame?perts.com [5.79.73.204]
                """

        email = """From: test@test.spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_with_regex(self):
        lists = """
                    def_whitelist_from_rcvd .*.com [5.79.73.204]
                    whitelist_from_rcvd     .*.com [5.79.73.204]
                """

        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_def_wl_with_full_name_on_from_header(self):
        lists = """
            def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
            whitelist_from_rcvd     test@spamexperts.com [5.79.73.204]
        """

        email = """From: Full Name <test@spamexperts.com>
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_no_lists(self):
        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_def_wl_empty_lists(self):
        lists = """
            def_whitelist_from_rcvd
            whitelist_from_rcvd
        """

        email = """From: test@example.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_def_wl_invalid_lists(self):
        lists = """
            def_whitelist_from_rcvd spamexperts [5.79.73.204]
            whitelist_from_rcvd spamexperts [5.79.73.204]
        """

        email = """From: test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_def_wl_combined_lists(self):
        lists = """
            def_whitelist_from_rcvd .*example.com [1.2.3.4], example.net [1.2.3.5], test@spamexperts.com [5.79.73.204]
            whitelist_from_rcvd .*example.com  [1.2.3.4], example.net [1.2.3.5], test@spamexperts.com [5.79.73.204]
        """

        email = """From: test@example.com, test@example.net, test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_split_lists(self):
        lists = """
            def_whitelist_from_rcvd .*example.com [1.2.3.4]
            whitelist_from_rcvd .*example.com  [1.2.3.4]
            def_whitelist_from_rcvd example.net [1.2.3.5]
            whitelist_from_rcvd example.net [1.2.3.5]
            def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
            whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
        """

        email = """From: test@example.com, test@example.net, test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_multi_relay(self):
        lists ="""
            def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
            whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
        """

        email = """From: test@spamexperts.com
Received: from example.com [5.1.3.7]
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_subnet_relay(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com [5.79.73]
                    whitelist_from_rcvd     test@spamexperts.com [5.79.73]
                """

        email = """From: test@example.com, test@example.net, test@spamexperts.com
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_DEFAULT_WHITELIST'])

    def test_from_def_wl_no_match_relay(self):
        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com spamexperts.com
                    whitelist_from_rcvd test@spamexperts.com spamexperts.com
                """

        email = """From: test@spamexperts.com
Received: from example.com [1.2.3.4]
"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Enlist uri host tests

    def test_enlist_uri_host_domain_match(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_domain_match_sub_domain(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                """

        email = """Hello everyone this is a test email from http://sub.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                  'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_domain_not_match(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                """

        email = """Hello everyone this is a test email from example"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_enlist_uri_host_sub_domain_not_match(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com !sub.example.com
                    blacklist_uri_host example.com !sub.example.com
                    whitelist_uri_host example.com !sub.example.com
                """

        email = """From:Hello everyone this is a test email from http://sub.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_enlist_uri_host_ip_match(self):
        lists = """
                    enlist_uri_host (MYLIST) 1.2.3.4
                    blacklist_uri_host 1.2.3.4
                    whitelist_uri_host 1.2.3.4
                """

        email = """Hello everyone this is a test email from http://1.2.3.4"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_multi_list(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com example.net example.org
                    blacklist_uri_host example.com example.net example.org
                    whitelist_uri_host example.com example.net example.org
                """

        email = """Hello everyone this is a test email from http://example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_split_list(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    enlist_uri_host (MYLIST) example.net
                    blacklist_uri_host example.net
                    whitelist_uri_host example.net
                    enlist_uri_host (MYLIST) example.org
                    blacklist_uri_host example.org
                    whitelist_uri_host example.org
                """

        email = """Hello everyone this is a test email from http://example.org"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_multi_url(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.net
                    whitelist_uri_host example.org
                """

        email = """Hello everyone this is a test email from http://example.org please visit http://example.net and
        http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_enlist_uri_host_empty_list(self):
        lists = """
                    enlist_uri_host (MYLIST)
                    blacklist_uri_host
                    whitelist_uri_host
                """

        email = """Hello everyone this is a test email from http://example.org please visit http://example.net and
            http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Delist uri host tests

    def test_delist_uri_host_remove_domain_from_all_lists(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    delist_uri_host example.com
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_delist_uri_host_remove_ip_from_all_lists(self):
        lists = """
                    enlist_uri_host (MYLIST) 1.2.3.4
                    blacklist_uri_host 1.2.3.4
                    whitelist_uri_host 1.2.3.4
                    delist_uri_host 1.2.3.4
                """

        email = """Hello everyone this is a test email from http://1.2.3.4"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_delist_uri_host_remove_domain_from_single_list(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    delist_uri_host (MYLIST) example.com
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_URI_HOST_IN_WHITELIST', 'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_delist_uri_host_remove_not_existing_domain(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    delist_uri_host example.org
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_delist_uri_host_remove_domain_with_exclamation_mark(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    delist_uri_host !example.com
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_delist_uri_host_remove_not_matching_domain(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com !sub.example.com
                    blacklist_uri_host example.com !sub.example.com
                    whitelist_uri_host example.com !sub.example.com
                    delist_uri_host sub.example.com
                """

        email = """Hello everyone this is a test email from http://sub.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_delist_uri_host_no_effect(self):
        lists = """
                    delist_uri_host example.com
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])

    def test_delist_uri_host_empty_list(self):
        lists = """
                    enlist_uri_host (MYLIST) example.com
                    blacklist_uri_host example.com
                    whitelist_uri_host example.com
                    delist_uri_host
                """

        email = """Hello everyone this is a test email from http://example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_URI_HOST_LISTED_MYLIST', 'CHECK_URI_HOST_IN_WHITELIST',
                                      'CHECK_URI_HOST_IN_BLACKLIST'])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')