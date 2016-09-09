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
body   CHECK_FROM_IN_LIST                  eval:check_from_in_list('whitelist_from')
body   CHECK_TO_IN_WHITELIST               eval:check_to_in_whitelist()
body   CHECK_TO_IN_BLACKLIST               eval:check_to_in_blacklist()
body   CHECK_TO_IN_MORE_SPAM               eval:check_to_in_more_spam()
body   CHECK_TO_IN_ALL_SPAM                eval:check_to_in_all_spam()
body   CHECK_TO_IN_LIST                    eval:check_to_in_list('whitelist_to')
header CHECK_URI_HOST_LISTED_MYLIST        eval:check_uri_host_listed('MYLIST')
body   CHECK_URI_HOST_IN_WHITELIST         eval:check_uri_host_in_whitelist()
body   CHECK_URI_HOST_IN_BLACKLIST         eval:check_uri_host_in_blacklist()
body   CHECK_MAILFROM_MATCHES_RCVD         eval:check_mailfrom_matches_rcvd()
body   CHECK_FORGED_IN_WHITELIST           eval:check_forged_in_whitelist()
body   CHECK_FORGED_IN_DEFAULT_WHITELIST   eval:check_forged_in_default_whitelist()
"""


class TestFunctionalWLBLEval(tests.util.TestBase):
    """Functional Tests for the WLBLEval Plugin"""

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
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

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
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

    def test_from_wlbl_with_full_domain(self):
        lists = """
                    whitelist_from example.com
                    blacklist_from example.com
                """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

    def test_from_wlbl_with_wild_domain(self):
        lists = """
                    whitelist_from *exam?le.com
                    blacklist_from *exam?le.com
                """

        email = """From: test@test.example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

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

        email = """From: Full Name <test@example.com>"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

    def test_from_wlbl_no_lists(self):
        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_empty_lists(self):
        lists = """
                    whitelist_from
                    blacklist_from
                """

        email = """From: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_from_wlbl_invalid_lists(self):
        lists = """
                    whitelist_from example
                    blacklist_from example
                """

        email = """From: test@example.com"""

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
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

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
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

    def test_from_wlbl_ignore_headers_if_resent_from_exist(self):
        lists = """
                    whitelist_from test@example.com
                    blacklist_from test@example.com
                """

        email = """Resent-From: email@example.com
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
        self.check_report(result, 3, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST', 'CHECK_FROM_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

    def test_to_wlbl_no_lists(self):
        email = """To: test@example.com"""

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

        email = """To: test@example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_to_wlbl_invalid_lists(self):
        lists = """
                    whitelist_to example
                    blacklist_to example
                """

        email = """To: test@example.com"""

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

    def test_to_wlbl_ignore_headers_if_resent_to_exist(self):
        lists = """
                    whitelist_to test@example.com
                    blacklist_to test@example.com
                    more_spam_to test@example.com
                    all_spam_to  test@example.com
                """

        email = """Resent-To: email@example.com
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

        email = """Resent-Cc: email@example.com
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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
        self.check_report(result, 5, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST',
                                      'CHECK_TO_IN_MORE_SPAM', 'CHECK_TO_IN_ALL_SPAM',
                                      'CHECK_TO_IN_LIST'])

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
Received: from spamexperts.com [5.79.73.204]"""

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
        trusted_networks = """
                                trusted_networks 5.1.3.7
                                trusted_networks 5.79.73.204
                           """

        lists = """
                    def_whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
                    whitelist_from_rcvd test@spamexperts.com [5.79.73.204]
                """

        email = """From: test@spamexperts.com
Received: from example.com [5.1.3.7]
Received: from spamexperts.com [5.79.73.204]"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG + lists)
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

        email = """Hello everyone this is a test email from http://example.org please visit http://example.net
        and http://example.com"""

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

    # Check mailfrom matches rcvd

    def test_mailfrom_matches_rcvd_with_untrusted_relays(self):
        untrusted_networks = """
                                    trusted_networks !1.2.3.4
                                    trusted_networks !4.5.6.7
                                    trusted_networks !7.8.9.0
                             """

        email = """Received: from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.com>)
Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.com [7.8.9.0])
    by example.com"""

        self.setup_conf(config=CONFIG + untrusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    def test_mailfrom_matches_rcvd_with_default_untrusted_relays(self):
        email = """Received: from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.com>)
Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.com [7.8.9.0])
    by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    def test_mailfrom_matches_rcvd_with_trusted_relays_match_on_field_1(self):
        trusted_networks = """
                                trusted_networks 1.2.3.4
                                trusted_networks 4.5.6.7
                                trusted_networks 7.8.9.0
                           """

        email = """Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.net [7.8.9.0])
    by example.com
Received: from example.com (example.org [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.com>)"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    @unittest.skip("Issues with the parsing method")
    def test_mailfrom_matches_rcvd_with_trusted_relays_match_on_field_2(self):
        trusted_networks = """
                                trusted_networks 1.2.3.4
                                trusted_networks 4.5.6.7
                                trusted_networks 7.8.9.0
                           """

        email = """Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.net [7.8.9.0])
    by example.com
Received: from example.com (example.org [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.net>)"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    @unittest.skip("Issues with the parsing method")
    def test_mailfrom_matches_rcvd_with_trusted_relays_match_on_field_3(self):
        trusted_networks = """
                                trusted_networks 1.2.3.4
                                trusted_networks 4.5.6.7
                                trusted_networks 7.8.9.0
                           """

        email = """Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.net [7.8.9.0])
    by example.com
Received: from example.com (example.org [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.org>)"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    def test_mailfrom_matches_rcvd_with_mixed_relays_negative(self):
        trusted_networks = """trusted_networks 1.2.3.4"""

        email = """Received: from example.com (example.com [1.2.3.4])
    by example.com
    (envelope-from <envfrom@example.com>)
Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
Received: from sub2.example.com (sub2.example.com [7.8.9.0])
    by example.com"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_mailfrom_matches_rcvd_with_mixed_relays_positive(self):
        trusted_networks = """trusted_networks 1.2.3.4"""

        email = """Received: from example.com (example.com [1.2.3.4])
    by example.com
Received: from sub1.example.com (sub1.example.com [4.5.6.7])
    by example.com
    (envelope-from <envfrom@example.com>)
Received: from sub2.example.com (sub2.example.com [7.8.9.0])
    by example.com"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_MAILFROM_MATCHES_RCVD'])

    # Check forged in whitelist and default whitelist tests

    def test_forged_in_whitelist_with_ip(self):

        lists = """whitelist_from_rcvd test@example.com [1.2.3.4]"""

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_with_domain(self):

        lists = """
                    whitelist_from_rcvd test@example.com example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_multi_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com example.com, test@example.net example.net
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_split_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com example.com
                    whitelist_from_rcvd test@example.net example.net
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_default_whitelist_with_ip(self):

        lists = """def_whitelist_from_rcvd test@example.com [1.2.3.4]"""

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_with_domain(self):

        lists = """def_whitelist_from_rcvd test@example.com example.com"""

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_multi_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com example.com, test@example.net example.net
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_split_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com example.com
                    def_whitelist_from_rcvd test@example.net example.net
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com [5.79.73.204])
        by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    # Check whitelist allow relays list

    def test_forged_in_whitelist_alow_relays_with__full_address(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays test@example.com
                """

        email = """From: test@example.com
        Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
                by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_whitelist_alow_relays_with__wild_local_part(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays *@e?ample.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_whitelist_alow_relays_with__full_domain(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_whitelist_alow_relays_with__wild_domain(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays *exam?le.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_whitelist_alow_relays_with_regex(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays .*.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_alow_relays_with_empty_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_alow_relays_with_invalid_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_WHITELIST'])

    def test_forged_in_whitelist_alow_relays_with_combined_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.net example.org example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_whitelist_alow_relays_with_split_list(self):
        lists = """
                    whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.net
                    whitelist_allow_relays example.org
                    whitelist_allow_relays example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with__full_address(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays test@example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with__wild_local_part(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays *@e?ample.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with__full_domain(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with__wild_domain(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays *exam?le.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with_regex(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays .*.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_alow_relays_with_empty_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_alow_relays_with_invalid_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FORGED_IN_DEFAULT_WHITELIST'])

    def test_forged_in_default_whitelist_alow_relays_with_combined_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.net example.org example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_forged_in_default_whitelist_alow_relays_with_split_list(self):
        lists = """
                    def_whitelist_from_rcvd test@example.com [1.2.3.4]
                    whitelist_allow_relays example.net
                    whitelist_allow_relays example.org
                    whitelist_allow_relays example.com
                """

        email = """From: test@example.com
Received: from spamexperts.com (spamexperts.com. [5.79.73.204])
    by mx.google.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    
def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
