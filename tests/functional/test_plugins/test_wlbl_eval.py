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

    # General cases

    def test_wlbl_from_when_resent_from_is_set(self):
        """ If Resent-From is set, use that; otherwise check all addresses
        taken from the following set of headers: Envelope-Sender, Resent-Sender
        X-Envelope-From, From"""
        lists = """
            whitelist_from test@example.com
            blacklist_from test@example.com
        """

        email = """Resent-From: email@example.com
From: test@example.com
        """

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_to_header(self):
        lists = """
            whitelist_from test@example.com
            blacklist_from test@example.com
        """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])


    # Tests for From header, blacklist and whitelist

    def test_wlbl_from_full_address_on_from_header(self):
        lists = """
            whitelist_from fulladdress@example.com
            blacklist_from fulladdress@example.com
        """

        email = "From: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
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

        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_list_on_from_header(self):
        lists = """
            whitelist_from *
            blacklist_from *
        """

        email = "From: test@example.com"

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

    def test_wlbl_from_on_from_header_containing_full_name_negative(self):
        lists = """
            whitelist_from example.com
            blacklist_from example.com
        """

        email = "From: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_from_header(self):
        lists = """
            whitelist_from .*example.com example.net test@example.org
            blacklist_from .*example.com example.net test@example.org
        """

        email = "From: test@example.com, test@example.net, test@example.org"

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

        email = "From: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_from_header_containing_combined_stuff(self):
        lists = """
            whitelist_from test@example.com test2@example.com
            blacklist_from test@example.com test2@example.com
        """

        email = "From: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_from_header_no_list(self):
        email = "From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Tests for Resent-From header, blacklist and whitelist

    def test_wlbl_from_full_address_on_resent_from_header(self):
        lists = """
            whitelist_from fulladdress@example.com
            blacklist_from fulladdress@example.com
        """

        email = "Resent-From: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_local_part_on_resent_from_header(self):
        lists = """
            whitelist_from *@e?ample.com
            blacklist_from *@e?ample.com
        """

        email = "Resent-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_domain_on_resent_from_header(self):
        lists = """
            whitelist_from *exampl?.com
            blacklist_from *exampl?.com
        """

        email = "Resent-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_full_domain_on_resent_from_header(self):
        lists = """
            whitelist_from example.com
            blacklist_from example.com
        """

        email = "Resent-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_invalid_globing_on_resent_from_header(self):
        lists = """
            whitelist_from .*example.com
            blacklist_from .*example.com
        """

        email = "Resent-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_resent_from_header_containing_full_name_negative(self):
        lists = """
            whitelist_from example.com
            blacklist_from example.com
        """

        email = "Resent-From: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_resent_from_header(self):
        lists = """
            whitelist_from .*example.com example.net test@example.org
            blacklist_from .*example.com example.net test@example.org
        """

        email = "Resent-From: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_split_list_on_resent_from_header(self):
        lists = """
            whitelist_from .*example.com
            whitelist_from example.net
            whitelist_from test@example.org
            blacklist_from .*example.com
            blacklist_from example.net
            blacklist_from test@example.org
        """

        email = "Resent-From: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_resent_from_header_containing_combined_stuff(self):
        lists = """
            whitelist_from test@example.com test2@example.com
            blacklist_from test@example.com test2@example.com
        """

        email = "Resent-From: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_resent_from_header_no_list(self):
        email = "Resent-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Tests for Envelope-Sender header, blacklist and whitelist

    def test_wlbl_from_full_address_on_envelope_sender_header(self):
        lists = """
               whitelist_from fulladdress@example.com
               blacklist_from fulladdress@example.com
           """

        email = "Envelope-Sender: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_local_part_on_envelope_sender_header(self):
        lists = """
               whitelist_from *@e?ample.com
               blacklist_from *@e?ample.com
           """

        email = "Envelope-Sender: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_domain_on_envelope_sender_header(self):
        lists = """
               whitelist_from *exampl?.com
               blacklist_from *exampl?.com
           """

        email = "Envelope-Sender: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_full_domain_on_envelope_sender_header(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "Envelope-Sender: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_invalid_globing_on_envelope_sender_header(self):
        lists = """
               whitelist_from .*example.com
               blacklist_from .*example.com
           """

        email = "Envelope-Sender: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_envelope_sender_header_containing_full_name_negative(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "Envelope-Sender: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_envelope_sender_header(self):
        lists = """
               whitelist_from .*example.com example.net test@example.org
               blacklist_from .*example.com example.net test@example.org
           """

        email = "Envelope-Sender: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_split_list_on_envelope_sender_header(self):
        lists = """
               whitelist_from .*example.com
               whitelist_from example.net
               whitelist_from test@example.org
               blacklist_from .*example.com
               blacklist_from example.net
               blacklist_from test@example.org
           """

        email = "Envelope-Sender: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_envelope_sender_header_containing_combined_stuff(self):
        lists = """
               whitelist_from test@example.com test2@example.com
               blacklist_from test@example.com test2@example.com
           """

        email = "Envelope-Sender: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_envelope_sender_header_no_list(self):
        email = "Envelope-Sender: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Tests for Envelope-From header, blacklist and whitelist

    def test_wlbl_from_full_address_on_envelope_from_header(self):
        lists = """
               whitelist_from fulladdress@example.com
               blacklist_from fulladdress@example.com
           """

        email = "EnvelopeFrom: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_local_part_on_envelope_from_header(self):
        lists = """
               whitelist_from *@e?ample.com
               blacklist_from *@e?ample.com
           """

        email = "EnvelopeFrom: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_domain_on_envelope_from_header(self):
        lists = """
               whitelist_from *exampl?.com
               blacklist_from *exampl?.com
           """

        email = "EnvelopeFrom: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_full_domain_on_envelope_from_header(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "EnvelopeFrom: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_invalid_globing_on_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com
               blacklist_from .*example.com
           """

        email = "EnvelopeFrom: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_envelope_from_header_containing_full_name_negative(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "EnvelopeFrom: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com example.net test@example.org
               blacklist_from .*example.com example.net test@example.org
           """

        email = "EnvelopeFrom: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_split_list_on_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com
               whitelist_from example.net
               whitelist_from test@example.org
               blacklist_from .*example.com
               blacklist_from example.net
               blacklist_from test@example.org
           """

        email = "EnvelopeFrom: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_envelope_from_header_containing_combined_stuff(self):
        lists = """
               whitelist_from test@example.com test2@example.com
               blacklist_from test@example.com test2@example.com
           """

        email = "EnvelopeFrom: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_envelope_from_header_no_list(self):
        email = "EnvelopeFrom: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    # Tests for X-Envelope-From header, blacklist and whitelist

    def test_wlbl_from_full_address_on_x_envelope_from_header(self):
        lists = """
               whitelist_from fulladdress@example.com
               blacklist_from fulladdress@example.com
           """

        email = "X-Envelope-From: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_local_part_on_x_envelope_from_header(self):
        lists = """
               whitelist_from *@e?ample.com
               blacklist_from *@e?ample.com
           """

        email = "X-Envelope-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_wild_domain_on_x_envelope_from_header(self):
        lists = """
               whitelist_from *exampl?.com
               blacklist_from *exampl?.com
           """

        email = "X-Envelope-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_full_domain_on_x_envelope_from_header(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "X-Envelope-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_invalid_globing_on_x_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com
               blacklist_from .*example.com
           """

        email = "X-Envelope-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_on_x_envelope_from_header_containing_full_name_negative(self):
        lists = """
               whitelist_from example.com
               blacklist_from example.com
           """

        email = "X-Envelope-From: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_from_combined_on_x_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com example.net test@example.org
               blacklist_from .*example.com example.net test@example.org
           """

        email = "X-Envelope-From: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_split_list_on_x_envelope_from_header(self):
        lists = """
               whitelist_from .*example.com
               whitelist_from example.net
               whitelist_from test@example.org
               blacklist_from .*example.com
               blacklist_from example.net
               blacklist_from test@example.org
           """

        email = "X-Envelope-From: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_x_envelope_from_header_containing_combined_stuff(self):
        lists = """
               whitelist_from test@example.com test2@example.com
               blacklist_from test@example.com test2@example.com
           """

        email = "X-Envelope-From: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_FROM_IN_WHITELIST', 'CHECK_FROM_IN_BLACKLIST'])

    def test_wlbl_from_on_x_envelope_from_header_no_list(self):
        email = "X-Envelope-From: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

##########################################################################################################
# Tests for Resent-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_resent_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Resent-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_resent_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_resent_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_resent_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_resent_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_resent_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Resent-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_resent_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Resent-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_resent_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Resent-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_resent_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Resent-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_resent_to_header_no_list(self):
        email = "Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Resent-Cc header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_resent_cc_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Resent-Cc: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_resent_cc_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Resent-Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_resent_cc_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Resent-Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_resent_cc_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Resent-Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_resent_cc_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Resent-Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_resent_cc_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Resent-Cc: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_resent_cc_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Resent-Cc: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_resent_cc_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Resent-Cc: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_resent_cc_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Resent-Cc: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_resent_cc_header_no_list(self):
        email = "Resent-Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 


# Tests for To header, check_to_in_blacklist, check_to_in_whitelist

    def test_wlbl_to_full_address_on_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_to_header_no_list(self):
        email = "To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])   

# Tests for Apparently-To header, check_to_in_blacklist, check_to_in_whitelist

    def test_wlbl_to_full_address_on_apparently_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Apparently-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_apparently_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Apparently-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_apparently_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Apparently-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_apparently_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Apparently-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_apparently_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Apparently-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_apparently_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Apparently-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_apparently_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Apparently-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_apparently_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Apparently-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_apparently_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Apparently-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_apparently_to_header_no_list(self):
        email = "Apparently-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Delivered-To header, check_to_in_blacklist, check_to_in_whitelist

    def test_wlbl_to_full_address_on_delivered_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Delivered-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_delivered_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_delivered_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_delivered_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_delivered_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Delivered-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Delivered-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Delivered-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_delivered_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Delivered-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_delivered_to_header_no_list(self):
        email = "Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Envelope-Recipients header, check_to_in_blacklist, check_to_in_whitelist

    def test_wlbl_to_full_address_on_envelope_recipients_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Envelope-Recipients: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_envelope_recipients_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Envelope-Recipients: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_envelope_recipients_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Envelope-Recipients: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_envelope_recipients_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Envelope-Recipients: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_envelope_recipients_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Envelope-Recipients: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_envelope_recipients_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Envelope-Recipients: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_envelope_recipients_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Envelope-Recipients: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_envelope_recipients_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Envelope-Recipients: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_envelope_recipients_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Envelope-Recipients: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_envelope_recipients_header_no_list(self):
        email = "Envelope-Recipients: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Apparently-Resent-To header, check_to_in_blacklist, check_to_in_whitelist

    def test_wlbl_to_full_address_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Apparently-Resent-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Apparently-Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Apparently-Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Apparently-Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Apparently-Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_apparently_resent_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Apparently-Resent-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Apparently-Resent-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_apparently_resent_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Apparently-Resent-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_apparently_resent_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Apparently-Resent-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_apparently_resent_to_header_no_list(self):
        email = "Apparently-Resent-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for X-Envelope-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_x_envelope_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "X-Envelope-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_x_envelope_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "X-Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_x_envelope_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "X-Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_x_envelope_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_x_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "X-Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_x_envelope_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Envelope-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_x_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "X-Envelope-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_x_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "X-Envelope-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_envelope_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "X-Envelope-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_envelope_to_header_no_list(self):
        email = "X-Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Envelope-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_envelope_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Envelope-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_envelope_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_envelope_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_envelope_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_envelope_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Envelope-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Envelope-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_envelope_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Envelope-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_envelope_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Envelope-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_envelope_to_header_no_list(self):
        email = "Envelope-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for X-Delivered-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_x_delivered_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "X-Delivered-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_x_delivered_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "X-Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_x_delivered_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "X-Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_x_delivered_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_x_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "X-Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_x_delivered_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Delivered-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_x_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "X-Delivered-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_x_delivered_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "X-Delivered-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_delivered_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "X-Delivered-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_delivered_to_header_no_list(self):
        email = "X-Delivered-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for X-Original-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_x_originals_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "X-Original-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_x_originals_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "X-Original-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_x_originals_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "X-Original-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_x_originals_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Original-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_x_originals_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "X-Original-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_x_originals_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Original-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_x_originals_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "X-Original-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_x_originals_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "X-Original-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_originals_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "X-Original-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_originals_to_header_no_list(self):
        email = "X-Original-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for X-Rcpt-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "X-Rcpt-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "X-Rcpt-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "X-Rcpt-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Rcpt-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "X-Rcpt-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_x_rcpt_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Rcpt-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "X-Rcpt-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_x_rcpt_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "X-Rcpt-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_rcpt_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "X-Rcpt-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_rcpt_to_header_no_list(self):
        email = "X-Rcpt-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for X-Real-To header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_x_real_to_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "X-Real-To: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_x_real_to_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "X-Real-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_x_real_to_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "X-Real-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_x_real_to_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Real-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_x_real_to_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "X-Real-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_x_real_to_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "X-Real-To: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_x_real_to_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "X-Real-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_x_real_to_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "X-Real-To: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_real_to_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "X-Real-To: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_x_real_to_header_no_list(self):
        email = "X-Real-To: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, []) 

# Tests for Cc header, check_to_in_blacklist, check_to_in_whitelist
    
    def test_wlbl_to_full_address_on_cc_header(self):
        lists = """
               whitelist_to fulladdress@example.com
               blacklist_to fulladdress@example.com
           """

        email = "Cc: fulladdress@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        print(result)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_local_part_on_cc_header(self):
        lists = """
               whitelist_to *@e?ample.com
               blacklist_to *@e?ample.com
           """

        email = "Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_wild_domain_on_cc_header(self):
        lists = """
               whitelist_to *exampl?.com
               blacklist_to *exampl?.com
           """

        email = "Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_full_domain_on_cc_header(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_invalid_globing_on_cc_header(self):
        lists = """
               whitelist_to .*example.com
               blacklist_to .*example.com
           """

        email = "Cc: test@example.com"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_on_cc_header_containing_full_name_negative(self):
        lists = """
               whitelist_to example.com
               blacklist_to example.com
           """

        email = "Cc: Full Name <example.net>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_wlbl_to_combined_on_cc_header(self):
        lists = """
               whitelist_to .*example.com example.net test@example.org
               blacklist_to .*example.com example.net test@example.org
           """

        email = "Cc: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_split_list_on_cc_header(self):
        lists = """
               whitelist_to .*example.com
               whitelist_to example.net
               whitelist_to test@example.org
               blacklist_to .*example.com
               blacklist_to example.net
               blacklist_to test@example.org
           """

        email = "Cc: test@example.com, test@example.net, test@example.org"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_cc_header_containing_combined_stuff(self):
        lists = """
               whitelist_to test@example.com test2@example.com
               blacklist_to test@example.com test2@example.com
           """

        email = "Cc: email@example.com, Full Name <test2@example.com>"

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG + lists)
        result = self.check_pad(email)
        self.check_report(result, 2, ['CHECK_TO_IN_WHITELIST', 'CHECK_TO_IN_BLACKLIST'])

    def test_wlbl_to_on_cc_header_no_list(self):
        email = "Cc: test@example.com"

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

