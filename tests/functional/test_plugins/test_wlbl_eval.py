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

    def test_wlbl_from_on_from_header_containing_full_name(self):
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

    def test_wlbl_from_on_resent_from_header_containing_full_name(self):
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

    def test_wlbl_from_on_envelope_sender_header_containing_full_name(self):
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

    def test_wlbl_from_on_envelope_from_header_containing_full_name(self):
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

    def test_wlbl_from_on_x_envelope_from_header_containing_full_name(self):
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


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalWLBLEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')

