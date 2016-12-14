"""Functional tests for RelayEval Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load plugin and report matched RULES and SCORE
PRE_CONFIG = """
loadplugin pad.plugins.relay_eval.RelayEval

report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """
header CHECK_FOR_NUMERIC_HELO                      eval:check_for_numeric_helo()
header CHECK_FOR_RDNS_HELO_MISMATCH                eval:check_for_rdns_helo_mismatch()
header CHECK_ALL_TRUSTED                           eval:check_all_trusted()
header CHECK_NO_RELAYS                             eval:check_no_relays()
header CHECK_RELAYS_UNPARSEABLE                    eval:check_relays_unparseable()
header CHECK_FOR_SENDER_NO_REVERSE                 eval:check_for_sender_no_reverse()
header CHECK_FOR_FROM_DOMAIN_IN_RECEIVED_HEADERS   eval:check_for_from_domain_in_received_headers('nonexisting.com', 'true')
header CHECK_FOR_FORGED_RECEIVED_TRAIL             eval:check_for_forged_received_trail()
header CHECK_FOR_FORGED_RECEIVED_IP_HELO           eval:check_for_forged_received_ip_helo()
header HELO_IP_MISSMATCH                           eval:helo_ip_mismatch()
header CHECK_FOR_NO_RDNS_DOTCOM_HELO               eval:check_for_no_rdns_dotcom_helo()
"""

class TestFunctionalRelayEval(tests.util.TestBase):
    """Class containing functional tests for the Relay Plugin"""

    def test_relay_check_for_numeric_helo_positive(self):

        email = """Received: from 1.2.3.4 ([1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_NUMERIC_HELO'])

    def test_relay_check_for_helo_numeric_forged_and_missmatch_positive(self):

        email = """Received: from 1.2.3.4 ([4.4.4.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FOR_FORGED_RECEIVED_IP_HELO', 'HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_check_for_helo_numeric_forged_and_missmatch_positive_with_multiple_headers(self):

        email = """Received: from ceva.com ([1.2.3.4]) by example.com
Received: from example.com (ceva.com [1.2.3.4]) by example.com
Received: from 1.2.3.4 ([4.4.4.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FOR_FORGED_RECEIVED_IP_HELO', 'HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_check_for_helo_numeric_forged_and_missmatch_with_ipv6(self):

        email = """Received: from 1.2.3.4 ([2001:1af8:4700:a02d:2::1]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FOR_FORGED_RECEIVED_IP_HELO', 'HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_check_for_helo_numeric_and_missmatch_positive(self):

        email = """Received: from 4.4.6.4 ([4.4.4.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_helo_numeric_forged_and_missmatch_with_ipv6_different_16(self):

        email = """Received: from 2001:1af7:4700:a02d:2::1 ([2001:1af8:4700:a02d:2::1]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 3, ['CHECK_FOR_FORGED_RECEIVED_IP_HELO', 'HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_helo_numeric_forged_and_missmatch_with_ipv6_different_24(self):

        email = """Received: from 2001:1af8:4702:a02d:2::1 ([2001:1af8:4700:a02d:2::1]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 2, ['HELO_IP_MISSMATCH', 'CHECK_FOR_NUMERIC_HELO'])

    def test_relay_helo_numeric_forged_and_missmatch_with_ipv6_different_32(self):

        email = """Received: from 2001:1af8:4700:a02c:2::1 ([2001:1af8:4700:a02d:2::1]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_NUMERIC_HELO'])

    def test_relay_check_for_helo_missmatch_negative(self):

        email = """Received: from 4.4.4.177 ([4.4.4.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_NUMERIC_HELO'])

    def test_relay_sender_no_reverse_positive(self):

        email = """Received: from example.com (ceva.com [1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_SENDER_NO_REVERSE'])

    def test_relay_sender_no_reverse_negative(self):

        email = """Received: from example.com (ceva [1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_relay_all_trusted_domain_helo_positive(self):

        trusted_networks = """
                                trusted_networks 1.2.3.4
                           """

        email = """Received: from example.com ([1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_ALL_TRUSTED'])

    def test_relay_all_trusted_domain_helo_negative(self):

        trusted_networks = """
                                trusted_networks !1.2.3.4
                           """

        email = """Received: from example.com ([1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 0, [])

    def test_relay_all_trusted_ip_helo_positive(self):

        trusted_networks = """
                                trusted_networks 1.2.3.4
                           """

        email = """Received: from 4.4.4.4 ([1.2.3.4]) by example.com"""

        self.setup_conf(config=CONFIG + trusted_networks, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_ALL_TRUSTED'])

    def test_relay_no_relays_positive(self):

        email = """X-Received: by 10.98.4.193 with SMTP id 184mr20495892pfe.98.1467619884181;
Mon, 04 Jul 2016 01:11:24 -0700 (PDT)
From: test@test.example.com
Received: by mail-pf0-x248.google.com with SMTP id e189so378665533pfa.2
for <cosmin.b@gapps.spamexperts.com>; Mon, 04 Jul 2016 01:11:24 -0700 (PDT)"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_NO_RELAYS'])

    def test_relay_no_relays_negative(self):

        email = """X-Received: by 10.98.4.193 with SMTP id 184mr20495892pfe.98.1467619884181;
        Mon, 04 Jul 2016 01:11:24 -0700 (PDT)
From: test@test.example.com
Received: from example.com (ceva.com [1.2.3.4]) by example.com
Received: by mail-pf0-x248.google.com with SMTP id e189so378665533pfa.2
        for <cosmin.b@gapps.spamexperts.com>; Mon, 04 Jul 2016 01:11:24 -0700 (PDT)"""

        self.setup_conf(config=CONFIG, pre_config=PRE_CONFIG)
        result = self.check_pad(email)
        self.check_report(result, 1, ['CHECK_FOR_SENDER_NO_REVERSE'])

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalRelayEval, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
