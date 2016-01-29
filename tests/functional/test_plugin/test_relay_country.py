"""Tests for pad.plugins.relay_country. In order to run this test you have to
download the geodb databases GeoIP.dat.gz, and  GeoIPv6.dat.gz:
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
gunzip GeoIP.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
gunzip GeoIPv6.dat.gz
"""
import email
import unittest
import tests.util

PRE_CONFIG = r"""
# Plugins and settings here
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
geodb ./GeoIP.dat

report _SCORE_
report _TESTS_
"""

CONFIG = r"""
# Rule definitions here
   header          RELAYCOUNTRY_BAD X-Relay-Countries =~ /%s/
   describe        RELAYCOUNTRY_BAD Relayed through %s at some point
   score           RELAYCOUNTRY_BAD 3.0
   add_header all Relay-Country _RELAYCOUNTRY_
"""
GOOD_CONFIG = r"""
# Rule definitions here
   header          RELAYCOUNTRY_GOOD X-Relay-Countries =~ /(%s|%s)/
   describe        RELAYCOUNTRY_GOOD First untrusted relay is %s or %s
   score           RELAYCOUNTRY_GOOD -0.2
   add_header all Relay-Country _RELAYCOUNTRY_

"""

MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [213.133.99.176]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test message.

This is a test.
"""
MSG_PARENTHESES = """Received: from 127.0.0.1  (EHLO m1.util24.eu) (213.133.99.176)
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test message.

This is a test.
"""
MSG_PARENTHESES_IPV6 = """Received: from 127.0.0.1  (EHLO m1.util24.eu) (2a01:4f8:a0:9208::2)
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test message.

This is a test.
"""
GOOD_MSG = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [85.77.239.17]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test message.

This is a test.
"""
MSG_IPV6 = """Received: from 127.0.0.1  (EHLO m1.util24.eu) [2a01:4f8:a0:9208::2]
  by mta1329.mail.bf1.yahoo.com with SMTPS; Fri, 29 Jan 2016 05:57:28 +0000
Subject: Test message.

This is a test.
"""


class TestFunctionalRelayCountry(tests.util.TestBase):
    """Functional Tests for the RelayCountryPlugin"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_bad_relay_add_header_all(self):
        """Test the bad relay with add header all rule"""
        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG, message_only=True, report_only=False)
        msg = email.message_from_string(result)
        self.assertEqual(msg["X-Spam-Relay-Country"], "** DE")

    def test_bad_relay(self):
        """Test the bad relay rule with a msg containing ipV4"""
        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 3.0, ["RELAYCOUNTRY_BAD"])

    def test_bad_relay_ipV6(self):
        """Test the bad relay rule with a msg containing ipV6"""

        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_IPV6)
        self.check_report(result, 3.0, ["RELAYCOUNTRY_BAD"])

    def test_bad_relay_parentheses(self):
        """Test the bad relay rule with a msg containing ipV4 in parentheses"""

        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARENTHESES)
        self.check_report(result, 3.0, ["RELAYCOUNTRY_BAD"])

    def test_bad_relay_parentheses_ipv6(self):
        """Test the bad relay rule with a msg containing ipV6 in parentheses"""
        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARENTHESES_IPV6)
        self.check_report(result, 3.0, ["RELAYCOUNTRY_BAD"])

    def test_good_relay(self):
        """Test the good relay rule with a msg containing ipV4"""
        self.setup_conf(config=GOOD_CONFIG % ("FI", "RO", "Finland", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(GOOD_MSG)
        self.check_report(result, -0.2, ["RELAYCOUNTRY_GOOD"])

    def test_good_relay_add_header_all(self):
        """Test the add header all rule from good relay config"""
        self.setup_conf(config=GOOD_CONFIG % ("FI", "RO", "Finland", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(GOOD_MSG, message_only=True, report_only=False)
        msg = email.message_from_string(result)
        self.assertEqual(msg["X-Spam-Relay-Country"], "** FI")

    def test_good_relay_ipV6(self):
        """Test the good relay rule with a msg containing ipV6"""
        self.setup_conf(config=GOOD_CONFIG % ("DE", "RO", "Germany", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_IPV6)
        self.check_report(result, -0.2, ["RELAYCOUNTRY_GOOD"])

    def test_good_relay_ipV6_add_header_all(self):
        """Test the good relay rule with a msg containing ipV6"""
        self.setup_conf(config=GOOD_CONFIG % ("DE", "RO", "Germany", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(GOOD_MSG, message_only=True, report_only=False)
        msg = email.message_from_string(result)
        self.assertEqual(msg["X-Spam-Relay-Country"], "** FI")

    def test_good_relay_parentheses(self):
        """Test the good relay rule with a msg containing ipV4 in parentheses"""
        self.setup_conf(config=GOOD_CONFIG % ("DE", "RO", "Germany", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARENTHESES)
        self.check_report(result, -0.2, ["RELAYCOUNTRY_GOOD"])

    def test_good_relay_parentheses_ipv6(self):
        """Test the bad relay rule with a msg containing ipV6 in parentheses"""
        self.setup_conf(config=GOOD_CONFIG % ("DE", "RO", "Germany", "Romania"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG_PARENTHESES_IPV6)
        self.check_report(result, -0.2, ["RELAYCOUNTRY_GOOD"])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalRelayCountry, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
