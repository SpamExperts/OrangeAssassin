"""Tests for pad.plugins.relay_country. In order to run this test you have to
download the geodb database (GeoLite2-Country.mmdb) :
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
gunzip GeoIP.dat.gz
"""

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
"""
GOOD_CONFIG = r"""
# Rule definitions here
   header          RELAYCOUNTRY_GOOD X-Relay-Countries =~ /^(%s|%s)/
   describe        RELAYCOUNTRY_GOOD First untrusted relay is %s or %s
   score           RELAYCOUNTRY_GOOD -0.2
"""

MSG = """Received: by 213.133.99.176 with SMTP id a42csp2965082wli;
 Tue, 12 Jan 2016 14:23:21 -0800 (PST)

This is a test
"""


class TestFunctionalRelayCountry(tests.util.TestBase):
    """comment"""

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    @unittest.skip("pygeoip.GeoIPError: Corrupt database")
    def test_bad_relay(self):
        self.setup_conf(config=CONFIG % ("DE", "Germany"),
                        pre_config=PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 3.0, ["RELAYCOUNTRY_BAD"])


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalRelayCountry, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
