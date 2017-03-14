"""Tests for pad.plugins.relay_country."""
import unittest

try:
    from unittest.mock import patch, MagicMock
except ImportError:
    from mock import patch, MagicMock

import oa.context
import oa.message
import oa.plugins.relay_country

MSGTEST="""Delivered-To: user@example.com
Received: by 10.107.130.85 with SMTP id e82csp671450iod;
        Fri, 8 Jan 2016 10:27:27 -0800 (PST)
X-Received: by 10.194.24.226 with SMTP id x2mr119688960wjf.43.1452277647087;
        Fri, 08 Jan 2016 10:27:27 -0800 (PST)
Return-Path: <tr70955@mpmserv.co.uk>
Received: from mail45.mpmailserv.co.uk (mail45.mpmailserv.co.uk. [178.62.26.182])
        by mx.example.com with ESMTP id m80si439375wmd.112.2016.01.08.10.27.26
        for <user@example.com>;
        Fri, 08 Jan 2016 10:27:27 -0800 (PST)
Received-SPF: pass (example.com: domain of tr70955@mpmserv.co.uk designates 178.62.26.182 as permitted sender) client-ip=178.62.26.182;
Authentication-Results: mx.example.com;
       spf=pass (example.com: domain of tr70955@mpmserv.co.uk designates 178.62.26.182 as permitted sender) smtp.mailfrom=tr70955@mpmserv.co.uk;
       dkim=pass header.i=@mpmailserver.co.uk
From: "=?utf-8?B?UENIIE1heW9yZW8=?=" <ventas@pch-mayoreo.com.mx>
To: user@example.com
Subject: =?utf-8?B?TGlxdWlkYWNpb24gZGVsIDIwMTUg?=
 =?utf-8?B?YSBDbGllbnRlc2==?=
Date: Fri, 08 Jan 2016 18:27:22 -0000
Message-ID: <20160108-18272230-3030-0@DSVR021489>
List-Unsubscribe: <mailto:tr16147476@web2.mpmailserv.co.uk>, <http://web2.mpmailserv.co.uk/bg/unsubscribe.asp?sid=16147476&cid=52463>
Feedback-ID: 52463:16147476:Campaign:70955
DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple;
 d=mpmailserver.co.uk; s=dkim1;
 h=From:To:Subject:Date:Message-ID:MIME-Version:Content-Type;
 bh=OAQ8l70XSu555kegpIQDGx0twRMltOiKK9/pzRATUT0=;
 b=G4p5eIlu7dXOD9krH5BosMOJksrKgkBB85BgVZeyh0l0JfLhwve7WVMfR5jtDgae
  ET9Rh9rfmIEnXv4cb5Hy727huDWTLZionBaoJCx+gIIRBQTfJDn1Jxyq/XAZMuot
  BF2IOcAnjgkb8AXCz7zSIbw475llXxcwB5o44vxuHxE=
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary="--=7879796F323D48C3BF41_0C5C_5373_A518"

"""

MSG_NORECEIVED="""Delivered-To: user@example.com
X-Received: by 10.194.24.226 with SMTP id x2mr119688960wjf.43.1452277647087;
        Fri, 08 Jan 2016 10:27:27 -0800 (PST)
Return-Path: <tr70955@mpmserv.co.uk>
Authentication-Results: mx.example.com;
       spf=pass (example.com: domain of tr70955@mpmserv.co.uk designates 178.62.26.182 as permitted sender) smtp.mailfrom=tr70955@mpmserv.co.uk;
       dkim=pass header.i=@mpmailserver.co.uk
From: "=?utf-8?B?UENIIE1heW9yZW8=?=" <ventas@pch-mayoreo.com.mx>
To: user@example.com
Subject: =?utf-8?B?TGlxdWlkYWNpb24gZGVsIDIwMTUg?=
 =?utf-8?B?YSBDbGllbnRlc2==?=
Date: Fri, 08 Jan 2016 18:27:22 -0000
Message-ID: <20160108-18272230-3030-0@DSVR021489>
List-Unsubscribe: <mailto:tr16147476@web2.mpmailserv.co.uk>, <http://web2.mpmailserv.co.uk/bg/unsubscribe.asp?sid=16147476&cid=52463>
Feedback-ID: 52463:16147476:Campaign:70955
DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple;
 d=mpmailserver.co.uk; s=dkim1;
 h=From:To:Subject:Date:Message-ID:MIME-Version:Content-Type;
 bh=OAQ8l70XSu555kegpIQDGx0twRMltOiKK9/pzRATUT0=;
 b=G4p5eIlu7dXOD9krH5BosMOJksrKgkBB85BgVZeyh0l0JfLhwve7WVMfR5jtDgae
 ET9Rh9rfmIEnXv4cb5Hy727huDWTLZionBaoJCx+gIIRBQTfJDn1Jxyq/XAZMuot
 BF2IOcAnjgkb8AXCz7zSIbw475llXxcwB5o44vxuHxE=
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary="--=7879796F323D48C3BF41_0C5C_5373_A518"

"""

MSG_UNKNOWN="""Delivered-To: user@example.com
Received: from [189.23.4.1] with SMTP id e82csp671450iod;
 Fri, 8 Jan 2016 10:27:27 -0800 (PST)
From: "=?utf-8?B?UENIIE1heW9yZW8=?=" <ventas@pch-mayoreo.com.mx>
To: user@example.com
Subject: =?utf-8?B?TGlxdWlkYWNpb24gZGVsIDIwMTUg?=
 =?utf-8?B?YSBDbGllbnRlc2==?=

"""


class MockGeoIP(object):
    """Mocking GeoIP class"""
    IPADDRESSES = {"10.107.130.85": "**",
                   "178.62.26.182": "GB",
                   }

    def country_code_by_addr(self, addr):
        """Mock country_code_by_addr the result is taken from the
        IPADDRESSES dictionary above"""
        return self.IPADDRESSES.get(addr, "")


class TestRelayCountry(unittest.TestCase):
    """Tests for the RelayCountryPlugin"""

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {"ipv4": MockGeoIP(),
                            "ipv6": MockGeoIP()}
        patch("oa.plugins.relay_country.RelayCountryPlugin.options",
              self.options).start()
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: 
            self.global_data.setdefault(
                k, v)}
                                   )
        self.plugin = oa.plugins.relay_country.RelayCountryPlugin(
            self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_matching_relay_countries(self):
        """Test getting all the countries"""
        message = oa.message.Message(self.mock_ctxt, MSGTEST)
        self.plugin.parsed_metadata(message)
        expected_result = ['GB']
        self.assertEqual(message.headers["X-Relay-Countries"], expected_result)

    def test_no_received_headers(self):
        """Test a message where there are no "Received" headers"""
        message = oa.message.Message(self.mock_ctxt, MSG_NORECEIVED)
        self.plugin.parsed_metadata(message)
        expected_result = []
        self.assertEqual(message.headers["X-Relay-Countries"], expected_result)

    def test_unknown_ipdaddress(self):
        """Test a message where there are no "Received" headers"""
        message = oa.message.Message(self.mock_ctxt, MSG_UNKNOWN)
        self.plugin.parsed_metadata(message)
        expected_result = ["XX"]
        self.assertEqual(message.headers["X-Relay-Countries"], expected_result)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestRelayCountry, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
