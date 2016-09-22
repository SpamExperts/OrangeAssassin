"""Test the dns_eval plugin"""

import os
import time
import unittest
import platform
import subprocess

import sqlite3
import tests.util
import pad.dns_interface

PRE_CONFIG = r"""
report _SCORE_
report _TESTS_

dns_server      127.0.0.1:30053
default_dns_lifetime 0.5
default_dns_timeout 0.5
envelope_sender_header X-From

loadplugin      pad.plugins.dns_eval.DNSEval
"""

CONFIG = r"""
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

CONFIG_TXT = r"""
header      IP_IN_TXT_LIST      eval:check_rbl_txt('example', 'example.com')
header      IP_IN_TXT_LIST_SUB      eval:check_rbl_txt('example', 'example.com, '127.0.0.3')
"""

CONFIG_SUB = r"""
header      IP_IN_LIST          eval:check_rbl('example', 'example.com')
header      IP_IN_SUB_LIST      eval:check_rbl_sub('example', '127.0.0.3')
"""

CONFIG_SENDER_DNS = r"""
header      SENDER_DNS      eval:check_dns_sender()
describe    SENDER_DNS      Check if the sender domain has MX or A records.
"""
# Note the envelope sender is determined according to the
# envelope_sender_header option.
CONFIG_RBL_ENVFROM = r"""
header      RBL_ENVFROM_SENDER      eval:check_rbl_envfrom('example', 'example.net')
describe    RBL_ENVFROM_SENDER      Check the envelope sender domain for
                                    matches on this list.
"""

CONFIG_RBL_FROM_HOST = r"""
header      RBL_FROM_HOST       eval:check_rbl_from_host('example', 'example.net', '127.0.2.1')
describe    RBL_FROM_HOST       Check the From header domain for matches on
                                this list.
"""

CONFIG_RBL_FROM_DOMAIN = r"""
header      RBL_FROM_DOMAIN     eval:check_rbl_from_host('example', 'example.net')
describe    RBL_FROM_DOMAIN     Check the From header domain for matches on
                                this list.
"""
# An accreditor tag can be specified like:
# listowner@a--accreditor.mail.example.com
CONFIG_RBL_ACCREDITOR = r"""
header      RBL_ACCREDITOR      eval:check_rbl_accreditor('accredit', 'example.net', '127.0.1.2','accreditor1')
describe    RBL_ACCREDITOR      Checks all the IPs of this message on the
                                specified list, but only if the sender has the
                                specified accreditor tag.
"""

CONFIG_DNS_AVAILABLE = r"""
dns_available yes
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

CONFIG_DNS_NOT_AVAILABLE = r"""
dns_available no
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

CONFIG_DNS_TEST_AVAILABLE = r"""
dns_available test
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

CONFIG_DNS_TEST_CUSTOM_AVAILABLE = r"""
dns_available test: fakecheck.net
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""


CONFIG_DNS_RESTRICTED_ALLOW = r"""
dns_query_restriction allow example.com
dns_query_restriction deny 1.example.com
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

CONFIG_DNS_RESTRICTED_DENY = r"""
dns_query_restriction deny example.com
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

MSG = r"""Received: from mail-wm0-f50.google.com ([93.184.216.34])
 by example.com with esmtps (TLSv1.2:RC4-SHA:128)
 (Exim 4.85)
 (envelope-from <sender@example.com>)
 id 1aaNAy-0006fq-LZ
 for chirila@example.com; Mon, 29 Feb 2016 13:43:53 +0100
Received: from host.example.com (example.org. [2604:9a00:2100:a00d:7::1])
        by me.example.org with ESMTPS id qg1si11179246igb.97.2016.02.29.04.27
        for <teo@example.com>
        Mon, 29 Feb 2016 04:27:52 -0800 (PST)
Accreditor: accreditor1, parm=value; accreditor2, parm-value
X-From: sender@example.com
From: sender@example.com
To: chirila@example.com
Subject: Test message

This is a test email
"""


class TestDNSEval(tests.util.TestBase):

    path = "local_dns.sql"
    rpath = "local_dns2.sql"
    mdns_procs = []

    @classmethod
    def setUpClass(cls):
        args = ["mdns.py", "--port", "30053", "--db-filepath", cls.path]
        cls.mdns_procs.append(subprocess.Popen(args))
        # Allow time for server to initialize
        sleep_time = 1.0
        if platform.python_implementation().lower() == "pypy":
            # PyPy is much slower at initialization, so allow
            # for more time. This is only ran once so the impact
            # is minimal anyway.
            # This should prevent random test failures on PyPy.
            sleep_time = 2.0
        time.sleep(sleep_time)

    @classmethod
    def tearDownClass(cls):
        for proc in cls.mdns_procs:
            proc.terminate()
            proc.wait()
        try:
            os.remove(cls.rpath)
        except OSError:
            pass

    def setUp(self):
        tests.util.TestBase.setUp(self)
        db = sqlite3.connect(self.rpath)
        c = db.cursor()
        # Delete all DNS server so we only do checks
        # against our own local server.
        c.execute('DELETE FROM DNS')
        db.commit()
        c.close()
        db.close()

    def tearDown(self):
        tests.util.TestBase.tearDown(self)
        db = sqlite3.connect(self.rpath)
        c = db.cursor()
        c.execute("DELETE FROM IP")
        db.commit()
        c.close()
        db.close()

    def add(self, domain, ip, rtype="A", rclass="IN", ttl=None):
        if ttl is None:
            ttl = int(time.time()) + 10 ** 6
        db = sqlite3.connect(self.rpath)
        c = db.cursor()
        c.execute('INSERT OR REPLACE INTO IP (domain, ip, rtype, rclass, ttl) '
                  'VALUES (?,?,?,?,?);', (domain, ip, rtype, rclass, ttl))
        db.commit()
        c.close()
        db.close()

    def test_check_rbl(self):
        """Check real multipart message"""
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.setup_conf(CONFIG, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_rbl_with_dns(self):
        """Check rbl without dns"""
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.setup_conf(CONFIG_DNS_AVAILABLE, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_rbl_without_dns(self):
        """Check rbl without dns"""
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.setup_conf(CONFIG_DNS_NOT_AVAILABLE, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 0.0, [])

    def test_check_rbl_with_test_dns(self):
        """Check rbl with test dns"""
        self.add("adelphia.net.", "127.0.0.21")
        self.add("akamai.com.", "127.0.0.2")
        self.add("apache.org.", "127.0.0.3")
        self.add("cingular.com.", "127.0.0.4")
        self.add("colorado.edu.", "127.0.0.5")
        self.add("comcast.net.", "127.0.0.6")
        self.add("doubleclick.com.", "127.0.0.7")
        self.add("ebay.com.", "127.0.0.8")
        self.add("gmx.net.", "127.0.0.9")
        self.add("google.com.", "127.0.0.10")
        self.add("intel.com.", "127.0.0.11")
        self.add("kernel.org.", "127.0.0.12")
        self.add("linux.org.", "127.0.0.13")
        self.add("mit.edu.", "127.0.0.14")
        self.add("motorola.com.", "127.0.0.15")
        self.add("msn.com.", "127.0.0.16")
        self.add("sourceforge.net.", "127.0.0.17")
        self.add("sun.com.", "127.0.0.18")
        self.add("w3.org.", "127.0.0.19")
        self.add("yahoo.com.", "127.0.0.20")
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.setup_conf(CONFIG_DNS_TEST_AVAILABLE, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_rbl_with_test_custom_dns(self):
        """Check rbl with test dns"""
        self.add("fakecheck.net.", "127.0.0.2")
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        #import pdb;pdb.set_trace()
        self.setup_conf(CONFIG_DNS_TEST_CUSTOM_AVAILABLE, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_dns_restricted_allow(self):
        """Check dns_restrictions for allow option"""
        self.add("example.com.", "127.0.0.1")
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.setup_conf(CONFIG_DNS_RESTRICTED_ALLOW, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_dns_restricted_deny(self):
        """Check dns_restrictions for allow option"""
        self.add("example.com.", "127.0.0.1")
        self.setup_conf(CONFIG_DNS_RESTRICTED_DENY, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 0.0, [])

    def test_check_rbl_ipv6(self):
        """Check real multipart message"""
        self.add(
            "1.0.0.0.0.0.0.0.0.0.0.0.7.0.0.0.d.0.0.a.0.0.1.2.0.0.a.9.4.0.6.2."
            "example.com.", "127.0.2.16"
        )
        self.setup_conf(CONFIG, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    @unittest.skip("The mindns server that we are using doesn't work with TXT")
    def test_check_rbl_txt(self):
        """Check real multipart message on a TXT list"""
        self.add("34.216.184.93.example.com.", "127.0.0.1", rtype='TXT')
        self.setup_conf(CONFIG_TXT, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_TXT_LIST"])

    def test_check_rbl_sub(self):
        """Check real multipart message on a SUB list"""
        self.add("34.216.184.93.example.com.", "127.0.0.1")
        self.add("34.216.184.93.example.com.", "127.0.0.3")
        self.setup_conf(CONFIG_SUB, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 2.0, ["IP_IN_LIST", "IP_IN_SUB_LIST"])

    def test_check_dns_sender(self):
        """Check on real multipart message if the sender domain has MX or
        A records"""
        self.setup_conf(CONFIG_SENDER_DNS, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["SENDER_DNS"])

    def test_check_rbl_envfrom(self):
        """Check on real multipart message if the envelope sender domain for
        matches on this list"""
        self.add("example.com.example.net.", "127.0.0.2")
        self.setup_conf(CONFIG_RBL_ENVFROM, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["RBL_ENVFROM_SENDER"])

    def test_check_rbl_from_host(self):
        """Check on real multipart message that From header domain for matches
        on this list."""
        self.add("example.com.example.net.", "127.0.2.1")
        self.setup_conf(CONFIG_RBL_FROM_HOST, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["RBL_FROM_HOST"])

    def test_check_rbl_from_domain(self):
        """Check on real multipart message that From header domain for matches
        on this list."""
        self.add("example.com.example.net.", "127.0.0.7")
        self.setup_conf(CONFIG_RBL_FROM_DOMAIN, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["RBL_FROM_DOMAIN"])

    def test_check_rbl_accreditor(self):
        """Check on real multipart message all the IPs of this message on the
        specified list, but only if the sender has the specified accreditor
        tag."""
        self.add("34.216.184.93.example.net.", "127.0.1.2")
        self.setup_conf(CONFIG_RBL_ACCREDITOR, PRE_CONFIG)
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["RBL_ACCREDITOR"])
