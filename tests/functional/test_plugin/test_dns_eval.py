"""Test the dns_eval plugin"""

import os
import time
import unittest
import platform
import subprocess

import sqlite3
import tests.util

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
header      IP_IN_TXT_LIST      eval:check_rbl_txt('example', '127.0.0.3')
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
        result = self.check_pad(MSG)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    def test_check_rbl_ipv6(self):
        """Check real multipart message"""
        self.add(
            "1.0.0.0.0.0.0.0.0.0.0.0.7.0.0.0.d.0.0.a.0.0.1.2.0.0.a.9.4.0.6.2."
            "example.com.", "127.0.2.16"
        )
        self.setup_conf(CONFIG, PRE_CONFIG)
        result = self.check_pad(MSG, debug=True)
        self.check_report(result, 1.0, ["IP_IN_LIST"])

    @unittest.skip("check_rbl_txt - is not working")
    def test_check_rbl_txt(self):
        """Check real multipart message on a TXT list"""
        self.add("34.216.184.93.example.com.", "127.0.0.1", rtype='TXT')
        self.setup_conf(CONFIG_TXT, PRE_CONFIG)
        result = self.check_pad(MSG)
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
