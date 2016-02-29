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

loadplugin      pad.plugins.dns_eval.DNSEval
"""

CONFIG = r"""
header      IP_IN_LIST      eval:check_rbl('example', 'example.com')
describe    IP_IN_LIST      IP in example.com list
"""

MSG = r"""Received: from mail-wm0-f50.google.com ([93.184.216.34])
 by example.com with esmtps (TLSv1.2:RC4-SHA:128)
 (Exim 4.85)
 (envelope-from <sender@example.com>)
 id 1aaNAy-0006fq-LZ
 for chirila@example.com; Mon, 29 Feb 2016 13:43:53 +0100
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

