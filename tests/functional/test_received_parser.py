# -*- coding: UTF-8 -*-

"""Test received header parser"""

from __future__ import absolute_import, print_function
import unittest

import tests.util

MSG_IGNORE = """Received: by rdns.example.com ([217.70.183.195])
 by by.example.org with esmtps (TLSv1.2:DHE-RSA-AES256-SHA:256)
 (Exim 4.85)
 (envelope-from <envfrom@example.com>)
 id 1aVFVG-0000me-LC
 for user@example.org; Mon, 15 Feb 2016 10:31:35 +0100"""

MSG_IGNORE2 = """Received: from [193.176.251.166] (ident=mail)
 by by.example.org with local (envelope-from <envfrom@example.com>)
 id 1aXSvr-0003uW-IS; Sun, 21 Feb 2016 15:16:12 +0300"""

MSG_IGNORE3 = """Received: from root by server6.seinternal.com with
 local-spamexperts-generated (Exim 4.80) id 1abp1W-0007Xm-KO for
 spam@spamexperts.wiredtree.com"""

MSG_IGNORE4 = """Received: from cabbage.jmason.org [127.0.0.1]
 by localhost with IMAP (fetchmail-5.9.0)
 for jm@localhost (single-drop)"""

MSG_IGNORE5 = """Received: from faerber.muc.de by slarti.muc.de with
 BSMTP (rsmtp-qm-ot 0.4) for asrg@ietf.org; 7 Mar 2003 21:10:38 -0000"""

MSG_IGNORE6 = """Received: from scv3.apple.com (scv3.apple.com) by mailgate2.apple.com
 (Content Technologies SMTPRS 4.2.1) with ESMTP id
 <T61095998e1118164e13f8@mailgate2.apple.com>"""

MSG_IGNORE7 = """Received: from raptor.research.att.com (bala@localhost) by
 raptor.research.att.com (SGI-8.9.3/8.8.7)
 with ESMTP id KAA14788
 for <asrg@example.com>"""

MSG_IGNORE8 = """Received: from 127.0.0.1 (AVG SMTP 9.0.935 [4365.1.1/10645]);
"""

MSG_IGNORE9 = """Received: from qmail-scanner-general-admin@lists.sourceforge.net
 by alpha by uid 7791 with qmail-scanner-1.14 (spamassassin: 2.41.
 Clear:SA:0(-4.1/5.0):. Processed in 0.209512 secs)"""

MSG_IGNORE10 = """Received: from DSmith1204@aol.com by imo-m09.mx.aol.com
 (mail_out_v34.13.) id 7.53.208064a0 (4394); Sat, 11 Jan 2003 23:24:31 -0500 (EST)"""

MSG1 = """Received: from rdns.example.com ([217.70.183.195])
 by by.example.org with esmtps (TLSv1.2:DHE-RSA-AES256-SHA:256)
 (Exim 4.85)
 (envelope-from <envfrom@example.com>)
 id 1aVFVG-0000me-LC
 for user@example.org; Mon, 15 Feb 2016 10:31:35 +0100"""

MSG2 = """Received: from localhost (localhost [127.0.0.1])
 by by.example.org (Postfix) with ESMTP id 48963245BF8;
 Tue, 23 Feb 2016 22:02:04 +0700 (WIB)"""

MSG3 = """Received: from [88.247.157.17] (helo=helo.example.com)
 by by.example.org with esmtp (Exim 4.85)
 (envelope-from <envfrom@example.com>) id 1aaNYs-0002bJ-A9
 for user@example.com; Mon, 29 Feb 2016 14:08:30 +0100"""

MSG4 = """Received: from rdns.example.com (172.17.210.11) by by.example.org
 (172.17.210.2) with Microsoft SMTP Server (TLS) id 15.0.1104.5 via Mailbox
 Transport; Tue, 23 Feb 2016 19:12:22 +0100"""

MSG5 = """Received: from rdns.example.com
 (helo.example.com [236.44.62.230])
 (authenticated bits=0)
 by by.example.org (8.12.10/8.12.9) with ESMTP id
 o6PCS1im002238
 for <user@example.com>; Mon, 01 Feb 2016 03:45:37 -0600 (EST)"""

MSG6 = """Received: from mx6-05.smtp.antispamcloud.com
 (mx6-05.smtp.antispamcloud.com. [95.211.2.196]) by mx.google.com with ESMTPSA id
 ld8si17897891wjc.77.2016.03.07.00.56.45 for <backendteam@gapps.spamexperts.com>
 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)"""


class TestReceivedParser(tests.util.TestBase):

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_pass(self):
        """No rule matched here, no report"""
        self.setup_conf()
        result = self.check_pad("")
        self.assertEqual(result, "")

    def _check_parser(self, msg, expected):
        self.setup_conf(pre_config="report {'rdns': '_RDNS_', 'ip': '_IP_', "
                                   "'by': '_BY_', 'helo': '_HELO_', "
                                   "'ident': '_IDENT_', 'id': '_ID_', "
                                   "'envfrom': '_ENVFROM_', 'auth': '_AUTH_'}")
        result = eval(self.check_pad(msg))
        self.assertEqual(result, expected)

    def _check_for_skip(self, msg):
        rdns = "@@RDNS@@"
        ip = "@@IP@@"
        by = "@@BY@@"
        helo = "@@HELO@@"
        ident = "@@IDENT@@"
        id = "@@ID@@"
        envfrom = "@@ENVFROM@@"
        auth = "@@AUTH@@"
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(msg, expected)

    def test_header_msg_ignore_by(self):
        """Ignore headers which starts with 'by'
        """
        self._check_for_skip(MSG_IGNORE)

    def test_header_msg_ignore_with_local(self):
        """Ignore headers received 'with local'
        """
        self._check_for_skip(MSG_IGNORE2)

    def test_header_msg_ignore_with_local2(self):
        """Ignore headers received 'with local'
        """
        self._check_for_skip(MSG_IGNORE3)

    def test_header_msg_ignore_fetchmail(self):
        """Ignore headers with fetchmail
        """
        self._check_for_skip(MSG_IGNORE4)

    def test_header_msg_ignore_bsmtp(self):
        """Ignore headers with BSMTP
        """
        self._check_for_skip(MSG_IGNORE5)

    def test_header_msg_ignore_content_tech(self):
        """Ignore headers with content technology
        """
        self._check_for_skip(MSG_IGNORE6)

    def test_header_msg_ignore_localhost(self):
        """Ignore headers from example@localhost
        """
        self._check_for_skip(MSG_IGNORE7)

    def test_header_msg_ignore_AVG(self):
        """Ignore headers with AVG SMTP
        """
        self._check_for_skip(MSG_IGNORE8)

    def test_header_msg_ignore_qmail(self):
        """Ignore headers qmail
        """
        self._check_for_skip(MSG_IGNORE9)

    def test_header_msg_ignore_aol(self):
        """Ignore headers qmail
        """
        self._check_for_skip(MSG_IGNORE10)

    def test_header_MSG1(self):
        rdns = "rdns.example.com"
        ip = "217.70.183.195"
        by = "by.example.org"
        helo = "rdns.example.com"
        ident = ""
        id = "1aVFVG-0000me-LC"
        envfrom = "envfrom@example.com"
        auth = ""
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG1, expected)

    def test_header_MSG2(self):
        rdns = "localhost"
        ip = "127.0.0.1"
        by = "by.example.org"
        helo = "localhost"
        ident = ""
        id = "48963245BF8"
        envfrom = ""
        auth = ""
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG2, expected)

    def test_header_MSG3(self):
        rdns = ""
        ip = "88.247.157.17"
        by = "by.example.org"
        helo = "helo.example.com"
        ident = ""
        id = "1aaNYs-0002bJ-A9"
        envfrom = "envfrom@example.com"
        auth = ""
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG3, expected)

    def test_header_MSG4(self):
        rdns = "rdns.example.com"
        ip = "172.17.210.11"
        by = "by.example.org"
        helo = "rdns.example.com"
        ident = ""
        id = "15.0.1104.5"
        envfrom = ""
        auth = ""
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG4, expected)

    def test_header_MSG5(self):
        rdns = "rdns.example.com"
        ip = "236.44.62.230"
        by = "by.example.org"
        helo = "helo.example.com"
        ident = ""
        id = "o6PCS1im002238"
        envfrom = ""
        auth = "Sendmail"
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG5, expected)

    def test_header_MSG6(self):
        rdns = "mx6-05.smtp.antispamcloud.com"
        ip = "95.211.2.196"
        by = "mx.google.com"
        helo = "mx6-05.smtp.antispamcloud.com."
        ident = ""
        id = "ld8si17897891wjc.77.2016.03.07.00.56.45"
        envfrom = ""
        auth = "GMail - transport=TLS1_2 " \
               "cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128"
        expected = {
                "rdns": rdns, "ip": ip, "by": by,
                "helo": helo, "ident": ident, "id": id, "envfrom": envfrom,
                "auth": auth}
        self._check_parser(MSG6, expected)
