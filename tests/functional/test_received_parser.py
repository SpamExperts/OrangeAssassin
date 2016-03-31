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

TEST_IDENT = """Received: from [2a01:4f8:161:124b::3026] (ident=mail)
        by parser.example.com with esmtpa (Exim 4.85)
        (envelope-from <sender@parser.example.com>)
        id 1akrrE-2016TL-NN
        for teo@gapps.spamexperts.com; Tue, 29 Mar 2016 14:30:49 +0300"""

TEST_IP4_MAPPED = """Received: from relay.example.com ([IPv6:::ffff:217.70.183.195])
 by mfilter.example.net (mfilter.example.net [::ffff:10.0.15.180])
 (amavisd-new, port 10024)
 with ESMTP id hWQzvlEtNu8a for <teo@example.com>;
 Mon, 29 Mar 2016 17:33:40 +0100 (CET)"""

TEST_IDNA = """Received: from %s
 (%s [236.44.62.230])
 (authenticated bits=0)
 by %s (8.12.10/8.12.9) with ESMTP id
 o6PCS1im002238
 for <user@example.com>; Mon, 01 Feb 2016 03:45:37 -0600 (EST)"""


MSGTRUSTEDRELAYS = """Received: from mx6-05.smtp.antispamcloud.com
 (mx6-05.smtp.antispamcloud.com. [95.211.2.196]) by mx.google.com with ESMTPSA id
 ld8si17897891wjc.77.2016.03.07.00.56.45 for <backendteam@gapps.spamexperts.com>
 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)

Received: from mx6-05.smtp.antispamcloud.com
 (mx6-05.smtp.antispamcloud.com. [95.211.3.196]) by mx.google.com with ESMTPSA id
 ld8si17897891wjc.77.2016.03.07.00.56.45 for <backendteam@gapps.spamexperts.com>
 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)

Received: from mx6-05.smtp.antispamcloud.com
 (mx6-05.smtp.antispamcloud.com. [95.211.4.196]) by mx.google.com with ESMTPSA id
 ld8si17897891wjc.77.2016.03.07.00.56.45 for <backendteam@gapps.spamexperts.com>
 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)
 
 """


class TestReceivedParser(tests.util.TestBase):
    """Test the parser for received headers"""
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
        """Ignore headers which starts with 'by'"""
        self._check_for_skip(MSG_IGNORE)

    def test_header_msg_ignore_with_local(self):
        """Ignore headers received 'with local'"""
        self._check_for_skip(MSG_IGNORE2)

    def test_header_msg_ignore_with_local2(self):
        """Ignore headers received 'with local'"""
        self._check_for_skip(MSG_IGNORE3)

    def test_header_msg_ignore_fetchmail(self):
        """Ignore headers with fetchmail"""
        self._check_for_skip(MSG_IGNORE4)

    def test_header_msg_ignore_bsmtp(self):
        """Ignore headers with BSMTP"""
        self._check_for_skip(MSG_IGNORE5)

    def test_header_msg_ignore_content_tech(self):
        """Ignore headers with content technology"""
        self._check_for_skip(MSG_IGNORE6)

    def test_header_msg_ignore_localhost(self):
        """Ignore headers from example@localhost"""
        self._check_for_skip(MSG_IGNORE7)

    def test_header_msg_ignore_AVG(self):
        """Ignore headers with AVG SMTP"""
        self._check_for_skip(MSG_IGNORE8)

    def test_header_msg_ignore_qmail(self):
        """Ignore headers qmail"""
        self._check_for_skip(MSG_IGNORE9)

    def test_header_msg_ignore_aol(self):
        """Ignore headers qmail"""
        self._check_for_skip(MSG_IGNORE10)

    def test_header_MSG1(self):
        rdns = "rdns.example.com"
        ip = "217.70.183.195"
        by = "by.example.org"
        helo = "rdns.example.com"
        id = "1aVFVG-0000me-LC"
        envfrom = "envfrom@example.com"
        auth = ""
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": envfrom, "auth": auth}
        self._check_parser(MSG1, expected)

    def test_header_MSG2(self):
        rdns = "localhost"
        ip = "127.0.0.1"
        by = "by.example.org"
        helo = "localhost"
        id = "48963245BF8"
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": "", "auth": ""}
        self._check_parser(MSG2, expected)

    def test_header_MSG3(self):
        ip = "88.247.157.17"
        by = "by.example.org"
        helo = "helo.example.com"
        id = "1aaNYs-0002bJ-A9"
        envfrom = "envfrom@example.com"
        expected = {"rdns": "", "ip": ip, "by": by, "helo": helo, "ident": "",
                    "id": id, "envfrom": envfrom, "auth": ""}
        self._check_parser(MSG3, expected)

    def test_header_MSG4(self):
        rdns = "rdns.example.com"
        ip = "172.17.210.11"
        by = "by.example.org"
        helo = "rdns.example.com"
        id = "15.0.1104.5"
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": "", "auth": ""}
        self._check_parser(MSG4, expected)

    def test_header_MSG5(self):
        rdns = "rdns.example.com"
        ip = "236.44.62.230"
        by = "by.example.org"
        helo = "helo.example.com"
        id = "o6PCS1im002238"
        auth = "Sendmail"
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": "", "auth": auth}
        self._check_parser(MSG5, expected)

    def test_header_MSG6(self):
        rdns = "mx6-05.smtp.antispamcloud.com"
        ip = "95.211.2.196"
        by = "mx.google.com"
        helo = "mx6-05.smtp.antispamcloud.com."
        id = "ld8si17897891wjc.77.2016.03.07.00.56.45"
        auth = ("GMail - transport=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 "
                "bits=128/128")
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": "", "auth": auth}
        self._check_parser(MSG6, expected)

    def test_header_ident(self):
        """Test parsing ident from Received header"""
        ip = "2a01:4f8:161:124b::3026"
        by = "parser.example.com"
        ident = "mail"
        id = "1akrrE-2016TL-NN"
        envfrom = "sender@parser.example.com"
        auth = "esmtpa"
        expected = {"rdns": '', "ip": ip, "by": by, "helo": '', "ident": ident,
                    "id": id, "envfrom": envfrom, "auth": auth}
        self._check_parser(TEST_IDENT, expected)

    def test_header_ip4_mapped(self):
        """Test parsing IPs from Received header with IPv4 mapped"""
        rdns = "relay.example.com"
        ip = "217.70.183.195"
        by = "mfilter.example.net"
        helo = "relay.example.com"
        id = "hWQzvlEtNu8a"
        expected = {"rdns": rdns, "ip": ip, "by": by, "helo": helo,
                    "ident": "", "id": id, "envfrom": "", "auth": ""}
        self._check_parser(TEST_IP4_MAPPED, expected)

    def test_header_idna_domain(self):
        """Test parsing Received header with non-ASCII domains"""
        domain = ("xn--0cacdeehfljkltmnp5mraqt3eyba51bgd4bx7apd12f."
                  "xn--ss-5ia4bbgfkgw3owcu1b6a1j2dvgqe9vjb2b.example.com")
        ip = "236.44.62.230"
        id = "o6PCS1im002238"
        auth = "Sendmail"
        msg = TEST_IDNA % (domain, domain, domain)
        expected = {"rdns": domain, "ip": ip, "by": domain, "helo": domain,
                    "ident": "", "id": id, "envfrom": "", "auth": auth}
        self._check_parser(msg, expected)


class TestTrustPath(tests.util.TestBase):

    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_relays_trusted(self):
        self.setup_conf(pre_config="report _RELAYSTRUSTED_")
        expected = ("[ ip=95.211.2.196 rdns=mx6-05.smtp.antispamcloud.com "
                    "helo=mx6-05.smtp.antispamcloud.com. "
                    "by=mx.google.com ident= intl=1 id=ld8si17897891wjc.77."
                    "2016.03.07.00.56.45 auth=GMail - transport=TLS1_2 "
                    "cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128 msa=0 ]")
        result = self.check_pad(MSGTRUSTEDRELAYS)
        self.assertEqual(result, expected)

