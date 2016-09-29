"""
Tests for pad.received_parser
"""

import unittest
import collections
import email.header

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import pad.received_parser


class TestReceivedParser(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_check_for_skip_with_local(self):
        header = (
            "root by server6.seinternal.com with "
            "local-spamexperts-generated (Exim 4.80) id 1abp1W-0007Xm-KO for "
            "spam@spamexperts.wiredtree.com"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_fetchmail(self):
        header = (
                "cabbage.jmason.org [127.0.0.1] "
                "by localhost with IMAP (fetchmail-5.9.0) "
                "for jm@localhost (single-drop)"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_with_bsmtp(self):
        header = (
            "faerber.muc.de by slarti.muc.de with BSMTP (rsmtp-qm-ot 0.4) "
            "for asrg@ietf.org; 7 Mar 2003 21:10:38 -0000"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_content_tech(self):
        header = ("scv3.apple.com (scv3.apple.com) by mailgate2.apple.com "
                  "(Content Technologies SMTPRS 4.2.1) with ESMTP id "
                  "<T61095998e1118164e13f8@mailgate2.apple.com>")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_localhost(self):
        header = (
            "raptor.research.att.com (bala@localhost) by"
            " raptor.research.att.com (SGI-8.9.3/8.8.7)"
            " with ESMTP id KAA14788"
            " for <asrg@example.com>"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_avg_smtp(self):
        header = ("127.0.0.1 (AVG SMTP 7.0.299 [265.6.8])")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_qmail(self):
        header = (
            "qmail-scanner-general-admin@lists.sourceforge.net by alpha by "
            "uid 7791 with qmail-scanner-1.14 (spamassassin: 2.41."
            "Clear:SA:0(-4.1/5.0):. Processed in 0.209512 secs)"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_from(self):
        header = (
            "DSmith1204@aol.com by imo-m09.mx.aol.com (mail_out_v34.13.) "
            "id 7.53.208064a0 (4394); Sat, 11 Jan 2003 23:24:31 -0500 (EST)"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_unknown(self):
        header = ("Unknown/Local ([?.?.?.?]) by mailcity.com")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_auth(self):
        header = ("(AUTH: e40a9cea) by vqx.net with esmtp (courier-0.40) "
        "for <asrg@ietf.org>")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_local(self):
        header = ("localhost (localhost [[UNIX: localhost]]) "
        "by home.barryodonovan.com (8.12.11/8.12.11/Submit) id iBADHRP6011034")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_amazon(self):
        header = (
            "dc-mail-3102.iad3.amazon.com by mail-store-2001.amazon.com with "
            "ESMTP (peer crosscheck: dc-mail-3102.iad3.amazon.com)"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_novell(self):
        header = (
            "dc-mail-3102.iad3.amazon.com by mail-store-2001.amazon.com with "
            "ESMTP (peer crosscheck: dc-mail-3102.iad3.amazon.com)"
        )
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_no_name(self):
        header = ("no.name.available by [165.224.216.88] via smtpd "
         "(for lists.sourceforge.net [66.35.250.206]) with ESMTP")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_check_for_skip_smtpsvc(self):
        header = ("mail pickup service by www.fmwebsite.com with "
                  "Microsoft SMTPSVC")
        result = pad.received_parser.ReceivedParser.check_for_skip(header)
        self.assertTrue(result)

    def test_get_envfrom(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "user@example.org"
        result = pad.received_parser.ReceivedParser.get_envfrom(header)
        self.assertEqual(result, expected)

    def test_get_envfrom_sender(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-sender <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "user@example.org"
        result = pad.received_parser.ReceivedParser.get_envfrom(header)
        self.assertEqual(result, expected)

    def test_get_envfrom_big(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from "
            "<bounce-163362-375-29447-michael=username@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "username@example.org"
        result = pad.received_parser.ReceivedParser.get_envfrom(header)
        self.assertEqual(result, expected)

    def test_get_envfrom_empty(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) id 1aNgjg-00006s-19 for john@example.com")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_envfrom(header)
        self.assertEqual(result, expected)

    def test_get_rdns(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) id 1aNgjg-00006s-19 for john@example.com")
        expected = "server1.example.com"
        result = pad.received_parser.ReceivedParser.get_rdns(header)
        self.assertEqual(result, expected)

    def test_get_rdns_unknown_postfix(self):
        header = (
            "SC505052 (unknown [194.2.76.77]) (Authenticated sender: "
            "fax@example.com) by relay5.example.com (Postfix) "
            "with ESMTPA id 5781D41C091 for <username@example.org>")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_rdns(header)
        self.assertEqual(result, expected)

    def test_get_rdns_from_ip(self):
        header = (
            "[10.254.253.199] (helo=inside-relay.example.com) by "
            "fierwall.example.com with esmtpsa "
            "(TLSv1.2:DHE-RSA-AES256-SHA:256) (Exim 4.85) "
            "(envelope-from <username@example.org>) "
            "id 1aaP1E-0002Y1-0k for john@example.com")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_rdns(header)
        self.assertEqual(result, expected)

    def test_get_ip_inside_from(self):
        header = (
            "[10.254.253.199] (helo=inside-relay.example.com) by "
            "fierwall.example.com with esmtpsa "
            "(TLSv1.2:DHE-RSA-AES256-SHA:256) (Exim 4.85) "
            "(envelope-from <username@example.org>) "
            "id 1aaP1E-0002Y1-0k for john@example.com")
        expected = "10.254.253.199"
        result = pad.received_parser.ReceivedParser.get_ip(header)
        self.assertEqual(result, expected)

    def test_get_ip(self):
        header = (
            "server1.example.com ([216.219.119.8] helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from "
            "<bounce-163362-375-29447-michael=username@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "216.219.119.8"
        result = pad.received_parser.ReceivedParser.get_ip(header)
        self.assertEqual(result, expected)

    def test_get_ip_no_ip(self):
        header = (
            "server1.example.com (helo=relay.example.com) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from "
            "<bounce-163362-375-29447-michael=username@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_ip(header)
        self.assertEqual(result, expected)

    def test_get_ip_private(self):
        header = (
            "BMRGALNAV1 (192.168.2.30) by BMRGALMAIL1.BMRGAL.LOCAL "
            "(192.168.2.12) with Microsoft SMTP Server id 8.3.406.0")
        expected = "192.168.2.30"
        result = pad.received_parser.ReceivedParser.get_ip(header)
        self.assertEqual(result, expected)

    def test_get_ip_ipv6(self):
        header = (
            "host.example.com (example.org. [2604:9a00:2100:a00d:7::1]) "
            "by me.example.org with ESMTPS id "
            "qg1si11179246igb.97.2016.02.29.04.27 for <teo@example.com>")
        expected = "2604:9a00:2100:a00d:7::1"
        result = pad.received_parser.ReceivedParser.get_ip(header)
        self.assertEqual(result, expected)

    def test_get_by(self):
        header = (
            "host.example.com (example.org. [2604:9a00:2100:a00d:7::1]) "
            "by me.example.org with ESMTPS id "
            "qg1si11179246igb.97.2016.02.29.04.27 for <teo@example.com>")
        expected = "me.example.org"
        result = pad.received_parser.ReceivedParser.get_by(header)
        self.assertEqual(result, expected)

    def test_get_by_empty(self):
        header = (
            "host.example.com (example.org. [2604:9a00:2100:a00d:7::1]) "
            "with ESMTPS id "
            "qg1si11179246igb.97.2016.02.29.04.27 for <teo@example.com>")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_by(header)
        self.assertEqual(result, expected)

    def test_get_helo(self):
        header = (
            "root (helo=candygram.thunk.org) by thunker.thunk.org with "
            "local-esmtps (tls_cipher TLS-1.0:RSA_AES_256_CBC_SHA:32) "
            "(Exim 4.50 #1 (Debian)) id 1FwHqR-0008Bw-OG")
        expected = "candygram.thunk.org"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_helo_HELO(self):
        header = (
            "unknown (HELO delivery.antispamcloud.com) ([95.211.233.206]) "
            "by 192.168.50.233 with (DHE-RSA-AES256-SHA encrypted) SMTP")
        expected = "delivery.antispamcloud.com"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_helo_inside_group(self):
        header = (
            "[10.254.253.199] (helo=inside-relay.example.com) by "
            "fierwall.example.com with esmtpsa "
            "(TLSv1.2:DHE-RSA-AES256-SHA:256) (Exim 4.85) "
            "(envelope-from <username@example.org>) "
            "id 1aaP1E-0002Y1-0k for john@example.com")
        expected = "inside-relay.example.com"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_helo_rdns(self):
        header = (
            "server1.example.com ([216.219.119.8]) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "server1.example.com"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_helo_rdns2(self):
        header = (
            "server1.example.com (216.219.119.8) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "server1.example.com"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_helo_unknown(self):
        header = (
            "server1.example.com (unknown [216.219.119.8]) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "server1.example.com"
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_ident(self):
        header = (
            "from [107.172.93.124] (ident=mail) by mail.example.org with local "
            "(envelope-from <username@example.net>) id 1a7QMI-0004Ag-Ky "
            "for john@example.com")
        expected = "mail"
        result = pad.received_parser.ReceivedParser.get_ident(header)
        self.assertEqual(result, expected)

    def test_get_ident_empty(self):
        header = (
            "server1.example.com (unknown [216.219.119.8]) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_ident(header)
        self.assertEqual(result, expected)

    def test_get_id(self):
        header = (
            "server1.example.com (unknown [216.219.119.8]) "
            "by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256) "
            "(Exim 4.85) (envelope-from <user@example.org>) "
            "id 1aNgjg-00006s-19 for john@example.com")
        expected = "1aNgjg-00006s-19"
        result = pad.received_parser.ReceivedParser.get_id(header)
        self.assertEqual(result, expected)

    @unittest.skip("The parser was checking in the wrong order")
    def test_get_auth_google(self):
        header = (
            "mx6-05.smtp.antispamcloud.com (mx6-05.smtp.antispamcloud.com. "
            "[95.211.2.196]) by mx.google.com with ESMTPSA id "
            "ld8si17897891wjc.77.2016.03.07.00.56.45 for "
            "<backendteam@gapps.spamexperts.com> "
            "(version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)")
        expected = "GMail - transport=TLS1_2 " \
                   "cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    @unittest.skip("The parser was checking in the wrong order")
    def test_get_auth_postfix(self):
        header = (
            "SCC827BB (unknown [194.2.76.77]) (Authenticated sender: "
            "fax@example.net) by relay2-d.mail.gandi.net (Postfix) "
            "with ESMTPA id 8DF03C5AB5 for <john@example.com>")
        expected = "Postfix"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_get_auth_ESMTSPA(self):
        header = (
            "mx6-05.smtp.antispamcloud.com (mx6-05.smtp.antispamcloud.com. "
            "[95.211.2.196]) by test.example.com with ESMTPSA id "
            "ld8si17897891wjc.77.2016.03.07.00.56.45 for "
            "<backendteam@gapps.spamexperts.com> "
            "(version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)")
        expected = "ESMTPSA"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_get_auth_squirrelmail(self):
        header = (
            "165.228.131.11 (proxying for 139.130.20.189) (SquirrelMail "
            "authenticated user jmmail) by jmason.org with HTTP")
        expected = "SquirrelMail"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_get_auth_squirrelmail(self):
        header = (
            "[41.71.176.172] (41.71.176.172) by smtp.example.org "
            "(8.7.004.06) (authenticated as user@example.com) "
            "id 55F054B600FC5AB5; Wed, 14 Oct 2015 22:36:42 +0800")
        expected = "CriticalPath"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    @unittest.skip("The parser was checking in the wrong order")
    def test_get_auth_criticalpath(self):
        header = (
            "165.228.131.11 (proxying for 139.130.20.189) (SquirrelMail "
            "authenticated user jmmail) by example.org with HTTP")
        expected = "SquirrelMail"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_get_auth_sendmail(self):
        header = (
            "server1.example.com (host.example.com "
            "[64.91.78.197]) (authenticated bits=0) by fierwall.example.org "
            "(8.14.4/8.14.4) with ESMTP id tBCFWrhS080562")
        expected = "Sendmail"
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_get_auth_no_auth(self):
        header = (
            "[107.172.93.124] (ident=mail) by server.example.org with local "
            "(envelope-from <example@test.org>) id 1a7QMI-0004Ag-Ky "
            "for asellitto@a3mediallc.com")
        expected = ""
        result = pad.received_parser.ReceivedParser.get_auth(header)
        self.assertEqual(result, expected)

    def test_check_parser(self):
        header = ["""from server1.example.com ([216.219.119.8]
                 helo=relay.example.com)
                 by server.example.org with esmtps (TLSv1:DHE-RSA-AES256-SHA:256)
                 (Exim 4.85) (envelope-from <user@example.org>)
                 id 1aNgjg-00006s-19
                 for john@example.com; Mon, 25 Jan 2016 06:59:12 -0600
                """]
        expected = [{
                "rdns": "server1.example.com", "ip": "216.219.119.8",
                "by": "server.example.org", "helo": "relay.example.com",
                "ident": "", "id": "1aNgjg-00006s-19", "envfrom": "user@example.org",
                "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_for_originating_ip_header(self):
        header = ["X-ORIGINATING-IP: 1.2.3.4"]
        expected = [{
            "rdns": "", "ip": "1.2.3.4",
            "by": "", "helo": "",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]

        parsed_data = pad.received_parser.ReceivedParser(
            header).received
        self.assertEqual(parsed_data, expected)

    def test_received_547(self):
        header = ["from sc8-sf-list1-b.sourceforge.net ([10.3.1.13] "
                  "helo=sc8-sf-list1.sourceforge.net) by sc8-sf-list2.sourceforge.net with esmtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t301-0007Bh-00; Wed, 12 Mar 2003 01:58:13 -0800"]
        expected = [{
            "rdns": "sc8-sf-list1-b.sourceforge.net", "ip": "10.3.1.13",
            "by": "sc8-sf-list2.sourceforge.net", "helo": "sc8-sf-list1.sourceforge.net",
            "ident": "", "id": "18t301-0007Bh-00", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_564(self):
        header = ["from boggle.ihug.co.nz [203.109.252.209] by "
                  "grunt6.ihug.co.nz with esmtp (Exim 3.35 #1 (Debian)) id 18SWRe-0006X6-00; Sun, 29 Dec "
                  "2002 18:57:06 +1300"]
        expected = [{
            "rdns": "boggle.ihug.co.nz", "ip": "203.109.252.209",
            "by": "grunt6.ihug.co.nz",
            "helo": "boggle.ihug.co.nz",
            "ident": "", "id": "18SWRe-0006X6-00", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_596(self):
        header = ["from localhost (unknown [127.0.0.1]) by cabbage.jmason.org (Postfix) with ESMTP id A96E18BD97 for <jm@localhost>; Thu, 13 Mar 2003 15:23:15 -0500 (EST)"]
        expected = [{
            "rdns": "", "ip": "127.0.0.1",
            "by": "cabbage.jmason.org",
            "helo": "localhost",
            "ident": "", "id": "A96E18BD97", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_606(self):
        header = ["from 207.8.214.3 (unknown[211.94.164.65]) by "
                  "puzzle.pobox.com (Postfix) with SMTP id 9029AFB732 Sat,  "
                  "8 Nov 2003 17:57:46 -0500 (EST) (Pobox.com version: "
                  "reported in bug 2745)"]
        expected = [{
            "rdns": "", "ip": "211.94.164.65",
            "by": "puzzle.pobox.com",
            "helo": "207.8.214.3",
            "ident": "", "id": "9029AFB732", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_619(self):
        header = ["from DPLAPTOP ( 72.242.176.162) by mail.puryear-it.com (Scalix SMTP Relay 10.0.1.3) via ESMTP; Fri, 23 Jun 2006 16:39:47 -0500 (CDT)"]
        expected = [{
            "rdns": "", "ip": "72.242.176.162",
            "by": "mail.puryear-it.com",
            "helo": "DPLAPTOP",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_651(self):
        header = ["from mail1.insuranceiq.com (host66.insuranceiq.com [65.217.159.66] (may be forged)) by dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id h2F0c2x31856 for <jm@jmason.org>; Sat, 15 Mar 2003 00:38:03 GMT"]
        expected = [{
            "rdns": "host66.insuranceiq.com", "ip": "65.217.159.66",
            "by": "dogma.slashnull.org",
            "helo": "mail1.insuranceiq.com",
            "ident": "", "id": "h2F0c2x31856", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_669(self):
        header = ["from ns.elcanto.co.kr (66.161.246.58 [66.161.246.58]) by mail.ssccbelen.edu.pe with SMTP (Microsoft Exchange Internet Mail Service Version 5.5.1960.3) id G69TW478; Thu, 13 Mar 2003 14:01:10 -0500"]
        expected = [{
            "rdns": "66.161.246.58", "ip": "66.161.246.58",
            "by": "mail.ssccbelen.edu.pe",
            "helo": "ns.elcanto.co.kr",
            "ident": "", "id": "G69TW478", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_677(self):
        header = ["from mail2.detr.gsi.gov.uk ([51.64.35.18] helo=ahvfw.dtlr.gsi.gov.uk) by mail4.gsi.gov.uk with smtp id 190K1R-0000me-00 for spamassassin-talk-admin@lists.sourceforge.net; Tue, 01 Apr 2003 12:33:46 +0100"]
        expected = [{
            "rdns": "mail2.detr.gsi.gov.uk", "ip": "51.64.35.18",
            "by": "mail4.gsi.gov.uk",
            "helo": "ahvfw.dtlr.gsi.gov.uk",
            "ident": "", "id": "190K1R-0000me-00", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_683(self):
        header = ["from 12-211-5-69.client.attbi.com (<unknown.domain>[12.211.5.69]) by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <2002112823351305300akl1ue>; Thu, 28 Nov 2002 23:35:13 +0000"]
        expected = [{
            "rdns": "", "ip": "12.211.5.69",
            "by": "rwcrmhc53.attbi.com",
            "helo": "12-211-5-69.client.attbi.com",
            "ident": "", "id": "2002112823351305300akl1ue", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_689(self):
        header = ["from attbi.com (h000502e08144.ne.client2.attbi.com ["
                  "24.128.27.103]) by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <20030222193438053008f7tee>; Sat, 22 Feb 2003 19:34:39 +0000"]
        expected = [{
            "rdns": "h000502e08144.ne.client2.attbi.com", "ip": "24.128.27.103",
            "by": "rwcrmhc53.attbi.com",
            "helo": "attbi.com",
            "ident": "", "id": "20030222193438053008f7tee", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_697(self):
        header = ["from 4wtgRl (kgbxn@[211.244.147.115]) by dogma.slashnull.org (8.11.6/8.11.6) with SMTP id h8BBsUJ18848; Thu, 11 Sep 2003 12:54:31 +0100"]
        expected = [{
            "rdns": "", "ip": "211.244.147.115",
            "by": "dogma.slashnull.org",
            "helo": "4wtgRl",
            "ident": "kgbxn", "id": "h8BBsUJ18848", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_706(self):
        header = ["from 213.123.174.21 by lw11fd.law11.hotmail.msn.com with "
                  "HTTP; Wed, 24 Jul 2002 16:36:44 GMT"]
        expected = [{
            "rdns": "", "ip": "213.123.174.21",
            "by": "lw11fd.law11.hotmail.msn.com",
            "helo": "",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_713(self):
        header = ["from x71-x56-x24-5.webspeed.dk (HELO niels) (69.96.3.15) by la.mx.develooper.com (qpsmtpd/0.27-dev) with SMTP; Fri, 02 Jan 2004 19:26:52 -0800"]
        expected = [{
            "rdns": "x71-x56-x24-5.webspeed.dk", "ip": "69.96.3.15",
            "by": "la.mx.develooper.com",
            "helo": "niels",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_720(self):
        header = ["from dslb-082-083-045-064.pools.arcor-ip.net (EHLO homepc) [82.83.45.64] by mail.gmx.net (mp010) with SMTP; 03 Feb 2007 13:13:47 +0100"]
        expected = [{
            "rdns": "dslb-082-083-045-064.pools.arcor-ip.net", "ip": "82.83.45.64",
            "by": "mail.gmx.net",
            "helo": "homepc",
            "ident": "", "id": "", "envfrom": "",
            "auth": "GMX (SMTP / mail.gmx.net)"}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

    def test_received_729(self):
        header = ["from imo-m01.mx.aol.com ([64.12.136.4]) by "
                  "eagle.glenraven.com via smtpd (for [198.85.87.98]) with SMTP; Wed, 08 Oct 2003 16:25:37 -0400"]
        expected = [{
            "rdns": "", "ip": "64.12.136.4",
            "by": "eagle.glenraven.com",
            "helo": "imo-m01.mx.aol.com",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        parsed_data = pad.received_parser.ReceivedParser(header).received
        self.assertEqual(parsed_data, expected)

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestReceivedParser, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
