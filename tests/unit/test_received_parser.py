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
        expected = ""
        result = pad.received_parser.ReceivedParser.get_helo(header)
        self.assertEqual(result, expected)

    def test_get_ident(self):
        header = (
            "from [107.172.93.124] (ident=mail) by mail.example.org with local "
            "(envelope-from <username@example.net>) id 1a7QMI-0004Ag-Ky "
            "for john@example.com")
        print(header)
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


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestReceivedParser, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
