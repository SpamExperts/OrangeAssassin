"""Tests the Razor2 Plugin"""

from __future__ import absolute_import
import unittest
import tests.util

# Load Razor2 plugin and report SCORE and matching RULES
PRE_CONFIG = """loadplugin pad.plugins..Razor2
report _SCORE_
report _TESTS_
"""

# Define rules for plugin
CONFIG = """"""


# Define sample spam email
SPAM_EMAIL = """Subject: Test spam mail (GTUBE)
Message-ID: <GTUBE1.1010101@example.net>
Date: Wed, 23 Jul 2003 23:30:00 +0200
From: Sender <sender@example.net>
To: Recipient <recipient@example.net>
Precedence: junk
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

This is the GTUBE, the
    Generic
    Test for
    Unsolicited
    Bulk
    Email

If your spam filter supports it, the GTUBE provides a test by which you
can verify that the filter is installed correctly and is detecting incoming
spam. You can send yourself a test mail containing the following string of
characters (in upper case and with no white spaces and line breaks):

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

You should send this test mail from an account outside of your network.

"""

# Define sample no spam email
NO_SPAM_EMAIL = """Return-Path: <tbtf-approval@world.std.com>
Delivered-To: foo@foo.com
Received: from europe.std.com (europe.std.com [199.172.62.20])
    by mail.netnoteinc.com (Postfix) with ESMTP id 392E1114061
    for <foo@foo.com>; Fri, 20 Apr 2001 21:34:46 +0000 (Eire)
Received: (from daemon@localhost)
    by europe.std.com (8.9.3/8.9.3) id RAA09630
    for tbtf-outgoing; Fri, 20 Apr 2001 17:31:18 -0400 (EDT)
Received: from sgi04-e.std.com (sgi04-e.std.com [199.172.62.134])
    by europe.std.com (8.9.3/8.9.3) with ESMTP id RAA08749
    for <tbtf@facteur.std.com>; Fri, 20 Apr 2001 17:24:31 -0400 (EDT)
Received: from world.std.com (world-f.std.com [199.172.62.5])
    by sgi04-e.std.com (8.9.3/8.9.3) with ESMTP id RAA8278330
    for <tbtf@facteur.std.com>; Fri, 20 Apr 2001 17:24:31 -0400 (EDT)
Received: (from dawson@localhost)
    by world.std.com (8.9.3/8.9.3) id RAA26781
    for tbtf@world.std.com; Fri, 20 Apr 2001 17:24:31 -0400 (EDT)
Received: from sgi04-e.std.com (sgi04-e.std.com [199.172.62.134])
    by europe.std.com (8.9.3/8.9.3) with ESMTP id RAA07541
    for <tbtf@facteur.std.com>; Fri, 20 Apr 2001 17:12:06 -0400 (EDT)
Received: from world.std.com (world-f.std.com [199.172.62.5])
    by sgi04-e.std.com (8.9.3/8.9.3) with ESMTP id RAA8416421
    for <tbtf@facteur.std.com>; Fri, 20 Apr 2001 17:12:06 -0400 (EDT)
Received: from [208.192.102.193] (ppp0c199.std.com [208.192.102.199])
    by world.std.com (8.9.3/8.9.3) with ESMTP id RAA14226
    for <tbtf@world.std.com>; Fri, 20 Apr 2001 17:12:04 -0400 (EDT)
Mime-Version: 1.0
Message-Id: <v0421010eb70653b14e06@[208.192.102.193]>
Date: Fri, 20 Apr 2001 16:59:58 -0400
To: tbtf@world.std.com
From: Keith Dawson <dawson@world.std.com>
Subject: TBTF ping for 2001-04-20: Reviving
Content-Type: text/plain; charset="us-ascii"
Sender: tbtf-approval@world.std.com
Precedence: list
Reply-To: tbtf-approval@europe.std.com

-----BEGIN PGP SIGNED MESSAGE-----

TBTF ping for 2001-04-20: Reviving

    T a s t y   B i t s   f r o m   t h e   T e c h n o l o g y   F r o n t

    Timely news of the bellwethers in computer and communications
    technology that will affect electronic commerce -- since 1994

    Your Host: Keith Dawson

    ISSN: 1524-9948

    This issue: < http://tbtf.com/archive/2001-04-20.html >

    To comment on this issue, please use this forum at Quick Topic:
    < http://www.quicktopic.com/tbtf/H/kQGJR2TXL6H >
    ________________________________________________________________________

Q u o t e   O f   T h e   M o m e n t

    Even organizations that promise "privacy for their customers" rarely
    if ever promise "continued privacy for their former customers..."
    Once you cancel your account with any business, their promises of
    keeping the information about their customers private no longer
    apply... you're not a customer any longer.

    This is in the large category of business behaviors that individuals
    would consider immoral and deceptive -- and businesses know are not
    illegal.

    -- "_ankh," writing on the XNStalk mailing list
    ________________________________________________________________________

..TBTF's long hiatus is drawing to a close

    Hail subscribers to the TBTF mailing list. Some 2,000 [1] of you
    have signed up since the last issue [2] was mailed on 2000-07-20.
    This brief note is the first of several I will send to this list to
    excise the dead addresses prior to resuming regular publication.

    While you time the contractions of the newsletter's rebirth, I in-
    vite you to read the TBTF Log [3] and sign up for its separate free
    subscription. Send "subscribe" (no quotes) with any subject to
    tbtf-log-request@tbtf.com . I mail out collected Log items on Sun-
    days.

    If you need to stay more immediately on top of breaking stories,
    pick up the TBTF Log's syndication file [4] or read an aggregator
    that does. Examples are Slashdot's Cheesy Portal [5], Userland [6],
    and Sitescooper [7]. If your news obsession runs even deeper and you
    own an SMS-capable cell phone or PDA, sign up on TBTF's WebWire-
    lessNow portal [8]. A free call will bring you the latest TBTF Log
    headline, Jargon Scout [9] find, or Siliconium [10].

    Two new columnists have bloomed on TBTF since last summer: Ted By-
    field's roving_reporter [11] and Gary Stock's UnBlinking [12]. Late-
    ly Byfield has been writing in unmatched depth about ICANN, but the
    roving_reporter nym's roots are in commentary at the intersection of
    technology and culture. Stock's UnBlinking latches onto topical sub-
    jects and pursues them to the ends of the Net. These writers' voices
    are compelling and utterly distinctive.

    [1]  http://tbtf.com/growth.html
    [2]  http://tbtf.com/archive/2000-07-20.html
    [3]  http://tbtf.com/blog/
    [4]  http://tbtf.com/tbtf.rdf
    [5]  http://www.slashdot.org/cheesyportal.shtml
    [6]  http://my.userland.com/
    [7]  http://www.sitescooper.org/
    [8]  http://tbtf.com/pull-wwn/
    [9]  http://tbtf.com/jargon-scout.html
    [10] http://tbtf.com/siliconia.html
    [11] http://tbtf.com/roving_reporter/
    [12] http://tbtf.com/unblinking/
    ________________________________________________________________________

S o u r c e s

> For a complete list of TBTF's email and Web sources, see
    http://tbtf.com/sources.html .
    ________________________________________________________________________

B e n e f a c t o r s

    TBTF is free. If you get value from this publication, please visit
    the TBTF Benefactors page < http://tbtf.com/the-benefactors.html >
    and consider contributing to its upkeep.
    ________________________________________________________________________

    TBTF home and archive at http://tbtf.com/ . To unsubscribe send
    the message "unsubscribe" to tbtf-request@tbtf.com. TBTF is Copy-
    right 1994-2000 by Keith Dawson, <dawson@world.std.com>. Commercial
    use prohibited. For non-commercial purposes please forward, post,
    and link as you see fit.
    _______________________________________________
    Keith Dawson               dawson@world.std.com
    Layer of ash separates morning and evening milk.

-----BEGIN PGP SIGNATURE-----
Version: PGPfreeware 6.5.2 for non-commercial use <http://www.pgp.com>

iQCVAwUBOuCi3WAMawgf2iXRAQHeAQQA3YSePSQ0XzdHZUVskFDkTfpE9XS4fHQs
WaT6a8qLZK9PdNcoz3zggM/Jnjdx6CJqNzxPEtxk9B2DoGll/C/60HWNPN+VujDu
Xav65S0P+Px4knaQcCIeCamQJ7uGcsw+CqMpNbxWYaTYmjAfkbKH1EuLC2VRwdmD
wQmwrDp70v8=
=8hLB
-----END PGP SIGNATURE-----


"""

class TestFunctionalRazor2(tests.util.TestBase):

    def test_example(self):
        pass


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestFunctionalRazor2, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
