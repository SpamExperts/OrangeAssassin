"""
Parser for Received headers
It extracts the following metadata:
:rdns
:ip
:helo
:by
:ident
:id
:auth
"""

import re
from oa.regex import Regex

LOCALHOST = Regex(r"""
(?:
              # as a string
              localhost(?:\.localdomain)?
            |
              \b(?<!:)    # ensure no "::" IPv6 marker before this one
              # plain IPv4
              127\.0\.0\.1 \b
            |
              # IPv6 addresses
              # don't use \b here, it hits on :'s
              (?:IPv6:    # with optional prefix
                        | (?<![a-f0-9:])
                      )
              (?:
            # IPv4 mapped in IPv6
            # note the colon after the 12th byte in each here
            (?:
              # first 6 (12 bytes) non-zero
              (?:0{1,4}:){5}        ffff:
              |
              # leading zeros omitted (note {0,5} not {1,5})
              ::(?:0{1,4}:){0,4}        ffff:
              |
              # trailing zeros (in the first 6) omitted
              (?:0{1,4}:){1,4}:        ffff:
              |
              # 0000 in second up to (including) fifth omitted
              0{1,4}::(?:0{1,4}:){1,3}    ffff:
              |
              # 0000 in third up to (including) fifth omitted
              (?:0{1,4}:){2}:0{1,2}:    ffff:
              |
              # 0000 in fourth up to (including) fifth omitted
              (?:0{1,4}:){3}:0:        ffff:
              |
              # 0000 in fifth omitted
              (?:0{1,4}:){4}:        ffff:
            )
            # and the IPv4 address appended to all of the 12 bytes above
            127\.0\.0\.1    # no \b, we check later

            | # or (separately) a pure IPv6 address

            # all 8 (16 bytes) of them present
            (?:0{1,4}:){7}            0{0,3}1
            |
            # leading zeros omitted
            :(?::0{1,4}){0,6}:        0{0,3}1
            |
            # 0000 in second up to (including) seventh omitted
            0{1,4}:(?::0{1,4}){0,5}:    0{0,3}1
            |
            # 0000 in third up to (including) seventh omitted
            (?:0{1,4}:){2}(?::0{1,4}){0,4}:    0{0,3}1
            |
            # 0000 in fouth up to (including) seventh omitted
            (?:0{1,4}:){3}(?::0{1,4}){0,3}:    0{0,3}1
            |
            # 0000 in fifth up to (including) seventh omitted
            (?:0{1,4}:){4}(?::0{1,4}){0,2}:    0{0,3}1
            |
            # 0000 in sixth up to (including) seventh omitted
            (?:0{1,4}:){5}(?::0{1,4}){0,1}:    0{0,3}1
            |
            # 0000 in seventh omitted
            (?:0{1,4}:){6}:            0{0,3}1
              )
              (?![a-f0-9:])
            )
""", re.I | re.X)

IP_PRIVATE = Regex(r"""
^(?:
  (?:   # IPv4 addresses
    10|                    # 10.0.0.0/8      Private Use (5735, 1918)
    127|                            # 127.0.0.0/8     Host-local  (5735, 1122)
    169\.254|                # 1690.0/12   Private Use (5735, 1918)
    192\.168|                 # 192.168.0.0/16  Private Use (5735, 1918)
    100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])  # 100.64.0.0/10 CGN (6598)
    )\..*
|
  (?:   # IPv6 addresses
    # don't use \b here, it hits on :'s
    (?:IPv6:    # with optional prefix
      | (?<![a-f0-9:])
    )
    (?:
      # IPv4 mapped in IPv6
      # note the colon after the 12th byte in each here
      (?:
        # first 6 (12 bytes) non-zero
        (?:0{1,4}:){5}        ffff:
        |
        # leading zeros omitted (note {0,5} not {1,5})
        ::(?:0{1,4}:){0,4}        ffff:
        |
        # trailing zeros (in the first 6) omitted
        (?:0{1,4}:){1,4}:        ffff:
        |
        # 0000 in second up to (including) fifth omitted
        0{1,4}::(?:0{1,4}:){1,3}    ffff:
        |
        # 0000 in third up to (including) fifth omitted
        (?:0{1,4}:){2}:0{1,2}:    ffff:
        |
        # 0000 in fourth up to (including) fifth omitted
        (?:0{1,4}:){3}:0:        ffff:
        |
        # 0000 in fifth omitted
        (?:0{1,4}:){4}:        ffff:
      )
      # and the IPv4 address appended to all of the 12 bytes above
      (?:
        10|
        127|
        169\.254|
        172\.(?:1[6-9]|2[0-9]|3[01])|
        192\.168|
        100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])
      )\..*

    | # or IPv6 link-local address space, fe80::/10
      fe[89ab][0-9a-f]:.*

    | # or the host-local ::1 addr, as a pure IPv6 address

      # all 8 (16 bytes) of them present
      (?:0{1,4}:){7}            0{0,3}1
      |
      # leading zeros omitted
      :(?::0{1,4}){0,6}:        0{0,3}1
      |
      # 0000 in second up to (including) seventh omitted
      0{1,4}:(?::0{1,4}){0,5}:    0{0,3}1
      |
      # 0000 in third up to (including) seventh omitted
      (?:0{1,4}:){2}(?::0{1,4}){0,4}:    0{0,3}1
      |
      # 0000 in fouth up to (including) seventh omitted
      (?:0{1,4}:){3}(?::0{1,4}){0,3}:    0{0,3}1
      |
      # 0000 in fifth up to (including) seventh omitted
      (?:0{1,4}:){4}(?::0{1,4}){0,2}:    0{0,3}1
      |
      # 0000 in sixth up to (including) seventh omitted
      (?:0{1,4}:){5}(?::0{1,4}){0,1}:    0{0,3}1
      |
      # 0000 in seventh omitted
      (?:0{1,4}:){6}:            0{0,3}1
    )
    (?![a-f0-9:])
  )
)
""", re.X | re.I)

IP_ADDRESS = Regex(r"""
            (?:
              \b(?<!:)    # ensure no "::" IPv4 marker before this one
              # plain IPv4, as above
              (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
              (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
              (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
              (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\b
            |
              # IPv6 addresses
              # don't use \b here, it hits on :'s
              (?:IPv6:    # with optional prefix
                        | (?<![a-f0-9:])
                      )
              (?:
            # IPv4 mapped in IPv6
            # note the colon after the 12th byte in each here
            (?:
              # first 6 (12 bytes) non-zero
              (?:[a-f0-9]{1,4}:){6}
              |
              # leading zeros omitted (note {0,5} not {1,5})
              ::(?:[a-f0-9]{1,4}:){0,5}
              |
              # trailing zeros (in the first 6) omitted
              (?:[a-f0-9]{1,4}:){1,5}:
              |
              # 0000 in second up to (including) fifth omitted
              [a-f0-9]{1,4}::(?:[a-f0-9]{1,4}:){1,4}
              |
              # 0000 in third up to (including) fifth omitted
              (?:[a-f0-9]{1,4}:){2}:(?:[a-f0-9]{1,4}:){1,3}
              |
              # 0000 in fourth up to (including) fifth omitted
              (?:[a-f0-9]{1,4}:){3}:(?:[a-f0-9]{1,4}:){1,2}
              |
              # 0000 in fifth omitted
              (?:[a-f0-9]{1,4}:){4}:[a-f0-9]{1,4}:
            )
            # and the IPv4 address appended to all of the 12 bytes above
            (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
            (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
            (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
            (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)   # no \b, we check later

            | # or (separately) a pure IPv6 address

            # all 8 (16 bytes) of them present
            (?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}
            |
            # leading zeros omitted
            :(?::[a-f0-9]{1,4}){1,7}
            |
            # trailing zeros omitted
            (?:[a-f0-9]{1,4}:){1,7}:
            |
            # 0000 in second up to (including) seventh omitted
            [a-f0-9]{1,4}:(?::[a-f0-9]{1,4}){1,6}
            |
            # 0000 in third up to (including) seventh omitted
            (?:[a-f0-9]{1,4}:){2}(?::[a-f0-9]{1,4}){1,5}
            |
            # 0000 in fouth up to (including) seventh omitted
            (?:[a-f0-9]{1,4}:){3}(?::[a-f0-9]{1,4}){1,4}
            |
            # 0000 in fifth up to (including) seventh omitted
            (?:[a-f0-9]{1,4}:){4}(?::[a-f0-9]{1,4}){1,3}
            |
            # 0000 in sixth up to (including) seventh omitted
            (?:[a-f0-9]{1,4}:){5}(?::[a-f0-9]{1,4}){1,2}
            |
            # 0000 in seventh omitted
            (?:[a-f0-9]{1,4}:){6}:[a-f0-9]{1,4}
            |
            # :: (the unspecified address 0:0:0:0:0:0:0:0)
            # dos: I don't expect to see this address in a header, and
            # it may cause non-address strings to match, but we'll
            # include it for now since it is valid
            ::
              )
              (?![a-f0-9:])
            )""", re.X)

IPFRE = Regex(r"[\[ \(]{1}[a-fA-F\d\.\:]{7,}?[\] \n;\)]{1}")

FETCHMAIL = Regex(r"""
.*?\s(\S+)\s(?:\[({IP_ADDRESS})\]\s)?
by\s(\S+)\swith
\s\S+\s\(fetchmail""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)

LOCALHOST_RE = Regex(r"""
^\S+\s\([^\s\@]+\@{LOCALHOST}\)\sby\s\S+\s\(
""".format(LOCALHOST=LOCALHOST.pattern), re.X | re.I)

UNKNOWN_RE_RDNS = Regex(r"""
^(\S+)\s\((unknown)\s\[({IP_ADDRESS})\]\)\s\(
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)

# ================ check_for_skip regex ==================
WITH_LOCAL_RE = Regex(r'\bwith local(?:-\S+)? ', re.I)
BSMTP_RE = Regex(r'^\S+ by \S+ with BSMTP', re.I)
CONTENT_TECH_RE = Regex(r"""
^\S+\s\(\S+\)\sby\s\S+\s\(Content\sTechnologies\s""", re.X | re.I)
AVG_SMTP_RE = Regex(r'^127\.0\.0\.1 \(AVG SMTP \S+ \[\S+\]\)')
QMAIL_RE = Regex(r'^\S+\@\S+ by \S+ by uid \S+ ')
FROM_RE = Regex(r'^\S+\@\S+ by \S+ ')
UNKNOWN_RE = Regex(r'^Unknown\/Local \(')
AUTH_SKIP_RE = Regex(r'^\(AUTH: \S+\) by \S+ with ')
LOCAL_SKIP_RE = Regex(r"""
^localhost\s\(localhost\s\[\[UNIX:\slocalhost\]\]\)\sby\s""", re.X)
AMAZON_RE = Regex(r"""
^\S+\.amazon\.com\sby
\s\S+\.amazon\.com\swith\sESMTP\s\(peer\scrosscheck:\s""", re.X)
NOVELL_RE = Regex(r'^[^\.]+ by \S+ with Novell_GroupWise')
NO_NAME_RE = Regex(r'^no\.name\.available by \S+ via smtpd \(for ')
SMTPSVC_RE = Regex(r"""
^mail\spickup\sservice\sby\s(\S+)\swith\sMicrosoft\sSMTPSVC$""", re.X)

# ========================================================

# ================ function regex ====================
ENVFROM_RE = Regex(r"""
.*?(?:return-path:?\s|envelope-(?:sender|from)[\s=])(\S+)\b""", re.X)
RDNS_RE = Regex(r'^(\S+) ')
RDNS_RE2 = Regex(r'^(\S+)\(')
HEADER_RE = Regex(r"""
    ^\(?\[?({IP_ADDRESS})\]?\)?\sby
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_IP_RE = Regex(r"""
    ^\[({IP_ADDRESS})\]
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_SMTP = Regex(r"""
    ^(\S+)\s\(\s?{IP_ADDRESS}\)\sby.*\({IP_ADDRESS}\)\swith.*(ESMTP|SMTP)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_SMTP1 = Regex(r"""
    ^(\S+)\s\(\s?\[{IP_ADDRESS}\]\)\sby.*(\S+)\swith.*(esmtp|smtp|ESMTP|SMTP)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_RE4 = Regex(r"""
    ^((\S+)\s\(\[{IP_ADDRESS})(?:[.:]\d+)?\]\).*?\sby\s(\S+)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_RE1 = Regex(r"""
    ^\(\[({IP_ADDRESS})\]\)\sby\s(\S+)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
RDNS_RE3 = Regex(r"""
    ^(\S+)\s\[({IP_ADDRESS})\]\sby\s(\S+)\s\[({IP_ADDRESS})]
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
BY_RE = Regex(r'.*? by (\S+) .*')
HELO_RE = Regex(r'.*?\((?:HELO|EHLO) (\S*)\)', re.I)
HELO_RE10 = Regex(r'.*\(.* (HELO|EHLO) (\S+)\)', re.I)
HELO_RE2 = Regex(r"""
    .*?\((\S+)\s\[{IP_ADDRESS}\]\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE3 = Regex(r'.*?helo=(\S+)\)', re.I)
HELO_RE4 = Regex(r"""
    ^\(?(\S+)\s\(?\s?\[{IP_ADDRESS}\]\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE5 = Regex(r"""
    ^(\S+)\s\(\s?{IP_ADDRESS}\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE6 = Regex(r"""
    ^(\S+)\s\(\[{IP_ADDRESS}\]\s\[{IP_ADDRESS}\]\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE7 = Regex(r"""
    ^(\S+)\s\((\S+)\s?\[{IP_ADDRESS}\].*\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE8 = Regex(r"""
    ^\(?(\S+)\s\[\s?{IP_ADDRESS}\]
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE9 = Regex(r"""
    ^\(?(\S+)\s\(?\s?\[{IP_ADDRESS}\] \s?(\S+)\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
IDENT_RE = Regex(r'.*ident=(\S+)\)')
IDENT_RE2 = Regex(r'.*\((\S+)@')
ID_RE = Regex(r'.*id (\S+)')
AUTH_RE = Regex(r"""
.*?\swith\s((?:ES|L|UTF8S|UTF8L)MTPS?A|ASMTP|HTTPU?)(?:\s|;|$)""", re.X | re.I)
AUTH_VC_RE = Regex(r'.*? \(version=([^ ]+) cipher=([^\)]+)\)')
AUTH_RE2 = Regex(r'.*? \(authenticated as (\S+)\)')
AUTH_RE3 = Regex(r"""
\)\s\(Authenticated\ssender:\s\S+\)\sby\s\S+\s\(Postfix\)\swith\s""", re.X)
AUTH_RE4 = Regex(r'.* by (mail\.gmx\.(net|com)) \([^\)]+\) with ((ESMTP|SMTP))')
AUTH_RE5 = Regex(r'.* \(account .* by .* \(CommuniGate Pro ('
                      r'HTTP|SMTP)')

ORIGINATING_IP_HEADER_RE = r"^X-ORIGINATING-IP: ({}).*"

# ========================================================


class ReceivedParser(object):
    def __init__(self, received_headers):
        self.received_headers = list()
        self.received = list()
        for header in received_headers:
            if header.startswith('from'):
                header = re.sub(r'\s+', ' ', header)  # removing '\n\t' chars
                header = header.replace('from ', '', 1)
                header = header.split(';')[0]
                self.received_headers.append(header)
            elif header.startswith("X-ORIGINATING-IP"):
                self.received_headers.append(header)

        self._parse_message()

    @staticmethod
    def check_for_skip(header):
        """STUFF TO IGNORE

        # Received headers which doesn't start with 'from'
        # Skip fetchmail handovers
        # BSMTP != a TCP/IP handover, ignore it
        # Content Technology

        :return: True or False
        """
        # Received: from root by server6.seinternal.com with
        # local-spamexperts-generated (Exim 4.80) id 1abp1W-0007Xm-KO for
        # spam@spamexperts.wiredtree.com
        if WITH_LOCAL_RE.search(header):
            return True
        # Received: from cabbage.jmason.org [127.0.0.1]
        # by localhost with IMAP (fetchmail-5.9.0)
        # for jm@localhost (single-drop); Thu, 13 Mar 2003 20:39:56 -0800 (PST)
        if 'fetchmail' in header and FETCHMAIL.search(header):
            return True
        # Received: from faerber.muc.de by slarti.muc.de with BSMTP (rsmtp-qm)
        # for asrg@ietf.org; 7 Mar 2003 21:10:38 -0000
        if ' with BSMTP' in header and BSMTP_RE.search(header):
            return True
        # Received: from scv3.apple.com (scv3.apple.com) by mailgate2.apple.com
        # (Content Technologies SMTPRS 4.2.1) with ESMTP id <T61095998e1118164e
        # 13f8@mailgate2.apple.com>; Mon, 17 Mar 2003 17:04:54 -0800
        if CONTENT_TECH_RE.search(header):
            return True
        # Received: from raptor.research.att.com (bala@localhost) by
        # raptor.research.att.com (SGI-8.9.3/8.8.7) with ESMTP id KAA14788
        # for <asrg@example.com>; Fri, 7 Mar 2003 10:37:56 -0500 (EST)
        # make this localhost-specific, so we know it's safe to ignore
        if LOCALHOST_RE.search(header):
            return True
        # from 127.0.0.1 (AVG SMTP 7.0.299 [265.6.8]);
        # Wed, 05 Jan 2005 15:06:48 -0800
        if AVG_SMTP_RE.search(header):
            return True
        # from qmail-scanner-general-admin@lists.sourceforge.net by alpha by
        # uid 7791 with qmail-scanner-1.14 (spamassassin: 2.41.
        # Clear:SA:0(-4.1/5.0):. Processed in 0.209512 secs)
        if QMAIL_RE.search(header):
            return True
        # from DSmith1204@aol.com by imo-m09.mx.aol.com (mail_out_v34.13.)
        # id 7.53.208064a0 (4394); Sat, 11 Jan 2003 23:24:31 -0500 (EST)
        if FROM_RE.search(header):
            return True
        # from Unknown/Local ([?.?.?.?]) by mailcity.com; Fri, 17
        # Jan 2003 15:23:29 -0000
        if UNKNOWN_RE.search(header):
            return True
        # from (AUTH: e40a9cea) by vqx.net with esmtp (courier-0.40)
        # for <asrg@ietf.org>; Mon, 03 Mar 2003 14:49:28 +0000
        if AUTH_SKIP_RE.search(header):
            return True
        # from localhost (localhost [[UNIX: localhost]])
        # by home.barryodonovan.com
        # (8.12.11/8.12.11/Submit) id iBADHRP6011034; Fri, 10 Dec 2004 13:17:27
        if LOCAL_SKIP_RE.search(header):
            return True
        # Internal Amazon traffic
        # from dc-mail-3102.iad3.amazon.com by mail-store-2001.amazon.com with
        # ESMTP (peer crosscheck: dc-mail-3102.iad3.amazon.com)
        if AMAZON_RE.search(header):
            return True
        # from GWGC6-MTA by gc6.jefferson.co.us with Novell_GroupWise;
        #  Tue, 30 Nov 2004 10:09:15 -0700
        if NOVELL_RE.search(header):
            return True
        # Received: from no.name.available by [165.224.216.88] via smtpd
        # (for lists.sourceforge.net [66.35.250.206]) with ESMTP
        # These are from an internal host protected by a Raptor firewall,
        # to hosts outside the firewall.  We can only ignore the handover
        # since we don't have enough info in those headers; however, from
        # googling, it appears that all samples are cases where the handover is
        # safely ignored.
        if NO_NAME_RE.search(header):
            return True
        # from mail pickup service by www.fmwebsite.com with Microsoft SMTPSVC;
        # Tue, 12 Jan 2016 17:51:31 -0500
        if SMTPSVC_RE.search(header):
            return True
        return False

    @staticmethod
    def get_envfrom(header):
        """Parsing envelope-from or envelope-sender from Received header

        :param header: The received header without the 'from ' at the begin
        :return: envfrom if is found if not it returns an empty string
        """
        envfrom = ""
        try:
            envfrom = ENVFROM_RE.match(header).groups()[0]
            envfrom = envfrom.strip("><[]")
        except (AttributeError, IndexError):
            pass
        if '=' in envfrom:
            envfrom = envfrom.rsplit("=", 1)[1]
        return envfrom

    @staticmethod
    def get_rdns(header):
        """Parsing rdns from Received header

        :param header: The received header without the 'from ' at the begin
        :return: rdns if is found if not it returns an empty string
        """
        rdns = ""
        try:
            if HELO_RE7.match(header):
                rdns = HELO_RE7.match(header).groups()[1]
                if rdns == "softdnserr":
                    rdns = ""
            elif HELO_RE5.match(header):
                if "(Scalix SMTP Relay" in header:
                    rdns = ""
                else:
                    rdns = HELO_RE5.match(header).groups()[0]
            elif HELO_RE4.match(header) and "Exim" not in header:
                if RDNS_SMTP.match(header):
                    rdns = RDNS_SMTP.match(header).groups()[0]
                else:
                    rdns = ""
            elif HEADER_RE.match(header):
                rdns = ""
            elif RDNS_RE2.match(header):
                rdns = RDNS_RE2.match(header).groups()[0]
            elif RDNS_SMTP1.match(header) and "Exim" not in header:
                rdns = ""
            else:
                if RDNS_RE1.match(header) or RDNS_RE3.match(header):
                    rdns = ""
                elif RDNS_RE4.match(header) and "Exim" not in header:
                    rdns = ""
                else:
                    rdns = RDNS_RE.match(header).groups()[0]
        except (AttributeError, IndexError):
            pass
        if "@" in rdns:
            rdns = ""
        if '(Postfix)' in header:
            if UNKNOWN_RE_RDNS.match(header):
                rdns = UNKNOWN_RE_RDNS.match(header).groups()[1]
        if RDNS_IP_RE.match(rdns):
            rdns = ""
        if 'unknown' in rdns or rdns == 'UnknownHost':
            rdns = ""
        rdns = rdns.strip("[]")
        return rdns

    @staticmethod
    def get_ip(header):
        """Parsing the relay ip address from Received header

        :param header: The received header without the 'from ' at the begin
        :return: ip address if is found if not it returns an empty string
        """
        ip = ""
        ips = IP_ADDRESS.findall(header.split(" by ")[0])
        no_ips = len(ips)
        private_ips = list()
        count = 0
        for item in ips:
            clean_ip = item.strip("[ ]();\n")
            clean_ip = clean_ip.lower().replace('ipv6:','')
            clean_ip = clean_ip.lower().replace('::ffff:','')
            if IP_PRIVATE.search(clean_ip):
                count += 1
                private_ips.append(clean_ip)
            if not IP_PRIVATE.search(clean_ip):
                ip = clean_ip
                # break
        if no_ips != 0 and count == no_ips:
            ip = private_ips[0]
        return ip

    @staticmethod
    def get_by(header):
        """Parsing the relay server from Received header

        :param header: The received header without the 'from ' at the begin
        :return: by if is found if not it returns an empty string
        """
        by = ""
        try:
            if RDNS_RE3.match(header):
                by = RDNS_RE3.match(header).groups()[3]
            else:
                by = BY_RE.match(header).groups()[0]
        except (AttributeError, IndexError):
            pass
        return by

    @staticmethod
    def get_helo(header):
        """Parsing the helo server from Received header

        :param header: The received header without the 'from ' at the begin
        :return: helo if is found if not it returns an empty string
        """
        helo = ""
        try:
            if HELO_RE2.match(header):
                helo = HELO_RE2.match(header).groups()[0]
                if helo == 'unknown':
                    helo = ""
            if HELO_RE7.match(header):
                helo = HELO_RE7.match(header).groups()[0]
            if HELO_RE.match(header):
                helo = HELO_RE.match(header).groups()[0]
            elif HELO_RE3.match(header):
                helo = HELO_RE3.match(header).groups()[0]
                helo = helo.strip("[ ]();\n")
            elif HELO_RE4.match(header):
                helo = HELO_RE4.match(header).groups()[0]
            elif HELO_RE5.match(header):
                helo = HELO_RE5.match(header).groups()[0]
            elif HELO_RE6.match(header):
                helo = HELO_RE6.match(header).groups()[0]
            elif HELO_RE8.match(header):
                helo = HELO_RE8.match(header).groups()[0]
            elif HELO_RE9.match(header):
                helo = HELO_RE9.match(header).groups()[0]
            elif RDNS_RE4.match(header):
                helo = RDNS_RE4.match(header).groups()[1]
            elif HELO_RE10.match(header):
                helo = HELO_RE10.match(header).groups()[1].strip("[]")
        except (AttributeError, IndexError):
            pass
        return helo

    @staticmethod
    def get_ident(header):
        """Parsing the ident from Received header

        :param header: The received header without the 'from ' at the begin
        :return: ident if is found if not it returns an empty string
        """
        ident = ""
        try:
            if IDENT_RE.match(header):
                ident = IDENT_RE.match(header).groups()[0]
            elif IDENT_RE2.match(header):
                ident = IDENT_RE2.match(header).groups()[0]
        except (AttributeError, IndexError):
            pass
        return ident

    @staticmethod
    def get_id(header):
        """Parsing the id of the relay from Received header

        :param header: The received header without the 'from ' at the begin
        :return: id if is found if not it returns an empty string
        """
        id = ""
        try:
            id = ID_RE.match(header).groups()[0]
            id = id.strip("<>")
        except (AttributeError, IndexError):
            pass
        return id

    @staticmethod
    def get_auth(header):
        """Parsing the authentication from Received header

        :param header: The received header without the 'from ' at the begin
        :return: auth if is found if not it returns an empty string
        """
        auth = ""
        if ' by ' in header and AUTH_RE.match(header):
            try:
                auth = AUTH_RE.match(header).groups()[0]
            except IndexError:
                pass
        elif AUTH_RE3.search(header):
            auth = 'Postfix'
        elif ' by mx.google.com with ESMTPS id ' in header:
            try:
                version, cipher = AUTH_VC_RE.match(header).groups()
                auth = "GMail - transport={version} " \
                       "cipher={cipher}".format(version=version, cipher=cipher)
            except (AttributeError, IndexError):
                pass
        elif 'SquirrelMail authenticated ' in header:
            auth = "SquirrelMail"
        elif 'authenticated' in header and AUTH_RE2.search(header):
            auth = "CriticalPath"
        elif 'authenticated' in header:
            auth = "Sendmail"
        elif AUTH_RE4.search(header):
            re_auth = AUTH_RE4.search(header).groups()
            auth = "GMX (%s / %s)" % (re_auth[3], re_auth[0])
        elif AUTH_RE5.search(header):
            auth = "Communigate"
        return auth

    def _parse_message(self):
        for header in self.received_headers:
            if not self.check_for_skip(header):
                rdns = self.get_rdns(header)
                ip = self.get_ip(header)
                by = self.get_by(header)
                helo = self.get_helo(header)
                ident = self.get_ident(header)
                id = self.get_id(header)
                envfrom = self.get_envfrom(header)
                auth = self.get_auth(header)
                if header.startswith("X-ORIGINATING-IP"):
                    self.received.append({
                        "rdns": "", "ip": ip, "by": "",
                        "helo": "", "ident": "", "id": "", "envfrom": "",
                        "auth": ""})
                else:
                    self.received.append({
                        "rdns": rdns, "ip": ip, "by": by, "helo": helo,
                        "ident": ident, "id": id, "envfrom": envfrom, "auth":
                        auth})
