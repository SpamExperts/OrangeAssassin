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

LOCALHOST = re.compile(r"""
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

IP_PRIVATE = re.compile(r"""
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

IP_ADDRESS = re.compile(r"""
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

IPFRE = re.compile(r"[\[ \(]{1}[a-fA-F\d\.\:]{7,}?[\] \n;\)]{1}")

FETCHMAIL = re.compile(r"""
.*?\s(\S+)\s(?:\[({IP_ADDRESS})\]\s)?
by\s(\S+)\swith
\s\S+\s\(fetchmail""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)

LOCALHOST_RE = re.compile(r"""
^\S+\s\([^\s\@]+\@{LOCALHOST}\)\sby\s\S+\s\(
""".format(LOCALHOST=LOCALHOST.pattern), re.X | re.I)

UNKNOWN_RE_RDNS = re.compile(r"""
^(\S+)\s\((unknown)\s\[({IP_ADDRESS})\]\)\s\(
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)

# ================ check_for_skip regex ==================
WITH_LOCAL_RE = re.compile(r'\bwith local(?:-\S+)? ', re.I)
BSMTP_RE = re.compile(r'^\S+ by \S+ with BSMTP', re.I)
CONTENT_TECH_RE = re.compile(r"""
^\S+\s\(\S+\)\sby\s\S+\s\(Content\sTechnologies\s""", re.X | re.I)
AVG_SMTP_RE = re.compile(r'^127\.0\.0\.1 \(AVG SMTP \S+ \[\S+\]\)')
QMAIL_RE = re.compile(r'^\S+\@\S+ by \S+ by uid \S+ ')
FROM_RE = re.compile(r'^\S+\@\S+ by \S+ ')
UNKNOWN_RE = re.compile(r'^Unknown\/Local \(')
AUTH_SKIP_RE = re.compile(r'^\(AUTH: \S+\) by \S+ with ')
LOCAL_SKIP_RE = re.compile(r"""
^localhost\s\(localhost\s\[\[UNIX:\slocalhost\]\]\)\sby\s""", re.X)
AMAZON_RE = re.compile(r"""
^\S+\.amazon\.com\sby
\s\S+\.amazon\.com\swith\sESMTP\s\(peer\scrosscheck:\s""", re.X)
NOVELL_RE = re.compile(r'^[^\.]+ by \S+ with Novell_GroupWise')
NO_NAME_RE = re.compile(r'^no\.name\.available by \S+ via smtpd \(for ')
SMTPSVC_RE = re.compile(r"""
^mail\spickup\sservice\sby\s(\S+)\swith\sMicrosoft\sSMTPSVC$""", re.X)

# ========================================================

# ================ function regex ====================
ENVFROM_RE = re.compile(r"""
.*?(?:return-path:?\s|envelope-(?:sender|from)[\s=])(\S+)\b""", re.X)
RDNS_RE = re.compile(r'^(\S+) ')
RDNS_IP_RE = re.compile(r"""
    ^\[({IP_ADDRESS})\]
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
BY_RE = re.compile(r'.*? by (\S+) .*')
HELO_RE = re.compile(r'.*?\((?:HELO|EHLO) (\S*)\)', re.I)
HELO_RE2 = re.compile(r"""
    .*?\((\S+)\s\[{IP_ADDRESS}\]
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE3 = re.compile(r'.*?helo=(\S+)\)', re.I)
HELO_RE4 = re.compile(r"""
    ^(\S+)\s\(\[{IP_ADDRESS}\]\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
HELO_RE5 = re.compile(r"""
    ^(\S+)\s\({IP_ADDRESS}\)
""".format(IP_ADDRESS=IP_ADDRESS.pattern), re.X)
IDENT_RE = re.compile(r'.*ident=(\S+)\)')
ID_RE = re.compile(r'.*id (\S+)')
AUTH_RE = re.compile(r"""
.*?\swith\s((?:ES|L|UTF8S|UTF8L)MTPS?A|ASMTP|HTTPU?)(?:\s|;|$)""", re.X | re.I)
AUTH_VC_RE = re.compile(r'.*? \(version=([^ ]+) cipher=([^\)]+)\)')
AUTH_RE2 = re.compile(r'.*? \(authenticated as (\S+)\)')
AUTH_RE3 = re.compile(r"""
\)\s\(Authenticated\ssender:\s\S+\)\sby\s\S+\s\(Postfix\)\swith\s""", re.X)

ORIGINATING_IP_HEADER_RE = r"^({}).*"

# ========================================================


class ReceivedParser(object):
    def __init__(self, received_headers, originating_header_names=None):
        self.originating_header_names = tuple()
        if originating_header_names:
            self.originating_header_names = tuple(originating_header_names)
        self.received_headers = list()
        self.received = list()
        for header in received_headers:
            if (self.originating_header_names and
                    header.startswith(self.originating_header_names)):
                self.received_headers.append(header)
            elif header.startswith('from'):
                header = re.sub(r'\s+', ' ', header)  # removing '\n\t' chars
                header = header.replace('from ', '', 1)
                header = header.split(';')[0]
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
            rdns = RDNS_RE.match(header).groups()[0]
        except (AttributeError, IndexError):
            pass
        if '(Postfix)' in header:
            if UNKNOWN_RE_RDNS.match(header):
                rdns = UNKNOWN_RE_RDNS.match(header).groups()[1]
        if RDNS_IP_RE.match(rdns):
            rdns = ""
        if rdns == 'unknown' or rdns == 'UnknownHost':
            rdns = ""
        return rdns

    @staticmethod
    def get_ip(header):
        """Parsing the relay ip address from Received header

        :param header: The received header without the 'from ' at the begin
        :return: ip address if is found if not it returns an empty string
        """
        ip = ""
        ips = IP_ADDRESS.findall(header)
        no_ips = len(ips)
        count = 0
        private_ips = list()
        for item in ips:
            clean_ip = item.strip("[ ]();\n")
            clean_ip = clean_ip.lower().replace('ipv6:','')
            clean_ip = clean_ip.lower().replace('::ffff:','')
            if IP_PRIVATE.search(clean_ip):
                count += 1
                private_ips.append(clean_ip)
            if not IP_PRIVATE.search(clean_ip):
                ip = clean_ip
                break
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
            if HELO_RE.match(header):
                helo = HELO_RE.match(header).groups()[0]
            elif HELO_RE3.match(header):
                helo = HELO_RE3.match(header).groups()[0]
                helo = helo.strip("[ ]();\n")
            elif HELO_RE4.match(header):
                helo = HELO_RE4.match(header).groups()[0]
            elif HELO_RE5.match(header):
                helo = HELO_RE5.match(header).groups()[0]
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
            ident = IDENT_RE.match(header).groups()[0]
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
                if (self.originating_header_names and
                        header.startswith(self.originating_header_names)):
                    self.received.append({
                        "rdns": "", "ip": ip, "by": "",
                        "helo": "", "ident": "", "id": "", "envfrom": "",
                        "auth": ""})
                else:
                    self.received.append({
                        "rdns": rdns, "ip": ip, "by": by, "helo": helo,
                        "ident": ident, "id": id, "envfrom": envfrom, "auth":
                        auth})
