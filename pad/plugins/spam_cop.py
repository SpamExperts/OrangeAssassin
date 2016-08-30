"""SpamCop plugin"""

from __future__ import absolute_import
from collections import defaultdict

import email.utils
import smtplib
import random
import datetime
import time
import sys
import platform
import dns.resolver
import re

import pad.plugins.base


class SpamCopPlugin(pad.plugins.base.BasePlugin):
    options = {
        "dont_report_to_spamcop": ("bool", False),
        "spamcop_from_address": ("str", ""),
        "spamcop_to_address": ("str", "spamassassin-submit@spam.spamcop.net"),
        "spamcop_max_report_size": ("int", 50)
    }

    def _spamcop_report(self, msg):
        if not self["dont_report_to_spamcop"]:
            if self.plugin_report(msg):
                self.ctxt.log.debug("Spam reported to SpamCop")
                return True
            else:
                self.ctxt.log.debug("Could not report spam to SpamCop")
        return False

    def get_now_date(self):
        """
        Get actual date in timestamp format.
        """
        time_now = datetime.datetime.now()
        now_date = time.mktime(time_now.timetuple())
        return now_date

    def get_mail_date(self, msg):
        """
        Get mail date in timestamp format.
        :param msg:
        """
        time_mail = msg.get_raw_mime_header('Date')[0]
        mail_date = time.mktime(email.utils.parsedate(time_mail))
        return mail_date

    def send_mail_method(self, sender, receiver, message):
        """
        Send mail using smtplib module.
        :param sender:
        :param receiver:
        :param message:
        """
        regex = re.search(".*@.*", receiver)
        domain = regex.group().split('@')[1]
        # return value like '0 mail.domain.com.'
        mx_domain = dns.resolver.query(domain, 'MX')[0].to_text()
        mx_domain = mx_domain.split()[1][:-1]
        try:
            smtp_obj = smtplib.SMTP()
            smtp_obj.connect(mx_domain, 25)
            smtp_obj.helo(mx_domain.split('.')[1])
            smtp_obj.sendmail(sender, receiver, message)
            smtp_obj.quit()
        except BaseException:
            self.ctxt.log.warning("SpamCop report failed.")
            return False
        return True

    def plugin_report(self, msg):
        mail_date = self.get_mail_date(msg)
        now_date = self.get_now_date()
        if not mail_date or mail_date < now_date - 2*86400:
            self.ctxt.log.debug("SpamCop message older than 2 days, not reporting")
            return False

        boundary = "----------=_%X.%X" % (int(now_date),
                                          random.randint(1, 2 ** 23))
        description = "spam report via %s" % sys.version[:5]
        trusted = msg.trusted_relays
        untrusted = msg.untrusted_relays
        host = platform.node()

        head = defaultdict()
        head["From"] = self["spamcop_from_address"]
        head["Subject"] = "report spam"
        head["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z")
        head["Message-Id"] = "<%X.%X@%s>" % (int(now_date),
                                             random.randint(1, 2 ** 23),
                                             host)
        head["MIME-Version"] = "1.0"
        head["Content-Type"] = "multipart/mixed; boundary = %s" % boundary

        original = msg.raw_msg
        if len(original) > self["spamcop_max_report_size"]*1024:
            x = self["spamcop_max_report_size"]*1024
            original = original[:x] + "\n[truncated by SpamPad]\n"

        self.ctxt.log.debug("Sending email to... %s",
                            self["spamcop_to_address"])
        message = ""
        head["To"] = self["spamcop_to_address"]
        for header in head:
            message += "%s: %s \n" % (header, head[header])
        message += """
\nThis is a multi-part message in MIME format.

--%s
Content-Type: message/rfc822; x-spam-type=report
Content-Description: %s
Content-Disposition: attachment
Content-Transfer-Encoding: 8bit
X-Spam-Relays-Trusted: %s
X-Spam-Relays-Untrusted: %s

%s
--%s--
        """ % (boundary, description, trusted, untrusted, original,
                   boundary)
        return self.send_mail_method(self["spamcop_from_address"],
                              self["spamcop_to_address"], message)

        # 206
