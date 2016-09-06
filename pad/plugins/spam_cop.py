"""SpamCop plugin"""

from __future__ import absolute_import

import os
import re
import pwd
import sys
import time
import random
import smtplib
import email.utils
from email.mime import multipart, text, base

import pad.plugins.base


class SpamCopPlugin(pad.plugins.base.BasePlugin):
    options = {
        "dont_report_to_spamcop": ("bool", False),
        "spamcop_from_address": ("str", ""),
        "spamcop_to_address": ("str", "spamassassin-submit@spam.spamcop.net"),
        "spamcop_max_report_size": ("int", 50)
    }

    def _spamcop_report(self, msg):
        """
        Check if message should be reported as spam or not.
        :param msg:
        """
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
        time_now = email.utils.formatdate(localtime=True)
        now_date = time.mktime(email.utils.parsedate(time_now))
        return now_date

    def get_mail_date(self, msg):
        """
        Get mail date in timestamp format.
        :param msg:
        """
        received_header = msg.get_decoded_header("Received")[0]
        time_mail = received_header.split(";")[1]
        mail_date = time.mktime(email.utils.parsedate(time_mail))
        return mail_date

    def send_mail_method(self, sender, receiver, message):
        """
        Send mail using smtplib module.
        :param sender:
        :param receiver:
        :param message:
        """
        try:
            regex = re.search(".*@.*", receiver)
            domain = regex.group().split('@')[1]
            # return value like '0 mail.domain.com.'
            mx_domain = self.ctxt.dns.query(domain, 'MX')[0].to_text()
            mx_domain = mx_domain.split()[1][:-1]

            smtp_obj = smtplib.SMTP()
            smtp_obj.connect(mx_domain, 587)
            smtp_obj.helo(mx_domain.split('.')[1])
            smtp_obj.sendmail(sender, receiver, message)
            smtp_obj.quit()
        except BaseException:
            self.ctxt.log.warning("SpamCop report failed.")
            return False
        return True

    def plugin_report(self, msg):
        """
        Report spam to "spamcop_to_address". If the message is larger than
        "spamcop_max_report_size", then it will be truncated in report
        message.
        :param msg:
        """
        if not re.match(".+@.+", self["spamcop_to_address"]):
            self.ctxt.log.warning("Missing required value")
            return False
        mail_date = self.get_mail_date(msg)
        now_date = self.get_now_date()
        if not mail_date or mail_date < now_date - 2*86400:
            self.ctxt.log.debug("Message older than 2 days, not reporting")
            return False

        original = msg.raw_msg
        description = "spam report via %s" % sys.version[:5]
        trusted = str(msg.trusted_relays).strip('[]')
        untrusted = str(msg.untrusted_relays).strip('[]')
        host = os.uname()[1] or "unknown"
        user = pwd.getpwuid(os.getuid())[0] or "unknown"

        message = email.mime.multipart.MIMEMultipart()
        message["From"] = self["spamcop_from_address"] or "%s@%s" % (user, host)
        message["To"] = self["spamcop_to_address"]
        message["Subject"] = "report spam"
        message["Date"] = email.utils.formatdate(localtime=True)
        message["Message-Id"] = "<%X.%X@%s>" % (int(now_date),
                                                random.randint(1, 2 ** 32),
                                                host)
        if len(original) > self["spamcop_max_report_size"]*1024:
            x = self["spamcop_max_report_size"]*1024
            original = original[:x] + "\n[truncated by SpamPad]\n"

        message.attach(email.mime.text.MIMEText(
            'This is a multi-part message in MIME format.'))
        original_attachment = email.mime.base.MIMEBase(
            "message", "rfc822; x-spam-type=report")
        original_attachment.add_header("Content-Disposition", "attachment")
        original_attachment.add_header("Content-Description", description)
        original_attachment.add_header("X-Spam-Relays-Trusted", trusted)
        original_attachment.add_header("X-Spam-Relays-Untrusted", untrusted)
        original_attachment.set_payload(original)
        message.attach(original_attachment)

        self.ctxt.log.debug("Sending email to...%s", self["spamcop_to_address"])
        return self.send_mail_method(self["spamcop_from_address"],
                                     self["spamcop_to_address"],
                                     message.as_string())


