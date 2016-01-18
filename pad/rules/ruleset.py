"""A set of rules."""

from builtins import dict
from builtins import object

from future import standard_library
standard_library.install_hooks()

import socket
import email.utils
import collections
import email.message
import email.mime.text
import email.mime.base
import email.mime.multipart

import pad
import pad.errors


class RuleSet(object):
    """A set of rules used to match against a message."""
    header_start = "X-Spam-"

    def __init__(self, ctxt):
        """Create a new empty RuleSet if paranoid is set to False any
        invalid rule is ignored.
        """
        self.ctxt = ctxt
        self.report = []
        # Store modification that need to be done to the message in
        # the following format:
        # (True/False, header_name, value)
        # Where the first argument is True if the header should be
        # removed instead of added.
        self.header_mod = {
            "spam": [],
            "ham": [],
            "all": [],
        }
        self.checked = collections.OrderedDict()
        self.not_checked = dict()
        # XXX Hardcoded at the moment, should be loaded from configuration.
        self.autolearn = False
        self.use_bayes = True
        self.use_network = True
        self.required_score = 5

    def _interpolate(self, text, msg):
        # XXX Some plugins might define custom tags here.
        # XXX We need to check them as well.
        spam = msg.score >= self.required_score
        # XXX We can probably do this smarter than just
        # XXX replacing.
        text = text.replace("_HOSTNAME_", socket.gethostname())
        text = text.replace("_REPORT_", self.get_matched_report(msg))
        text = text.replace("_YESNOCAPS_", "YES" if spam else "FALSE")
        text = text.replace("_YESNO_", "Yes" if spam else "False")
        text = text.replace("_SCORE_", str(msg.score))
        text = text.replace("_REQD_", str(self.required_score))
        text = text.replace(
            "_TESTS_", ",".join(
                name for name, result in msg.rules_checked.items() if result
            )
        )
        text = text.replace("_SUBVERSION_", pad.__release_date__)
        text = text.replace("_VERSION_", pad.__version__)
        text = text.replace("_SUMMARY_", self.get_summary_report(msg))
        return text

    def add_rule(self, rule):
        """Add a rule to the ruleset, execute any pre and post processing
        that's defined for the rule.
        """
        rule.preprocess(self)
        if rule.should_check():
            self.checked[rule.name] = rule
        else:
            self.not_checked[rule.name] = rule
        rule.postprocess(self)

    def add_report(self, text):
        """Add some text to the report used when the message
        is classified as Spam.
        """
        self.report.append(text)

    def get_report(self, msg):
        """Get the Spam report for this message

        :return: A string representing the report for this
        Spam message.
        """
        return self._interpolate("\n".join(self.report), msg) + "\n"

    def get_matched_report(self, msg):
        """Get a report of rules that matched this message."""
        report = "\r\n".join(str(self.get_rule(name))
                             for name, result in msg.rules_checked.items()
                             if result)
        return "\r\n%s" % report

    def get_summary_report(self, msg):
        """Get summary report."""
        summary = []
        for name, result in msg.rules_checked.items():
            if not result:
                continue
            rule = self.get_rule(name)
            if rule.score == int(rule.score):
                score = str(int(rule.score)).rjust(4)
            else:
                score = ("%0.1f" % rule.score).rjust(4)
            summary.append(
                "%s %s %s" %
                (score, rule.name.ljust(22), rule.description)
            )
        return "\r\n".join(summary)

    def clear_report_template(self):
        """Reset the report."""
        self.report = []

    def add_header_rule(self, value, remove=False):
        """Add rule to add a header for the corresponding.

        The value must be in the following format:

         [all|spam|ham] [header_name] [header_value]

        If remove is set to True, then the header is removed
        instead of added.
        """
        self.ctxt.log.debug("Adding header rule: %s (%s)", value, remove)
        if not remove:
            msg_status, header_name, header_value = value.split(None, 2)
            header_value = header_value.strip("'\"")
        else:
            msg_status, header_name = value.split(None, 1)
            header_value = None

        msg_status = msg_status.lower()
        if msg_status not in self.header_mod:
            raise pad.errors.InvalidRule("add_header", value)

        header_name = self.header_start + header_name

        self.header_mod[msg_status].append((remove, header_name, header_value))

    def clear_headers(self):
        """Remove all rules that modify headers to the message."""
        self.header_mod = {
            "spam": [],
            "ham": [],
            "all": [],
        }

    def get_adjusted_message(self, msg, header_only=False):
        """Get message adjusted by the rules."""
        spam = msg.score >= self.required_score
        if not spam or header_only:
            newmsg = email.message_from_string(msg.raw_msg)
        else:
            newmsg = self._get_bounce_message(msg)
        newmsg["Received"] = (
            "from localhost by %s with SpamPad (version %s); %s" %
            (socket.gethostname(), pad.__version__,
             email.utils.formatdate(localtime=True))
        )
        self._adjust_headers(msg, newmsg, self.header_mod["all"])
        if spam:
            self._adjust_headers(msg, newmsg, self.header_mod["spam"])
        else:
            self._adjust_headers(msg, newmsg, self.header_mod["ham"])

        return newmsg.as_string()

    def _adjust_headers(self, msg, newmsg, rules):
        """Adjust the headers of this message according to
        this list of rules. The rules are tuples in the following
        format:

        True/False, header_name, header_value

        If the first argument is True then remove the header
        instead of adding it.
        """
        for remove, name, value in rules:
            if remove:
                del newmsg[name]
            else:
                newmsg.add_header(name, self._interpolate(value, msg))

    def _get_bounce_message(self, msg):
        """Create a bounce message from the original."""
        newmsg = email.mime.multipart.MIMEMultipart("mixed")
        # Switched around
        if "To" in msg.msg:
            newmsg["From"] = msg.msg['To']
        if "From" in msg.msg:
            newmsg["To"] = msg.msg['From']
        if "Subject" in msg.msg:
            newmsg["Subject"] = msg.msg["Subject"]
        msg_date = msg.msg["Date"] or email.utils.formatdate(localtime=True)
        newmsg["Date"] = msg_date
        newmsg.preamble = "This is a multi-part message in MIME format."
        newmsg.epilogue = ""

        newmsg.attach(email.mime.text.MIMEText(self.get_report(msg)))
        original_attachment = email.mime.base.MIMEBase("message", "rfc822",
                                                   x_spam_type="original")
        original_attachment.add_header("Content-Disposition", "inline")
        original_attachment.add_header("Content-Description",
                                       "original message before SpamPAD")
        original_attachment.set_payload(msg.raw_msg)
        newmsg.attach(original_attachment)
        return newmsg

    def get_rule(self, name, checked_only=False):
        """Gets the rule with the given name. If checked_only is set to True
        then only returns the rule if it is going to be checked.

        Raises KeyError if no rule is found.
        """
        try:
            return self.checked[name]
        except KeyError:
            if checked_only:
                raise
        return self.not_checked[name]

    def post_parsing(self):
        """Run all post processing hooks."""
        for rule_list in (self.checked, self.not_checked):
            for name, rule in list(rule_list.items()):
                try:
                    rule.postparsing(self)
                except pad.errors.InvalidRule as e:
                    self.ctxt.err(e)
                    if self.ctxt.paranoid:
                        raise
                    del rule_list[name]

    def match(self, msg):
        """Match the message against all the rules in this ruleset."""
        for name, rule in self.checked.items():
            result = rule.match(msg)
            self.ctxt.log.debug("Checked rule %s: %s", rule, result)
            msg.rules_checked[name] = result
            if result:
                msg.score += rule.score
        self.ctxt.hook_check_end(msg)
