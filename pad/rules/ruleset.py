"""A set of rules."""

from builtins import dict
from builtins import object
from builtins import str

import re
import socket
import email.utils
import collections
import email.message
import email.mime.text
import email.mime.base
import email.mime.multipart
from operator import itemgetter

import pad
import pad.errors

_TAG_RE = re.compile(r"(_([A-Z_]*?)_)")

_DNS_OPTIONS_RE = re.compile(r"""
[
(?P<edns>(no)?edns0?=\d*)?,?
(?P<rotate>(no)?rotate)?,?
(?P<dns0x20>(no)?dns0x20)?,?
]
""", re.I | re.X | re.M)


class RuleSet(object):
    """A set of rules used to match against a message."""
    header_start = "X-Spam-"

    def __init__(self, ctxt):
        """Create a new empty RuleSet if paranoid is set to False any
        invalid rule is ignored.
        """
        self.ctxt = ctxt
        self.conf = ctxt.conf
        self.tags = set()
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

    def _interpolate(self, text, msg):
        if msg.interpolate_data:
            return text % msg.interpolate_data

        spam = msg.score >= self.conf["required_score"]
        data = msg.interpolate_data
        # Initialize all tags with a empty value
        for tag in self.tags:
            data[tag] = "@@%s@@" % tag

        data["CONTACTADDRESS"] = self.conf["report_contact"]
        data["HOSTNAME"] = socket.gethostname()
        data["YESNOCAPS"] = "YES" if spam else "NO"
        data["YESNO"] = "Yes" if spam else "No"
        data["SCORE"] = "%0.1f" % msg.score
        data["REQD"] = "%0.1f" % self.conf["required_score"]
        data["SUBVERSION"] = pad.__release_date__
        data["VERSION"] = pad.__version__

        # Some of these tags are more expensive to create,
        # so only add them if they are required.
        if "REPORT" in self.tags:
            data["REPORT"] = self.get_matched_report(msg)
        if "TESTS" in self.tags:
            matched_rules = [name for name, result in msg.rules_checked.items()
                             if result]
            if not matched_rules:
                data["TESTS"] = "none"
            else:
                data["TESTS"] = ",".join(matched_rules)

        if "TESTSSCORES" in self.tags:
            matched_rules = ["%s=%s" % (name, int(result))
                             for name, result in msg.rules_checked.items()
                             if result]
            if not matched_rules:
                data["TESTSSCORES"] = "none"
            else:
                data["TESTSSCORES"] = ",".join(matched_rules)

        if "SUMMARY" in self.tags:
            data["SUMMARY"] = self.get_summary_report(msg)
        if "PREVIEW" in self.tags:
            preview = " ".join(msg.raw_text.split("\n", 3)[:3])[:200] + "[...]"
            data["PREVIEW"] = preview

        # Plugin can store custom tags in the the message
        # after they perform check. Add them to the data
        # as well.
        data.update(msg.plugin_tags)
        return text % msg.interpolate_data

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

    def _convert_tags(self, text):
        """Replace _TAGS_ with placeholders. %(TAG)s"""
        text = text.strip("'\"")
        for tag in _TAG_RE.findall(text):
            self.tags.add(tag[1])
        return _TAG_RE.sub(r"%(\2)s", text)

    def get_report(self, msg):
        """Get the Spam report for this message

        :return: A string representing the report for this
          Spam message.

        """
        if not self.conf["report"]:
            return "\n(no report template found)\n"
        return self._interpolate(self.conf["report"], msg) + "\n"

    def _add_header_rule(self, value, remove=False):
        """Add rule to add a header for the corresponding.

        The value must be in the following format:

         [all|spam|ham] [header_name] [header_value]

        If remove is set to True, then the header is removed
        instead of added.
        """
        self.ctxt.log.debug("Adding header rule: %s (%s)", value, remove)
        if not remove:
            msg_status, header_name, header_value = value.split(None, 2)
            header_value = self._convert_tags(header_value)
        else:
            msg_status, header_name = value.split(None, 1)
            header_value = None

        msg_status = msg_status.lower()
        if msg_status not in self.header_mod:
            raise pad.errors.InvalidRule("add_header", value)

        header_name = self.header_start + header_name

        self.header_mod[msg_status].append((remove, header_name, header_value))

    def get_adjusted_message(self, msg, header_only=False):
        """Get message adjusted by the rules."""
        spam = msg.score >= self.conf["required_score"]
        if not spam or header_only or self.conf["report_safe"] == 0:
            newmsg = email.message_from_string(msg.raw_msg)
        else:
            newmsg = self._get_bounce_message(msg)
        if self.conf["report_safe"] == 0:
            newmsg.add_header("X-Spam-Report",
                              self.get_matched_report(msg))
        self._adjust_headers(msg, newmsg, self.header_mod["all"])
        if spam:
            self._adjust_headers(msg, newmsg, self.header_mod["spam"])
        else:
            self._adjust_headers(msg, newmsg, self.header_mod["ham"])
        if header_only:
            return newmsg.as_string().split("\n\n", 1)[0] + "\n\n"
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
        newmsg["Received"] = (
            "from localhost by %s with SpamPad (version %s); %s" %
            (socket.gethostname(), pad.__version__,
             email.utils.formatdate(localtime=True))
        )
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

        attach_type = ("message", "rfc882")
        if self.conf["report_safe"] == 2:
            attach_type = ("text", "plain")

        newmsg.attach(email.mime.text.MIMEText(self.get_report(msg)))
        original_attachment = email.mime.base.MIMEBase(
                *attach_type, x_spam_type="original"
        )
        original_attachment.add_header("Content-Disposition", "inline")
        original_attachment.add_header("Content-Description",
                                       "original message before SpamPAD")
        original_attachment.set_payload(msg.raw_msg)
        newmsg.attach(original_attachment)
        return newmsg

    def get_matched_report(self, msg):
        """Get a report of rules that matched this message."""
        report = []
        for name, result in msg.rules_checked.items():
            if not result:
                continue
            rule = self.get_rule(name)
            report.append(
                "* %s %s %s%s" %
                (rule.score, rule.name, rule._rule_type, msg.rules_descriptions[name])
            )

        report = "\r\n".join(report)
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
        self.checked = collections.OrderedDict(
            sorted(self.checked.items(), key=itemgetter(1), reverse=False))
        for rule_list in (self.checked, self.not_checked):
            for name, rule in list(rule_list.items()):
                try:
                    rule.postparsing(self)
                except pad.errors.InvalidRule as e:
                    self.ctxt.err(e)
                    if self.ctxt.paranoid:
                        raise
                    del rule_list[name]
        # Convert some of the parsed information
        self.conf["report"] = "\n".join(
            self._convert_tags(value)
            for value in self.conf["report"]
        )
        for value in self.conf["add_header"]:
            self._add_header_rule(value, False)
        del self.conf["add_header"]
        for value in self.conf["remove_header"]:
            self._add_header_rule(value, True)
        del self.conf["remove_header"]

        for value in self.conf['dns_query_restriction']:
            try:
                option, qname = value.split(" ", 1)
            except ValueError:
                self.ctxt.log.info(
                    "Invalid value for dns_query_restriction: %s", value)

            if option not in ("allow", "deny"):
                self.ctxt.log.info(
                    "Invalid value for dns_query_restriction %s", value)
                continue
            self.ctxt.dns.query_restrictions[qname] = option == "deny"
        dns_options = {"edns": "edns=4096",
                       "rotate": "norotate",
                       "dns0x20": "nodns0x20"}
        dns_options_match = _DNS_OPTIONS_RE.match(self.conf['dns_options'])
        if dns_options_match:
            dns_options.update(dns_options_match.groupdict())
        self.ctxt.dns.rotate = dns_options['rotate']
        self.ctxt.dns.edns = dns_options['edns']

    def match(self, msg):
        """Match the message against all the rules in this ruleset."""
        try:
            for name, rule in self.checked.items():
                result = rule.match(msg)
                if isinstance(result, str):
                    msg.rules_descriptions[name] = result
                    result = True
                elif result:
                    msg.rules_descriptions[name] = rule.description
                self.ctxt.log.debug("Checked rule %s: %s", rule, result)
                msg.rules_checked[name] = result
                if result:
                    msg.score += rule.score
        except pad.errors.StopProcessing as e:
            self.ctxt.log.debug("Stop processing the messages as "
                                "requested: %s", e)
        self.ctxt.hook_check_end(self, msg)
