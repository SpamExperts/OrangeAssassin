"""A set of rules."""

from builtins import dict
from builtins import object

from future import standard_library
standard_library.install_hooks()
import socket
import collections

import pad.errors


class RuleSet(object):
    """A set of rules used to match against a message."""
    def __init__(self, ctxt):
        """Create a new empty RuleSet if paranoid is set to False any
        invalid rule is ignored.
        """
        self.ctxt = ctxt
        self.report = []
        self.checked = collections.OrderedDict()
        self.not_checked = dict()
        # XXX Hardcoded at the moment, should be loaded from configuration.
        self.use_bayes = True
        self.use_network = True
        self.required_score = 5

    def _interpolate(self, text, msg):
        # XXX Some plugins might define custom tags here.
        # XXX We need to check them as well.
        text = text.replace("_HOSTNAME_", socket.gethostname())
        text = text.replace("_REPORT_", self.get_matched_report(msg))
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
        report = "\n".join(str(self.get_rule(name))
                           for name, result in msg.rules_checked.items()
                           if result)
        return "\n%s" % report

    def clear_report_template(self):
        """Reset the report."""
        self.report = []

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
