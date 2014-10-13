"""A set of rules."""

from builtins import object

from future import standard_library
standard_library.install_hooks()

import collections


class RuleSet(object):
    """A set of rules used to match against a message."""
    def __init__(self):
        self.checked = collections.OrderedDict()
        self.not_checked = {}
        # XXX Hardcoded at the moment, should be loaded from configuration.
        self.use_bayes = True
        self.use_network = True

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

    def match(self, msg):
        """Match the message against all the rules in this ruleset."""
        for name, rule in self.checked.items():
            msg.rules_checked[name] = rule.match(msg)
