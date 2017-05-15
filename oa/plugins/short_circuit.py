"""This plugin implements simple, test-based shortcircuiting.
Short-circuiting a test will force all other pending rules to be
skipped, if that test is hit.
"""

import functools

import oa.errors
import oa.plugins.base


class ShortCircuitRule(object):
    """Encapsulates the rule into a short circuited rule."""

    def __init__(self, rule, match_func, stype, spam_score, ham_score):
        self.rule = rule
        # This needs to be encapsulated here otherwise we
        # create a infinite recursive function.
        self.match_func = match_func
        self.stype = stype
        self.spam_score = spam_score
        self.ham_score = ham_score

    def __call__(self, msg):
        """Wraps the original method to trigger an
        exception that will stop processing if it
        returns True.
        """
        result = self.match_func(msg)
        if not result:
            return result

        # Add tags to the message
        msg.plugin_tags["SCRULE"] = self.rule.name
        msg.plugin_tags["SCTYPE"] = self.stype
        msg.plugin_tags["SC"] = "%s (%s)" % (self.rule.name, self.stype)
        # Add the score of the current rule (this will
        # be skipped in the ruleset otherwise
        msg.rules_checked[self.rule.name] = result
        msg.score += self.rule.score

        if self.stype == "spam":
            msg.score += self.spam_score
        elif self.stype == "ham":
            msg.score += self.ham_score

        raise oa.errors.StopProcessing("ShortCircuit: %s", self.rule.name)


class ShortCircuit(oa.plugins.base.BasePlugin):
    """ShortCircuit rules to stop processing the
    message immediately if the rule is matched.
    """

    eval_rules = ()

    options = {
        "shortcircuit_spam_score": ("float", 100.0),
        "shortcircuit_ham_score": ("float", -100.0),
        "shortcircuit": ("append", []),
    }

    def parsed_metadata(self, msg):
        """Add default tags to the message."""
        super(ShortCircuit, self).parsed_metadata(msg)
        msg.plugin_tags["SCRULE"] = "none"
        msg.plugin_tags["SCTYPE"] = "off"
        msg.plugin_tags["SC"] = "no"

    def get_wrapped_method(self, rule, stype):
        """Create a new match method for the rule and return
        it. This method will stop processing of other rules
        by raising an exception.
        """
        return ShortCircuitRule(rule, rule.match, stype,
                                self["shortcircuit_spam_score"],
                                self["shortcircuit_ham_score"])

    def finish_parsing_end(self, ruleset):
        """Go through the list of rules defined in the
        configuration and shortcircuit them.
        """
        super(ShortCircuit, self).finish_parsing_end(ruleset)
        for config in self["shortcircuit"]:
            try:
                rule_name, stype = config.split(None, 1)
            except ValueError:
                self.ctxt.err("Invalid short circuit: %s", config)
                continue
            try:
                rule = ruleset.get_rule(rule_name)
            except KeyError:
                self.ctxt.err("Unknown rule: %s", rule_name)
                continue

            # Nothing to do here.
            if stype == "off":
                continue
            if stype not in ("on", "ham", "spam"):
                self.ctxt.err("Invalid short circuit type: %s" % stype)
                continue
            self.ctxt.log.debug("Short-circuiting rule: %s (%s)",
                                rule.name, stype)
            new_method = self.get_wrapped_method(rule, stype)
            rule.match = new_method
