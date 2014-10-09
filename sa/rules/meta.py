"""Rules that are boolean or arithmetic combinations of other rules."""

import re

import sa.rules.base

# Syntax differences between Perl and Python.
CONVERT = (
    ("&&", "&"),
    ("||", '|'),
    ("!", "not "),
)


class MetaRule(sa.rules.base.BaseRule):
    """These rules are boolean or arithmetic combinations of other rules."""

    def __init__(self, name, rule, score=None, desc=None):
        """Convert the rule into Python executable code."""
        super(MetaRule, self).__init__(name, score=score, desc=desc)
        self.subrules = self._get_subrules(rule)
        for subrule in self.subrules:
            rule = rule.replace(subrule, subrule + "(msg)")
        for operator, repl in CONVERT:
            rule = rule.replace(operator, repl)
        self.rule = "match = lambda msg: %s" % rule
        self._location = {}
        # XXX we should check for potentially unsafe code or run it in
        # XXX RestrictedPython.
        self._code_obj = compile(self.rule, "<meta>", "exec")

    @staticmethod
    def _get_subrules(rule):
        return set(re.findall(r"(\w+)\W", rule))

    def preprocess(self, ruleset):
        """Get the referenced sub-rules of this meta-rule and add execute the
        python code creating an appropriate match function for this meta-rule.
        """
        sa.rules.base.BaseRule.preprocess(self, ruleset)
        for subrule_name in self.subrules:
            subrule = ruleset.get_rule(subrule_name)
            self._location[subrule_name] = subrule.match
        exec(self._code_obj, self._location)
        assert "match" in self._location

    def match(self, msg):
        return self._location["match"](msg)

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = sa.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["rule"] = data["value"]
        return kwargs
