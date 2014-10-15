"""Rules that are boolean or arithmetic combinations of other rules."""

from builtins import dict

import re

import sa.errors
import sa.rules.base

# Syntax differences between Perl and Python.
CONVERT = (
    ("&&", " and "),
    ("||", " or "),
    ("!", " not "),
)

_SUBRULE_P = re.compile(r"([_a-zA-Z]\w*)(?=\W|$)")


class MetaRule(sa.rules.base.BaseRule):
    """These rules are boolean or arithmetic combinations of other rules."""

    def __init__(self, name, rule, score=None, desc=None):
        """Convert the rule into Python executable code."""
        super(MetaRule, self).__init__(name, score=score, desc=desc)
        self.subrules = set(_SUBRULE_P.findall(rule))
        rule = _SUBRULE_P.sub(r"\1(msg)", rule)
        for operator, repl in CONVERT:
            rule = rule.replace(operator, repl)
        self.rule = "match = lambda msg: %s" % rule
        self._location = dict()
        # XXX we should check for potentially unsafe code or run it in
        # XXX RestrictedPython.
        self._code_obj = compile(self.rule, "<meta>", "exec")

    def postparsing(self, ruleset):
        """Get the referenced sub-rules of this meta-rule and add execute the
        python code creating an appropriate match function for this meta-rule.
        """
        sa.rules.base.BaseRule.postparsing(self, ruleset)
        for subrule_name in self.subrules:
            try:
                subrule = ruleset.get_rule(subrule_name)
            except KeyError:
                raise sa.errors.InvalidRule(self.name, "Undefined subrule "
                                            "referenced %r" % subrule_name)
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
