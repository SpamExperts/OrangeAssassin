"""Base for rules."""

from builtins import map
from builtins import object

import sa.errors

# Maps flags for Bayesian classifier and network tests to the
# corresponding score to use
_ADVANCED_SCORING = {
    (False, False): lambda scores: scores[0],
    (False, True): lambda scores: scores[1],
    (True, False): lambda scores: scores[2],
    (True, True): lambda scores: scores[3],
}


class BaseRule(object):
    """Abstract class for rules."""
    _rule_type = ""

    def __init__(self, name, score=None, desc=None):
        self.name = name
        if score is None:
            score = [1.0]
        self._scores = score

        if len(self._scores) not in (1, 4):
            raise sa.errors.InvalidRule(name, "Expected 1 or 4 values for the "
                                        "score and got %s" % len(self._scores))

        if desc is None:
            desc = "No description available."
        self.description = desc
        # Public score, the value is change accordingly when the
        # rule is added to a ruleset.
        self.score = self._scores[0]

    def preprocess(self, ruleset):
        """Runs before the rule is added to the Ruleset."""
        if len(self._scores) == 1:
            return
        flags = ruleset.use_bayes, ruleset.use_network
        self.score = _ADVANCED_SCORING[flags](self._scores)

    def postprocess(self, ruleset):
        """Runs after the rule is added to the Ruleset."""
        pass

    def postparsing(self, ruleset):
        """Runs after all the rules have been parsed."""
        pass

    def match(self, msg):
        """Check if the rule matches the message. 'msg' must be a object of
        type ``sa.message.Message``.
        """
        raise NotImplementedError()

    def should_check(self):
        """Check if the rule should be processed or not."""
        if self.name.startswith("__"):
            return False
        elif self.score == 0:
            return False
        return True

    @staticmethod
    def get_rule_kwargs(data):
        """Extract the keyword arguments necessary to create a new instance
        for this class.
        """
        kwargs = {}
        try:
            kwargs["score"] = list(map(float, data["score"].strip().split()))
        except KeyError:
            pass
        try:
            kwargs["desc"] = data["describe"].strip()
        except KeyError:
            pass
        return kwargs

    @classmethod
    def get_rule(cls, name, data):
        """Create a instance of this class from the parsed ruleset
        configuration files.
        """
        return cls(name, **cls.get_rule_kwargs(data))

    def __str__(self):
        return "* %s %s %s%s" % (self.score, self.name, self._rule_type,
                                 self.description)


class _NOOPRule(BaseRule):
    """Placeholder for rules we don't have support yet."""
    def match(self, msg):
        return False

