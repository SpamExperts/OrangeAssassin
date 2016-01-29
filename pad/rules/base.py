"""Base for rules."""

from __future__ import absolute_import

from builtins import map
from builtins import dict
from builtins import list
from builtins import object

import pad.errors

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
        if name.startswith("__"):
            score = [0.0]
        elif score is None:
            score = [1.0]
        self._scores = score

        if len(self._scores) not in (1, 4):
            err_msg = ("Expected 1 or 4 values for the score and got %s" %
                       len(self._scores))
            raise pad.errors.InvalidRule(name, err_msg)

        if desc is None:
            desc = "No description available."
        self.description = desc
        # Public score, the value is change accordingly when the
        # rule is added to a ruleset.
        self.score = self._scores[0]

    def preprocess(self, ruleset):
        """Adjust the score for this rule taking into consideration
        the advanced scoring, if there are 4 scores provided.
        """
        if len(self._scores) != 4:
            # Nothing to do
            return
        flags = ruleset.use_bayes, ruleset.use_network
        self.score = _ADVANCED_SCORING[flags](self._scores)

    def postprocess(self, ruleset):
        """Runs after the rule is added to the Ruleset."""
        pass

    def postparsing(self, ruleset, _depth=0):
        """Runs after all the rules have been parsed."""
        pass

    def match(self, msg):
        """Check if the rule matches the message. 'msg' must be a object of
        type ``pad.message.Message``.
        """
        raise NotImplementedError()

    def should_check(self):
        """Check if the rule should be processed or not."""
        if self.name.startswith("__"):
            # This might be checked in a META rule, but
            # don't check it by default.
            return False
        elif self.score == 0:
            return False
        return True

    @staticmethod
    def get_rule_kwargs(data):
        """Extract the keyword arguments necessary to create a new instance
        for this class.
        """
        kwargs = dict()
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

