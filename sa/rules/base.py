"""Base for rules."""

from builtins import map
from builtins import object


class BaseRule(object):
    """Abstract class for rules."""
    _rule_type = ""

    def __init__(self, name, score=None, desc=None):
        self.name = name
        if score is None:
            score = [1.0]
        self.score = score
        if desc is None:
            desc = "No description available."
        self.description = desc

    def preprocess(self, ruleset):
        """Runs before the rule is added to the Ruleset."""
        pass

    def postprocess(self, ruleset):
        """Runs after the rule is added to the Ruleset."""
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
        elif self.score == [0]:
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
        return "* %s %s %s%s" % (self.score[0], self.name, self._rule_type,
                                 self.description)
