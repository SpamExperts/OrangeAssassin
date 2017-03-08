"""Rule that evaluate a predefined registered function."""

import re

import pad.errors
import pad.rules.base

from pad.regex import Regex

# Used to extract the eval rule data
_EVAL_RULE_P = Regex(r"""
    ([_a-zA-Z]\w*)     # First matching group for the eval rule name
    \((.*)\)           # Greedy matching group for the eval rule args
""", re.VERBOSE)


class EvalMethod(object):
    def __init__(self, method, eval_args, target):
        self.method = method
        self.eval_args = eval_args
        self.target = target

    def __call__(self, msg):
        return self.method(*((msg,) + self.eval_args), target=self.target)


class EvalRule(pad.rules.base.BaseRule):
    """Evaluates a registered eval function."""

    def __init__(self, name, eval_rule, score=None, desc=None, target=None,
                 priority=0, tflags=None):
        super(EvalRule, self).__init__(name, score=score, desc=desc,
                                       priority=priority, tflags=tflags)
        self.rule_type = target
        try:
            eval_rule_name, eval_args = _EVAL_RULE_P.match(eval_rule).groups()
            self.eval_rule_name = eval_rule_name
            if eval_args:
                self.eval_args = tuple(
                        eval(arg) for arg in eval_args.split(","))
            else:
                self.eval_args = tuple()
        except (TypeError, ValueError, AttributeError):
            raise pad.errors.InvalidRule(self.name, "Invalid eval rule: %s" %
                                         eval_rule)
        except SyntaxError:
            err_msg = "Invalid arguments for eval rule: %s" % eval_rule
            raise pad.errors.InvalidRule(self.name, err_msg)

        self.target = target
        self.eval_rule = None

    def preprocess(self, ruleset):
        """Get the eval rule from the global context and create a partial method
        from it and the specified argument from the configuration.

        The message and target object is always passed as the first
        argument.
        """
        super(EvalRule, self).preprocess(ruleset)
        try:
            method = ruleset.ctxt.eval_rules[self.eval_rule_name]
        except KeyError:
            raise pad.errors.InvalidRule(self.name, "Undefined eval rule "
                                                    "referenced: %s" %
                                         self.eval_rule_name)

        self.eval_rule = EvalMethod(method, self.eval_args, self.target)

    def match(self, msg):
        try:
            return self.eval_rule(msg)
        except Exception as e:
            log = msg.ctxt.log
            log.critical("Error while processing %s in function %s: %s",
                         self.name, self.eval_rule_name, e, exc_info=True)
            return False

    @staticmethod
    def get_rule_kwargs(data):
        kwargs = pad.rules.base.BaseRule.get_rule_kwargs(data)
        kwargs["eval_rule"] = data['value'].lstrip('eval:').strip()
        if "target" in data:
            kwargs["target"] = data['target']
        return kwargs
