"""Parse SA rule sets.

The general syntax for SpamAssassin rules is (on one line):

<type> <name> <value>

Various options can be defined for a rule and they get bundled up using
the name as unique identifier.
"""

from __future__ import absolute_import
from future import standard_library
standard_library.install_hooks()

import collections

import sa.rules.uri
import sa.rules.body
import sa.rules.meta
import sa.rules.header
import sa.rules.ruleset


# These are the types of rules that we know how to interpret, ignore anything
# else. These include rule types and option types.
KNOWN_RTYPE = frozenset(
    (
        "score",  # Specifies the score adjustment if the rule matches
        "describe",  # Specifies a comment describing the rule
        "body",  # Specifies a BodyRule
        "rawbody",  # Specifies a RawBodyRule
        "uri",  # Specifies a URIRule
        "header",  # Specifies a HeaderRule
        "mimeheader",  # Specifies a MimeHeaderRule
        "meta",  # Specifies a MetaRule
    )
)

# These types define rules and not options. Map against their specific class.
RULES = {
    "body": sa.rules.body.BodyRule,
    "rawbody": sa.rules.body.RawBodyRule,
    "uri": sa.rules.uri.URIRule,
    "meta": sa.rules.meta.MetaRule,
    "header": sa.rules.header.HeaderRule,
    "mimeheader": sa.rules.header.MimeHeaderRule,
}


def parse_sa_file(rulef, results):
    """Parse a single SpamAssasin Rule and add the data to the 'results'
    dictionary.
    """
    for line in rulef:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rtype, name, value = line.split(None, 2)
        except ValueError:
            continue
        if rtype not in KNOWN_RTYPE:
            continue
        if name not in results:
            results[name] = {}

        if rtype in RULES:
            results[name]["type"] = rtype
            results[name]["value"] = value
        else:
            results[name][rtype] = value


def parse_sa_rules(files):
    """Parse a list of SpamAssasin rules and returns the corresponding ruleset.

    'files' - a list of file paths.

    Returns a dictionary that maps rule names to a dictionary of rule options.
    Every rule will contain "type" and "value" which corresponds to the
    mandatory line for defining a rule. For example (type, name value):

    body LOCAL_DEMONSTRATION_RULE   /test/

    Other options may be included such as "score", "describe".
    """
    # XXX This should be a default OrderedDict
    results = collections.OrderedDict()
    for file_name in files:
        with open(file_name) as rulef:
            parse_sa_file(rulef, results)

    ruleset = sa.rules.ruleset.RuleSet()
    for name, data in results.items():
        rule = RULES[data["type"]].get_rule(name, data)
        ruleset.add_rule(rule)

    return ruleset
