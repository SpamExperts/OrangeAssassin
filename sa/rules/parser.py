"""Parse SA rule sets.

The general syntax for SpamAssassin rules is (on one line):

<type> <name> <value>

Various options can be defined for a rule and they get bundled up using
the name as unique identifier.
"""

from __future__ import absolute_import
from future import standard_library
standard_library.install_hooks()

import re
import collections

import sa.errors
import sa.rules.uri
import sa.rules.body
import sa.rules.meta
import sa.rules.full
import sa.rules.header
import sa.rules.ruleset

# Simple protection against recursion with "include".
MAX_RECURSION = 10

# Rules that require 2 arguments
KNOWN_2_RTYPE = frozenset(
    (
        "score",  # Specifies the score adjustment if the rule matches
        "describe",  # Specifies a comment describing the rule
        "full",  # Specifies a FullRule
        "body",  # Specifies a BodyRule
        "rawbody",  # Specifies a RawBodyRule
        "uri",  # Specifies a URIRule
        "header",  # Specifies a HeaderRule
        "mimeheader",  # Specifies a MimeHeaderRule
        "meta",  # Specifies a MetaRule
    )
)
# Rules that require 1 arguments
KNOWN_1_RTYPE = frozenset(
    (
        "include",  # Include another file in the current one
    )
)

# These are the types of rules that we know how to interpret, ignore anything
# else. These include rule types and option types.
KNOWN_RTYPE = KNOWN_1_RTYPE | KNOWN_2_RTYPE

# These types define rules and not options. Map against their specific class.
RULES = {
    "full": sa.rules.full.FullRule,
    "body": sa.rules.body.BodyRule,
    "rawbody": sa.rules.body.RawBodyRule,
    "uri": sa.rules.uri.URIRule,
    "meta": sa.rules.meta.MetaRule,
    "header": sa.rules.header.HeaderRule,
    "mimeheader": sa.rules.header.MimeHeaderRule,
}


def parse_sa_file(rulef, results, paranoid=False, depth=0):
    """Parse a single SpamAssasin Rule and add the data to the 'results'
    dictionary.
    """
    ignore = False
    for line_no, line in enumerate(rulef):
        try:
            line = line.decode("iso-8859-1").strip()
        except UnicodeDecodeError as e:
            if paranoid:
                raise sa.errors.InvalidSyntax(rulef.name, line_no, line,
                                              "Decoding Error: %s" % e)
            else:
                continue
        if not line or line.startswith("#") or ignore:
            continue

        # Remove any comments
        line = re.sub(r"((?<=[^\\])#.*)", "", line).strip()

        # XXX We don't have any support for plugins
        if line.startswith("ifplugin"):
            ignore = True
            continue
        elif line.startswith("endif"):
            ignore = False
            continue

        try:
            rtype, value = line.split(None, 1)
        except ValueError:
            continue
        if rtype in KNOWN_1_RTYPE:
            if rtype == "include":
                if depth + 1 > MAX_RECURSION:
                    raise sa.errors.MaxRecursionDepthExceeded(rulef.name,
                                                              line_no + 1, line)
                with open(value) as inc_rulef:
                    try:
                        parse_sa_file(inc_rulef, results, paranoid=paranoid,
                                      depth=depth + 1)
                    except sa.errors.MaxRecursionDepthExceeded as e:
                        e.add_call(rulef.name, line_no + 1, line)
                        raise e
        elif rtype in KNOWN_2_RTYPE:
            try:
                rtype, name, value = line.split(None, 2)
            except ValueError:
                raise sa.errors.InvalidSyntax(rulef.name, line_no + 1, line,
                                              "Missing argument")
            if name not in results:
                results[name] = {}

            if rtype in RULES:
                results[name]["type"] = rtype
                results[name]["value"] = value
            else:
                results[name][rtype] = value


def parse_sa_rules(files, paranoid=False):
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
        with open(file_name, "rb") as rulef:
            parse_sa_file(rulef, results, paranoid=paranoid)

    ruleset = sa.rules.ruleset.RuleSet(paranoid)
    for name, data in results.items():
        try:
            rule_type = data["type"]
        except KeyError:
            if paranoid:
                raise sa.errors.InvalidRule(name, "No rule type defined.")
        else:
            try:
                rule = RULES[rule_type].get_rule(name, data)
                ruleset.add_rule(rule)
            except sa.errors.InvalidRule:
                if paranoid:
                    raise
    ruleset.post_parsing()
    return ruleset
