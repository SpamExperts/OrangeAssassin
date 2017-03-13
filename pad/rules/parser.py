"""Parse PAD rule sets.

The general syntax for PAD rules is (on one line):

<type> <name> <value>

Various options can be defined for a rule and they get bundled up using
the name as unique identifier.
"""

from __future__ import absolute_import

from builtins import dict
from builtins import object


import os
import yaml
import warnings
import contextlib
import collections
import locale

import pad.config
import pad.errors
import pad.context
import pad.plugins
import pad.rules.uri
import pad.rules.body
import pad.rules.meta
import pad.rules.full
import pad.rules.eval_
import pad.rules.header
import pad.rules.ruleset

from pad.regex import Regex

# Simple protection against recursion with "include".
MAX_RECURSION = 10

# Rules that require 2 arguments
KNOWN_2_RTYPE = frozenset(
        (
            "score",  # Specifies the score adjustment if the rule matches
            "priority",  # Specifies the priority of the rule
            "describe",  # Specifies a comment describing the rule
            "full",  # Specifies a FullRule
            "body",  # Specifies a BodyRule
            "rawbody",  # Specifies a RawBodyRule
            "uri",  # Specifies a URIRule
            "header",  # Specifies a HeaderRule
            "mimeheader",  # Specifies a MimeHeaderRule
            "meta",  # Specifies a MetaRule
            "eval",  # Specifies a EvalRule
            "lang",  # Specifies a language
            "tflags", #Specifies a TflagRule
        )
)
# Rules that require 1 arguments
KNOWN_1_RTYPE = frozenset(
        (
            "report",  # Add some text to the report template
            "unsafe_report", # Add some text to the unsafe report template
            "add_header",  # Adds a header to the message
            "remove_header",  # Remove header from message
            "include",  # Include another file in the current one
            "ifplugin",  # Check if plugin is loaded.
            "loadplugin",  # Load a plugin.
            "require_version",  # Only load this file if the version matches
            "required_score",  # Set the required score for this ruleset
            "report_safe",  # Set the method of reporting spam
            "report_contact",  # Set the contact address
            "required_score",  # Set the required score (default 5)
        )
)

# These are the types of rules that we know how to interpret, ignore anything
# else. These include rule types and option types.
KNOWN_RTYPE = KNOWN_1_RTYPE | KNOWN_2_RTYPE

# These types define rules and not options. Map against their specific class.
RULES = {
    "full": pad.rules.full.FullRule,
    "body": pad.rules.body.BodyRule,
    "rawbody": pad.rules.body.RawBodyRule,
    "uri": pad.rules.uri.URIRule,
    "meta": pad.rules.meta.MetaRule,
    "header": pad.rules.header.HeaderRule,
    "mimeheader": pad.rules.header.MimeHeaderRule,
    "eval": pad.rules.eval_.EvalRule,
}

# Params that a YAML rule can have
YAML_RULE_PARAMS = frozenset(
    (
        "type", # Rule type (see RULES)
        "score", # Rule score - number
        "priority", # Rule priority - number
        "describe", # Rule description
        "lang", # Rule language
        "tflags", # Rule tflags option (list)
        "value", # Rule value (regex)
    )
)

_COMMENT_P = Regex(r"((?<=[^\\])#.*)")


class PADParser(object):
    """Parses PAD ruleset and extracts and combines the relevant data.

    Note that this is not thread-safe.
    """

    def __init__(self, paranoid=False, ignore_unknown=True, lazy_mode=True):
        self.ctxt = pad.context.GlobalContext(paranoid=paranoid,
                                              ignore_unknown=ignore_unknown,
                                              lazy_mode=lazy_mode)
        # XXX This could be a default OrderedDict
        self.results = collections.OrderedDict()
        self.ruleset = pad.rules.ruleset.RuleSet(self.ctxt)
        self._ignore = False

    @contextlib.contextmanager
    def _paranoid(self, *exceptions):
        """If not paranoid ignore the specified exceptions."""
        try:
            yield
        except exceptions as e:
            self.ctxt.err(e)
            if self.ctxt.paranoid:
                raise

    def parse_file(self, filename, _depth=0):
        """Parses a single PAD ruleset file."""
        if _depth > MAX_RECURSION:
            raise pad.errors.MaxRecursionDepthExceeded()
        self.ctxt.log.debug("Parsing file: %s", filename)
        if not os.path.isfile(filename):
            self.ctxt.log.warn("Ignoring %s, not a file", filename)
            return
        with open(filename, "rb") as rulef:
            # Extract file extension
            base_name, extension = os.path.splitext(filename)

            # Parse YML configuration file
            if extension in (".yml", ".yaml"):
                chunk = str()

                # Since the parsing order counts we cannot load the
                # entire file using yaml.safe_load() so we split it
                # in chunks where each chunks represent a single element
                for line_no, line in enumerate(rulef):

                    # Decode the line
                    line = line.decode("iso-8859-1")

                    # Skip comments or empty lines
                    if not line or line.startswith("#") or line.startswith(
                            "\n"):
                        continue

                    # A line not starting with space indicate the
                    # begin of a new element
                    if not line.startswith(' '):

                        # The previous element ended so we need to
                        # parse the YAML inside chunk
                        if chunk:
                            element = yaml.safe_load(chunk)
                            self._handle_yaml_element(element, _depth)

                        # A new element starts so we need to reset the
                        # chunk before appendint to it
                        chunk = str()
                        chunk += line
                    else:
                        chunk += line

                # Parse the YAML inside the last chunk
                if chunk:
                    element = yaml.safe_load(chunk)
                    self._handle_yaml_element(element, _depth)

            else:
                # Parse UNIX-style configuration file
                for line_no, line in enumerate(rulef):
                    try:
                        with self._paranoid(pad.errors.InvalidSyntax):
                            self._handle_line(filename, line, line_no + 1, _depth)
                    except pad.errors.PluginLoadError as e:
                        warnings.warn(str(e))
                        self.ctxt.log.warn("%s", e)

    def _handle_yaml_element(self, yaml_dict, _depth):
        """Method that adds the YAML parsed element to the self.results"""

        if not isinstance(yaml_dict, dict):
            return

        for key, value in yaml_dict.items():
            if key == "include":
                self._handle_include(value, None, None, _depth)
            elif key == "loadplugin":
                self._handle_loadplugin(value)
            elif key == "lang":
                # If current locale match update report
                for lang, desc in value.items():
                    locale.setlocale(locale.LC_ALL, '')
                    locale_language = locale.getlocale(locale.LC_MESSAGES)[0]

                    if locale_language.startswith(lang):
                        self.ctxt.hook_parse_config("report", desc)

            # If the element is a dict maybe it can describe a rule
            elif isinstance(value, dict):
                # If the rule is not present in the results
                if key not in self.results:
                    self.results[key] = dict()

                # Put in the result just the valid rule params
                for param in sorted(value.keys()):
                    if param in YAML_RULE_PARAMS or param in self.ctxt.cmds:

                        # Score and priority should be converted to string
                        if param == "score" or param == "priority":
                            self.results[key][param] = str(value[param])

                        # Type should be added only if is a valid one
                        elif param == "type":
                            if value[param] in RULES or value[
                                param] in self.ctxt.cmds:

                                # If we have an eval rule and no target was setted
                                if self.results[key].get("type", None) == "eval":
                                    if "target" not in self.results[key]:
                                        # Set just the target
                                        self.results[key]["target"] = value["type"]
                                        continue

                                self.results[key][param] = value[param]

                        elif param == "value":

                            if "type" in self.results[key]:
                                if self.results[key]["type"] == "uri_detail":
                                    continue

                            # If we have an eval rule
                            # -type becomes "eval"
                            # -target becomes type
                            if value[param].startswith("eval:"):

                                # If type was already set
                                target = self.results[key].get("type", None)

                                # If type is in the same dict
                                if not target:
                                    target = value.get("type", None)

                                # Set target only if we have a type
                                if target:
                                    self.results[key]["target"] = target

                                self.results[key]["type"] = "eval"

                            self.results[key]["value"] = value[param]

                        elif param == "lang":

                            # If current locale match, update rule description
                            for lang, desc in value[param].items():
                                locale.setlocale(locale.LC_ALL, '')
                                locale_language = \
                                locale.getlocale(locale.LC_MESSAGES)[0]

                                if locale_language.startswith(lang):
                                    self.results[key]["describe"] = desc

                        # Set rule type to uri_detail and set rule value
                        # to the value of uri_detail key
                        elif param == "uri_detail":
                            self.results[key]["type"] = "uri_detail"
                            self.results[key]["value"] = value["uri_detail"]
                        else:
                            self.results[key][param] = value[param]

            # If no case from above matched maybe a plugin can use this
            # key and value
            else:
                self.ctxt.hook_parse_config(key, value)

    def _handle_line(self, filename, line, line_no, _depth=0):
        """Handles a single line."""
        try:
            line = line.decode("iso-8859-1").strip()
        except UnicodeDecodeError as e:
            raise pad.errors.InvalidSyntax(filename, line_no, line,
                                           "Decoding Error: %s" % e)
        if line.startswith("if can"):
            # XXX We don't support for this check, simply
            # XXX skip everything for now.
            self._ignore = True
            return

        if line.startswith("endif"):
            self._ignore = False
            return

        if line.startswith("else"):
            if self._ignore:
                self._ignore = False
            else:
                self._ignore = True
            return

        if line.startswith("require_version"):
            # XXX We don't really have any use for this now
            # XXX Just skip it.
            return

        if not line or line.startswith("#") or self._ignore:
            return

        # Remove any comments
        line = _COMMENT_P.sub("", line).strip()

        try:
            rtype, value = line.split(None, 1)
        except ValueError:
            # Some plugin might know how to handle this line
            rtype, value = line, ""

        if rtype == "include":
            self._handle_include(value, line, line_no, _depth)
        elif rtype == "ifplugin":
            self._handle_ifplugin(value)
        elif rtype == "loadplugin":
            self._handle_loadplugin(value)
        elif rtype in KNOWN_2_RTYPE or rtype in self.ctxt.cmds:
            try:
                rtype, name, value = line.split(None, 2)
            except ValueError:
                raise pad.errors.InvalidSyntax(filename, line_no, line,
                                               "Missing argument")

            if rtype == "tflags":
                value = value.split()

            if rtype == "lang":
                locale.setlocale(locale.LC_ALL, '')
                locale_language = locale.getlocale(locale.LC_MESSAGES)[0]
                if not locale_language.startswith(name):
                    self.ctxt.log.debug("Lang argument does not"
                                        "correspond with locales")
                    return

                if "report" in value:
                    try:
                        rtype, value = value.split(None, 1)
                    except ValueError:
                        raise pad.errors.InvalidSyntax(filename, line_no, line,
                                                       "Missing argument")

                    if not self.ctxt.hook_parse_config(rtype, value):
                        self.ctxt.err("%s:%s Ignoring unknown"
                                      "configuration line: %s",
                                      filename, line_no, line)
                    return

                try:
                    rtype, name, value = value.split(None, 2)
                except ValueError:
                    raise pad.errors.InvalidSyntax(filename, line_no, line,
                                                   "Missing argument")

            if name not in self.results:
                self.results[name] = dict()

            if rtype in RULES or rtype in self.ctxt.cmds:
                if value.startswith("eval:"):
                    # This is for compatibility with SA ruleset
                    self.results[name]["target"] = rtype
                    rtype = "eval"
                self.results[name]["type"] = rtype
                self.results[name]["value"] = value
            else:
                if rtype == 'priority':
                    try:
                        int(value)
                    except ValueError:
                        self.ctxt.err("%s:%s Invalid type for priority value "
                                      "in configuration line: %s, setting it by"
                                      " default to 0", filename, line_no, line)
                self.results[name][rtype] = value

        else:
            if not self.ctxt.hook_parse_config(rtype, value):
                self.ctxt.err("%s:%s Ignoring unknown configuration line: %s",
                              filename, line_no, line)


    def _handle_include(self, value, line, line_no, _depth=0):
        """Handles the 'include' keyword."""
        filename = value.strip()
        try:
            self.parse_file(filename, _depth=_depth + 1)
        except pad.errors.MaxRecursionDepthExceeded as e:
            e.add_call(filename, line_no, line)
            raise e

    def _handle_ifplugin(self, value):
        """Handles the 'ifplugin' keyword."""
        plugin_name = pad.plugins.REIMPLEMENTED_PLUGINS.get(value, value)
        try:
            plugin_name = plugin_name.rsplit(".", 1)[1]
        except IndexError:
            pass
        if plugin_name not in self.ctxt.plugins:
            self.ctxt.log.debug("Plugin %s not loaded, skipping.", plugin_name)
            self._ignore = True

    def _handle_loadplugin(self, value):
        """Handles the 'loadplugin' keyword."""
        try:
            plugin_name, path = value.split(None, 1)
        except ValueError:
            plugin_name, path = value, None
        if "::" in plugin_name:
            plugin_name = pad.plugins.REIMPLEMENTED_PLUGINS.get(plugin_name)
        if plugin_name:
            self.ctxt.load_plugin(plugin_name, path)
        else:
            self.ctxt.log.warn("Plugin not available: %s", value)

    def get_ruleset(self):
        """Create and return the corresponding ruleset for the parsed files."""
        self.ctxt.hook_parsing_start(self.results)
        for name, data in self.results.items():
            try:
                rule_type = data["type"]
            except KeyError:
                e = pad.errors.InvalidRule(name, "No rule type defined.")
                self.ctxt.err(e)
                if self.ctxt.paranoid:
                    raise e
            else:
                with self._paranoid(pad.errors.InvalidRule,
                                    pad.errors.InvalidRegex):
                    try:
                        rule_class = RULES[rule_type]
                    except KeyError:
                        # A plugin might have been loaded that
                        # can handle this.
                        rule_class = self.ctxt.cmds[rule_type]
                    self.ctxt.log.debug("Adding rule %s with: %s", name, data)
                    rule = rule_class.get_rule(name, data)
                    self.ruleset.add_rule(rule)
        self.ctxt.hook_parsing_end(self.ruleset)
        self.ctxt.log.info("%s rules loaded", len(self.ruleset.checked))
        self.ruleset.post_parsing()
        return self.ruleset


def parse_pad_rules(files, paranoid=False, ignore_unknown=True):
    """Parse a list of PAD rules and returns the corresponding ruleset.

    'files' - a list of file paths.

    Returns a dictionary that maps rule names to a dictionary of rule options.
    Every rule will contain "type" and "value" which corresponds to the
    mandatory line for defining a rule. For example (type, name value):

    body LOCAL_DEMONSTRATION_RULE   /test/

    Other options may be included such as "score", "describe".
    """
    parser = PADParser(paranoid=paranoid, ignore_unknown=ignore_unknown)
    for filename in files:
        parser.parse_file(filename)

    return parser
