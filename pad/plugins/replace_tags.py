"""This plugin allows rules to contain regular expression tags."""

import re

import pad.errors
import pad.plugins.base

from pad.regex import Regex

# This splits value in the corresponding tags
SPLIT_TAGS = Regex(r"(<[^<>]+>)")


class ReplaceTags(pad.plugins.base.BasePlugin):
    """Replace tags in various rules."""

    eval_rules = ()

    options = {
        "replace_start": ("str", "<"),
        "replace_end": ("str", ">"),
        # These configs defines the tags
        "replace_pre": ("append", []),
        "replace_inter": ("append", []),
        "replace_post": ("append", []),
        "replace_tag": ("append", []),
        # This config defines the rules that will
        # have their values inspected for tags
        "replace_rules": ("append_split", []),
    }

    def prepare_tags(self, which="tag"):
        """Prepare the configured tags for easy replacement.
        Valid options for which are: pre, intern, post, tag.

        This converts the list of defined TAG to a dictionary
        and stores it back in the context. The dictionary maps
        the full tag name, including the start and end
        characters, to their values.
        """
        # Extra text besides the tag name, for example:
        # <inter A>
        extra = "%s " % which
        if which == "tag":
            extra = ""
        template = "%s%s%%s%s" % (
            self["replace_start"],
            extra,
            self["replace_end"]
        )
        result = {}
        for config in self["replace_%s" % which]:
            try:
                tag_name, value = config.split(None, 1)
            except ValueError:
                self.ctxt.err("Invalid replace tag: %r", config)
                continue
            full_name = template % tag_name
            if full_name in result:
                self.ctxt.err("Redefining replace tag: %r", full_name)
            result[template % tag_name] = value
        # Replace the list with a dictionary in the global
        # context.
        self["replace_%s" % which] = result

    def get_metatags(self, rule_value, which):
        """Check the rule value for meta tags and return
        the value and the adjusted rule.

        >>> self.get_metatags("/<post P3>(?!tion)/", "post")
        >>> ('{3}', '/(?!tion)/')
        """
        result = []
        for tag, tag_value in self["replace_%s" % which].items():
            if tag in rule_value:
                result.append(tag_value)
                rule_value = rule_value.replace(tag, "")
        return "".join(result), rule_value

    def replace_tags(self, rule_value):
        """Replace a single rule result."""
        pre_replace, rule_value = self.get_metatags(rule_value, "pre")
        inter_replace, rule_value = self.get_metatags(rule_value, "inter")
        post_replace, rule_value = self.get_metatags(rule_value, "post")

        results = []
        replace_tags = self["replace_tag"]
        splits = SPLIT_TAGS.split(rule_value)
        for i, value in enumerate(splits):
            try:
                replace_value = replace_tags[value]
            except KeyError:
                # This is not a tag just add it to the result
                results.append(value)
                continue

            results.append(pre_replace)
            results.append(replace_value)
            results.append(post_replace)

            # Check the next value in the list to see if
            # it's also a tag. If so then add the INTER.
            try:
                if splits[i + 1] == '' and splits[i + 2] in replace_tags:
                    # The split will actually return a empty string
                    # in these cases.
                    results.append(inter_replace)
            except IndexError:
                pass
        return "".join(results)

    def finish_parsing_start(self, results):
        """All configuration file have been read. Check the existing
        rules and replace any available tags.
        """
        super(ReplaceTags, self).finish_parsing_start(results)
        for which in ("pre", "inter", "post", "tag"):
            self.prepare_tags(which)

        for rule_name in self["replace_rules"]:
            try:
                rule_results = results[rule_name]
            except KeyError:
                self.ctxt.err("No such rule defined: %s", rule_name)
                continue
            rule_value = rule_results["value"]
            new_rule_value = self.replace_tags(rule_value)
            self.ctxt.log.debug("Replaced %r with %r in %s", rule_value,
                                new_rule_value, rule_name)
            rule_results["value"] = new_rule_value
