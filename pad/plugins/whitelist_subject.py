""" Whitelist Subject plugin."""

from __future__ import absolute_import

import re

import pad.regex
import pad.plugins.base


class WhiteListSubjectPlugin(pad.plugins.base.BasePlugin):
    eval_rules = (
        "check_subject_in_whitelist",
        "check_subject_in_blacklist"
    )
    options = {
        "whitelist_subject": ("list", []),
        "blacklist_subject": ("list", [])
    }

    def parse_config(self, key, value):
        """ Parse a config line, instead of using the regular
        set_?_option we need to use set_append_option because
        we need to append the setting to the current existing one instead
        of adding one more.
        """
        # Need to check if the option is a valid regular expression.
        if key in self.options:
            try:
                re.compile(value.strip())
            except re.error:
                return
            self.set_append_option(key, value)
            self.inhibit_further_callbacks()

    def set_append_option(self, key, value):
        """Append the key to the whitelist_subject option
        """
        self.options[key][1].append(value)
        self.set_global(key, self.options[key][1])

    def check_subject_in_whitelist(self, msg, target=None):
        """Check the subject in the blacklist subjects list
        """
        return self._check_subject(msg, self.options["whitelist_subject"][1])

    def check_subject_in_blacklist(self, msg, target=None):
        """Check the subject in the blacklist subjects list
        """
        return self._check_subject(msg, self.options["blacklist_subject"][1])

    def _check_subject(self, msg, option_list):
        """ Does the work for checking the subject in the whitelist/blacklist
        subjects list.

        option_list is either self.options["whitelist_subject"] or
        self.options["blacklist_subject"]
        """
        subject = msg.msg["subject"]
        for item in option_list:
            mo = re.match(item, subject)
            if mo:
                return True
        return False
