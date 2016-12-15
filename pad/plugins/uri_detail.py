"""URIDetail Plugin."""

from __future__ import absolute_import

import re

from html.parser import HTMLParser

try:
    from urllib.parse import unquote
    from urllib.parse import urlparse
except ImportError:
    from urllib import unquote
    from urlparse import urlparse

import pad.regex
import pad.rules.uri
import pad.plugins.base
import pad.html.html_parser

URI_DRREG = pad.regex.Regex(
        r"(?P<key>\w*)\s+(?P<op>[\=\!\~]{1,2})\s+(?P<regex>/.*?/)")


class URIDetailRule(pad.rules.uri.URIRule):
    """Implements the uri_detail rule
    """
    _rule_type = "uri_detail"

    def __init__(self, name, pattern, score=None, desc=None):
        super(URIDetailRule, self).__init__(name, pattern, score, desc)

    def check_single_item(self, value):
        """Checks one item agains the patterns, return True if all
        matches.
        """
        for key, regex in self._pattern:
            if key not in value:
                # Does not match...
                return False
            data = value[key]
            match = regex.match(data)
            # All items should match to return True.
            if not match:
                return False
        return True

    def match(self, msg):
        for key in msg.uri_detail_links:
            value = msg.uri_detail_links[key]
            result = self.check_single_item(value)
            if result:
                # At least this link match, return True
                return True
        return False

    @staticmethod
    def get_rule_kwargs(data):
        rule_value = data["value"]
        checks = URI_DRREG.findall(rule_value)
        patterns = []
        for key, oper, regex in checks:
            pyregex = pad.regex.perl2re(regex, oper)
            patterns.append((key, pyregex))
        kwargs = {"pattern": patterns}
        return kwargs


class URIDetailPlugin(pad.plugins.base.BasePlugin):
    """Implements URIDetail plugin.
    """
    options = {'uri_detail': ("list", [])}
    cmds = {"uri_detail": URIDetailRule}

    def __init__(self, *args, **kwargs):
        super(URIDetailPlugin, self).__init__(*args, **kwargs)

    def parsed_metadata(self, msg):
        """Goes through the URIs, parse them and store them locally in the
        message"""
        pad.html.html_parser.parsed_metadata(msg, self.ctxt)
