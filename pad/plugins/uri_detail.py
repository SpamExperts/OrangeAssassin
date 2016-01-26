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


URI_DRREG = re.compile(r"(?P<key>\w*)\s+(?P<op>[\=\!\~]{1,2})\s+(?P<regex>/.*?/)")

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

def parse_link(value, linktype=""):
    """ Returns a dictionary with information for the link"""
    link = {}
    link["raw"] = value
    urlp = urlparse(value)
    link["scheme"] = urlp.scheme
    link["cleaned"] = unquote(value)
    if linktype:
        link["type"] = linktype
    link["domain"] = urlp.netloc
    return link

class HTML(HTMLParser):
    """HTML parser to fetch all links in the message with the
    corresponding value of the anchor"""
    def __init__(self, logger):
        HTMLParser.__init__(self)
        self.links = {}
        self.last_start_tag = None
        self.current_link = None
        self.logger = logger

    def handle_starttag(self, tag, attrs):
        '''
        Handle the start of a tag.
        '''
        if tag in ('a', 'link'):
            self.last_start_tag = tag
            for item in attrs:
                prop, value = item
                if prop not in  ("href", "src"):
                    continue
                link = parse_link(value, tag)
                self.links[value] = link
                self.current_link = value

    def handle_endtag(self, tag):
        self.last_start_tag = None
        self.current_link = None

    def handle_data(self, data):
        """Handle the text in anchors"""
        if self.last_start_tag in ("a", "link"):
            self.links[self.current_link]["text"] = data


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
        parser = HTML(self.ctxt.log)
        parser.feed(msg.raw_text)
        for uri in msg.uri_list:
            if uri in parser.links:
                continue
            link = parse_link(uri, "parsed")
            parser.links[uri] = link
        msg.uri_detail_links = parser.links
        self.ctxt.set_plugin_data("URIDetailPlugin", "links", parser.links)
