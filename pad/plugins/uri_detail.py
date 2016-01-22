"""URIDetail Plugin."""

from __future__ import absolute_import

import re
import urllib
import urlparse

try:
    import HTMLParser
except ImportError:
    from html.parser import HTMLParser

import pad.plugins.base
import pad.rules.uri

class URIDetailRule(pad.rules.uri.URIRule):
    _rule_type = "uri_detail"
    def __init__(self, name, pattern, score=None, desc=None):
        super(URIDetailRule, self).__init__(name, pattern, score, desc)

    def check_single_item(self, value):
        """Checks one item agains the patterns, return True if all
        matches.
        """
        for key, regex in self._pattern:
            if not key in value:
                # Does not match... 
                return False
            data = value[key]
            match = regex.match(data)
            # All items should match to return True.
            # Since we need to find at least one match, we don't return
            # False here, just continue with the next link
            if not match: 
                return False
        return True


    def match(self, msg):
        for ukey, value in msg.uri_detail_links.iteritems():
            print value
            result = self.check_single_item(value)
            if result:
                print value
                # At least this link match, return True
                return True
        return False

    @staticmethod
    def get_rule_kwargs(data):
        print data
        rule_value = data["value"]
        r = re.compile("(?P<key>\w*)\s+(?P<op>[\=\!\~]{1,2})\s+(?P<regex>/.*?/)")
        checks = r.findall(rule_value)
        patterns = []
        for key, op, regex in checks:
            pyregex = pad.regex.perl2re(regex, op)
            patterns.append((key, pyregex))
        kwargs = {"pattern": patterns}
        return kwargs
    
def parse_link(value):
    """ Returns a dictionary with information for the link"""
    link = {}
    link["raw"] = value
    urlp = urlparse.urlparse(value)
    link["scheme"] = urlp.scheme
    link["cleaned"] = urllib.unquote(value)
    link["type"] = "a"
    link["domain"] = urlp.netloc
    return link

class HTML(HTMLParser.HTMLParser):
    def __init__(self, logger):
        HTMLParser.HTMLParser.__init__(self)
        self.links = {}
        self.last_start_tag = None
        self.logger = logger

    def handle_starttag(self, tag, attrs):
        '''
        Handle the start of a tag.
        '''
        if tag == 'a':
            self.last_start_tag = "a"
            for item in attrs:
                prop, value = item
                if prop != "href":
                    continue
                link = parse_link(value)
                self.links[value] = link
                self.current_link = value
    
    def handle_endtag(self, tag):
        self.last_start_tag = None
        self.current_link = None
        pass

    def handle_data(self, data):
        """Handle the text in anchors"""
        if self.last_start_tag == "a":
            self.links[self.current_link]["text"] = data


class URIDetailPlugin(pad.plugins.base.BasePlugin):
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
            link = parse_link(uri)
            parser.links[uri] = link
        msg.uri_detail_links = parser.links
        self.ctxt.set_plugin_data("URIDetailPlugin", "links", parser.links)
