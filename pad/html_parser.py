"""Parser for fetching all links in a message"""

from html.parser import HTMLParser

try:
    from urllib.parse import unquote
    from urllib.parse import urlparse
except ImportError:
    from urllib import unquote
    from urlparse import urlparse


class HTML(HTMLParser):
    """HTML parser to fetch all links in the message with the
    corresponding value of the anchor"""

    def __init__(self, logger):
        try:
            HTMLParser.__init__(self, convert_charrefs=False)
        except TypeError:
            # Python 2 does not have the convert_charrefs argument
            HTMLParser.__init__(self)
        self.links = {}
        self.last_start_tag = None
        self.last_link_details = {}
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
                if prop not in ("href", "src"):
                    continue
                link = parse_link(value, tag)
                if value in self.links:
                    if tag in self.links[value]:
                        self.links[value][tag].update(link[tag])
                        self.current_link = value
                        continue
                else:
                    self.links[value] = {}
                link[tag]['text'] = []
                self.links[value][tag] = link[tag]
                self.current_link = value

    def handle_endtag(self, tag):
        self.last_start_tag = None
        self.current_link = None

    def handle_data(self, data):
        """Handle the text in anchors"""
        if not all([data, self.last_start_tag, self.current_link]):
            return
        if self.last_start_tag in ("a", "link"):
            self.links[self.current_link][self.last_start_tag]["text"].\
                append(data)

def parse_link(value, linktype):
    """ Returns a dictionary with information for the link"""
    link = {}
    link[linktype] = {}
    link[linktype]["raw"] = value
    urlp = urlparse(value)
    link[linktype]["scheme"] = urlp.scheme
    link[linktype]["cleaned"] = unquote(value)
    link[linktype]["domain"] = urlp.netloc
    return link


def parsed_metadata(msg, ctxt):
    """Goes through the URIs, parse them and store them locally in the
            message"""
    parser = HTML(ctxt.log)
    parser.feed(msg.raw_text)
    for uri in msg.uri_list:
        if uri in parser.links:
            continue
        link = parse_link(uri, "parsed")
        parser.links[uri] = link
    msg.uri_detail_links = parser.links
    ctxt.set_plugin_data("URIDetailPlugin", "links", parser.links)