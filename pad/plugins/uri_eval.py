"""URIEval plugin."""

from __future__ import absolute_import

from html.parser import HTMLParser

try:
    from urllib.parse import unquote
    from urllib.parse import urlparse, urlsplit
except ImportError:
    from urllib import unquote
    from urlparse import urlparse


import pad.plugins.base
from pad.plugins.uri_detail import HTML
from pad.regex import Regex



HTTP_REDIR = Regex(r'(^https?:\/\/[^\/:\?]+.+?)(https?:\/{0,2}?[^\/:\?]+.*)')
HTTP_URI = Regex(r'(^https?:\/\/[^\/:\?]+.+?)')
HTTP_IP = Regex(r'(^https?:/*(?:[^\@/]+\@)?\d+\.\d+\.\d+\.\d+)')
HTTPS = Regex(r'(https:)')


class URIEvalPlugin(pad.plugins.base.BasePlugin):
    eval_rules = ("check_for_http_redirector",
                  "check_https_ip_mismatch",
                  "check_uri_truncated"
                  )

    def parse_link(self, value, linktype=""):
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

    def parsed_metadata_uri(self, msg):
        """Goes through the URIs, parse them and store them locally in the
        message"""
        parser = HTML(self.ctxt.log)
        parser.feed(msg.raw_text)
        for uri in msg.uri_list:
            if uri in parser.links:
                continue
            link = self.parse_link(uri, "parsed")
            parser.links[uri] = link
        msg.uri_detail_links = parser.links

    def check_for_http_redirector(self, msg, target=None):
        for uri in msg.uri_list:
            while HTTP_REDIR.match(uri):
                h_redir = HTTP_REDIR.match(uri).groups()[0]
                h_dest = HTTP_REDIR.match(uri).groups()[1]
                h_redir = urlparse(h_redir).netloc
                h_dest = urlparse(h_dest).netloc
                if h_redir != h_dest:
                    return 1
                uri = h_dest
        return 0

    def check_https_ip_mismatch(self, msg, target=None):
        if not hasattr(msg, "uri_detail_links"):
            self.parsed_metadata_uri(msg)
        for key in msg.uri_detail_links:
            type = msg.uri_detail_links[key].get("type", None)
            if type in ("a", "link"):
                try:
                    value = msg.uri_detail_links[key]["text"]
                    uri_list = self.extract_url_from_text(value)
                except KeyError:
                    return 0
                for uri in uri_list:
                    if not HTTP_IP.match(uri) and HTTPS.match(uri):
                        return 1
        return 0

    def extract_url_from_text(self, text):
        urls_list = []
        for value in text.split():
            if HTTPS.match(value):
                urls_list.append(value)
        return urls_list

    def match_uri_truncatred(self, key, uri_list, uri_details):
        if HTTPS.match(key) and len(uri_list) != 0:
            for uri in uri_list:
                key_domain = urlparse(uri).netloc
                uri_domain = uri_details.get("domain", None)
                if len(key) > len(uri) and uri_domain == key_domain:
                    return True
        return False

    def check_uri_truncated(self, msg, target=None):
        if not hasattr(msg, "uri_detail_links"):
            self.parsed_metadata_uri(msg)
        for key in msg.uri_detail_links:
            type = msg.uri_detail_links[key].get("type", None)
            if type in ("a", "link"):
                uri_details = msg.uri_detail_links[key]
                try:
                    value = msg.uri_detail_links[key]["text"]
                    uri_list = self.extract_url_from_text(value)
                except KeyError:
                    return 0

                if self.match_uri_truncatred(key, uri_list, uri_details):
                    return 1

        return 0

