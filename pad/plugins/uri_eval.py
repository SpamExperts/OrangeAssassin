"""URIEval plugin."""

from __future__ import absolute_import

import ipaddress
from builtins import str

try:
    from urllib.parse import unquote
    from urllib.parse import urlparse
except ImportError:
    from urllib import unquote
    from urlparse import urlparse


import pad.plugins.base
import pad.html_parser
from pad.regex import Regex

HTTP_REDIR = Regex(r'(^https?:\/\/[^\/:\?]+.+?)(https?:\/{0,2}?[^\/:\?]+.*)')
HTTP_URI = Regex(r'(^https?:\/\/[^\/:\?]+.+?)')
HTTP_IP = Regex(r'(^https?:/*(?:[^\@/]+\@)?\d+\.\d+\.\d+\.\d+)')
HTTPS = Regex(r'(https:)')


class URIEvalPlugin(pad.plugins.base.BasePlugin):
    """Implements the uri_eval rule
        """

    eval_rules = ("check_for_http_redirector",
                  "check_https_ip_mismatch",
                  "check_uri_truncated"
                  )

    def check_for_http_redirector(self, msg, target=None):
        """Checks if the uri has been redirected.
            -use HTTP_REDIR regex in order to extract the
            destination domain and compare it with source
            domain
        """
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
        """Checks if in <a> or <link> tags we have an ip and
        if in anchor text we have an uri without ip.
        """
        if not hasattr(msg, "uri_detail_links"):
            pad.html_parser.parsed_metadata(msg, self.ctxt)
        for key in msg.uri_detail_links:
            type = msg.uri_detail_links[key].get("type", None)
            domain = msg.uri_detail_links[key].get("domain", None)
            if type == "a":
                try:
                    ipaddress.ip_address(str(domain))
                except ValueError:
                    return 0
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
        """Parses anchor text from html tags in order to extract
        a list with uri.
        """
        urls_list = []
        for value in text.split():
            if HTTPS.match(value):
                urls_list.append(value)
        return urls_list

    def match_uri_truncated(self, key, uri_list, uri_details):
        """Returns True if the uri length from href attribute is
        greater than uri length from anchor text.
        """
        if HTTPS.match(key) and len(uri_list) != 0:
            for uri in uri_list:
                key_domain = urlparse(uri).netloc
                uri_domain = uri_details.get("domain", None)
                if len(key) > len(uri) and uri_domain == key_domain:
                    return True
        return False

    def check_uri_truncated(self, msg, target=None):
        """Checks if we have uri truncated in msg.
        """
        if not hasattr(msg, "uri_detail_links"):
            pad.html_parser.parsed_metadata(msg, self.ctxt)
        for key in msg.uri_detail_links:
            type = msg.uri_detail_links[key].get("type", None)
            if type in ("a", "link"):
                uri_details = msg.uri_detail_links[key]
                try:
                    value = msg.uri_detail_links[key]["text"]
                    uri_list = self.extract_url_from_text(value)
                except KeyError:
                    return 0

                if self.match_uri_truncated(key, uri_list, uri_details):
                    return 1

        return 0

