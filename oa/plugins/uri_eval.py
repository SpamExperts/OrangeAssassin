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


import oa.plugins.base
import oa.html_parser
from oa.regex import Regex

HTTP_REDIR = Regex(r'(^https?:\/\/[^\/:\?]+.+?)(https?:\/{0,2}?[^\/:\?]+.*)')

MAX_URI_LENGTH = 8192

class URIEvalPlugin(oa.plugins.base.BasePlugin):
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
                uri = h_dest
                h_redir = urlparse(h_redir).netloc
                h_dest = urlparse(h_dest).netloc
                if h_redir != h_dest:
                    return 1
        return 0

    def check_https_ip_mismatch(self, msg, target=None):
        """Checks if in <a> or <link> tags we have an ip and
        if in anchor text we have an uri without ip.
        """
        if not hasattr(msg, "uri_detail_links"):
            oa.html_parser.parsed_metadata(msg, self.ctxt)
        for key, uri_details in msg.uri_detail_links.items():
            a_tag = uri_details.get("a", None)
            if a_tag:
                domain = a_tag.get("domain", None)
                try:
                    ipaddress.ip_address(str(domain))
                except ValueError:
                    return 0
                value = a_tag.get("text", "")
                uri_list = self.extract_url_from_text(value)
                for uri in uri_list:
                    domain = urlparse(uri).netloc
                    try:
                        ipaddress.ip_address(str(domain))
                    except ValueError:
                        if uri.startswith("https://"):
                            return 1
        return 0

    def extract_url_from_text(self, anchor_text):
        """Parses anchor text from html tags in order to extract
        a list with uri.
        """
        urls_list = []
        for text in anchor_text:
            for value in text.split():
                if value.startswith("https://"):
                    urls_list.append(value)
        return urls_list

    def check_uri_truncated(self, msg, target=None):
        """Checks if the uri length is greater than MAX_URI_LENGTH.
        """
        if not hasattr(msg, "uri_detail_links"):
            oa.html_parser.parsed_metadata(msg, self.ctxt)
        for key in msg.uri_detail_links:
            for type in msg.uri_detail_links[key]:
                if type in ("a", "link"):
                    if len(key) > MAX_URI_LENGTH:
                        return 1
        return 0

