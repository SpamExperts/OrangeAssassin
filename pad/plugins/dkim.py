"DKIM Plugin."

from __future__ import absolute_import

import re
from collections import defaultdict

import dns
import dkim

import pad.plugins.base

FROM_HEADERS = ('From', "Envelope-Sender", 'Resent-From', 'X-Envelope-From',
                'EnvelopeFrom')


def get_txt(name):
    """Return a TXT record associated with a DNS name.

    @param name: The bytestring domain name to look up.
    """
    try:
        unicode_name = name.decode('ascii')
    except UnicodeDecodeError:
        return None
    txt = get_txt_dnspython(unicode_name)
    if txt:
      txt = txt.encode('utf-8')
    return txt


def get_txt_dnspython(name):
    """Return a TXT record associated with a DNS name."""
    try:
        a = dns.resolver.query(name, dns.rdatatype.TXT, raise_on_no_answer=False)
        for r in a.response.answer:
            if r.rdtype == dns.rdatatype.TXT:
                return "".join(r.items[0].strings)
    except dns.resolver.NXDOMAIN: pass
    return None


class DKIMPlugin(pad.plugins.base.BasePlugin):
    signatures = ""
    valid_signatures = ""
    author_addresses = []
    author_domains = []

    dkim_checked_signature = 0
    dkim_signed = 0
    dkim_valid = 0
    dkim_has_valid_author_sig = 0
    dkim_signatures_dependable = 0
    is_valid = 1

    eval_rules = (
        "check_dkim_adsp",
        "check_dkim_signed",
        "check_dkim_valid",
        "check_dkim_valid_author_sig",
        "check_dkim_dependable",
        "check_for_dkim_whitelist_from",
        "check_for_def_dkim_whitelist_from"
    )
    options = {
        "whitelist_from_dkim": ("list", []),
        "def_whitelist_from_dkim": ("append_split", []),
        "unwhitelist_from_dkim": ("list", []),
        "adsp_override": ("list", []),
        "dkim_timeout": ("int", 1024),
        "dkim_minimum_key_bits": ("int", 1024)
    }

    adsp_options = {
        "A": "all",
        "D": "discardable",
        "1": "custom_low",
        "2": "custom_med",
        "3": "custom_high",
        "U": "unknown"
    }

    def get_from_addresses(self, msg):
        """Get addresses from 'Resent-From' header,
        and if there are no addresses, get from
        all FROM_HEADERS.
        """
        addresses = msg.get_all_addr_header('Resent-From')
        if addresses:
            for address in addresses:
                yield address
        else:
            for key in FROM_HEADERS:
                for address in msg.get_all_addr_header(key):
                    yield address

    def parse_input(self, list_name):
        parsed_list = defaultdict(list)
        for addr in self[list_name]:
            line = addr.split(None, 1)
            if line[0]:
                if line[0] in self["unwhitelist_from_dkim"]:
                    continue
                if len(line) == 2:
                    for dom in line[1].split():
                        parsed_list[line[0].encode().replace(b'*', b'.*')] = dom
                else:
                    parsed_list[line[0].encode().replace(b'*', b'.*')] = ""
        return parsed_list

    def check_dkim_adsp(self, msg, adsp_char="", domains_list=None,
                        target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if self.dkim_valid:
            return False
        parsed_adsp_override = self.parse_input("adsp_override")
        for author in self.author_domains:
            if domains_list and domains_list.encode() != author:
                continue
            if not parsed_adsp_override[author]:
                if adsp_char == 'D':
                    return True
            if adsp_char == "*":
                return True
            if self.adsp_options[adsp_char] == parsed_adsp_override[author].lower():
                return True
        return False

    def check_dkim_signed(self, msg, acceptable_domains=None, target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if not self.dkim_signed:
            return False
        return self._check_dkim_signed_by(msg, 0, 0, acceptable_domains)

    def check_dkim_valid(self, msg, acceptable_domains=None, target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if not self.dkim_valid:
            return False
        return self._check_dkim_signed_by(msg, 1, 0, acceptable_domains)

    def check_dkim_valid_author_sig(self, msg, acceptable_domains=None,
                                    target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if not self.dkim_has_valid_author_sig:
            return False
        return self._check_dkim_signed_by(msg, 1, 1, acceptable_domains)

    def check_dkim_dependable(self, msg, target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        return self.dkim_signatures_dependable

    def check_for_dkim_whitelist_from(self, msg, target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if not self.dkim_valid:
            return False
        whitelist_address = self.parse_input("whitelist_from_dkim")
        for address in self.author_addresses:
            for domain in self.author_domains:
                try:
                    if whitelist_address[address.encode()] == domain.decode() \
                            or whitelist_address[address.encode()] == "":
                        return True
                except KeyError:
                    return False
        return False

    def check_for_def_dkim_whitelist_from(self, msg, target=None):
        if not self.dkim_checked_signature:
            self.check_dkim_signature(msg)
        if not self.dkim_valid:
            return False
        whitelist_address = self.parse_input("def_whitelist_from_dkim")
        for author in self.author_addresses:
            for key, value in whitelist_address.items():
                if re.match(key, author.encode()):
                    if value == "":
                        return True
                    elif value.encode() in self.author_domains:
                        return True
        return False

    def _get_authors(self, msg):
        self.author_addresses = msg.get_addr_header("From")
        for header in self.author_addresses:
            match_domain = re.search("@([^@]+?)[ \t]*$", header)
            if match_domain:
                domain = match_domain.group(1)
                self.author_domains.append(domain.encode())

    def _check_dkim_signed_by(self, msg, must_be_valid,
                              must_be_author_domain_signature,
                              acceptable_domains=None):
        if not acceptable_domains:
            return True
        result = 0
        signature = msg.msg.get('DKIM-Signature', "")
        parsed_signature = dkim.util.parse_tag_value(signature.encode())
        if must_be_valid and acceptable_domains:
            if not self.is_valid:
                return False
        try:
            signature_domain = parsed_signature[b'd']
        except KeyError:
            return False
        if must_be_author_domain_signature:
            if not self.author_domains:
                self._get_authors(msg)
            if signature_domain not in self.author_domains:
                return False

        parts = acceptable_domains.split('.')
        if len(parts) > 1:
            domain = ".".join(parts[-2:]).encode()
            if domain == signature_domain or domain in signature_domain:
                result = 1
        elif acceptable_domains == signature_domain:
            result = 1
        return result

    def check_dkim_signature(self, msg):
        self.dkim_checked_signature = 1
        self.dkim_signed = 1
        self.dkim_valid = 1
        self.dkim_signatures_dependable = 1
        self.dkim_has_valid_author_sig = 1
        message = msg.raw_msg

        if not self.author_domains:
            self._get_authors(msg)
        signature = msg.msg.get('DKIM-Signature', "")
        parsed_signature = dkim.util.parse_tag_value(signature.encode())
        try:
            if parsed_signature[b'd'] not in self.author_domains:
                self.dkim_valid = 0
                self.dkim_signed = 0
                self.dkim_has_valid_author_sig = 0
                self.dkim_signatures_dependable = 0
        except KeyError:
            self.dkim_valid = 0

        try:
            minimum_key_bits = self["dkim_minimum_key_bits"]
            if minimum_key_bits < 0:
                minimum_key_bits = 0
            result = dkim.verify(message.encode(), dnsfunc=get_txt,
                                 minkey=minimum_key_bits*2)
            if not result:
                self.is_valid = 0
                self.dkim_valid = 0
            dkim.validate_signature_fields(parsed_signature)
        except dkim.MessageFormatError:
            self.dkim_valid = 0
            self.dkim_has_valid_author_sig = 0
            self.dkim_signatures_dependable = 0
        except dkim.ValidationError:
            self.dkim_valid = 0
            self.dkim_has_valid_author_sig = 0
        except dkim.KeyFormatError:
            self.dkim_valid = 0
            self.dkim_has_valid_author_sig = 0











