from __future__ import absolute_import

import re
import pad.regex
import pad.errors
import pad.plugins.base
import logging
import os
import dns
#import spamexperts
import pad.message
import ipaddress
from collections import defaultdict
from pad.networks import _format_network_str
#USER_AGENT = "SpamExperts/%s (filter/dns)" % spamexperts.__version__

FROM_HEADERS = ('From', "Envelope-Sender", 'Resent-From', 'X-Envelope-From', 'EnvelopeFrom')
TO_HEADERS = ('To', 'Resent-To', 'Resent-Cc', 'Apparently-To', 'Delivered-To',
              'Envelope-Recipients', 'Apparently-Resent-To', 'X-Envelope-To', 'Envelope-To',
              'X-Delivered-To', 'X-Original-To', 'X-Rcpt-To', 'X-Real-To', 'Cc')
TL_TLDS = ['.com', '.co.uk']

class WLBLEvalPlugin(pad.plugins.base.BasePlugin):
    eval_rules = ("check_from_in_whitelist", "check_to_in_whitelist",
                  "check_from_in_blacklist", "check_to_in_blacklist",
                  "check_from_in_list", "check_to_in_all_spam",
                  "check_to_in_list", "check_mailfrom_matches_rcvd",
                  "check_from_in_default_whitelist", "check_forged_in_whitelist",
                  "check_to_in_more_spam", "check_uri_host_listed", "check_uri_host_in_whitelist",
                  "check_uri_host_in_blacklist"
                  )
    options = {
        "blacklist_from": ("list", []),
        "whitelist_from": ("list", []),
        "whitelist_to": ("list", []),
        "blacklist_to": ("list", []),
        "all_spam_to": ("list", []),
        "more_spam_to list": ("list", []),
        "def_whitelist_from_rcvd": ("list", []),
        "whitelist_from_rcvd": ("list", []),
        "whitelist_allow_relays": ("list", []),
        "enlist_uri_host": ("list", []),
        "delist_uri_host": ("list", []),
        "blacklist_uri_host": ("list", []),
        "whitelist_uri_host": ("list", [])
    }

    parsed_lists = {
        "parsed_blacklist_from": ("dict", {}),
        "parsed_whitelist_from": ("dict", {}),
        "parsed_whitelist_to": ("dict", {}),
        "parsed_blacklist_to": ("dict", {}),
        "parsed_all_spam_to": ("dict", {}),
        "parsed_more_spam_to list": ("dict", {}),
        "parsed_def_whitelist_from_rcvd": ("dict", {}),
        "parsed_whiparsed_telist_from_rcvd": ("dict", {}),
        "parsed_whitelist_allow_relays": ("dict", {}),
        "parsed_enlist_uri_host": ("dict", {}),
        "parsed_delist_uri_host": ("dict", {})
    }


    def parse_list(self, list_name):
        parsed_list = defaultdict(list)
        for x in self[list_name]:
            parsed_list[x.split()[0]].append(x.split()[1])
        return parsed_list

    def my_list(self):
        return {"in_list": [], "not_in_list": []}

    def parse_delist_uri(self):
        parsed_list = defaultdict(list)
        for x in self['delist_uri_host']:
            uri_host_list = x.split()
            if "(" in x:
                key = uri_host_list[0].strip("( ").rstrip(" )")
                parsed_list[key].extend(uri_host_list[1:])
            else:
                parsed_list['ALL'].extend(uri_host_list)
        return parsed_list

    def add_in_list(self, key, item, parsed_list):
        if item.startswith("!"):
            parsed_list[key]["not_in_list"].append(item.strip("!"))
        else:
            parsed_list[key]["in_list"].append("." + item)
        return parsed_list

    def parse_list_uri(self, list_name):
        parsed_list = defaultdict(self.my_list)
        for x in self[list_name]:
            uri_host_list = x.split()
            key = uri_host_list[0].strip("( ").rstrip(" )")
            for item in uri_host_list[1:]:
                if item in self['parsed_delist_uri_host'][key]:
                    continue
                if item in self['parsed_delist_uri_host']['ALL']:
                    continue
                self.add_in_list(key, item, parsed_list)
        return parsed_list

    def check_start(self, msg):
        self['parsed_whitelist_from'] = self.parse_list('whitelist_from')
        self['parsed_whitelist_to'] = self.parse_list('whitelist_to')
        self['parsed_blacklist_from'] = self.parse_list('blacklist_from')
        self['parsed_blacklist_to'] = self.parse_list('blacklist_to')
        self['parsed_all_spam_to'] = self.parse_list('all_spam_to')
        self['parsed_more_spam_to list'] = self.parse_list('more_spam_to list')
        self['parsed_def_whitelist_from_rcvd'] = self.parse_list('def_whitelist_from_rcvd')
        self['parsed_whitelist_from_rcvd'] = self.parse_list('whitelist_from_rcvd')
        self['parsed_whitelist_allow_relays'] = self.parse_list('whitelist_allow_relays')
        self['parsed_enlist_uri_host'] = self.parse_list_uri('enlist_uri_host')
        self['parsed_delist_uri_host'] = self.parse_list_uri('delist_uri_host')

    def check_in_list(self, msg, addresses, list_name, param):
        for address in addresses:
            for regex in self[list_name]:
                if re.search(regex.replace("*", ".*"), address):
                    self.set_local(msg, param, 1)
                    return True
            wh = self.check_whitelist_rcvd(msg, list_name, None)
            if wh == 1:
                self.set_local(msg, param, 1)
                return True
            elif wh == -1:
                self.set_local(msg, param, -1)
        return False

    def check_address_in_list(self, addresses, list_name):
        for address in addresses:
            for regex in self[list_name]:
                if re.search(regex.replace("*", ".*"), address):
                    return True
        return False

    def check_in_default_whitelist(self, msg, addresses, list_name, param):
        for address in addresses:
            wh = self.check_whitelist_rcvd(msg, list_name, None)
            if wh == 1:
                self.set_local(msg, param, 1)
                return True
            elif wh == -1:
                self.set_local(msg, param, -1)
        return False

    def get_from_addresses(self, msg):
        addresses = msg.get_addr_header('Resent-From')
        if addresses:
            for address in addresses:
                yield address
        else:
            for key in FROM_HEADERS:
                for address in msg.get_addr_header(key):
                    yield address

    def get_to_addresses(self, msg):
        addresses = msg.get_addr_header('Resent-To')
        addresses.extend(msg.get_addr_header('Resent-Cc'))
        if addresses:
            for address in addresses:
                yield address
        else:
            for key in TO_HEADERS:
                for address in msg.get_addr_header(key):
                    yield address

    def base_domain(self, address):
        domain = address
        parts = domain.split('.')
        if len(parts) < 3:
            return ".".join(parts)
        if len([p for p in parts if not p.isdigit()]) == 0:
            # Handle numeric IPs in URIs similarly, but reverse the octet
            # ordering before comparison against the RBL. For example,
            # http://10.20.30.40/ is checked as 40.30.20.10.multi.surbl.org.
            return ".".join(parts[::-1])
        if ".".join(parts[-3:]) in TL_TLDS:
            return ".".join(parts[-4:])
        if ".".join(parts[-2:]) in TL_TLDS:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])


    def check_from_in_whitelist(self, msg, target = None):
        addresses = self.get_from_addresses(msg)
        list_name = 'parsed_whitelist_from'
        if self.get_local(msg, "from_in_whitelist") == 0:
            exists = self.check_in_list(msg, addresses, list_name,
                                        "from_in_whitelist")
        return self.get_local(msg, "from_in_whitelist") > 0


    def check_to_in_whitelist(self, msg, target = None):
        addresses = self.get_to_addresses(msg)
        list_name = 'parsed_whitelist_to'
        return self.check_address_in_list(addresses, list_name)


    def check_from_in_blacklist(self, msg, target = None):
        addresses = self.get_from_addresses(msg)
        list_name = 'parsed_blacklist_from'
        return self.check_address_in_list(addresses, list_name)


    def check_to_in_blacklist(self, msg, target = None):
        addresses = self.get_to_addresses(msg)
        list_name = 'parsed_blacklist_to'
        return self.check_address_in_list(addresses, list_name)


    def check_from_in_list(self, msg, list_name, target = None):
        if not list_name:
            return False
        addresses = self.get_from_addresses(msg)
        return self.check_address_in_list(addresses, list_name)


    def check_to_in_all_spam(self, msg, target=None):
        addresses = self.get_to_addresses(msg)
        list_name = 'parsed_all_spam_to'
        return self.check_address_in_list(addresses, list_name)

    def check_to_in_more_spam(self, msg, target=None):
        addresses = self.get_to_addresses(msg)
        list_name = 'parsed_more_spam_to list'
        return self.check_address_in_list(addresses, list_name)

    def check_to_in_list(self, msg, list_name, target=None):
        if not list_name:
            return False
        addresses = self.get_to_addresses(msg)
        return self.check_address_in_list(addresses, list_name)


    def check_from_in_default_whitelist(self, msg, target=None):
        addresses = self.get_from_addresses(msg)
        list_name = 'parsed_def_whitelist_from_rcvd'
        if self.get_local(msg, "from_in_default_whitelist") == 0:
            exists = self.check_in_list(msg, addresses, list_name,
                                        "from_in_default_whitelist")
        return self.get_local(msg, "from_in_default_whitelist") > 0


    def check_mailfrom_matches_rcvd(self, msg, target = None):
        """ test
            :param pad.message.Message msg: test
            :param list target: test
        """
        address = msg.sender_address
        relays = []
        if address:
            domain = self.base_domain(address.split("@")[1])
        else:
            return False
        if len(msg.untrusted_relays) > 0:
            relays.append(msg.untrusted_relays[0])
        elif len(msg.trusted_relays) > 0:
            relays.extend(msg.trusted_relays)
        else:
            return False
        relay_domain = ''
        for relay in relays:
            ip = ipaddress.ip_address(relay['ip']).exploded
            reversed_ip = str(dns.reversename.from_address(ip))
            parts = reversed_ip.rsplit(".",2)
            ip = parts.pop(0)
            relay_domain = ".".join(parts)
            if relay_domain == domain:
                return True
        return False


    def check_forged_in_whitelist(self, msg, target = None):
        self.check_from_in_whitelist(msg)
        self.check_from_in_default_whitelist(msg)
        checked_w = (self.get_local(msg, "from_in_whitelist") < 0)
        checked_dw = (self.get_local(msg, "from_in_default_whitelist") == 0)
        return checked_w and checked_dw


    check_forged_in_default_whitelist = check_forged_in_whitelist

    def check_whitelist_rcvd(self, msg, list_name, target = None):
        self.ctxt.log.debug("MESSAGE CHECK_WHITELIST_RCVD")
        if len(msg.untrusted_relays) + len(msg.trusted_relays) < 0:
            return 0
        relays = []
        if len(msg.untrusted_relays) > 0:
            relays = msg.untrusted_relays[0]
        elif len(msg.trusted_relays) > 0:
            relays.extend(msg.trusted_relays)

        address = msg.sender_address.lower()
        found_forged = 0
        for white_addr in self[list_name]:
            regexp = white_addr.replace("*", ".*")
            for domain in self[list_name][white_addr]:
                if re.search(regexp, address):
                    match = 0 # pe else
                    for relay in relays:
                        # extract the string between "[ ... ]"
                        wl_ip = domain.strip("[ ").rstrip(" ]")
                        rly_ip = relay['ip']
                        # check if is an IP address
                        try:
                            network = _format_network_str(str(wl_ip), None)
                            network = ipaddress.ip_network(network)
                            # same network
                            if ipaddress.ip_address(rly_ip) in network:
                                match = 1
                                break
                        except ValueError:
                            # it's not a valid IP - match by rdns
                            rdns = relay['rdns'].lower()
                            if domain in rdns:
                                match = 1
                                break
                    if match:
                        return 1
                    found_forged = -1
        if found_forged:
            wlist = self['parsed_whitelist_allow_relays']
            for key in wlist:
                for fuzzy_addr in wlist[key]:
                    if re.search(fuzzy_addr, address):
                        found_forged = 0
                        break
        return found_forged


    def check_uri_host_listed(self, msg, list_name, target=None):
        if self.get_local(msg, 'enlist_uri_host'):
            return self.get_local(msg, 'enlist_uri_host')
        for uri in msg.uri_list:
            if uri in self['parsed_enlist_uri_host'][list_name]['not_in_list']:
                continue
            for _uri_list_name in self['parsed_enlist_uri_host'][list_name]:
                if uri.endswith(_uri_list_name):
                    return True
        return True

    def check_uri_host_in_whitelist(self, msg, target=None):
        return self.check_uri_host_listed(self, msg, 'WHITE', None)

    def check_uri_host_in_blacklist(self, msg, target=None):
        return self.check_uri_host_listed(self, msg, 'BLACK', None)

