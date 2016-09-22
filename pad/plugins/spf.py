""" SPF Plugin."""

from __future__ import absolute_import

import re
import spf
import pad.plugins.base
import pad.message

RECEIVED_RE = re.compile(r"""
    ^(pass|neutral|(?:soft)?fail|none|
    permerror|temperror)
    \b(?:.*\bidentity=(\S+?);?\b)?
""", re.I | re.S | re.X | re.M)
AUTHRES_SPF = re.compile(r'.*;\s*spf\s*=\s*([^;]*)', re.I | re.S | re.X | re.M)
AUTHRES_RE = re.compile(r"""
    ^(pass|neutral|(?:hard|soft)?fail|none|
    permerror|temperror)(?:[^;]*?
    \bsmtp\.(\S+)\s*=[^;]+)?
""", re.I | re.S | re.X | re.M)


class SpfPlugin(pad.plugins.base.BasePlugin):
    spf_check = False
    spf_check_helo = False
    eval_rules = (
        "check_for_spf_pass",
        "check_for_spf_neutral",
        "check_for_spf_none",
        "check_for_spf_fail",
        "check_for_spf_softfail",
        "check_for_spf_permerror",
        "check_for_spf_temperror",
        "check_for_spf_helo_pass",
        "check_for_spf_helo_neutral",
        "check_for_spf_helo_none",
        "check_for_spf_helo_fail",
        "check_for_spf_helo_softfail",
        "check_for_spf_helo_permerror",
        "check_for_spf_helo_temperror",
        "check_for_spf_whitelist_from",
        "check_for_def_spf_whitelist_from"
    )
    options = {
        "whitelist_from_spf": ("append_split", []),
        "def_whitelist_from_spf": ("append_split", []),
        "spf_timeout": ("timevalue", 5),
        "do_not_use_mail_spf": ("bool", False),
        "do_not_use_mail_spf_query": ("bool", False),
        "ignore_received_spf_header": ("bool", False),
        "use_newest_received_spf_header": ("bool", False)
    }
    check_result = {
        "check_spf_pass": 0,
        "check_spf_neutral": 0,
        "check_spf_none": 0,
        "check_spf_fail": 0,
        "check_spf_softfail": 0,
        "check_spf_permerror": 0,
        "check_spf_temperror": 0,
        "check_spf_helo_pass": 0,
        "check_spf_helo_neutral": 0,
        "check_spf_helo_none": 0,
        "check_spf_helo_fail": 0,
        "check_spf_helo_softfail": 0,
        "check_spf_helo_permerror": 0,
        "check_spf_helo_temperror": 0,
        "check_spf_whitelist_from": 0,
        "check_def_spf_whitelist_from": 0
    }

    def parsed_metadata(self, msg):
        if self.get_global("ignore_received_spf_header"):
            # The plugin will ignore the spf headers and will perform
            # SPF check by itself by querying the dns
            if msg.get_decoded_header("received"):
                self.received_headers(msg, '')
                if msg.sender_address:
                    self.received_headers(msg, msg.sender_address)
        else:
            # # The plugin will try to use the SPF results found in any
            # # Received-SPF headers it finds in the message that could only
            # # have been added by an internal relay
            self.check_spf_header(msg)

    def check_for_spf_pass(self, msg, target=None):
        return self.check_result["check_spf_pass"] == 1

    def check_for_spf_neutral(self, msg, target=None):
        return self.check_result["check_spf_neutral"] == 1

    def check_for_spf_none(self, msg, target=None):
        return self.check_result["check_spf_none"] == 1

    def check_for_spf_fail(self, msg, target=None):
        return self.check_result["check_spf_fail"] == 1

    def check_for_spf_softfail(self, msg, target=None):
        return self.check_result["check_spf_softfail"] == 1

    def check_for_spf_permerror(self, msg, target=None):
        return self.check_result["check_spf_permerror"] == 1

    def check_for_spf_temperror(self, msg, target=None):
        return self.check_result["check_spf_temperror"] == 1

    def check_for_spf_helo_pass(self, msg, target=None):
        return self.check_result["check_spf_helo_pass"] == 1

    def check_for_spf_helo_neutral(self, msg, target=None):
        return self.check_result["check_spf_helo_neutral"] == 1

    def check_for_spf_helo_none(self, msg, target=None):
        return self.check_result["check_spf_helo_none"] == 1

    def check_for_spf_helo_fail(self, msg, target=None):
        return self.check_result["check_spf_helo_fail"] == 1

    def check_for_spf_helo_softfail(self, msg, target=None):
        return self.check_result["check_spf_helo_softfail"] == 1

    def check_for_spf_helo_permerror(self, msg, target=None):
        return self.check_result["check_spf_helo_permerror"] == 1

    def check_for_spf_helo_temperror(self, msg, target=None):
        return self.check_result["check_spf_helo_temperror"] == 1

    def check_for_spf_whitelist_from(self, msg, target=None):
        return self.check_spf_whitelist(msg, "whitelist_from_spf")

    def check_for_def_spf_whitelist_from(self, msg, target=None):
        return self.check_spf_whitelist(msg, "def_whitelist_from_spf")

    def check_spf_whitelist(self, msg, list_name):
        parsed_list = self.parse_list(list_name)
        if self[list_name]:
            if not self.check_for_spf_pass(msg):
                return False
        for regex in parsed_list:
            if re.match(regex, msg.sender_address):
                return True
        return False

    def parse_list(self, list_name):
        parsed_list = []
        characters = ["?", "@", ".", "*@"]
        for addr in self[list_name]:
            if len([e for e in characters if e in addr]):
                address = re.escape(addr).replace(r"\*", ".*").replace(r"\?",
                                                                       ".?")
                if "@" in address:
                    parsed_list.append(address)
                else:
                    parsed_list.append(".*@" + address)
        return parsed_list

    def check_spf_header(self, msg):
        authres_header = msg.msg["authentication-results"]
        received_spf_headers = msg.get_decoded_header("received-spf")
        if not self["use_newest_received_spf_header"]:
            received_spf_headers.reverse()
        if received_spf_headers:
            for spf_header in received_spf_headers:
                match = RECEIVED_RE.match(spf_header)
                if not match:
                    self.ctxt.log.debug("PLUGIN::SPF: invalid Received_SPF "
                                        "header")
                    continue
                result = match.group(1)
                if match.group() == result:
                    identity = ''
                elif match.group(2) != 'None':
                    identity = match.group(2)
                else:
                    # Received-SPF: fail (example.org: domain of test@example.org) identity=None
                    continue
                if identity:
                    if identity in ('mfrom', 'mailfrom', 'None'):
                        if self.spf_check:
                            continue
                        identity = ''
                        self.spf_check = True
                    elif identity == 'helo':
                        if self.spf_check_helo:
                            continue
                        self.spf_check_helo = True
                    else:
                        continue
                elif self.spf_check:
                    continue

                result.replace("error", "temperror")
                if identity:
                    spf_identity = "check_spf_%s_%s" % (identity, result)
                else:
                    spf_identity = "check_spf_%s" % result
                    self.spf_check = True
                self.check_result[spf_identity] = 1
            if self.spf_check and self.spf_check_helo:
                return

        elif authres_header:
            self.ctxt.log.debug("PLUGIN::SPF: %s",
                                "found an Authentication-Results header "
                                "added by an internal host")
            extract_spf = AUTHRES_SPF.match(authres_header)
            match = None
            if extract_spf:
                match = AUTHRES_RE.match(extract_spf.group(1))
            if match:
                result = 'fail' if match.group(
                    1) == 'hardfail' else match.group(1)
                identity = str(match.group(2))
                if identity in ('mfrom', 'mailfrom', 'None'):
                    identity = ''
                elif identity == 'helo':
                    identity = 'helo'
                if identity:
                    spf_identity = "check_spf_%s_%s" % (identity, result)
                else:
                    spf_identity = "check_spf_%s" % result
                self.check_result[spf_identity] = 1

        if msg.get_decoded_header("received"):
            if not received_spf_headers:
                self.received_headers(msg, '')
            if msg.sender_address:
                if self.spf_check_helo:
                    self.received_headers(msg, msg.sender_address)
                else:
                    self.received_headers(msg, '')

    def received_headers(self, msg, sender):
        timeout = self.get_global("spf_timeout")
        if not msg.external_relays:
            return
        mx = msg.external_relays[0]['rdns']
        ip = msg.external_relays[0]['ip']

        spf_result = self._query_spf(timeout, ip, mx, sender)
        if spf_result == "error":
            spf_result = "temperror"
        if self.spf_check_helo:
            spf_identity = "check_spf_%s" % spf_result
            self.check_result[spf_identity] = 1
        elif re.match(".*\..*", mx):
            spf_identity = "check_spf_helo_%s" % spf_result
            self.spf_check_helo = True
            self.check_result[spf_identity] = 1
        else:
            self.spf_check_helo = True

    def _query_spf(self, timeout, ip, mx, sender_address):
        self.ctxt.log.debug("SPF::Plugin %s",
                            "Querying the dns server(%s, %s, %s)..."
                            % (ip, mx, sender_address))
        print(timeout)
        result, comment = spf.check2(i=ip, s=sender_address,
                                     h=mx, timeout=timeout, querytime=timeout)
        return result




