""" SPF Plugin."""

from __future__ import absolute_import

import re
import spf
import pad.plugins.base


class SpfPlugin(pad.plugins.base.BasePlugin):
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
        "whitelist_from_spf": ("append", []),
        "def_whitelist_from_spf": ("append", []),
        "spf_timeout": ("int", 5),
        "do_not_use_mail_spf": ("bool", False),
        "do_not_use_mail_spf_query": ("bool", False),
        "ignore_received_spf_header": ("bool", True),
        "use_newest_received_spf_header": ("bool", False)
    }

    def parsed_metadata(self, msg):

        if self.get_global("ignore_received_spf_header"):
            """ If this option is true:
                The plugin will ignore the spf headers and will perform
                SPF check by itself by querying the dns
            """
            timeout = self.get_global('spf_timeout')
            mx, ip = msg.hostname_with_ip[0]
            spf_result = self._query_spf(timeout, ip, mx, msg.sender_address)
            self.set_local(msg, 'spf_result', spf_result)
        else:
            """ If this option is false:
                The plugin will try to use the SPF results found in any
                Received-SPF headers it finds in the message that could only
                have been added by an internal relay
            """
            self.set_local(msg, 'spf_result', self._check_spf_header(msg, self.get_global("use_newest_received_spf_header")))

    def check_for_spf_pass(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "pass"

    def check_for_spf_neutral(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "neutral"

    def check_for_spf_none(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "none"

    def check_for_spf_fail(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "fail"

    def check_for_spf_softfail(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "softfail"

    def check_for_spf_permerror(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "permerror"

    def check_for_spf_temperror(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "temperror"

    def check_for_spf_helo_pass(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_pass"

    def check_for_spf_helo_neutral(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_neutral"

    def check_for_spf_helo_none(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_none"

    def check_for_spf_helo_fail(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_fail"

    def check_for_spf_helo_softfail(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_softfail"

    def check_for_spf_helo_permerror(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_permerror"

    def check_for_spf_helo_temperror(self, msg, target=None):
        return self.get_local(msg, "spf_result") == "helo_permerror"

    def check_for_spf_whitelist_from(self, msg, target=None):
        if msg.sender_address in self.get_global("whitelist_from_spf"):
            return True
        return False

    def check_for_def_spf_whitelist_from(self, msg, target=None):
        pass



    def _check_spf_header(self, msg, newest_header):
        """
        :return: 'pass', 'permerror', 'fail', 'temperror', 'softfail', 'none', 'neutral'
        By default the plugin will attempt to use the oldest(bottom most)
        received-spf or authentication-result header
        If this option is true the plugin will attempt to sue the newest(top most)
        received-spf or authentication-result header
        """
        if newest_header:
            received_spf_header = msg.get_decoded_header("received-spf")[0]
            authres_header = msg.get_decoded_header("authentication-results")[0]
        else:
            received_spf_header = msg.get_decoded_header("received-spf")[-1]
            authres_header = msg.get_decoded_header("authentication-results")[-1]
        result = ''
        if received_spf_header:
            parser = re.compile(r'^(pass|neutral|(?:soft)?fail|none|permerror|temperror)\b(?:.*\bidentity=(\S+?);?\b)?')
            match = parser.match(received_spf_header)
            if match:
                result = match.group(1)
                identity = str(match.group(2))
                if identity == 'mfrom' or identity == 'mailfrom' or identity == 'None':
                    identity = ''
                elif identity == 'helo':
                    identity = 'helo_'
                result = identity + result
        elif authres_header:
            parser = re.compile(r'^(pass|neutral|(?:hard|soft)?fail|none|permerror|temperror)(?:[^;]*?\bsmtp\.(\S+)\s*=[^;]+)?')
            match = parser.match(authres_header)
            if match:
                result = 'fail' if match.group(1) == 'hardfail' else match.group(1)
                identity = str(match.group(2))
                if identity == 'mfrom' or identity == 'mailfrom' or identity == 'None':
                    identity = ''
                elif identity == 'helo':
                    identity = 'helo_'
                result = identity + result
        return result

    def _query_spf(self, timeout, ip, mx, sender_address):
        self.ctxt.log.debug("SPF::Plugin %s", "Querying the dns server(%s, %s, %s)" % (ip, mx, sender_address))
        result, comment = spf.check2(i=ip, s=sender_address, h=mx, timeout=timeout)
        return result

















