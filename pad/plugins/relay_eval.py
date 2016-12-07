"""RelayEval Plugin

Check the data parsed from ReceivedParser against different rules
"""

import pad.plugins.base

from pad.received_parser import IP_ADDRESS
from pad.received_parser import IP_PRIVATE

from pad.regex import Regex


class RelayEval(pad.plugins.base.BasePlugin):
    """RelayEval plugin"""
    eval_rules = (
        "check_for_numeric_helo",
        "check_for_illegal_ip",
        "check_all_trusted",
        "check_no_relays",
        "check_relays_unparseable",
        "check_for_sender_no_reverse",
        "check_for_from_domain_in_received_headers",
        "check_for_forged_received_trail",
        "check_for_forged_received_ip_helo",
        "helo_ip_mismatch",
        "check_for_no_rdns_dotcom_helo"
    )
    options = {}

    @staticmethod
    def hostname_to_domain(hostname):
        if not Regex(r"[a-zA-Z]").match(hostname):
            return hostname
        parts = hostname.split(".")
        if len(parts) > 1 and Regex(r"(?:\S{3,}|ie|fr|de)").match(parts[-1]):
            return ".".join(parts[-2:])
        elif len(parts) > 2:
            return ".".join(parts[-3:])
        else:
            return hostname

    @staticmethod
    def _helo_forgery_whitelisted(helo, rdns):
        if helo == 'msn.com' and rdns == 'hotmail.com':
            return True
        return False

    @staticmethod
    def _check_helo(relay):
        helo = relay.get("helo")
        if helo and IP_ADDRESS.match(helo) and not IP_PRIVATE.match(helo):
            return True
        return False

    def check_for_numeric_helo(self, msg, option=None, target=None):
        for relay in msg.untrusted_relays:
            if self._check_helo(relay):
                return True
        return False

    def check_for_illegal_ip(self, msg, option=None, target=None):
        self.ctxt.log.debug("RelayEval::Plugin the 'check_for_illegal_ip' eval "
                            "rule no longer available, please update your rules")
        return False

    def check_all_trusted(self, msg, option=None, target=None):
        if msg.trusted_relays and not msg.untrusted_relays:
            return True
        return False

    def check_no_relays(self, msg, option=None, target=None):
        if not msg.trusted_relays and not msg.untrusted_relays:
            return True
        return False

    def check_relays_unparseable(self, msg, option=None, target=None):
        pass

    def check_for_sender_no_reverse(self, msg, option=None, target=None):
        """Check if the apparent sender (in the last received header) had
        no reverse lookup for it's IP
        Look for headers like:

        Received: from mx1.eudoramail.com ([204.32.147.84])"""
        srcvd = None
        if msg.untrusted_relays:
            srcvd = msg.untrusted_relays[-1]
        if not srcvd:
            return False
        if "." not in srcvd.get("rdns"):
            return False
        if IP_PRIVATE.match(srcvd.get("ip")):
            return False
        return True

    def check_for_from_domain_in_received_headers(self, msg, domain, desired,
                                                  option=None, target=None):
        try:
            from_addr = msg.get_addr_header("from")[0]
        except IndexError:
            from_addr = ''
        if domain not in from_addr:
            return False
        for relay in msg.trusted_relays + msg.untrusted_relays:
            if domain in relay.get("rdns") and domain in relay.get("by"):
                return desired == "true"
        return desired != "true"

    def check_for_forged_received_trail(self, msg, option=None, target=None):
        try:
            mismatch_from = self.get_global("mismatch_from")
        except KeyError:
            mismatch_from = None
        if mismatch_from is None:
            self._check_for_forged_received(msg)
        else:
            return bool(mismatch_from > 1)
        return bool(self.get_global("mismatch_from") > 1)

    def check_for_forged_received_ip_helo(self, msg, option=None, target=None):
        try:
            mismatch_ip_helo = self.get_global("mismatch_ip_helo")
        except KeyError:
            mismatch_ip_helo = None
        if mismatch_ip_helo is None:
            self._check_for_forged_received(msg)
        else:
            return bool(mismatch_ip_helo > 0)
        return bool(self.get_global("mismatch_ip_helo") > 0)

    def helo_ip_mismatch(self, msg, option=None, target=None):
        for relay in msg.untrusted_relays:
            if not self._check_helo(relay):
                continue
            helo = relay.get("helo")
            ip = relay.get("ip")
            netmask_24 = Regex(r"(\d+\.\d+\.\d+\.)").match(helo).group()
            if helo != ip and not ip.startswith(netmask_24):
                return True
        return False

    def check_for_no_rdns_dotcom_helo(self, msg, option=None, target=None):
        no_rdns_dotcom_helo = False
        for relay in msg.untrusted_relays:
            if IP_PRIVATE.match(relay.get("ip")):
                continue
            from_host = relay.get("rdns")
            helo_host = relay.get("helo")
            if not helo_host:
                continue
            no_rdns_dotcom_helo = False
            big_isp_re = Regex(
                r".*(?:\.|^)(lycos\.com|lycos\.co\.uk|hotmail\.com"
                r"|localhost\.com|excite\.com|caramail\.com|"
                r"cs\.com|aol\.com|msn\.com|yahoo\.com|"
                r"drizzle\.com)$")
            if big_isp_re.match(helo_host):
                if not from_host:
                    no_rdns_dotcom_helo = True
        return no_rdns_dotcom_helo

    def _check_for_forged_received(self, msg):
        mismatch_from = 0
        mismatch_ip_helo = 0
        hostname_re = Regex(r"^\w+(?:[\w.-]+\.)+\w+$")
        ip_re = Regex(r"^(\d+\.\d+)\.\d+\.\d+")
        for index, relay in enumerate(msg.untrusted_relays):
            from_ip = relay.get("ip")
            from_host = self.hostname_to_domain(relay.get("rdns"))
            by_host = self.hostname_to_domain(relay.get("by"))
            helo_host = self.hostname_to_domain(relay.get("helo"))
            if not by_host or not hostname_re.match(by_host):
                continue
            if from_host and from_ip == '127.0.0.1':
                    from_host = "undef"
            self.ctxt.log.debug("eval: forged-HELO: from=%s helo=%s by=%s" % (
                from_host if from_host else "(undef)",
                helo_host if helo_host else "(undef)",
                by_host if by_host else "(undef)"
            ))
            if not hostname_re.match(by_host):
                continue
            if (ip_re.match(helo_host) and
                    ip_re.match(from_ip) and from_ip != helo_host):
                try:
                    hclassb = ip_re.match(helo_host).groups()[0]
                except (AttributeError, IndexError):
                    hclassb = ''
                try:
                    fclassb = ip_re.match(from_ip).groups()[0]
                except (AttributeError, IndexError):
                    fclassb = ''
                if (hclassb and fclassb and hclassb != fclassb and
                        not IP_PRIVATE.match(helo_host)):
                    self.ctxt.log.debug("eval: forged-HELO: massive mismatch "
                                        "on IP-addr HELO: %s != %s" %
                                        (helo_host, from_ip))
                    mismatch_ip_helo += 1
            prev = msg.untrusted_relays[index - 1]
            if prev and index > 0:
                prev_from_host = prev.get("rdns")
                if (hostname_re.match(prev_from_host)
                    and by_host != prev_from_host
                    and not self._helo_forgery_whitelisted(by_host,
                                                           prev_from_host)):
                    self.ctxt.log.debug("eval: forged-HELO: mismatch on from: "
                                        "%s != %s" % (prev_from_host, by_host))
                    mismatch_from += 1
        self.set_global("mismatch_from", mismatch_from)
        self.set_global("mismatch_ip_helo", mismatch_ip_helo)
