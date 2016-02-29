"""Expose some eval rules that do checks on DNS lists."""

from __future__ import division
from __future__ import absolute_import

import re
import ipaddress

import pad.rules.eval_
import pad.plugins.base


ACCREDITOR_RE = re.compile(r"[@.]a--([a-z0-9]{3,})\.", re.I)


class DNSEval(pad.plugins.base.BasePlugin):

    eval_rules = (
        "check_rbl",
        "check_rbl_txt",
        "check_rbl_sub",
        "check_dns_sender",
        "check_rbl_envfrom",
        "check_rbl_from_host",
        "check_rbl_from_domain",
        "check_rbl_accreditor",
        # Deprecated in SA
        #"check_rbl_results_for",
    )

    def finish_parsing_end(self, ruleset):
        """Configure any multi results RBL checks."""
        super(DNSEval, self).finish_parsing_end(ruleset)
        # This is one annoying workaround because SA has a
        # very strange way of defining these.
        # When a check_rbl_sub is called for one zone ID
        # a new rule is actually registered that is triggered
        # at some later point.
        # Instead of doing the same thing and registering new
        # rules every time we parse a message simply store
        # the required data here.

        # Map zone-ids to their corresponding lists.
        ignore_evals = (
            "check_dns_sender",
            "check_rbl_sub",
        )
        zones = {}
        for rule_list in (ruleset.checked, ruleset.not_checked):
            for rule in rule_list.values():
                if not isinstance(rule, pad.rules.eval_.EvalRule):
                    continue
                name = rule.eval_rule_name
                if name in ignore_evals or name not in self.eval_rules:
                    continue
                # This eval rule actually check one rbl servers
                # and adds a zone id.
                zone_id = rule.eval_args[0].rsplit("-")[0].strip()
                rbl_server = rule.eval_args[1]
                zones[zone_id] = rbl_server
        self["zones"] = zones

    def _check_rbl(self, msg, rbl_server, qtype="A", subtest=None):
        """Checks all the IPs of this message on the specified
        list.

        :param msg: The message that we perform the check on.
        :param rbl_server: The RBL list to check
        :param qtype: The DNS record type to check
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        if subtest is not None:
            try:
                subtest = re.compile(subtest)
            except re.error as e:
                self.ctxt.err("Invalid regex %s: %s", subtest, e)
                return False

        for ip in msg.get_untrusted_ips():
            rev = self.ctxt.reverse_ip(ip)
            results = self.ctxt.query_dns("%s.%s" % (rev, rbl_server), qtype)

            if results and not subtest:
                return True

            for result in results:
                if subtest.match(str(result)):
                    return True
        return False

    def _check_multi_rbl(self, msg, rbl_server, mask=None):
        """Checks all the IPs of this message on the specified
        list.

        :param msg: The message that we perform the check on.
        :param rbl_server: The RBL list to check
        :param mask: If specified the result is checked for
          the specified bits being set.
        :return: True if there is a match and the mask
          passes and False otherwise.
        """
        if mask is not None:
            try:
                mask = int(mask)
            except (ValueError, TypeError):
                try:
                    mask = int(ipaddress.ip_address(mask))
                except ValueError as e:
                    self.ctxt.err("Invalid mask %s: %s", mask, e)
                    return False

        for ip in msg.get_untrusted_ips():
            rev = self.ctxt.reverse_ip(ip)
            results = self.ctxt.query_dns("%s.%s" % (rev, rbl_server), "A")

            if results and not mask:
                return True

            for result in results:
                result = ipaddress.ip_address(str(result))
                if int(result) & mask:
                    return True
        return False

    def _check_rbl_addr(self, addresses, rbl_server, subtest=None):
        """Checks the specified addresses on the specified list.

        :param addresses: A list of addresses to check
        :param rbl_server: The RBL list to check
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        if subtest is not None:
            try:
                subtest = re.compile(subtest)
            except re.error as e:
                self.ctxt.err("Invalid regex %s: %s", subtest, e)
                return False

        for addr in addresses:
            if "@" in addr:
                domain = addr.rsplit("@", 1)[1].strip()
            else:
                domain = addr.strip()
            results = self.ctxt.query_dns("%s.%s" % (addr, rbl_server), "A")

            if results and not subtest:
                return True

            for result in results:
                if subtest.match(str(result)):
                    return True
        return False

    def check_rbl(self, msg, zone_set, rbl_server, subtest=None, target=None):
        """Checks all the IPs of this message on the specified
        list.

        :param zone_set: Define zone ID for this lookup.
        :param rbl_server: The RBL server to check.
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        return self._check_rbl(msg, rbl_server, qtype="A", subtest=subtest)

    def check_rbl_accreditor(self, msg, zone_set, rbl_server, subtest,
                             accreditor, target=None):
        """Checks all the IPs of this message on the specified
        list, but only if the sender has the specified
        accreditor tag.

        An accreditor tag can be specified like::

             listowner@a--accreditor.mail.example.com

        Or in a `Accreditor` header.

        :param zone_set:  Define zone ID for this lookup.
        :param rbl_server: The RBL server to check.
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :param accreditor: Only perform the check if the
          sender has this accreditor tag.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        tags = []
        try:
            tags.append(ACCREDITOR_RE.search(msg.sender_address).groups()[0])
        except (AttributeError, IndexError):
            pass

        for header in msg.get_decoded_header("Accreditor"):
            try:
                tags.extend(part.split(",")[0].strip()
                            for part in header.split(";"))
            except IndexError as e:
                self.ctxt.log.info("Unable to parse Accreditor header %r: %s",
                                   header, e)
                continue
        if accreditor not in tags:
            self.ctxt.log.debug("Accreditor %s not in message tags %s",
                                accreditor, tags)
            return False
        return self.check_rbl(msg, zone_set, rbl_server, subtest, target)

    def check_rbl_txt(self, msg, zone_set, rbl_server, subtest=None,
                      target=None):
        """Checks all the IPs of this message on the specified
        list.

        :param zone_set: Define zone ID for this lookup.
        :param rbl_server: The RBL server to check.
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        return self._check_rbl(msg, rbl_server, qtype="TXT", subtest=subtest)

    def check_rbl_sub(self, msg, zone_set, subtest, target=None):
        """Check the result of a previous lookup for multi response
        results.

        :param zone_set: A zone ID previously defined in another lookup.
        :param subtest: A integer or IP address that will be used as a
          mask for the check against the RBL result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        try:
            rbl_server = self["zones"][zone_set]
        except KeyError as e:
            self.ctxt.err("Invalid zone %s: %s", zone_set, e)
            return False
        return self._check_multi_rbl(msg,rbl_server, subtest)

    def check_dns_sender(self, msg, target=None):
        """Check if the sender domain has MX or A records.

        :return: True if the sender has neither MX or A
          records, and False otherwise.
        """
        if not msg.sender_address:
            self.ctxt.log.debug("Message has no envelope sender")
            return False

        if "@" in msg.sender_address:
            domain = msg.sender_address.rsplit("@", 1)[1]
        else:
            domain = msg.sender_address

        if self.ctxt.query_dns(domain, "A"):
            return False
        if self.ctxt.query_dns(domain, "MX"):
            return False
        self.ctxt.log.debug("Sending domain %s has no MX or A records",
                            domain)
        return True

    def check_rbl_envfrom(self, msg, zone_set, rbl_server, subtest=None,
                          target=None):
        """Check the envelope sender domain for matches on this
        list.

        Note the envelope sender is determined according to the
        envelope_sender_header option.

        :param zone_set: Define zone ID for this lookup.
        :param rbl_server: The RBL server to check.
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        if not msg.sender_address:
            self.ctxt.log.debug("Message has no envelope sender")
            return False
        return self._check_rbl_addr([msg.sender_address], rbl_server, subtest)

    def check_rbl_from_domain(self, msg, zone_set, rbl_server, subtest=None,
                              target=None):
        """Check the From header domain for matches on this
        list.

        :param zone_set: Define zone ID for this lookup.
        :param rbl_server: The RBL server to check.
        :param subtest: If specified then an additional check
          is done on the result of the DNS lookup by matching
          this regular expression against the result.
        :return: True if there is a match and the subtest
          passes and False otherwise.
        """
        from_addrs = msg.get_addr_header("From")
        if not from_addrs:
            self.ctxt.log.debug("Message has no From header")
            return False
        return self._check_rbl_addr(from_addrs, rbl_server, subtest)

    # This two do the same thing
    check_rbl_from_host = check_rbl_from_domain

