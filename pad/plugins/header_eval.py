"""Expose some eval rules that do checks on the headers."""

from __future__ import division
from __future__ import absolute_import

import re
import email.header

import pad.locales
import pad.plugins.base

from pad.regex import Regex
from pad.received_parser import IP_ADDRESS


class HeaderEval(pad.plugins.base.BasePlugin):
    eval_rules = (
        "check_for_fake_aol_relay_in_rcvd",
        "check_for_faraway_charset_in_headers",
        "check_for_unique_subject_id",
        "check_illegal_chars",
        "check_for_forged_hotmail_received_headers",
        "check_for_no_hotmail_received_headers",
        "check_for_msn_groups_headers",
        "check_for_forged_eudoramail_received_headers",
        "check_for_forged_yahoo_received_headers",
        "check_for_forged_juno_received_headers",
        "check_for_matching_env_and_hdr_from",
        "sorted_recipients",
        "similar_recipients",
        "check_for_missing_to_header",
        "check_for_forged_gw05_received_headers",
        "check_for_round_the_world_received_helo",
        "check_for_round_the_world_received_revdns",
        "check_for_shifted_date",
        "subject_is_all_caps",
        "check_for_to_in_subject",
        "check_outlook_message_id",
        "check_messageid_not_usable",
        "check_header_count_range",
        "check_unresolved_template",
        "check_ratware_name_id",
        "check_ratware_envelope_from",
        "gated_through_received_hdr_remover",
    )

    def check_for_fake_aol_relay_in_rcvd(self, msg, target=None):
        """Check for common AOL fake received header."""
        for recv in msg.get_decoded_header("Received"):
            if not Regex(r" rly-[a-z][a-z]\d\d\.", re.I).search(recv):
                continue
            if Regex(r"\/AOL-\d+\.\d+\.\d+\)").search(recv):
                continue
            if Regex(r"ESMTP id (?:RELAY|MAILRELAY|MAILIN)").search(recv):
                continue
            return True
        return False

    def check_for_faraway_charset_in_headers(self, msg, target=None):
        """Check if the Subject/From header is in a NOT ok locale.

        This eval rule requires the ok_locales setting configured,
        and not set to ALL.
        """
        ok_locales = self.get_global("ok_locales")
        if not ok_locales or ok_locales.lower() == "all":
            return False
        ok_locales = ok_locales.split()

        # XXX We should really be checking ALL headers here,
        # XXX not just Subject and From.
        for header_name in ("Subject", "From"):
            for header in msg.get_raw_header(header_name):
                try:
                    decoded_header = email.header.decode_header(header)
                except (ValueError, email.header.HeaderParseError):
                    continue

                for value, charset in decoded_header:
                    if not pad.locales.charset_ok_for_locales(
                            charset, ok_locales):
                        return True

        return False

    def check_for_unique_subject_id(self, msg, target=None):
        return False

    def check_illegal_chars(self, msg, header, ratio, count, target=None):
        """look for 8-bit and other illegal characters that should be MIME
        encoded, these might want to exempt languages that do not use
        Latin-based alphabets, but only if the user wants it that way
        """
        try:
            ratio = float(ratio)
        except ValueError:
            self.ctxt.logger.warn("HeaderEval::Plugin check_illegal_chars "
                                  "invalid option: %s", ratio)
            return False
        try:
            count = int(count)
        except ValueError:
            self.ctxt.logger.warn("HeaderEval::Plugin check_illegal_chars "
                                  "invalid option: %s", count)
            return False
        if header == 'ALL':
            raw_headers = msg.raw_headers
            for hdr in ("Subject", "From"):
                del raw_headers[hdr]
        else:
            raw_headers = {header: msg.get_raw_header(header)}
        raw_str = ''.join([''.join(value) for value in raw_headers.values()])
        clean_hdr = ''.join([i if ord(i) < 128 else '' for i in raw_str])
        illegal = len(raw_str) - len(clean_hdr)
        if illegal > 0 and header.lower() == "subject":
            exempt = 0
            for except_chr in (u'\xa2', u'\xa3', u'\xae'):
                if except_chr in raw_str:
                    exempt += 1
            illegal -= exempt
        return (illegal / len(raw_str)) >= ratio and illegal >= count

    def check_for_forged_hotmail_received_headers(self, msg, target=None):
        return False

    def check_for_no_hotmail_received_headers(self, msg, target=None):
        return False

    def check_for_msn_groups_headers(self, msg, target=None):
        """Check if the email's destination is a msn group"""
        to = ''.join(msg.get_decoded_header('To'))
        if not Regex(r"<(\S+)\@groups\.msn\.com>").search(to):
            return False
        listname = Regex(r"<(\S+)\@groups\.msn\.com>").match(to).groups()[0]
        server_rgx = Regex(r"from mail pickup service by "
                           r"((?:p\d\d\.)groups\.msn\.com)\b")
        server = ''
        for rcvd in msg.get_decoded_header('Received'):
            if server_rgx.search(rcvd):
                server = server_rgx.search(rcvd).groups()[0]
                break
        if not server:
            return False
        message_id = ''.join(msg.get_decoded_header('Message-Id'))
        if listname == "notifications":
            if not Regex(r"^<\S+\@{0}".format(server)).search(message_id):
                return False
        else:
            msn_addr = Regex(r"^<{0}-\S+\@groups\.msn\.com>".format(listname))
            if not msn_addr.search(message_id):
                return False
            msn_addr = "{0}-bounce@groups.msn.com".format(listname)
            if msg.sender_address != msn_addr:
                return False
        return True

    def check_for_forged_eudoramail_received_headers(self, msg, target=None):
        """Check if the email has forged eudoramail received header"""
        from_addr = ''.join(msg.get_all_addr_header("From"))
        if from_addr.rsplit("@", 1)[-1] != "eudoramail.com":
            return False
        rcvd = ''.join(msg.get_decoded_header("Received"))
        ip = ''.join(msg.get_decoded_header("X-Sender-Ip"))
        if ip and IP_ADDRESS.search(ip):
            ip = True
        else:
            ip = False
        if self.gated_through_received_hdr_remover(msg):
            return False
        if Regex(r"by \S*whowhere.com\;").search(rcvd) and ip:
            return False
        return True

    def check_for_forged_yahoo_received_headers(self, msg, target=None):
        return False

    def check_for_forged_juno_received_headers(self, msg, target=None):
        return False

    def check_for_matching_env_and_hdr_from(self, msg, target=None):
        return False

    def sorted_recipients(self, msg, target=None):
        return False

    def similar_recipients(self, msg, target=None):
        return False

    def check_for_missing_to_header(self, msg, target=None):
        """Check if the To header is missing."""
        if msg.get_raw_header("To"):
            return False
        if msg.get_raw_header("Apparently-To"):
            return False
        return True

    def check_for_forged_gw05_received_headers(self, msg, target=None):
        return False

    def check_for_round_the_world_received_helo(self, msg, target=None):
        return False

    def check_for_round_the_world_received_revdns(self, msg, target=None):
        return False

    def check_for_shifted_date(self, msg, target=None):
        return False

    def subject_is_all_caps(self, msg, target=None):
        """Checks if the subject is all capital letters.

        This eval rule ignore short subjects, one word subject and
        the prepended notations. (E.g. ``Re:``)
        """
        for subject in msg.get_decoded_header("Subject"):
            # Remove the Re/Fwd notations in the subject
            subject = Regex(r"^(Re|Fwd|Fw|Aw|Antwort|Sv):").sub("", subject)
            subject = subject.strip()
            if len(subject) < 10:
                # Don't match short subjects
                continue
            if len(subject.split()) == 1:
                # Don't match one word subjects
                continue
            if subject.isupper():
                return True
        return False

    def check_for_to_in_subject(self, msg, target=None):
        return False

    def check_outlook_message_id(self, msg, target=None):
        return False

    def check_messageid_not_usable(self, msg, target=None):
        return False

    def check_header_count_range(self, msg, header, minr, maxr, target=None):
        """Check if the count of the header is withing the given range.
        The range is inclusive in both ranges.

        :param header: the header name
        :param minr: the minimum number of headers with the same name
        :param maxr: the minimum number of headers with the same name
        :return: True if the header count is withing the range.
        """
        return int(minr) <= len(msg.get_raw_header(header)) <= int(maxr)

    def check_unresolved_template(self, msg, target=None):
        return False

    def check_ratware_name_id(self, msg, target=None):
        return False

    def check_ratware_envelope_from(self, msg, target=None):
        return False

    def gated_through_received_hdr_remover(self, msg, target=None):
        """Check if the email is gated through ezmlm"""
        txt = ''.join(msg.get_decoded_header("Mailing-List"))
        rcvd = ''.join(msg.get_decoded.header("Received"))
        if Regex(r"^contact \S+\@\S+\; run by ezmlm$").search(txt):
            dlto = ''.join(msg.get_decoded_header("Delivered-To"))
            mailing_list_re = Regex(r"^mailing list \S+\@\S+")
            qmail_re = Regex(r"qmail \d+ invoked (?:from "
                             r"network|by .{3,20})\); \d+ ... \d+")
            if mailing_list_re.search(dlto) and qmail_re.search(rcvd):
                return True
        if not rcvd:
            return True
        if Regex(r"from groups\.msn\.com \(\S+\.msn\.com ").search(rcvd):
            return True
        return False
