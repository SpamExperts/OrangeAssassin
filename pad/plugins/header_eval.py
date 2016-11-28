"""Expose some eval rules that do checks on the headers."""

from __future__ import division
from __future__ import absolute_import

import re
import collections

import pad.plugins.base

from pad.regex import Regex


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
        return False


    def check_for_unique_subject_id(self, msg, target=None):
        return False


    def check_illegal_chars(self, msg, target=None):
        return False


    def check_for_forged_hotmail_received_headers(self, msg, target=None):
        return False


    def check_for_no_hotmail_received_headers(self, msg, target=None):
        return False


    def check_for_msn_groups_headers(self, msg, target=None):
        return False


    def check_for_forged_eudoramail_received_headers(self, msg, target=None):
        return False


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
        return False


    def check_for_forged_gw05_received_headers(self, msg, target=None):
        return False


    def check_for_round_the_world_received_helo(self, msg, target=None):
        return False


    def check_for_round_the_world_received_revdns(self, msg, target=None):
        return False


    def check_for_shifted_date(self, msg, target=None):
        return False


    def subject_is_all_caps(self, msg, target=None):
        return False


    def check_for_to_in_subject(self, msg, target=None):
        return False


    def check_outlook_message_id(self, msg, target=None):
        return False


    def check_messageid_not_usable(self, msg, target=None):
        return False


    def check_header_count_range(self, msg, target=None):
        return False


    def check_unresolved_template(self, msg, target=None):
        return False


    def check_ratware_name_id(self, msg, target=None):
        return False


    def check_ratware_envelope_from(self, msg, target=None):
        return False
