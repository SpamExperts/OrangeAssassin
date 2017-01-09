***********
Header Eval
***********

Expose some eval rules that do checks on the headers.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.header_eval.HeaderEval

    header DATE_IN_PAST_03_06       eval:check_for_shifted_date('-6', '-3')
    describe DATE_IN_PAST_03_06     Date: is 3 to 6 hours before Received: date


Usage
=====

This plugin exposes various eval rules that perform checks on the headers
of the message.

See documentation for each individual rule.

Options
=======

**util_rb_tld** [] (type `append_split`)
    Add to the TLD list
**util_rb_2tld** [] (type `append_split`)
    Add to the 2 level TLD list
**util_rb_3tld** [] (type `append_split`)
    Add to the 3 level TLD list

EVAL rules
==========

.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_fake_aol_relay_in_rcvd
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_faraway_charset_in_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_unique_subject_id
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_illegal_chars
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_forged_hotmail_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_no_hotmail_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_msn_groups_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_forged_eudoramail_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_forged_yahoo_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_forged_juno_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_matching_env_and_hdr_from
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.sorted_recipients
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.similar_recipients
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_missing_to_header
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_forged_gw05_received_headers
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_shifted_date
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.subject_is_all_caps
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_for_to_in_subject
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_outlook_message_id
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_messageid_not_usable
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_header_count_range
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_unresolved_template
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_ratware_name_id
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_ratware_envelope_from
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.gated_through_received_hdr_remover
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.check_equal_from_domains
    :noindex:
.. automethod:: pad.plugins.header_eval.HeaderEval.received_within_months
    :noindex:

Tags
====

N/A
