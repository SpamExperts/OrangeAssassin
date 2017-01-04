***********
RelayEvalPlugin
***********

Check the data parsed from ReceivedParser against different rules.

Evaluate a set of rules against "Received" headers, they are form a list of all
the servers/computers through which the message traveled in order to reach
the destination.

Example usage
=============

.. code-block:: none

    loadplugin pad.plugins.relay_eval.RelayEval

    header RCVD_HELO_IP_MISMATCH	eval:helo_ip_mismatch()
    describe RCVD_HELO_IP_MISMATCH	Received: HELO and IP do not match, but should

    header RCVD_NUMERIC_HELO	eval:check_for_numeric_helo()
    describe RCVD_NUMERIC_HELO	Received: contains an IP address used for HELO

    header __FORGED_RCVD_TRAIL	eval:check_for_forged_received_trail()

    header NO_RDNS_DOTCOM_HELO	eval:check_for_no_rdns_dotcom_helo()
    describe NO_RDNS_DOTCOM_HELO	Host HELO'd as a big ISP, but had no rDNS


Usage
=====

This plugin only has EVAL methods. See :ref:`eval-rule` for general
details on how to use such methods.

Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_numeric_helo
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_illegal_ip
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_all_trusted
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_no_relays
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_relays_unparseable
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_sender_no_reverse
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_from_domain_in_received_headers
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_forged_received_trail
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_forged_received_ip_helo
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.helo_ip_mismatch
:noindex:
.. automethod:: pad.plugins.relay_eval.RelayEval.check_for_no_rdns_dotcom_helo
:noindex:

Tags
====

None
