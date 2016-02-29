
*******
DNSEval
*******

Expose some eval rules that do checks on DNS lists.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.dns_eval.DNSEval

Usage
=====

.. code-block:: none

    loadplugin      pad.plugins.dns_eval.DNSEval

    header IP_IN_LIST        eval:check_rbl('example', 'example.com.', '127.0.0.10')
    describe IP_IN_LIST      IP in example.com list with response 10

Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_txt
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_sub
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_dns_sender
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_envfrom
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_from_host
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_from_domain
    :noindex:
.. automethod:: pad.plugins.dns_eval.DNSEval.check_rbl_accreditor
    :noindex:

Tags
====

None

