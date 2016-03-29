***********
PyzorPlugin
***********

Checks the message against the Pyzor server.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.pyzor.PyzorPlugin

    body        PYZOR	    eval:check_pyzor()
    describe    PYZOR   	Listed in Pyzor (http://pyzor.org)
    score       PYZOR       2

Usage
=====

This plugin exposes a single eval rule that checks the message
against the Pyzor server. For more information about pyzor see
the `Pyzor documentation <http://pyzor.org>`_

Options
=======

**use_pyzor** True (type `bool`)
    Controls whether or not the message should be checked against the
    Pyzor server.
**pyzor_servers** ['public.pyzor.org:24441'] (type `list`)
    A list of Pyzor servers to check. The plugin will check ALL servers
    specified in this list.
**pyzor_max** 5 (type `int`)
    The minimum number of times a message needs to be reported as spam
    to have the rule match.
**pyzor_timeout** 3.5 (type `float`)
    The timeout for the server response.

EVAL rules
==========

.. automethod:: pad.plugins.pyzor.PyzorPlugin.check_pyzor
    :noindex:

Tags
====

**_PYZOR_DIGEST_**
    The pyzor digest
**_PYZOR_COUNT_**
    The number of times the message was reported as spam on Pyzor
**_PYZOR_WL_COUNT_**
    The number of times the message was whitelisted on Pyzor


