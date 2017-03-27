**********
SPF Plugin 
**********

This plugin checks a message against Sender Policy Framework (SPF) 
records published by the domain owners in DNS to fight email 
address forgery and make it easier to identify spams.

Example usage
=============
Evaluation of an SPF record can return any of these results:
**Pass**
    The SPF record designates the host to be allowed to send. 
    Action: accept.
**Fail**
    The SPF record has designated the host as NOT being allowed to send.
    Action: reject.
**SoftFail**
    The SPF record has designated the host as NOT being allowed to send 
    but is in transition. Action: accept but mark.
**Neutral**
    The SPF record specifies explicitly that nothing can be said about 
    validity. Action: accept.
**None**
    The domain does not have an SPF record or the SPF record does not 
    evaluate to a result. Action: accept.
**PermError**
    A permanent error has occured (eg. badly formatted SPF record).
    Action: unspecified.
**TempError**
    A transient error has occured. Action: accept or reject

.. code-block:: none

    loadplugin      pad.plugins.spf.SpfPlugin

    header SPF_PASS		eval:check_for_spf_pass()
    header SPF_NEUTRAL		eval:check_for_spf_neutral()
    header SPF_FAIL		eval:check_for_spf_fail()
    header SPF_SOFTFAIL		eval:check_for_spf_softfail()

Usage
=====

This plugin has EVAL methods. See :ref:`eval-rule` for general
details on how to use such methods.

Options
=======
**whitelist_from_spf address@example.com**
    <Not available yet>

**spf_timeout n (default: 5)**
    How many seconds to wait for an SPF query to complete, 
    before scanning continues without the SPF result.

**ignore_received_spf_header (False|True) (default: False)**
    By default, to avoid unnecessary DNS lookups, the plugin will try to 
    use the SPF results found in any `Received-SPF` headers it finds in
    the message that could only have been added by an internal relay

    Set this option to True to ignore any `Received-SPF` headers present
    and to have the plugin perform the SPF check itself.

**use_newest_received_spf_header (False|True) (default: False)**
    By default, when using `Received-SPF` headers, the plugin will attempt
    to use the oldest (bottom most) `Received-SPF` headers, that were added
    by internal relays, that it can parse the results from since they are
    the most likely to be accurate.This is done so that if you have an
    incoming mail setup where one of your primary MXes doesn't know about
    a secondary MX (or your MXes don't know about some sort of forwarding 
    relay that SA considers trusted+internal) but SA is aware of the actual
    domain boundary (internal_networks setting) SA will use the results 
    that are most accurate. 

    Use this option to start with the newest (top most) `Received-SPF` 
    headers, working downwards until results are successfully parsed.

EVAL rules
==========

.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_pass
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_neutral
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_none
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_fail
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_softfail
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_permerror
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_temperror
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_pass
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_neutral
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_none
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_fail
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_softfail
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_permerror
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_helo_temperror
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_spf_whitelist_from
    :noindex:
.. automethod:: pad.plugins.spf.SpfPlugin.check_for_def_spf_whitelist_from
    :noindex:

Tags
====

None
