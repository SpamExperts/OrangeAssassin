*************
WLBLEvalPlugin
*************

This plugin checks if from addresses and to addresses are in options list
by domanin, IP and URI.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.wlbl_eval.WLBLEvalPlugin

Usage
=====

<Description>

Options
=======

**blacklist_from** [] (type `list`)
    <Option description>
**whitelist_from** [] (type `list`)
    <Option description>
**whitelist_to** [] (type `list`)
    <Option description>
**blacklist_to** [] (type `list`)
    <Option description>
**all_spam_to** [] (type `list`)
    <Option description>
**more_spam_to** [] (type `list`)
    <Option description>
**def_whitelist_from_rcvd** [] (type `list`)
    <Option description>
**whitelist_from_rcvd** [] (type `list`)
    <Option description>
**whitelist_allow_relays** [] (type `list`)
    <Option description>
**enlist_uri_host** [] (type `list`)
    <Option description>
**delist_uri_host** [] (type `list`)
    <Option description>
**blacklist_uri_host** [] (type `list`)
    <Option description>
**whitelist_uri_host** [] (type `list`)
    <Option description>
**util_rb_tld** [] (type `append_split`)
    <Option description>
**util_rb_2tld** [] (type `append_split`)
    <Option description>
**util_rb_3tld** [] (type `append_split`)
    <Option description>


EVAL rules
==========

.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_from_in_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_from_in_blacklist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_blacklist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_from_in_list
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_all_spam
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_list
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.
                                        check_mailfrom_matches_rcvd
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.
                                        check_from_in_default_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_forged_in_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_more_spam
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.
                                        check_forged_in_default_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_uri_host_listed
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.
                                        check_uri_host_in_whitelist
:noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.
                                        check_uri_host_in_blacklist
:noindex:

Tags
====

<Describe TAGS>

