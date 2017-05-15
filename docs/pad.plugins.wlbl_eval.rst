**************
WLBLEvalPlugin
**************

This plugin checks if from addresses and to addresses are in options list
by domanin, IP and URI.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.wlbl_eval.WLBLEvalPlugin

Usage
=====

N/A

Options
=======

**blacklist_from** [] (type `append_split`)
    Used to specify addresses which send mail that is often tagged (incorrectly)
    as non-spam, but which the user doesn't want. Same format as whitelist_from.
**whitelist_from** [] (type `append_split`)
    Used to whitelist sender addresses which send mail that is often tagged
    (incorrectly) as spam.
**whitelist_to** [] (type `append_split`)
    If the given address appears as a recipient in the message headers
    (Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will be
    whitelisted. There are three levels of To-whitelisting, whitelist_to,
    more_spam_to and all_spam_to. Users in the first level may still get some
    spammish mails blocked, but users
    in all_spam_to should never get mail blocked.
**all_spam_to** [] (type `append_split`)
    See above.
**more_spam_to** [] (type `append_split`)
    See above.
**blacklist_to** [] (type `append_split`)
    If the given address appears as a recipient in the message headers
    (Resent-To, To, Cc, obvious envelope recipient, etc.) the mail will be blacklisted.
**def_whitelist_from_rcvd** [] (type `list`)
    Same as whitelist_from_rcvd, but used for the default whitelist entries
    in the OrangeAssassin distribution. The whitelist score is lower, because these
    are often targets for spammer spoofing.
**whitelist_from_rcvd** [] (type `list`)
    Works similarly to whitelist_from, except that in addition to matching a sender
    address, a relay's rDNS name or its IP address must match too for the whitelisting
    rule to fire. The first parameter is a sender's e-mail address to whitelist,
    and the second is a string to match the relay's rDNS, or its IP address.
**whitelist_allow_relays** [] (type `append_split`)
    Specify addresses which are in whitelist_from_rcvd that sometimes send through
    a mail relay other than the listed ones.
**enlist_uri_host** [] (type `list`)
    Adds one or more host names or domain names to a named list of URI domains.
**delist_uri_host** [] (type `list`)
    Removes one or more specified host names from a named list of URI domains.
**blacklist_uri_host** [] (type `list`)
    Is a shorthand for a directive: enlist_uri_host (BLACK) host.
**whitelist_uri_host** [] (type `list`)
    Is a shorthand for a directive: enlist_uri_host (WHITE) host
**util_rb_tld** [] (type `append_split`)
    This option maintains list of valid TLDs in the RegistryBoundaries code.
**util_rb_2tld** [] (type `append_split`)
    This option maintains list of valid 2nd-level TLDs in the RegistryBoundaries code.
**util_rb_3tld** [] (type `append_split`)
    This option maintains list of valid 3rd-level TLDs in the RegistryBoundaries code.


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
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_mailfrom_matches_rcvd
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_from_in_default_whitelist
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_forged_in_whitelist
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_to_in_more_spam
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_forged_in_default_whitelist
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_uri_host_listed
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_uri_host_in_whitelist
    :noindex:
.. automethod:: pad.plugins.wlbl_eval.WLBLEvalPlugin.check_uri_host_in_blacklist
    :noindex:

Tags
====

Non

