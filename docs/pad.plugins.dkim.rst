**********
DKIMPlugin
**********

This plugin performs verifications on DKIM signature

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.dkim.DKIMPLugin

Usage
=====

<Description>

Options
=======

**whitelist_from_dkim** [] (type `list`)
    Used to whitelist sender addresses which send mail that is often tagged
    (incorrectly) as spam.
**def_whitelist_from_dkim** [] (type `append_split`)
    Same as 'whitelist_from_dkim', but used for the deafult whitelist entries.
**unwhitelist_from_dkim** [] (type `list`)
    Removes an email address with its corresponding signing-domain field from
    def_whitelist_from_dkim and whitelist_from_dkim tables, if it exists.
**adsp_override** [] (type `list`)
    To override domain's signing practices in a SpamPad configuration file,
    specify an adsp_override directive for each sending domain to be overridden.
    An optional second parameter is one of the following keywords:
    nxdomain, unknown, all, discardable, custom_low, custom_med, custom_high.
    Absence of this second parameter implies discardable.
**dkim_minimum_key_bits** 1024 (type `int`)
    The smallest size of a signing key (in bits) for a valid signature to be
    considered for whitelisting.
EVAL rules
==========

.. automethod:: pad.plugins.dkim.DKIMPlugin.check_dkim_signed
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_dkim_valid
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_dkim_valid_author_sig
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_dkim_adsp
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_dkim_dependable
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_for_dkim_whitelist_from
    :noindex:
.. automethod:: pad.plugins.dkim.DKIMPlugin.check_for_def_dkim_whitelist_from
    :noindex:

Tags
====

<Describe TAGS>