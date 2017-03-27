*************
SpamCopPlugin
*************

SpamCop is a service for reporting spam. SpamCop determines the origin of
unwanted email and reports it to the relevant Internet service providers.
Note that spam reports sent by this plugin to SpamCop each include the
entire spam message.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.spam_cop.SpamCopPlugin

Usage
=====

N/A

Options
=======

**spamcop_from_address** "" (type `str`)
    This address is used during manual reports to SpamCop as the From: address.
    You can use your normal email address. If this is not set, a guess will be
    used as the From: address in SpamCop reports.
**spamcop_to_address** "spamassassin-submit@spam.spamcop.net" (type `str`)
    Your customized SpamCop report submission address. You need to obtain this
    address by registering at http://www.spamcop.net/. If this is not set,
    SpamCop reports will go to a generic reporting address for OrangeAssassin
    users and your reports will probably have less weight in the SpamCop system.
**spamcop_max_report_size** 50 (type `int`)
    Messages larger than this size (in kilobytes) will be truncated in report
    messages sent to SpamCop. The default setting is the maximum size that
    SpamCop will accept at the time of release.
**dont_report_to_spamcop** False (type `bool`)

EVAL rules
==========

None

Tags
====

None
