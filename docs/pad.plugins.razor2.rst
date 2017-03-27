************
Razor2Plugin
************

Checks the message against the Razor server.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.pyzor.Razor2Plugin

    body        RAZOR2	    eval:check_razor2()
    describe    RAZOR2   	Listed in Razor2 (http://razor.sf.net/)
    score       RAZOR2       1

Usage
=====

This plugin exposes a two eval rules that checks the message
against the Razor server. "check_razor2_range" method it is implemented,
but in order to verify a message, you can use PyzorPlugin.
For more information about pyzor see the
`Razor documentation <http://razor.sf.net/>`_

Options
=======

**use_razor2** True (type `bool`)
    Controls whether or not the message should be checked against the
    Razor server.
**razor_config** "" (type `str`)
    Define the filename used to store Razor's configuration settings.
    Currently this is left to Razor to decide.
**razor_timeout** 5 (type `int`)
    How many seconds you wait for Razor to complete before you go on without
    the results.

EVAL rules
==========

.. automethod:: pad.plugins.razor2.Razor2Plugin.check_razor2
    :noindex:

Tags
====

None
