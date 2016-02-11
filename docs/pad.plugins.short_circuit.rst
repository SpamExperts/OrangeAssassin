*************
Short Circuit
*************

This plugin implements simple, test-based shortcircuiting.
Short-circuiting a test will force all other pending rules
to be skipped, if that test is hit.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.short_circuit.ShortCircuit

    report Details: _SCORE_/_REQD_ (_SCTYPE_)
    add_header all Status "_YESNO_, score=_SCORE_ shortcircuit=_SCTYPE_"

    body            TEST_RULE   /test/
    describe        TEST_RULE   Test Rule
    score           TEST_RULE   0.01
    shortcircuit    TEST_RULE   on

Usage
=====

To short circuit a rule simply add the `shortcircuit` command to
the configuration file::

    shortcircuit    <rule identifier>   [on|off|ham|spam]

Depending on the short-circuit type you select, the following
behaviour is applied:

**on**
    If the rule matches the message the all following rules are
    skipped. No adjustments are done to the message score and
    the final result is whatever the total is at that point.

**off**
    Disables short-circuiting. The rule simply behaves as normal.

**spam**
    If the rule matches the message the all following rules are
    skipped. The message score is adjusted by adding the value
    of `shortcircuit_spam_score`.

**ham**
    If the rule matches the message the all following rules are
    skipped. The message score is adjusted by adding the value
    of `shortcircuit_ham_score`.

Options
=======

**shortcircuit_spam_score** `float` 100.0
    The score applied for short-circuited rules with the `spam`
    type

**shortcircuit_ham_score** `float` -100.0
    The score applied for short-circuited rules with the `ham`
    type

Tags
====

**_SCRULE_**
    The name of the rule that caused the short-circuit. This
    gets the value `none` if there was no such rule.

**_SCTYPE_**
    The type of short-circuit used. This can have the following
    values: on, off, ham or spam.

**_SC_**
    Combines the other two tags for convenience. Equivalent to
    `_SCRULE_ (_SCTYPE_)`
