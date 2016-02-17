
*************
TextCatPlugin
*************

Detect the language of the message.

Current available languages:

af ar bg bn ca cs cy da de el en es et fa fi fr gu
he hi hr hu id it ja kn ko lt lv mk ml mr ne nl no
pa pl pt ro ru sk sl so sq sv sw ta te th tl tr uk
ur vi zh-cn zh-tw

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.textcat.TextCatPlugin

Usage
=====

<Description>

Options
=======

**textcat_optimal_ngrams** 0 (type `int`)
    <Option description>
**textcat_max_ngrams** 400 (type `int`)
    <Option description>
**ok_languages** all (type `list`)
    <Option description>
**textcat_acceptable_prob** 0.7 (type `float`)
    <Option description>
**inactive_languages**  (type `list`)
    <Option description>
**textcat_acceptable_score** 1.05 (type `float`)
    <Option description>
**textcat_max_languages** 5 (type `int`)
    <Option description>

EVAL rules
==========

.. automethod:: pad.plugins.textcat.TextCatPlugin.check_language
    :noindex:

Tags
====

<Describe TAGS>

