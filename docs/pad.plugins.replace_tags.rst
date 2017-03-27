***********
ReplaceTags
***********

This plugin allows rules to contain regular expression tags.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.replace_tags.ReplaceTags

    replace_start <
    replace_end   >
    replace_tag   A       [a@]
    replace_tag   G       [gk]
    replace_tag   I       [il|!1y\?\xcc\xcd\xce\xcf\xec\xed\xee\xef]
    replace_tag   R       [r3]
    replace_tag   V       (?:[vu]|\\\/)
    replace_tag   SP      [\s~_-]

    body          VIAGRA_OBFU     /(?!viagra)<V>+<SP>*<I>+<SP>*<A>+<SP>*<G>+<SP>*<R>+<SP>*<A>+/i
    describe      VIAGRA_OBFU     Attempt to obfuscate "viagra"
    replace_rules VIAGRA_OBFU

Usage
=====

After configuring the replacement tags, the tag can then be used in any
regular expression rule. By adding the extra `replace_rules NAME` line.

Options
=======

**replace_tag** [] (type `append`)
    Assign a valid regular expression to tagname.
**replace_pre** [] (type `append`)
    Assign a valid regular expression to tagname. The expression will be placed
    before each tag that is replaced.
**replace_post** [] (type `append`)
    Assign a valid regular expression to tagname. The expression will be placed
    between each two immediately adjacent tags that are replaced.
**replace_inter** [] (type `append`)
    Assign a valid regular expression to tagname. The expression will be placed
    after each tag that is replaced.
**replace_rules** [] (type `append_split`)
    Specify a list of symbolic test names (separated by whitespace) of tests
    which should be modified using replacement tags. Only simple regular
    expression body, header, uri, full, rawbody tests are supported.
**replace_end** > (type `str`)
    String(s) which indicate the end of a tag inside a rule. Only tags enclosed
    by the start and end strings are found and replaced.
**replace_start** < (type `str`)
    String(s) which indicate the start of a tag inside a rule. Only tags enclosed
    by the start and end strings are found and replaced.

EVAL rules
==========

None

Tags
====

None
