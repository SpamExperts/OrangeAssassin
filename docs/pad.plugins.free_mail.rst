***********
FreeMailPlugin
***********

Checks the headers for indication that sender's domain is that of a site
offering free email services.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.free_mail.FreeMailPlugin

    header CHECK_FREEMAIL_FROM                 eval:check_freemail_from()
    header CHECK_FREEMAIL_FROM_REGEX           eval:check_freemail_from('\d@')

    header CHECK_FREEMAIL_BODY                 eval:check_freemail_body()
    header CHECK_FREEMAIL_BODY_REGEX           eval:check_freemail_body('\d@')

    header CHECK_FREEMAIL_HEADER               eval:check_freemail_header('From')
    header CHECK_FREEMAIL_HEADER_REGEX         eval:check_freemail_header('From', '\d@')

    header CHECK_FREEMAIL_REPLY_TO eval:check_freemail_replyto('replyto')
    header CHECK_FREEMAIL_REPLY eval:check_freemail_replyto('reply')

    util_rb_tld com
    util_rb_tld net

    freemail_domains example.com
    freemail_add_describe_email 1

    report _REPORT_
    report _SCORE_
    report _TESTS_


    The output:

    * 1.0 CHECK_FREEMAIL_BODY Body has freemails
        (test[at]example.com)
    * 1.0 CHECK_FREEMAIL_REPLY Different freemails in reply header and body
        (sender[at]example.com test[at]example.com)
    * 1.0 CHECK_FREEMAIL_FROM Sender address is freemail
        (sender[at]example.com)
    * 1.0 CHECK_FREEMAIL_HEADER Header From is freemail
        (sender[at]example.com)
    4.0
    CHECK_FREEMAIL_BODY,CHECK_FREEMAIL_REPLY,CHECK_FREEMAIL_FROM,CHECK_FREEMAIL_HEADER


Usage
=====

 If From-address is freemail, and Reply-To or address found in mail body is
a different freemail address, return success.

Options
=======

**freemail_domains** [] (type `append_split`)
    List of domains to be used in checks.
    Regexp is not supported, but following wildcards work:
       ? for single character (does not match a dot)
       * for multiple characters (does not match a dot)

    For example:
       freemail_domains hotmail.com hotmail.co.?? yahoo.* yahoo.*.*

**freemail_whitelist** [] (type `append_split`)
    Emails or domains listed here are ignored (pretend they are not freemails).
    No wildcards!

**freemail_max_body_emails** 5 (type `int`)

**freemail_max_body_freemails** 3 (type `int`)

**freemail_skip_when_over_max** True (type `bool`)

**freemail_skip_bulk_envfrom** True (type `bool`)

**freemail_add_describe_email** True (type `bool`)
    When this option is True (enabled), the report also contains the email
    that matched.

    For example:

    freemail_add_describe_email 1

    * 1.0 CHECK_FREEMAIL_FROM Sender address is freemail
         (sender[at]example.com)

       AND

    freemail_add_describe_email 0

    * 1.0 CHECK_FREEMAIL_FROM Sender address is freemail


**util_rb_tld** [] (type `append_split`)
    List of valid tlds (level 1)

    For example:
    .com, .ro

**util_rb_2tld** [] (type `append_split`)
    List of valid tlds (level 2)

    For example:
    .co.uk, .org.uk

**util_rb_3tld** [] (type `append_split`)
    List of valid tlds (level 3)

    For example:
    .sa.edu.au


EVAL rules
==========

.. automethod:: pad.plugins.free_mail.FreeMailPlugin.check_freemail_from
    :noindex:
.. automethod:: pad.plugins.free_mail.FreeMailPlugin.check_freemail_header
    :noindex:
.. automethod:: pad.plugins.free_mail.FreeMailPlugin.check_freemail_body
    :noindex:
.. automethod:: pad.plugins.free_mail.FreeMailPlugin.check_freemail_replyto
    :noindex:

Tags
====