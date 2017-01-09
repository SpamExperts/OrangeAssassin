*********
MIME Eval
*********

Expose some eval rules that do checks on the MIME headers

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.mime_eval.MIMEEval

    body CHARSET_FARAWAY            eval:check_for_faraway_charset()
    describe CHARSET_FARAWAY        Character set indicates a foreign language

Usage
=====

This plugin exposes various eval rules that perform checks on the MIME headers
of the message.

See documentation for each individual rule.


Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_mime
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_mime_html
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_mime_html_only
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_mime_multipart_ratio
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_msg_parse_flags
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_ascii_text_illegal
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_abundant_unicode_ratio
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_faraway_charset
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_for_uppercase
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_ma_non_text
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_base64_length
    :noindex:
.. automethod:: pad.plugins.mime_eval.MIMEEval.check_qp_ratio
    :noindex:

Tags
====

N/A
