*********
Body Eval
*********

Exposes several eval rules that perform checks on the body of the message.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.body_eval.BodyEval

    body        MPART_ALT_DIFF      eval:multipart_alternative_difference('99', '100')
    describe    MPART_ALT_DIFF      HTML and text parts are different

    body        MPART_ALT_DIFF_COUNT    eval:multipart_alternative_difference_count('3', '1')
    describe    MPART_ALT_DIFF_COUNT    HTML and text parts are different


Usage
=====

This plugin only has EVAL methods. See :ref:`eval-rule` for general
details on how to use such methods.

Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.body_eval.BodyEval.multipart_alternative_difference
    :noindex:
.. automethod:: pad.plugins.body_eval.BodyEval.multipart_alternative_difference_count
    :noindex:
.. automethod:: pad.plugins.body_eval.BodyEval.check_blank_line_ratio
    :noindex:
.. automethod:: pad.plugins.body_eval.BodyEval.tvd_vertical_words
    :noindex:
.. automethod:: pad.plugins.body_eval.BodyEval.check_stock_info
    :noindex:

Tags
====

None
