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

* :meth:`multipart_alternative_difference(min, max) <pad.plugins.body_eval.BodyEval.multipart_alternative_difference>`
* :meth:`multipart_alternative_difference_count(ratio, minhtml) <pad.plugins.body_eval.BodyEval.multipart_alternative_difference_count>`
* :meth:`check_blank_line_ratio(min, max, minlines=1) <pad.plugins.body_eval.BodyEval.check_blank_line_ratio>`
* :meth:`tvd_vertical_words(min, max) <pad.plugins.body_eval.BodyEval.tvd_vertical_words>`
* :meth:`check_stock_info(minwords) <pad.plugins.body_eval.BodyEval.check_stock_info>`

Tags
====

None
