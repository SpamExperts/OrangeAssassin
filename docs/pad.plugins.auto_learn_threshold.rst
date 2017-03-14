
******************
AutoLearnThreshold
******************

Implements the functionality to submit messages for learning when they
fall outside the defined threshold

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.auto_learn_threshold.AutoLearnThreshold
    bayes_auto_learn_threshold_nonspam 0.5 # optional, default is 0.1
    bayes_auto_learn_threshold_nonspam 12.0 # optional, default is 12.0
    bayes_auto_learn_on_error 1 # optional, default is 1

Usage
=====

When this plugin is loaded after the message has been evaluated by all other
plugins it will be evaluated for autolearning. It will be evalute accoring to the
following rules:

It calculates the total score for the message from tests that don't have the
noautolearn, userconf tflags

General requirements

- The autolearn score includes at least 3 body and 3 header tests scores
  (unless any test has the tflag **autolearn_force** in which case the header
   and body tests requirement drops to -99)
- The bayes plugin classified the message differently than this plugin
  (unless **bayes_auto_learn_on_error** option is set to 0)


Case 1
------
- The message score was higher than the required score
- The message is considered spam by the autolearn plugin
  (the autolearn score is higher than the spam threshold)
- The score from tests with the **learn** tflag is at least -1


Case 2
------
- The message score was lower than the required score
- The message is considered ham by the autolearn plugin
  (the autolearn score is lower than the ham threshold)
- The score from tests with the **learn** tflag is at least 1


Options
=======

**bayes_auto_learn_threshold_nonspam** 0.1 (type `float`)
    Messages that score below this value will be submitted for learning as HAM
**bayes_auto_learn_threshold_spam** 12.0 (type `float`)
    Messages that score over this value will be submitted for learning as SPAM
**bayes_auto_learn_on_error** 0 (type `bool`)
    Messages will be submitted for learning only if Bayes disagrees with the
    classification


EVAL rules
==========

This plugin doesn't expose any eval rules

Tags
====

<Describe TAGS>

