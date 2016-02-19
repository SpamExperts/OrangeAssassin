*************
Writing Rules
*************

The rules configuration defines the checks that are done on the messages.
Each rule has a unique identifier, writen in all caps, and can have multiple
options.

After all rules are checked a final score is provided for the message and
according to the `required_score` option the message is marked is spam.

.. _defining-rules:

Defining a rule
===============

Every rule must be in the following format::

    <rule type>     <rule identifier>   <value>

Simple rule definition example::

    body        LOOK_FOR_TEST   /test/

Where `body` is the rule type, `LOOK_FOR_TEST` is the identifier and the value
is `/test/`. This rule will look for the string "test" in the body of the
message and the rule will be triggered if it is found. When a rule is triggered
the corresponding score is added to the total score of the message.

For every message all defined rules are checked and the score applied with
the following exceptions:

* Any rule that has an identifier starting with `__` will not be checked.
* Any rule that has a score of `0` will not be checked.

.. note::

    Rule that are not checked can still be used in combination with other
    rules. See the `meta` rule type for more details.

.. _rule-options:

Rule options
============

Additional options can be configured to any rule in the following format::

    <option name> <rule identifier> <value>

The parser will use the unique identifier to configure the option to the
specific rule with the same name. The option **doesn't** have to be added
immediately after the rule definition (i.e. the next line), but it has to be
somewhere after the initial rule definition.

.. note::

    Defining the same rule or option twice **will override** the previous
    value.

.. _score-rule-options:

Scoring option
==============

Any rule defined will have by default a score of **1.0**. This can be adjusted
by using the score option:

* A positive score means that the message is more likely to be spam
* A negative score means that the message is more likely to be legitimate
* A score of `0` disables the rule

Examples::

    body    LOOK_FOR_TEST /test/
    score   LOOK_FOR_TEST 1.5

    header  LOOK_FOR_SUBJECT_TEST Subject =~ /test/
    score   LOOK_FOR_SUBJECT_TEST -5

More advance scoring can be specified for any rule depending on whether the
Bayesian classifier and network tests are activated. For example::

    body    LOOK_FOR_TEST /test/
    score   LOOK_FOR_TEST 1 1.5 0.5 3

For the advanced scoring the following final score will be used:

* The first score if the Bayesian classifier and networks tests are disabled
  (for this case `1`)
* The second score if the Bayesian classifier is disabled but the networks
  tests are enabled (for this case `1.5`)
* The third score if the Bayesian classifier is enabled but the networks
  tests are disabled (for this case `0.5`)
* The fourth score if the Bayesian classifier and the networks tests are
  enabled (for this case `3`)


.. note::

    This configuration is optional and any rule that doesn't have it will
    get the default score of `1.0`.

.. _describe-rule-options:

Describe option
===============

The describe option can be used to provide a small text that describes what
the rule is doing. This text is useful when debugging and when generating
various reports.

Example configuration::

    report ==== Start report ====
    report _REPORT_

    body        LOOK_FOR_TEST /test/
    describe    LOOK_FOR_TEST Look for the test string in the body.

And the result for a message that matches::

    $ ./scripts/match.py -t -C /root/myconf/ --sitepath /root/myconf/ < /root/test.eml
    Subject: Do you think this is Spam?

    This is a test.


    ==== Start report ====

    * 1.0 LOOK_FOR_TEST BODY: Look for the test string in the body.


For more details on the report see the report section of the documentation.

.. note::

    This configuration is optional and any rule that doesn't have it will
    get "No description available".
