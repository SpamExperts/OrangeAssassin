**********
Rule Types
**********

.. _full-rule:

Full Rule
=========

Example rule::

    full        NULL_IN_MESSAGES       /\x00/
    describe    NULL_IN_MESSAGES       Message has NULL characters.
    score       NULL_IN_MESSAGES       0.5

The `full` rule type matches a regular expression against the full raw
message. This means that no parts are decoded and the message is in the same
format as it was received.

.. _body-rule:

Body Rules
==========

The body rules will perform checks on the body part of the message. This means
that anything after the headers is included in the check.

Body Type
---------

Example rule::

    body        LOOK_FOR_SPAM       /spam/
    describe    LOOK_FOR_SPAM       Message has spam in it's text.

The `body` rule type matches a regular expression against extracted text of the
message. The message is decoded and only the text parts are included when
matching.

The message is:

- decoded and stripped of any headers
- all line break replaced with a single space
- all HTML tags removed
- subject headers prepended

RawBody Type
------------

Example rule::

    rawbody     LOOK_FOR_SPAM       /spam/
    describe    LOOK_FOR_SPAM       Message has spam in it's raw text.

A similar variant of this check is `rawbody`, which unlike `body` matches the
regular expression against the raw body of the message, without decoding any
parts or removing any HTML tags.

The message is:

- decoded and stripped of any headers

.. _header-rule:

Header Rule
===========

The header rule will match regular various regular expression only against one
or more headers of the message. The body of the message is completely ignored.

The are generally defined in the following format::

    header <rule identifier> <header name> <match operator> <regex>

Where the `<match operator>` can be either:

* `=~` for positive matching, i.e. the rule matches if the regex matches
* `!~` for negated matching, i.e. the rule matches if the regex doesn't match


.. note::

    If a message has multiple headers with the same name, **all** headers are
    verified.

Header Type
-----------

Example Rule::

    header      LOOK_FOR_SUBJECT_SPAM   Subject =~ /spam/
    describe    LOOK_FOR_SUBJECT_SPAM   Message has "spam" in Subject.

Note that the check is done on the decoded version of the subject and not on
the raw version. For example for a header like::

    Subject: =?utf8?B?VGhpcyBzcGFtIGlz?=

The check will be done on::

    Subject: This spam is

Modifiers
---------

For the header rules you can also append various modifiers to the header name.
These will change the string on which the check is done.

* The **RAW** modifier will perform the check on the raw header instead of the
  decoded version. Example::

    header      UTF8_ENCODED_SUBJECT   Subject:raw =~ /^=?utf8?/
    describe    UTF8_ENCODED_SUBJECT   Subject is encoded with UTF-8
    score       UTF8_ENCODED_SUBJECT   -0.5

Taking the above example the regex is matched against the original header::

    Subject: =?utf8?B?VGhpcyBzcGFtIGlz?=

* The **ADDR** modifier will perform the check on the address part of the
  header. Example::

    header      EXAMPLE_COM_SENDER   From:addr =~ /@example.com/
    describe    EXAMPLE_COM_SENDER   Message is from @example.com
    score       EXAMPLE_COM_SENDER   4

The specified header is parsed and the email address is extracted before the
check is performed. For a header like::

    From: Alexandru Chirila <chirila@example.com>

The check will be performed on `chirila@example.com`

* The **NAME** is similar to the addr modifier, but rather than checking the
  email address, the name of the user will be used. Example::

    header      EXAMPLE_COM_SENDER   From:name =~ /Alex/
    describe    EXAMPLE_COM_SENDER   Message is from Alex
    score       EXAMPLE_COM_SENDER   -4

Taking the above example the check is performed on the name instead of the
full header (`Alexandru Chirila`)

Exists
------

Another modifier that can be prepended is the `exists` modifier. This will make
the rule match if the message has at least one header with that name.
Regardless of the header value.

Note that unlike the other modifiers this one is prepended instead of appended.
Example::

    header      DKIM_EXISTS     exists:DKIM-Signature
    describe    DKIM_EXISTS     Message has DKIM signature


Header names
------------

Any header name can be used when matching. However there are a few special
header names that will change the behaviour.

* The **ALL** header name can be used to check all header of the message.
  Example::

    header      ONE_HEADER_WITH_SPAM   ALL =~ /spam/
    describe    ONE_HEADER_WITH_SPAM   One header had "spam"

* The **ToCc** header name can be used to check all the `To` and `Cc` header
  of the message. Example::

    header      ONE_EXAMPLE_RECIPIENT   ToCc =~ /@example.com/
    describe    ONE_EXAMPLE_RECIPIENT   One recipient to @example.com

* The **MESSAGEID** header name can be used to check various MessageID headers
  by  a regular expression. Example::

    header      ONE_EXAMPLE_ID   MESSAGEID =~ /example.com/
    describe    ONE_EXAMPLE_ID   Message ID from example.com

.. _mime-header-rule:

MimeHeader Rule
===============

The `mimeheader` rule is very similar to the `header` rule type, but unlike it,
all the checks are done on MIME header instead of the regular message headers.

The only modifier available for the `mimeheader` is **RAW**. Examples::

    mimeheader  HAS_PDF_ATTACHMENT  Content-Type =~ /^application\/pdf/i
    describe    HAS_PDF_ATTACHMENT  Message has pdf attachments

    mimeheader  HAS_PDF_ATTACHMENT  Content-Type:raw =~ /^application\/pdf/i
    describe    HAS_PDF_ATTACHMENT  Message has pdf attachments

.. _uri-rule:

URI Rule
========

The `uri` rules type will match regular expression on all URL extracted from
the message. Example::

    uri         HAS_EXAMPLE_HTTPS   /^https:\/\/example.com$/\
    describe    HAS_EXAMPLE_HTTPS   Message has HTTPS link to example.com

.. _meta-rule:

Meta Rule
=========

The `meta` rules can be used to combine various rules in complex logic
expression. This is usually used with rules that are not checked by default.

Operators that can be used in `meta` rules:

* `&&` - and operator; matches if both expression match
* `||` - or operator; matches if at least one expression matches
* `!` - not operator; matches if the expression doesn't match
* `()` - parentheses can be used to group multiple expressions

Examples::

    # These rules are only checked as part of meta rules.
    header      __DKIM_EXISTS           exists:DKIM-Signature
    header      __EXAMPLE_COM_SENDER    From:addr =~ /@example.com/
    uri         __HAS_EXAMPLE_HTTPS     /^https:\/\/example.com$/\

    # The meta rules combine the above.
    meta        NO_EXAMPLE_DKIM         __EXAMPLE_COM_SENDER && !__DKIM_EXISTS
    describe    NO_EXAMPLE_DKIM         @example.com sender but no DKIM signature
    score       NO_EXAMPLE_DKIM         5

    meta        EXAMPLE_URL_SENDER      __EXAMPLE_COM_SENDER || __HAS_EXAMPLE_HTTPS
    describe    EXAMPLE_URL_SENDER      example.com in sender or URL
    score       EXAMPLE_URL_SENDER      2

    # We can even combine meta rules in other meta rules.
    meta        NO_DKIM_AND_URL         EXAMPLE_URL_SENDER && NO_EXAMPLE_DKIM
    describe    NO_DKIM_AND_URL         No DKIM signature and example.com URL
    score       NO_DKIM_AND_URL         3.5

.. _eval-rule:

Eval Rule
=========

The `eval` rule type will simply call a registered evaluation function from
a plugin and apply the score if function returns True. Example::

    full        PYZOR_CHECK     eval:check_pyzor()
    describe    PYZOR_CHECK     Listed in Pyzor (http://pyzor.org/)
    score       PYZOR_CHECK     5.0

See the specific plugins documentation for all the EVAL methods it exposes and
any other relevant details.

.. note::

    When checking the method code reference ignore the **msg** and **target**
    parameters as those are passed by default to all eval methods.

