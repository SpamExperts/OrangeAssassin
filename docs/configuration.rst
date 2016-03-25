*************
Configuration
*************

This page describes how to configure SpamPAD.

.. _configuration-files:

Configuration files
===================

The SpamPAD configuration can be separated into multiple files. These are read
from the `configpath` and `sitepath` directories. You can change these
locations using the `-C` or `-S` options of the daemon and CLI script.

More files can be included from other location by using the include option::

    # This include a different file
    include /etc/spampad/custom_prefs.cf

Users can also configure custom preferences in their home directory when
running the CLI script. This location is also customizable with the `-P`
option. Note that daemon does NOT accept user preferences by default and you
will have to enable it with `allow_user_rules`.

.. note::

    The order the files IS important as it determines the order of the rules
    loading and executing. To change the order in which the rules are checked
    see the :ref:`priority rule option <priority-rule-options>`.

.. _configuration-types:

Configuration types
===================

SpamPAD accepts various types of configuration options. The current types are:

**int**
    Integer number.
**float**
    Floating point number.
**bool**
    Boolean value, can be one of: 1, 0, True, False.
**str**
    A simple string value.
**list**
    A comma separated list of strings. For example defining this::

        pyzor_servers public.pyzor.org,my.pyzor.example.com

    Will be evaluated as::

        ["public.pyzor.org", "my.pyzor.example.com"]

    Defining the same option multiple time WILL override the previous
    setting.
**append**
    This option can be specified multiple times without overriding previous
    settings. Every time the option is specified the values are appended to
    to a list. For example for the report option::

        report This message is was marked as spam on _HOSTNAME_.
        report The message score was _SCORE_.
        report Contact me at _CONTACTADDRESS_.

    Will result in the final option being evaluated as::

        ["This message is was marked as spam on _HOSTNAME_.",
         "The message score was _SCORE_.",
         "Contact me at _CONTACTADDRESS_."]
**clear**
    Clears one or more of the append type option.

.. _configuration-options:

Options
=======

.. _filtering-options:

Filtering options
-----------------

**required_score** 5.0 (type `float`)
    Set minimum required score for a message to get for it to be treated as
    spam.
**use_bayes**: True (type `bool`)
    Controls whether or not the bayesian filter should be checked.
**use_network**: True (type `bool`)
    Controls whether or not network checks should be perfomed on the message.
**envelope_sender_header**: ["X-Sender", "X-Envelope-From", "Envelope-Sender", "Return-Path", "From"] (type `append`)
    Specifies which header should be used when determining the envelope sender
    of the message.
**allow_user_rules**: False (type `bool`)
    If set to True the daemon will also load user preferences. Note that this
    can be a possible security risk, which is why it's disabled by default.


Message modifications
---------------------

**add_header** [] (type `append`)
    Adds one header to the message. The value for this option must be in the
    following format::

        add_header [all|spam|ham] [header_name] [header_value]

    If the first argument is `all` then the header is added to ALL
    messages. Otherwise the header is added only to messages that were
    classified as spam or ham. Note that the header name will be append with
    `X-Spam-` and the header string ill have any TAGS replaced with their
    values. For example::

        add_header all PAD-Report Checked with SpamPAD _SCORE_

    Will add a new header to every message like::

        X-Spam-PAD-Report: Checked with SpamPAD <score>
**remove_header** [] (type `append`)
    Removes all header from message with the specified name. The value for this
    option must be in the following format::

         remove_header [all|spam|ham] [header_name]

**clear_headers** N/A (type `clear`)
    Clear all previously set options that add or remove headers (i.e. any
    from `add_header` or `remove_header`).

.. _reporting-options:

Reporting
---------

**report** [] (type `append`)
    A list of strings that form the report. The report can be returned when
    the CLI script is called with `-t` and is also included by default in
    messages that have been marked as spam. Note that this string will have
    any TAGS replaced with their values.
**clear_report_template** N/A (type `clear`)
    Clear the report list.
**report_safe** 1 (type `int`)
    When this option is set to 0 only header modification are made to the
    messages. In addition an X-Spam-Report will be added to the messages that
    contains the `report` for this message. Note this only applies to
    messages classified as spam.

    When this option is set to 1 and the messages is marked as spam, SpamPAD
    will generate a multipart/mixed messages. The new message will have
    `text/plain` part with the SpamPAD report and `message/rfc882` part with
    the original message.

    When the option is set to 2 instead of using a `messages/rfc882` content
    type, a text/plain one will be used instead.
**report_contact** None (type `str`)
    Set the contact address that is exposed in the `_CONTACTADDRESS_` tag.

.. _dns-options:

DNS
---

**dns_server** [] (type `append`)
    Specify a list of nameservers to query when doing DNS lookups. These can
    specified as IPv4 or IPv6 address with an optional port followed. Example::

        dns_server 127.0.0.1
        dns_server 127.0.0.1:53
        dns_server [::1]:53

    If no such nameserver is specified, the default ones from `/etc/resolv.conf`
    will be used.
**clear_dns_servers** N/A (type `clear`)
    Clear any custom nameserver set by `dns_server`.
**default_dns_lifetime** 10.0 (type `float`)
    Sets the timeout for a full DNS lookup. I.e. any DNS lookup will have at
    most 10 seconds to get a valid response from one of the DNS server.
**default_dns_timeout** 2.0 (type `float`)
    Set the timeout for a DNS lookup from a single nameserver.
**dns_available** yes ( type `str` )
    Configure whether DNS resolving is available or not. If you specify it as
    yes or no then no tests will be performed. Example::
        
        dns_available yes
        dns_available no
    
    If you want to determine the availability dynamically you can use the value
    `test` or `test: domain1 domain2 ... domainN`. In that case a query will be
    performed for three of the domain names given chosen at random. If any of
    them gives a response then dns will be considered available.
    The test will be performed again according to the 
    :ref: `dns_test_interval option <dns_test_interval>` Example::

        dns_available test:domain1 domain2 domain3 domain4

    If no domains are specified with the test option then a default list will
    be used Example::
        
        dns_available test

**dns_test_interval** 600s ( type `str` )
    If you set the :ref:`dns_available option <dns_available>` to `test` then
    by setting, the actual test will be performed no sooner that the interval
    you set here. You can set just a number or a number with a suffix to
    determine the the time unit (s, m, h, d, w) Example::
    
        dns_test_interval 600
        dns_test_interval 600s
        dns_test_interval 10m 

**dns_query_restriction** "" ( type `string` )
    Configure restrictions for querying the dns. Almost all dns queries are
    subject to the dns_query_restriction. Before performing a query the domain
    is tested against these restrictions and when a match occurs the the query
    is performed according to the allow/deny setting for that match. If no
    match is found then the query is allowed by default.
    
    when testing a domain it's labels are stripped succesively to check if a
    parent matches. 
        
    All of the following would be denied example.com, 1.example.com
    1.2.example.com ::

        dns_query_restriction deny example.com

    This way 1.example.com 2.1.example.com would be denied
    but example.com would be allowed ::

        dns_query_restriction deny 1.example.com

    You can deny a wider group of domains and only allow one subgroup like this::

        dns_query_restriction deny example.com
        dns_query_restriction allow 1.example.com

    In this case example.com and all of it's subdomsins would be denied except
    1.example.com and all of it's subdomains which would be allowed


Tags
====

.. _received-headers-tags:

Template tags
-------------
The following tags can be used as placeholders in certain options.
They will be replaced by the corresponding value when they are used.

**_YESNOCAPS_**
    "YES"/"NO" for is/isn't spam
**_YESNO_**
    "Yes"/"No" for is/isn't spam
**_REQD_**
    Message threshold
**_VERSION_**
    version (eg. 1.0a)
**_SUBVERSION_**
    sub-version/code revision date (eg. 2016-01-15)
**_HOSTNAME_**
    Hostname of the machine the mail was processed on
**_TESTS(,)_**
    tests hit separated by "," (or other separator)
**_PREVIEW_**
    content preview
**_REPORT_**
    terse report of tests hit (for header reports)
**_SUMMARY_**
    summary of tests hit for standard report (for body reports)
**_CONTACTADDRESS_**
    Contents of the 'report_contact' setting

Received Headers tags
---------------------
These are metadata parsed from the last received header ( top most ) and exposed
in tags which can be accessed with the next keywords:

**_RDNS_**
    Reverse DNS made automatically by MTA
**_HELO_**
    Helo identification
**_IP_**
    Relay IP address
**_ENVFROM_**
    For routing the received e-mail to the intended recipient(s)
**_BY_**
    Mail server name and system: domain of the server receiving the e-mail
**_IDENT_**
    Ident lookup
**_ID_**
    Message identification number given by the machine who received the message
**_AUTH_**
    Authentication

