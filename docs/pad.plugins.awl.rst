*******************
AutoWhiteListPlugin
*******************

Normalize scores via auto-whitelist

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.awl.AutoWhiteListPlugin

    user_awl_sql_username username
    user_awl_sql_password password
    user_awl_sql_table tablename
    user_awl_dsn DBI:databasetype:databasename:hostname:port

    header AWL             eval:check_from_in_auto_whitelist()
    describe AWL           From: address is in the auto white-list
    priority AWL           1000

Usage
=====

The schema for the auto whitelist::

    CREATE TABLE `awl` (
      `username` varchar(255) NOT NULL DEFAULT '',
      `email` varchar(200) NOT NULL DEFAULT '',
      `ip` varchar(40) NOT NULL DEFAULT '',
      `count` int(11) NOT NULL DEFAULT '0',
      `totscore` float NOT NULL DEFAULT '0',
      `signedby` varchar(255) NOT NULL DEFAULT '',
      PRIMARY KEY (`username`,`email`,`signedby`,`ip`)
    ) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Used by SpamAssassin for the auto-whitelist functionality'


Options
=======

**auto_whitelist_ipv4_mask_len** 16 (type `int`)
    The AWL database keeps only the specified number of most-significant bits
    of an IPv4 address in its fields, so that different individual IP addresses
    within a subnet belonging to the same owner are managed under a single
    database record. As we have no information available on the allocated
    address ranges of senders, this CIDR mask length is only an approximation.
    The default is 16 bits, corresponding to a former class B. Increase the
    number if a finer granularity is desired, e.g. to 24 (class C) or 32.
    A value 0 is allowed but is not particularly useful, as it would treat the
    whole internet as a single organization. The number need not be a multiple
    of 8, any split is allowed.
**auto_whitelist_factor** 0.5 (type `float`)
    How much towards the long-term mean for the sender to regress a message.
    Basically, the algorithm is to track the long-term mean score of messages for
    the sender (C<mean>), and then once we have otherwise fully calculated the
    score for this message (C<score>), we calculate the final score for the
    message as: ``C<finalscore> = C<score> +  (C<mean> - C<score>) * C<factor>``
    So if C<factor> = 0.5, then we'll move to half way between the calculated
    score and the mean.  If C<factor> = 0.3, then we'll move about 1/3 of the way
    from the score toward the mean.  C<factor> = 1 means just use the long-term
    mean; C<factor> = 0 mean just use the calculated score.
**auto_whitelist_ipv6_mask_len** 48 (type `int`)
    The AWL database keeps only the specified number of most-significant bits
of an IPv6 address in its fields, so that different individual IP addresses
    within a subnet belonging to the same owner are managed under a single
    database record. As we have no information available on the allocated address
    ranges of senders, this CIDR mask length is only an approximation. The default
    is 48 bits, corresponding to an address range commonly allocated to individual
    (smaller) organizations. Increase the number for a finer granularity, e.g.
    to 64 or 96 or 128, or decrease for wider ranges, e.g. 32.  A value 0 is
    allowed but is not particularly useful, as it would treat the whole internet
    as a single organization. The number need not be a multiple of 4, any split
    is allowed.

EVAL rules
==========

.. automethod:: pad.plugins.awl.AutoWhiteListPlugin.check_from_in_auto_whitelist
    :noindex:

Tags
====

**_AWL_**
    AWL modifier
**_AWLMEAN_**
    Mean score on which AWL modification is based
**_AWLCOUNT_**
    Number of messages on which AWL modification is based
**_AWLPRESCORE_**
    Score before AWL
